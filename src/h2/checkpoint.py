"""
Versioned, pickle-free checkpoints for transferable HTTP/2 connections.

A checkpoint is taken at a quiescent byte boundary: immediately after
``H2Connection.receive_data`` has returned and no other connection method is
running. It contains protocol state only. It never contains a socket, event
callback, logger callback, or other user object.
"""

from __future__ import annotations

import base64
import binascii
import collections
import hashlib
import json
import struct
from typing import Any

from hpack.hpack import Decoder, Encoder
from hpack.table import HeaderTable, table_entry_size
from hyperframe.exceptions import InvalidDataError, InvalidFrameError
from hyperframe.frame import ContinuationFrame, Frame, HeadersFrame, PushPromiseFrame

from .config import DummyLogger, H2Configuration
from .connection import (
    ConnectionState,
    H2Connection,
    H2ConnectionStateMachine,
)
from .errors import ErrorCodes
from .exceptions import CheckpointError, ProtocolError
from .frame_buffer import CONTINUATION_BACKLOG, FrameBuffer
from .settings import Settings, _validate_setting
from .stream import (
    H2Stream,
    H2StreamStateMachine,
    StreamClosedBy,
    StreamState,
)
from .utilities import SizeLimitDict
from .windows import LARGEST_FLOW_CONTROL_WINDOW, WindowManager

CHECKPOINT_MAGIC = b"H2CKPNT0"
CHECKPOINT_VERSION = 1
_HEADER = struct.Struct(">BQ32s")
_HEADER_OFFSET = 8
_HEADER_TOTAL = _HEADER_OFFSET + _HEADER.size
_UINT31_MAX = 2**31 - 1
_UINT32_MAX = 2**32 - 1
_STREAM_ID_MAX = _UINT31_MAX
_DEFAULT_INITIAL_WINDOW_SIZE = 65535
_CONFIG_KEYS = {
    "client_side",
    "header_encoding",
    "validate_outbound_headers",
    "normalize_outbound_headers",
    "split_outbound_cookies",
    "validate_inbound_headers",
    "normalize_inbound_headers",
}


def export_checkpoint(connection: H2Connection) -> bytes:
    """Export an immutable checkpoint from a quiescent connection."""
    if type(connection) is not H2Connection:
        msg = "Only concrete H2Connection instances have portable checkpoints"
        raise CheckpointError(msg)
    payload = {
        "format": "h2-connection-checkpoint",
        "version": CHECKPOINT_VERSION,
        "config": _export_config(connection.config),
        "connection": _export_connection(connection),
        "settings": {
            "local": _export_settings(connection.local_settings),
            "remote": _export_settings(connection.remote_settings),
        },
        "hpack": {
            "encoder": _export_encoder(connection.encoder),
            "decoder": _export_decoder(connection.decoder),
        },
        "streams": [_export_stream(stream) for stream in connection.streams.values()],
        "closed_streams": [
            [stream_id, None if closed_by is None else closed_by.value] for stream_id, closed_by in connection._closed_streams.items()
        ],
        "frame_buffer": _export_frame_buffer(
            connection.incoming_buffer,
            connection.config.client_side,
        ),
    }
    return _encode_payload(payload)


def restore_checkpoint(data: bytes) -> H2Connection:
    """Restore a checkpoint, constructing a fresh connection."""
    payload = _decode_container(data)
    config = _import_config(_mapping_value(payload.get("config"), "config"))
    connection = H2Connection(config=config)
    _import_connection(connection, _mapping_value(payload.get("connection"), "connection"))

    settings_data = _mapping_value(payload.get("settings"), "settings")
    connection.local_settings = _import_settings(
        _mapping_value(settings_data.get("local"), "local"),
        config.client_side,
    )
    connection.remote_settings = _import_settings(
        _mapping_value(settings_data.get("remote"), "remote"),
        not config.client_side,
    )
    hpack_data = _mapping_value(payload.get("hpack"), "hpack")
    connection.encoder = _import_encoder(_mapping_value(hpack_data.get("encoder"), "encoder"))
    connection.decoder = _import_decoder(_mapping_value(hpack_data.get("decoder"), "decoder"))

    connection.streams = _import_streams(
        _list(payload.get("streams"), "streams"),
        config,
    )
    connection._closed_streams = _import_closed_streams(
        _list(payload.get("closed_streams"), "closed_streams"),
    )
    _validate_stream_ids(
        config.client_side,
        connection.highest_inbound_stream_id,
        connection.highest_outbound_stream_id,
        connection.streams,
        connection._closed_streams,
    )
    _validate_connection_consistency(connection)
    connection.incoming_buffer = _import_frame_buffer(
        _mapping_value(payload.get("frame_buffer"), "frame_buffer"),
        config.client_side,
    )
    return connection


def _validate_connection_consistency(connection: H2Connection) -> None:
    if connection.max_outbound_frame_size != connection.remote_settings.max_frame_size:
        msg = "Outbound frame size does not match acknowledged remote settings"
        raise CheckpointError(msg)
    if connection.max_inbound_frame_size != connection.local_settings.max_frame_size:
        msg = "Inbound frame size does not match acknowledged local settings"
        raise CheckpointError(msg)
    if connection.encoder.header_table.maxsize != connection.remote_settings.header_table_size:
        msg = "Encoder HPACK table size does not match remote settings"
        raise CheckpointError(msg)
    if connection.decoder.max_allowed_table_size != connection.local_settings.header_table_size:
        msg = "Decoder HPACK maximum does not match acknowledged local settings"
        raise CheckpointError(msg)
    expected_header_list_size = connection.local_settings.get(
        6,
        H2Connection.DEFAULT_MAX_HEADER_LIST_SIZE,
    )
    if connection.decoder.max_header_list_size != expected_header_list_size:
        msg = "Decoder header-list limit does not match acknowledged local settings"
        raise CheckpointError(msg)
    if connection._inbound_flow_control_window_manager.max_window_size != _DEFAULT_INITIAL_WINDOW_SIZE:
        msg = "Connection inbound window baseline is invalid"
        raise CheckpointError(msg)
    initial_window_size = connection.local_settings.initial_window_size
    for stream in connection.streams.values():
        if stream.max_outbound_frame_size != connection.max_outbound_frame_size:
            msg = "Stream frame size does not match connection frame size"
            raise CheckpointError(msg)
        if stream._inbound_window_manager.max_window_size != initial_window_size:
            msg = "Stream inbound window does not match local initial window size"
            raise CheckpointError(msg)


def _encode_payload(payload: dict[str, Any]) -> bytes:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    digest = hashlib.sha256(encoded).digest()
    return CHECKPOINT_MAGIC + _HEADER.pack(CHECKPOINT_VERSION, len(encoded), digest) + encoded


def _decode_container(data: bytes) -> dict[str, Any]:
    if not isinstance(data, bytes):
        msg = "Checkpoint must be bytes"
        raise CheckpointError(msg)
    if len(data) < _HEADER_TOTAL or data[:_HEADER_OFFSET] != CHECKPOINT_MAGIC:
        msg = "Invalid checkpoint magic"
        raise CheckpointError(msg)
    version, length, digest = _HEADER.unpack(data[_HEADER_OFFSET:_HEADER_TOTAL])
    if version != CHECKPOINT_VERSION:
        msg = f"Unsupported checkpoint version {version}"
        raise CheckpointError(msg)
    if length != len(data) - _HEADER_TOTAL:
        msg = "Corrupt checkpoint length"
        raise CheckpointError(msg)
    payload_bytes = data[_HEADER_TOTAL:]
    if hashlib.sha256(payload_bytes).digest() != digest:
        msg = "Corrupt checkpoint checksum"
        raise CheckpointError(msg)
    try:
        decoded = json.loads(
            payload_bytes.decode("utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = f"Corrupt checkpoint payload: {exc}"
        raise CheckpointError(msg) from exc
    payload = _mapping_value(decoded, "checkpoint")
    if _string(payload.get("format")) != "h2-connection-checkpoint":
        msg = "Unknown checkpoint format"
        raise CheckpointError(msg)
    if _integer(payload.get("version")) != CHECKPOINT_VERSION:
        msg = "Unknown checkpoint payload version"
        raise CheckpointError(msg)
    expected = {"format", "version", "config", "connection", "settings", "hpack", "streams", "closed_streams", "frame_buffer"}
    if set(payload) != expected:
        msg = "Corrupt checkpoint sections"
        raise CheckpointError(msg)
    return payload


def _reject_json_constant(value: str) -> None:
    msg = f"Invalid JSON constant {value}"
    raise ValueError(msg)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            msg = f"Duplicate checkpoint key {key}"
            raise ValueError(msg)
        result[key] = value
    return result


def _mapping_value(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        msg = f"{name} must be an object"
        raise CheckpointError(msg)
    return value


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        msg = f"{name} must be an array"
        raise CheckpointError(msg)
    return value


def _integer(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        msg = "Expected an integer"
        raise CheckpointError(msg)
    return value


def _uint(value: Any, name: str, maximum: int) -> int:
    result = _integer(value)
    if not 0 <= result <= maximum:
        msg = f"{name} is out of range"
        raise CheckpointError(msg)
    return result


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        msg = f"{name} must be a boolean"
        raise CheckpointError(msg)
    return value


def _string(value: Any) -> str | None:
    if value is None or isinstance(value, str):
        return value
    msg = "Expected a string or null"
    raise CheckpointError(msg)


def _enum_value(value: Any, enum_type: type[Any], name: str) -> Any:
    try:
        return enum_type(_uint(value, name, _UINT31_MAX))
    except ValueError as exc:
        msg = f"Unknown {name}"
        raise CheckpointError(msg) from exc


def _b64(value: Any, name: str) -> bytes:
    encoded = _string(value)
    if encoded is None:
        msg = f"{name} must be a string"
        raise CheckpointError(msg)
    try:
        return base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        msg = f"Invalid base64 value for {name}"
        raise CheckpointError(msg) from exc


def _b64_str(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _export_config(config: H2Configuration) -> dict[str, Any]:
    if type(config) is not H2Configuration or type(config.logger) is not DummyLogger:
        msg = "Custom configuration or logger cannot be represented in a checkpoint"
        raise CheckpointError(msg)
    return {
        "client_side": config.client_side,
        "header_encoding": config.header_encoding,
        "validate_outbound_headers": config.validate_outbound_headers,
        "normalize_outbound_headers": config.normalize_outbound_headers,
        "split_outbound_cookies": config.split_outbound_cookies,
        "validate_inbound_headers": config.validate_inbound_headers,
        "normalize_inbound_headers": config.normalize_inbound_headers,
    }


def _import_config(data: dict[str, Any]) -> H2Configuration:
    if set(data) != _CONFIG_KEYS:
        msg = "Corrupt config section"
        raise CheckpointError(msg)
    header_encoding = data["header_encoding"]
    if header_encoding is not None and not isinstance(header_encoding, str):
        msg = "header_encoding must be a string or null"
        raise CheckpointError(msg)
    return H2Configuration(
        client_side=_bool(data["client_side"], "client_side"),
        header_encoding=header_encoding,
        validate_outbound_headers=_bool(data["validate_outbound_headers"], "validate_outbound_headers"),
        normalize_outbound_headers=_bool(data["normalize_outbound_headers"], "normalize_outbound_headers"),
        split_outbound_cookies=_bool(data["split_outbound_cookies"], "split_outbound_cookies"),
        validate_inbound_headers=_bool(data["validate_inbound_headers"], "validate_inbound_headers"),
        normalize_inbound_headers=_bool(data["normalize_inbound_headers"], "normalize_inbound_headers"),
    )


def _export_window(manager: WindowManager) -> dict[str, Any]:
    if type(manager) is not WindowManager:
        msg = "Custom window managers cannot be represented in a checkpoint"
        raise CheckpointError(msg)
    return {
        "max": manager.max_window_size,
        "current": manager.current_window_size,
        "processed": manager._bytes_processed,
    }


def _import_window(data: dict[str, Any]) -> WindowManager:
    if set(data) != {"max", "current", "processed"}:
        msg = "Corrupt window section"
        raise CheckpointError(msg)
    maximum = _uint(data["max"], "window maximum", LARGEST_FLOW_CONTROL_WINDOW)
    current = _uint(data["current"], "window balance", LARGEST_FLOW_CONTROL_WINDOW)
    processed = _uint(data["processed"], "processed byte count", _UINT32_MAX)
    if current > maximum:
        msg = "Window balance exceeds its maximum size"
        raise CheckpointError(msg)
    manager = WindowManager(maximum)
    manager.current_window_size = current
    manager._bytes_processed = processed
    return manager


def _export_header_table(table: Any) -> dict[str, Any]:
    entries = list(table.dynamic_entries)
    current_size = sum(table_entry_size(name, value) for name, value in entries)
    if current_size != table._current_size or current_size > table.maxsize:
        msg = "Corrupt HPACK table state"
        raise CheckpointError(msg)
    return {
        "max": table.maxsize,
        "current": current_size,
        "resized": table.resized,
        "entries": [[_b64_str(name), _b64_str(value)] for name, value in entries],
    }


def _import_header_table(data: dict[str, Any]) -> tuple[Any, int]:
    if set(data) != {"max", "current", "resized", "entries"}:
        msg = "Corrupt HPACK table section"
        raise CheckpointError(msg)
    maximum = _uint(data["max"], "HPACK table size", _UINT32_MAX)
    current = _uint(data["current"], "HPACK table current size", _UINT32_MAX)
    resized = _bool(data["resized"], "HPACK resize marker")
    entries_data = _list(data["entries"], "HPACK entries")
    entries: collections.deque[tuple[bytes, bytes]] = collections.deque()
    for item in reversed(entries_data):
        if not isinstance(item, list) or len(item) != 2:
            msg = "HPACK entries must be name/value arrays"
            raise CheckpointError(msg)
        entries.appendleft((_b64(item[0], "HPACK name"), _b64(item[1], "HPACK value")))

    table = HeaderTable()
    table.maxsize = maximum
    table.dynamic_entries.clear()
    table._current_size = 0
    for name, value in entries:
        table.add(name, value)
    if table._current_size != current or list(table.dynamic_entries) != list(entries):
        msg = "HPACK table size does not match its entries"
        raise CheckpointError(msg)
    table.resized = resized
    return table, len(entries)


def _export_encoder(encoder: Encoder) -> dict[str, Any]:
    if type(encoder) is not Encoder:
        msg = "Custom HPACK encoders cannot be represented in a checkpoint"
        raise CheckpointError(msg)
    return {
        "table": _export_header_table(encoder.header_table),
        "size_changes": list(encoder.table_size_changes),
    }


def _import_encoder(data: dict[str, Any]) -> Encoder:
    if set(data) != {"table", "size_changes"}:
        msg = "Corrupt HPACK encoder section"
        raise CheckpointError(msg)
    encoder = Encoder()
    table, _ = _import_header_table(_mapping_value(data.get("table"), "table"))
    encoder.header_table = table
    changes_data = _list(data["size_changes"], "HPACK size changes")
    changes = [_uint(value, "HPACK size change", _UINT32_MAX) for value in changes_data]
    encoder.table_size_changes = changes
    return encoder


def _export_decoder(decoder: Decoder) -> dict[str, Any]:
    if type(decoder) is not Decoder:
        msg = "Custom HPACK decoders cannot be represented in a checkpoint"
        raise CheckpointError(msg)
    result = {
        "table": _export_header_table(decoder.header_table),
        "max_header_list_size": decoder.max_header_list_size,
        "max_allowed_table_size": decoder.max_allowed_table_size,
    }
    if decoder.header_table.maxsize > decoder.max_allowed_table_size:
        msg = "Decoder HPACK table exceeds its acknowledged maximum"
        raise CheckpointError(msg)
    return result


def _import_decoder(data: dict[str, Any]) -> Decoder:
    if set(data) != {"table", "max_header_list_size", "max_allowed_table_size"}:
        msg = "Corrupt HPACK decoder section"
        raise CheckpointError(msg)
    decoder = Decoder()
    table, _ = _import_header_table(_mapping_value(data.get("table"), "table"))
    decoder.header_table = table
    decoder.max_header_list_size = _uint(
        data["max_header_list_size"],
        "maximum header list size",
        _UINT32_MAX,
    )
    decoder.max_allowed_table_size = _uint(
        data["max_allowed_table_size"],
        "allowed HPACK table size",
        _UINT32_MAX,
    )
    if table.maxsize > decoder.max_allowed_table_size:
        msg = "Decoder HPACK table exceeds its acknowledged maximum"
        raise CheckpointError(msg)
    return decoder


def _export_settings(settings: Settings) -> dict[str, Any]:
    if type(settings) is not Settings:
        msg = "Custom settings objects cannot be represented in a checkpoint"
        raise CheckpointError(msg)
    return {
        "client": settings._client,
        "queues": [[int(code), [None if value is None else value for value in values]] for code, values in settings._settings.items()],
    }


def _import_settings(data: dict[str, Any], client: bool) -> Settings:
    if (
        set(data) != {"client", "queues"}
        or _bool(
            data["client"],
            "settings owner",
        )
        != client
    ):
        msg = "Corrupt settings section"
        raise CheckpointError(msg)
    settings = Settings(client=client)
    settings._settings.clear()
    for item in _list(data["queues"], "settings queues"):
        if not isinstance(item, list) or len(item) != 2:
            msg = "Settings queue must be a code/value array"
            raise CheckpointError(msg)
        code = _uint(item[0], "setting code", 65535)
        values_data = item[1]
        if not isinstance(values_data, list) or not values_data:
            msg = "Settings queue must contain at least one value"
            raise CheckpointError(msg)
        values: collections.deque[int | None] = collections.deque()
        for index, raw_value in enumerate(values_data):
            if raw_value is None:
                if index != 0:
                    msg = "Only a settings queue's active value may be null"
                    raise CheckpointError(msg)
                values.append(None)
                continue
            value = _uint(raw_value, "setting value", _UINT32_MAX)
            error = _validate_setting(code, value, client=client)
            if error is not ErrorCodes.NO_ERROR:
                msg = f"Invalid setting {code} value {value}"
                raise CheckpointError(msg)
            values.append(value)
        settings._settings[code] = values  # type: ignore[assignment]
    return settings


def _export_connection(connection: H2Connection) -> dict[str, Any]:
    if type(connection.state_machine) is not H2ConnectionStateMachine:
        msg = "Custom connection state machines cannot be represented in a checkpoint"
        raise CheckpointError(msg)
    if type(connection._inbound_flow_control_window_manager) is not WindowManager:
        msg = "Custom window managers cannot be represented in a checkpoint"
        raise CheckpointError(msg)
    return {
        "state": connection.state_machine.state.value,
        "highest_inbound_stream_id": connection.highest_inbound_stream_id,
        "highest_outbound_stream_id": connection.highest_outbound_stream_id,
        "outbound_flow_control_window": connection.outbound_flow_control_window,
        "max_outbound_frame_size": connection.max_outbound_frame_size,
        "max_inbound_frame_size": connection.max_inbound_frame_size,
        "data_to_send": _b64_str(bytes(connection._data_to_send)),
        "inbound_window": _export_window(connection._inbound_flow_control_window_manager),
    }


def _import_connection(connection: H2Connection, data: dict[str, Any]) -> None:
    keys = {
        "state",
        "highest_inbound_stream_id",
        "highest_outbound_stream_id",
        "outbound_flow_control_window",
        "max_outbound_frame_size",
        "max_inbound_frame_size",
        "data_to_send",
        "inbound_window",
    }
    if set(data) != keys:
        msg = "Corrupt connection section"
        raise CheckpointError(msg)
    connection.state_machine.state = _enum_value(
        data["state"],
        ConnectionState,
        "connection state",
    )
    connection.highest_inbound_stream_id = _uint(
        data["highest_inbound_stream_id"],
        "highest inbound stream ID",
        _STREAM_ID_MAX,
    )
    connection.highest_outbound_stream_id = _uint(
        data["highest_outbound_stream_id"],
        "highest outbound stream ID",
        _STREAM_ID_MAX,
    )
    connection.outbound_flow_control_window = _uint(
        data["outbound_flow_control_window"],
        "outbound connection window",
        LARGEST_FLOW_CONTROL_WINDOW,
    )
    connection.max_outbound_frame_size = _frame_size(data["max_outbound_frame_size"], "outbound frame size")
    connection.max_inbound_frame_size = _frame_size(data["max_inbound_frame_size"], "inbound frame size")
    connection._data_to_send = bytearray(_b64(data["data_to_send"], "outbound data"))
    connection._inbound_flow_control_window_manager = _import_window(
        _mapping_value(data.get("inbound_window"), "inbound_window"),
    )


def _frame_size(value: Any, name: str) -> int:
    return _uint(value, name, 2**24 - 1)


def _export_stream(stream: H2Stream) -> dict[str, Any]:
    if type(stream) is not H2Stream or type(stream.state_machine) is not H2StreamStateMachine:
        msg = "Custom streams cannot be represented in a checkpoint"
        raise CheckpointError(msg)
    machine = stream.state_machine
    if machine.state is StreamState.CLOSED or machine.stream_id != stream.stream_id:
        msg = "Invalid active stream state"
        raise CheckpointError(msg)
    return {
        "stream_id": stream.stream_id,
        "state": machine.state.value,
        "client": machine.client,
        "headers_sent": machine.headers_sent,
        "trailers_sent": machine.trailers_sent,
        "headers_received": machine.headers_received,
        "trailers_received": machine.trailers_received,
        "closed_by": None if machine.stream_closed_by is None else machine.stream_closed_by.value,
        "max_outbound_frame_size": stream.max_outbound_frame_size,
        "request_method": None if stream.request_method is None else _b64_str(stream.request_method),
        "outbound_flow_control_window": stream.outbound_flow_control_window,
        "inbound_window": _export_window(stream._inbound_window_manager),
        "expected_content_length": stream._expected_content_length,
        "actual_content_length": stream._actual_content_length,
        "authority": None if stream._authority is None else _b64_str(stream._authority),
    }


def _import_stream(data: dict[str, Any], config: H2Configuration) -> H2Stream:
    keys = {
        "stream_id",
        "state",
        "client",
        "headers_sent",
        "trailers_sent",
        "headers_received",
        "trailers_received",
        "closed_by",
        "max_outbound_frame_size",
        "request_method",
        "outbound_flow_control_window",
        "inbound_window",
        "expected_content_length",
        "actual_content_length",
        "authority",
    }
    if set(data) != keys:
        msg = "Corrupt stream section"
        raise CheckpointError(msg)
    stream = H2Stream(
        _uint(data["stream_id"], "stream ID", _STREAM_ID_MAX),
        config=config,
        inbound_window_size=65535,
        outbound_window_size=65535,
    )
    machine = stream.state_machine
    machine.state = _enum_value(data["state"], StreamState, "stream state")
    if machine.state is StreamState.CLOSED:
        msg = "Closed streams must be stored in the closed-stream map"
        raise CheckpointError(msg)
    machine.client = _optional_bool(data["client"], "stream client")
    machine.headers_sent = _optional_bool(data["headers_sent"], "headers-sent flag")
    machine.trailers_sent = _optional_bool(data["trailers_sent"], "trailers-sent flag")
    machine.headers_received = _optional_bool(data["headers_received"], "headers-received flag")
    machine.trailers_received = _optional_bool(data["trailers_received"], "trailers-received flag")
    machine.stream_closed_by = _optional_enum(
        data["closed_by"],
        StreamClosedBy,
        "stream closure",
    )
    _validate_stream_machine(machine)

    max_frame_size = data["max_outbound_frame_size"]
    stream.max_outbound_frame_size = (
        None
        if max_frame_size is None
        else _frame_size(
            max_frame_size,
            "stream frame size",
        )
    )
    stream.request_method = _optional_bytes(data["request_method"], "request method")
    stream.outbound_flow_control_window = _uint(
        data["outbound_flow_control_window"],
        "outbound stream window",
        LARGEST_FLOW_CONTROL_WINDOW,
    )
    stream._inbound_window_manager = _import_window(
        _mapping_value(data.get("inbound_window"), "inbound_window"),
    )
    stream._expected_content_length = _optional_uint(
        data["expected_content_length"],
        "expected content length",
        _UINT32_MAX,
    )
    actual_content_length = _uint(
        data["actual_content_length"],
        "actual content length",
        _UINT32_MAX,
    )
    if stream._expected_content_length is not None and actual_content_length > stream._expected_content_length:
        msg = "Actual content length exceeds expected content length"
        raise CheckpointError(msg)
    stream._actual_content_length = actual_content_length
    stream._authority = _optional_bytes(data["authority"], "stream authority")
    return stream


def _import_streams(data: list[Any], config: H2Configuration) -> dict[int, H2Stream]:
    streams: dict[int, H2Stream] = {}
    for item in data:
        stream = _import_stream(_mapping_value(item, "stream"), config)
        if stream.stream_id in streams:
            msg = f"Duplicate stream ID {stream.stream_id}"
            raise CheckpointError(msg)
        streams[stream.stream_id] = stream
    return streams


def _import_closed_streams(data: list[Any]) -> SizeLimitDict:
    closed_streams = SizeLimitDict(size_limit=H2Connection.MAX_CLOSED_STREAMS)
    for item in data:
        if not isinstance(item, list) or len(item) != 2:
            msg = "Corrupt closed-stream entry"
            raise CheckpointError(msg)
        stream_id = _uint(item[0], "closed stream ID", _STREAM_ID_MAX)
        if stream_id in closed_streams:
            msg = f"Duplicate closed stream ID {stream_id}"
            raise CheckpointError(msg)
        closed_by = _optional_enum(item[1], StreamClosedBy, "closed-stream reason")
        closed_streams[stream_id] = closed_by
    return closed_streams


def _optional_bool(value: Any, name: str) -> bool | None:
    if value is None:
        return None
    return _bool(value, name)


def _optional_bytes(value: Any, name: str) -> bytes | None:
    if value is None:
        return None
    return _b64(value, name)


def _optional_uint(value: Any, name: str, maximum: int) -> int | None:
    if value is None:
        return None
    return _uint(value, name, maximum)


def _optional_enum(value: Any, enum_type: type[Any], name: str) -> Any | None:
    if value is None:
        return None
    return _enum_value(value, enum_type, name)


def _validate_stream_machine(machine: H2StreamStateMachine) -> None:
    if machine.client is None:
        msg = "Active stream must have a direction"
        raise CheckpointError(msg)
    if machine.stream_closed_by is not None:
        msg = "Active stream cannot have a closure reason"
        raise CheckpointError(msg)
    if machine.trailers_sent and not machine.headers_sent:
        msg = "Trailers-sent flag requires the headers-sent flag"
        raise CheckpointError(msg)
    if machine.trailers_received and not machine.headers_received:
        msg = "Trailers-received flag requires the headers-received flag"
        raise CheckpointError(msg)
    if not machine.headers_sent and not machine.headers_received:
        msg = "Active stream must have sent or received headers"
        raise CheckpointError(msg)


def _validate_stream_ids(
    client_side: bool,
    highest_inbound: int,
    highest_outbound: int,
    streams: dict[int, H2Stream],
    closed_streams: dict[int, StreamClosedBy | None],
) -> None:
    if set(streams).intersection(closed_streams):
        msg = "Stream ID appears in both active and closed-stream maps"
        raise CheckpointError(msg)
    for stream_id in streams:
        _validate_stream_id(stream_id, client_side, highest_inbound, highest_outbound)
    for stream_id in closed_streams:
        _validate_stream_id(stream_id, client_side, highest_inbound, highest_outbound)
    if highest_inbound and highest_inbound % 2 == int(client_side):
        msg = "Highest inbound stream ID has the wrong parity"
        raise CheckpointError(msg)
    if highest_outbound and highest_outbound % 2 != int(client_side):
        msg = "Highest outbound stream ID has the wrong parity"
        raise CheckpointError(msg)


def _validate_stream_id(
    stream_id: int,
    client_side: bool,
    highest_inbound: int,
    highest_outbound: int,
) -> None:
    if stream_id == 0:
        msg = "Stream ID zero is invalid"
        raise CheckpointError(msg)
    is_outbound = stream_id % 2 == int(client_side)
    highest = highest_outbound if is_outbound else highest_inbound
    if stream_id > highest:
        msg = f"Stream ID {stream_id} exceeds its highest seen ID"
        raise CheckpointError(msg)


def _export_frame_buffer(buffer: FrameBuffer, client_side: bool) -> dict[str, Any]:
    if type(buffer) is not FrameBuffer:
        msg = "Custom frame buffers cannot be represented in a checkpoint"
        raise CheckpointError(msg)
    return {
        "server": not client_side,
        "remaining_preamble": _b64_str(bytes(buffer._preamble)),
        "remaining_preamble_len": buffer._preamble_len,
        "max_frame_size": buffer.max_frame_size,
        "data": _b64_str(bytes(buffer._data)),
        "header_frames": [_b64_str(frame.serialize()) for frame in buffer._headers_buffer],
    }


def _import_frame_buffer(data: dict[str, Any], client_side: bool) -> FrameBuffer:
    keys = {
        "server",
        "remaining_preamble",
        "remaining_preamble_len",
        "max_frame_size",
        "data",
        "header_frames",
    }
    if set(data) != keys or _bool(
        data["server"],
        "frame-buffer role",
    ) != (not client_side):
        msg = "Corrupt frame-buffer section"
        raise CheckpointError(msg)
    server = not client_side
    preamble, preamble_len = _import_preamble(data, server)
    raw_data = _b64(data["data"], "unparsed frame data")
    max_frame_size = _uint(
        data["max_frame_size"],
        "frame-buffer maximum frame size",
        2**24 - 1,
    )
    wire_frames = _list(data["header_frames"], "buffered header frames")
    frames = _import_buffered_header_frames(wire_frames, max_frame_size)
    _validate_header_frames(frames)
    _validate_unparsed_data(raw_data, preamble_len, max_frame_size)

    buffer = FrameBuffer(server=server)
    buffer._preamble = preamble if server else b""
    buffer._preamble_len = preamble_len
    buffer.max_frame_size = max_frame_size
    buffer._data = bytearray(raw_data)
    buffer._headers_buffer = frames
    return buffer


def _import_preamble(data: dict[str, Any], server: bool) -> tuple[bytes, int]:
    preamble = _b64(data["remaining_preamble"], "remaining preamble")
    preamble_len = _uint(data["remaining_preamble_len"], "remaining preamble length", 24)
    expected_preamble = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    preamble_valid = (preamble_len == 0 and preamble == b"") or (
        preamble_len > 0 and expected_preamble.endswith(preamble) and len(preamble) == preamble_len
    )
    if server and not preamble_valid:
        msg = "Corrupt server preamble"
        raise CheckpointError(msg)
    if not server and (preamble or preamble_len):
        msg = "Client frame buffers do not retain a preamble"
        raise CheckpointError(msg)
    return preamble, preamble_len


def _import_buffered_header_frames(wire_frames: list[Any], max_frame_size: int) -> list[Any]:
    if len(wire_frames) > CONTINUATION_BACKLOG:
        msg = "Too many buffered header frames"
        raise CheckpointError(msg)

    return [
        _import_buffered_header_frame(
            _b64(wire_value, "buffered header frame"),
            max_frame_size,
        )
        for wire_value in wire_frames
    ]


def _import_buffered_header_frame(wire: bytes, max_frame_size: int) -> Any:
    if len(wire) < 9:
        msg = "Buffered header frame is truncated"
        raise CheckpointError(msg)
    length = int.from_bytes(wire[:3], "big")
    if length != len(wire) - 9 or length > max_frame_size:
        msg = "Buffered header frame has a corrupt length"
        raise CheckpointError(msg)
    try:
        frame, _ = Frame.parse_frame_header(memoryview(wire[:9]))
        frame.parse_body(memoryview(wire[9:]))
    except (InvalidDataError, InvalidFrameError) as exc:
        msg = f"Invalid buffered header frame: {exc}"
        raise CheckpointError(msg) from exc
    return frame


def _validate_unparsed_data(raw_data: bytes, preamble_len: int, max_frame_size: int) -> None:
    if preamble_len and raw_data:
        msg = "Checkpoint input cannot contain frame data before preamble completion"
        raise CheckpointError(msg)
    if not raw_data:
        return
    probe = FrameBuffer(server=False)
    probe.max_frame_size = max_frame_size
    probe.add_data(raw_data)
    try:
        next(iter(probe))
    except StopIteration:
        return
    except (InvalidDataError, InvalidFrameError, ProtocolError) as exc:
        msg = f"Invalid complete frame in checkpoint input buffer: {exc}"
        raise CheckpointError(msg) from exc
    msg = "Checkpoint input buffer contains an unprocessed complete frame"
    raise CheckpointError(msg)


def _validate_header_frames(frames: list[Any]) -> None:
    if not frames:
        return
    first = frames[0]
    if not isinstance(first, (HeadersFrame, PushPromiseFrame)):
        msg = "Header block must begin with HEADERS or PUSH_PROMISE"
        raise CheckpointError(msg)
    if "END_HEADERS" in first.flags:
        msg = "Completed header blocks must not remain buffered"
        raise CheckpointError(msg)
    stream_id = first.stream_id
    for frame in frames[1:]:
        if not isinstance(frame, ContinuationFrame):
            msg = "Header block continuation must be a CONTINUATION frame"
            raise CheckpointError(msg)
        if frame.stream_id != stream_id or "END_HEADERS" in frame.flags:
            msg = "Buffered CONTINUATION frame has invalid stream or flags"
            raise CheckpointError(msg)
