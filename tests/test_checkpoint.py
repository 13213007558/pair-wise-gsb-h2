"""
Tests for explicit H2Connection checkpoint export and restoration.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct

import pytest
from hpack import HeaderTuple
from hyperframe.frame import ContinuationFrame

import h2.checkpoint
import h2.config
import h2.connection
import h2.exceptions
import h2.stream
import h2.windows

from . import helpers

REQUEST_HEADERS = [
    HeaderTuple(b":method", b"GET"),
    HeaderTuple(b":path", b"/"),
    HeaderTuple(b":scheme", b"https"),
    HeaderTuple(b":authority", b"example.com"),
]


def _event_key(event: object) -> object:
    if hasattr(event, "__dataclass_fields__"):
        return (
            type(event).__name__,
            tuple((name, _event_key(getattr(event, name))) for name in event.__dataclass_fields__),
        )
    if isinstance(event, (list, tuple)):
        return tuple(_event_key(item) for item in event)
    if isinstance(event, dict):
        return tuple((key, _event_key(value)) for key, value in sorted(event.items()))
    if isinstance(event, (bytes, str, int, bool)) or event is None:
        return event
    return repr(event)


def _server_connection() -> h2.connection.H2Connection:
    return h2.connection.H2Connection(
        h2.config.H2Configuration(client_side=False, header_encoding=None),
    )


class TestCheckpoint:
    def test_preserves_unread_output_before_any_received_bytes(self) -> None:
        connection = h2.connection.H2Connection()
        connection.initiate_connection()
        checkpoint = connection.export_checkpoint()

        restored = h2.connection.H2Connection.restore_checkpoint(checkpoint)

        assert connection.data_to_send() == restored.data_to_send()

    def test_rejects_custom_configuration_and_logger(self) -> None:
        class CustomConfig(h2.config.H2Configuration):
            pass

        class CustomLogger:
            def debug(self, *args: object) -> None:
                pass

            def trace(self, *args: object) -> None:
                pass

        custom_config = h2.connection.H2Connection(CustomConfig())
        with pytest.raises(h2.exceptions.CheckpointError):
            custom_config.export_checkpoint()

        custom_logger_config = h2.config.H2Configuration(logger=CustomLogger())
        custom_logger = h2.connection.H2Connection(custom_logger_config)
        with pytest.raises(h2.exceptions.CheckpointError):
            custom_logger.export_checkpoint()

    def test_checkpoint_does_not_contain_pickle_or_socket_data(self) -> None:
        connection = h2.connection.H2Connection()
        connection.initiate_connection()
        checkpoint = connection.export_checkpoint()

        assert b"socket" not in checkpoint
        assert b"pickle" not in checkpoint
        assert checkpoint[:8] == h2.checkpoint.CHECKPOINT_MAGIC
        assert b"\x80\x04" not in checkpoint[:16]

    def test_restore_rejects_connection_subclass(self) -> None:
        checkpoint = h2.connection.H2Connection().export_checkpoint()

        class CustomConnection(h2.connection.H2Connection):
            pass

        with pytest.raises(h2.exceptions.CheckpointError):
            CustomConnection.restore_checkpoint(checkpoint)

    def test_rejects_custom_internal_objects(self) -> None:
        connection = h2.connection.H2Connection()
        cp = h2.checkpoint
        with pytest.raises(h2.exceptions.CheckpointError):
            cp.export_checkpoint(object())

        connection.state_machine = object()  # type: ignore[assignment]
        with pytest.raises(h2.exceptions.CheckpointError):
            cp.export_checkpoint(connection)

        connection.state_machine = h2.connection.H2ConnectionStateMachine()
        connection._inbound_flow_control_window_manager = object()  # type: ignore[assignment]
        with pytest.raises(h2.exceptions.CheckpointError):
            cp.export_checkpoint(connection)

        with pytest.raises(h2.exceptions.CheckpointError):
            cp._export_settings(object())
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._export_encoder(object())
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._export_decoder(object())
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._export_window(object())
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._export_frame_buffer(object(), client_side=True)

        config = h2.config.H2Configuration()
        stream = h2.stream.H2Stream(1, config, 65535, 65535)
        stream.state_machine = object()  # type: ignore[assignment]
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._export_stream(stream)
        stream = h2.stream.H2Stream(1, config, 65535, 65535)
        stream.state_machine.state = h2.stream.StreamState.CLOSED
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._export_stream(stream)

        manager = h2.windows.WindowManager(65535)
        manager.current_window_size = 10
        manager.max_window_size = 5
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._import_window({"max": 5, "current": 10, "processed": 0})

        connection = h2.connection.H2Connection()
        connection.encoder.header_table._current_size += 1
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._export_encoder(connection.encoder)

        connection.decoder.header_table.maxsize = 1000
        connection.decoder.max_allowed_table_size = 100
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._export_decoder(connection.decoder)

    def test_rejects_malformed_nested_payload(self, frame_factory: helpers.FrameFactory) -> None:
        connection = _server_connection()
        connection.receive_data(frame_factory.preamble())
        headers = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        connection.receive_data(headers.serialize())
        valid = self._payload(connection.export_checkpoint())

        mutations = [
            ("config", "client_side", "yes"),
            ("config", "header_encoding", True),
            ("config", "extra", True),
            ("connection", "state", 99),
            ("connection", "state", False),
            ("connection", "outbound_flow_control_window", -1),
            ("connection", "max_outbound_frame_size", 2**24),
            ("connection", "data_to_send", "@@"),
            ("connection", "inbound_window", []),
            ("connection", "extra", 1),
            ("settings", None, None),
            ("hpack", None, None),
            (None, "streams", None),
            (None, "closed_streams", {0: 0}),
            ("frame_buffer", "server", "yes"),
            ("frame_buffer", "remaining_preamble", "@@"),
            ("frame_buffer", "remaining_preamble_len", 25),
            ("frame_buffer", "max_frame_size", 2**24),
            ("frame_buffer", "header_frames", {0: ""}),
            ("frame_buffer", "extra", 1),
        ]

        for section, key, value in mutations:
            payload = json.loads(json.dumps(valid))
            if section is None:
                payload[key] = value
            elif section == "settings" and key is None:
                payload["settings"] = value
            elif section == "hpack" and key is None:
                payload["hpack"] = value
            else:
                payload[section][key] = value
            with pytest.raises(h2.exceptions.CheckpointError):
                h2.connection.H2Connection.restore_checkpoint(self._container(payload))

        popped = json.loads(json.dumps(valid))
        popped["config"].pop("client_side")
        with pytest.raises(h2.exceptions.CheckpointError):
            h2.connection.H2Connection.restore_checkpoint(self._container(popped))

    def test_rejects_malformed_hpack_window_stream_and_frames(self) -> None:
        connection = h2.connection.H2Connection()
        stream = next(iter(connection.streams.values()), None)
        assert stream is None
        valid_stream = self._payload(connection.export_checkpoint())
        valid_stream["streams"].append(
            {
                "stream_id": 1,
                "state": 3,
                "client": True,
                "headers_sent": True,
                "trailers_sent": None,
                "headers_received": None,
                "trailers_received": None,
                "closed_by": None,
                "max_outbound_frame_size": 16384,
                "request_method": None,
                "outbound_flow_control_window": 65535,
                "inbound_window": {"max": 65535, "current": 65535, "processed": 0},
                "expected_content_length": 3,
                "actual_content_length": 4,
                "authority": None,
            },
        )
        valid_stream["connection"]["highest_outbound_stream_id"] = 1
        with pytest.raises(h2.exceptions.CheckpointError, match="content length"):
            h2.connection.H2Connection.restore_checkpoint(self._container(valid_stream))

        payload = self._payload(connection.export_checkpoint())
        payload["hpack"]["encoder"]["table"]["max"] = -1
        with pytest.raises(h2.exceptions.CheckpointError):
            h2.connection.H2Connection.restore_checkpoint(self._container(payload))

        payload = self._payload(connection.export_checkpoint())
        payload["hpack"]["encoder"]["table"]["entries"] = ["bad"]
        with pytest.raises(h2.exceptions.CheckpointError):
            h2.connection.H2Connection.restore_checkpoint(self._container(payload))

        payload = self._payload(connection.export_checkpoint())
        payload["frame_buffer"]["max_frame_size"] = 16384
        ping_frame = b"\x00\x00\x08\x06\x00\x00\x00\x00\x00" + b"12345678"
        payload["frame_buffer"]["data"] = base64.b64encode(ping_frame).decode()
        with pytest.raises(h2.exceptions.CheckpointError, match="unprocessed complete"):
            h2.connection.H2Connection.restore_checkpoint(self._container(payload))

        payload = self._payload(connection.export_checkpoint())
        payload["frame_buffer"]["header_frames"] = [
            base64.b64encode(b"AA").decode(),
        ]
        with pytest.raises(h2.exceptions.CheckpointError, match="truncated"):
            h2.connection.H2Connection.restore_checkpoint(self._container(payload))

        payload = self._payload(connection.export_checkpoint())
        payload["settings"]["remote"]["queues"].append([2, [1]])
        with pytest.raises(h2.exceptions.CheckpointError, match="Invalid setting"):
            h2.connection.H2Connection.restore_checkpoint(self._container(payload))

    def test_covers_all_invalid_state_and_buffer_branches(self) -> None:  # noqa: PLR0915
        cp = h2.checkpoint
        config = h2.config.H2Configuration(client_side=False)
        stream = h2.stream.H2Stream(3, config, 65535, 65535)
        machine = stream.state_machine

        with pytest.raises(h2.exceptions.CheckpointError):
            cp.restore_checkpoint(b"short")
        with pytest.raises(h2.exceptions.CheckpointError):
            cp.restore_checkpoint(123)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="constant"):
            cp._reject_json_constant("NaN")
        with pytest.raises(ValueError, match="Duplicate"):
            cp._reject_duplicate_keys([("a", 1), ("a", 2)])
        assert cp._reject_duplicate_keys([("a", 1)]) == {"a": 1}
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._mapping_value(1, "value")
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._list(1, "value")
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._integer(1.0)
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._uint(-1, "value", 1)
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._bool(1, "value")
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._string(1)
        assert cp._string(None) is None
        with pytest.raises(h2.exceptions.CheckpointError, match="state"):
            cp._enum_value(99, h2.stream.StreamState, "state")
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._b64(None, "value")
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._b64("@@", "value")
        assert cp._b64_str(b"x") == "eA=="

        with pytest.raises(h2.exceptions.CheckpointError):
            cp._import_window({"max": 1, "current": 1})
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._import_header_table({"max": 1, "current": 0, "resized": False})
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._import_encoder({"table": {}, "size_changes": []})
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._import_decoder({"table": {}})
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._import_settings({"client": True, "queues": []}, client=False)
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._import_settings({"client": True, "queues": [1]}, client=True)
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._import_settings({"client": True, "queues": [[2, [1, None]]]}, client=True)

        stream_item = {
            "stream_id": 0,
            "state": 3,
            "client": True,
            "headers_sent": True,
            "trailers_sent": None,
            "headers_received": None,
            "trailers_received": None,
            "closed_by": None,
            "max_outbound_frame_size": 16384,
            "request_method": None,
            "outbound_flow_control_window": 65535,
            "inbound_window": {"max": 65535, "current": 65535, "processed": 0},
            "expected_content_length": None,
            "actual_content_length": 0,
            "authority": None,
        }
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._import_stream({"x": 1}, config)
        with pytest.raises(h2.exceptions.CheckpointError, match="zero"):
            cp._validate_stream_id(0, client_side=True, highest_inbound=0, highest_outbound=0)

        stream_item["state"] = 6
        with pytest.raises(h2.exceptions.CheckpointError, match="Closed"):
            cp._import_stream(stream_item, config)
        stream_item["state"] = 3
        machine.client = None
        with pytest.raises(h2.exceptions.CheckpointError, match="direction"):
            cp._validate_stream_machine(machine)
        machine.client = True
        machine.stream_closed_by = h2.stream.StreamClosedBy.SEND_RST_STREAM
        with pytest.raises(h2.exceptions.CheckpointError, match="closure reason"):
            cp._validate_stream_machine(machine)
        machine.stream_closed_by = None
        machine.trailers_sent = True
        with pytest.raises(h2.exceptions.CheckpointError, match="Trailers"):
            cp._validate_stream_machine(machine)
        machine.trailers_sent = None
        machine.headers_sent = None
        with pytest.raises(h2.exceptions.CheckpointError, match="headers"):
            cp._validate_stream_machine(machine)
        machine.headers_sent = True

        with pytest.raises(h2.exceptions.CheckpointError, match="entry"):
            cp._import_closed_streams([1])
        with pytest.raises(h2.exceptions.CheckpointError, match="Duplicate closed"):
            cp._import_closed_streams([[1, 0], [1, 0]])
        assert cp._import_closed_streams([[1, 0]])[1] is h2.stream.StreamClosedBy.SEND_END_STREAM

        cp._validate_stream_machine(machine)
        machine.trailers_received = True
        with pytest.raises(h2.exceptions.CheckpointError, match="Trailers-received"):
            cp._validate_stream_machine(machine)
        machine.headers_received = True

        cp._validate_stream_ids(
            client_side=False,
            highest_inbound=3,
            highest_outbound=2,
            streams={1: stream},
            closed_streams={},
        )
        with pytest.raises(h2.exceptions.CheckpointError, match="both"):
            cp._validate_stream_ids(False, 3, 2, {1: stream}, {1: None})  # noqa: FBT003
        with pytest.raises(h2.exceptions.CheckpointError, match="wrong parity"):
            cp._validate_stream_ids(True, 2, 2, {}, {})  # noqa: FBT003
        with pytest.raises(h2.exceptions.CheckpointError, match="inbound"):
            cp._validate_stream_ids(False, 2, 2, {}, {})  # noqa: FBT003
        with pytest.raises(h2.exceptions.CheckpointError, match="wrong parity"):
            cp._validate_stream_ids(False, 3, 1, {}, {})  # noqa: FBT003
        with pytest.raises(h2.exceptions.CheckpointError, match="exceeds"):
            cp._validate_stream_ids(False, 3, 2, {5: stream}, {})  # noqa: FBT003
        cp._validate_stream_ids(
            client_side=False,
            highest_inbound=3,
            highest_outbound=2,
            streams={},
            closed_streams={1: None},
        )

        h2_table = cp.Encoder().header_table
        h2_table._current_size = 1
        with pytest.raises(h2.exceptions.CheckpointError, match="HPACK table"):
            cp._export_header_table(h2_table)
        with pytest.raises(h2.exceptions.CheckpointError, match="does not match"):
            cp._import_header_table({"max": 0, "current": 1, "resized": False, "entries": []})
        with pytest.raises(h2.exceptions.CheckpointError, match="encoder"):
            cp._import_encoder({"table": {"max": 0, "current": 0, "resized": False, "entries": []}, "extra": 1, "size_changes": []})
        decoder = cp.Decoder()
        decoder.max_allowed_table_size = 0
        decoder.header_table.maxsize = 1
        with pytest.raises(h2.exceptions.CheckpointError, match="acknowledged maximum"):
            cp._export_decoder(decoder)
        with pytest.raises(h2.exceptions.CheckpointError, match="decoder"):
            cp._import_decoder({"table": {"max": 1, "current": 0, "resized": False, "entries": []}})
        with pytest.raises(h2.exceptions.CheckpointError, match="exceeds its acknowledged"):
            cp._import_decoder({
                "table": {"max": 2, "current": 0, "resized": False, "entries": []},
                "max_header_list_size": 65536,
                "max_allowed_table_size": 1,
            })
        with pytest.raises(h2.exceptions.CheckpointError, match="queue"):
            cp._import_settings({"client": True, "queues": [[2, None]]}, client=True)
        with pytest.raises(h2.exceptions.CheckpointError, match="Only"):
            cp._import_settings({"client": True, "queues": [[2, [1, None]]]}, client=True)
        settings_with_null = cp._import_settings(
            {"client": True, "queues": [[99, [None, 1]]]},
            client=True,
        )
        assert list(settings_with_null._settings[99]) == [None, 1]

        optional_value = object()
        assert cp._optional_bytes(None, "optional") is None
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._optional_bytes(optional_value, "optional")
        assert cp._optional_uint(None, "optional", 1) is None
        assert cp._optional_uint(1, "optional", 1) == 1
        assert cp._optional_enum(None, h2.stream.StreamClosedBy, "optional") is None
        with pytest.raises(h2.exceptions.CheckpointError):
            cp._optional_enum(99, h2.stream.StreamClosedBy, "optional")

        server_data = {
            "server": True,
            "remaining_preamble": "",
            "remaining_preamble_len": 1,
            "max_frame_size": 16384,
            "data": "",
            "header_frames": [],
        }
        with pytest.raises(h2.exceptions.CheckpointError, match="preamble"):
            cp._import_frame_buffer(server_data, client_side=False)
        server_data["remaining_preamble_len"] = 0
        server_data["remaining_preamble"] = base64.b64encode(b"x").decode()
        with pytest.raises(h2.exceptions.CheckpointError, match="preamble"):
            cp._import_frame_buffer(server_data, client_side=False)
        server_data["server"] = False
        server_data["remaining_preamble"] = base64.b64encode(b"x").decode()
        with pytest.raises(h2.exceptions.CheckpointError, match="preamble"):
            cp._import_frame_buffer(server_data, client_side=True)

        server_data.update({
            "server": True,
            "remaining_preamble": "",
            "remaining_preamble_len": 0,
        })
        server_data["header_frames"] = [object()]
        with pytest.raises(h2.exceptions.CheckpointError, match="string"):
            cp._import_frame_buffer(server_data, client_side=False)
        server_data["header_frames"] = [base64.b64encode(b"x" * 66).decode()]
        with pytest.raises(h2.exceptions.CheckpointError, match="Too many"):
            cp._import_buffered_header_frames([b"x"] * 65, max_frame_size=16384)

        frame_factory = helpers.FrameFactory()
        headers_frame = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        headers_frame.flags.discard("END_HEADERS")
        wire_frame = headers_frame.serialize()
        short_frame = base64.b64encode(wire_frame[:8]).decode()
        bad_length_frame = bytearray(wire_frame)
        bad_length_frame[0] = 1
        invalid_type_frame = bytearray(wire_frame)
        invalid_type_frame[3] = 8
        for encoded, match in [
            (short_frame, "truncated"),
            (base64.b64encode(bytes(bad_length_frame)).decode(), "corrupt length"),
            (base64.b64encode(bytes(invalid_type_frame)).decode(), "Invalid buffered"),
        ]:
            with pytest.raises(h2.exceptions.CheckpointError, match=match):
                cp._import_buffered_header_frame(base64.b64decode(encoded), max_frame_size=16384)
        cp._validate_unparsed_data(b"", preamble_len=0, max_frame_size=16384)
        with pytest.raises(h2.exceptions.CheckpointError, match="before preamble"):
            cp._validate_unparsed_data(b"x", preamble_len=1, max_frame_size=16384)
        cp._validate_unparsed_data(b"x", preamble_len=0, max_frame_size=16384)
        ping_frame = b"\x00\x00\x08\x06\x00\x00\x00\x00\x00" + b"12345678"
        with pytest.raises(h2.exceptions.CheckpointError, match="unprocessed complete"):
            cp._validate_unparsed_data(ping_frame, preamble_len=0, max_frame_size=16384)
        invalid_ping = b"\x00\x00\x00\x06\x00\x00\x00\x00\x00"
        with pytest.raises(h2.exceptions.CheckpointError, match="Invalid complete frame"):
            cp._validate_unparsed_data(invalid_ping, preamble_len=0, max_frame_size=16384)
        cp._validate_header_frames([])
        with pytest.raises(h2.exceptions.CheckpointError, match="begin"):
            cp._validate_header_frames([cp.ContinuationFrame(1)])
        headers_frame.flags.add("END_HEADERS")
        with pytest.raises(h2.exceptions.CheckpointError, match="Completed"):
            cp._validate_header_frames([headers_frame])
        continuation_frame = cp.ContinuationFrame(1)
        continuation_frame.flags.add("END_HEADERS")
        wrong_continuation = cp.HeadersFrame(1)
        second_headers_frame = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        second_headers_frame.flags.discard("END_HEADERS")
        with pytest.raises(h2.exceptions.CheckpointError, match="CONTINUATION frame"):
            cp._validate_header_frames([second_headers_frame, wrong_continuation])
        valid_continuation = cp.ContinuationFrame(1)
        cp._validate_header_frames([second_headers_frame, valid_continuation])
        continuation_frame.stream_id = 3
        with pytest.raises(h2.exceptions.CheckpointError, match="invalid stream or flags"):
            cp._validate_header_frames([second_headers_frame, continuation_frame])

    @pytest.mark.parametrize("cut", [0, 1, 8, 9, 20, 41, 48, 49])
    def test_rejects_truncated_and_unknown_container(self, cut: int) -> None:
        checkpoint = h2.connection.H2Connection().export_checkpoint()

        if cut <= len(checkpoint):
            with pytest.raises(h2.exceptions.CheckpointError):
                h2.connection.H2Connection.restore_checkpoint(checkpoint[:cut])

        unknown_version = checkpoint[:8] + bytes([2]) + checkpoint[9:]
        with pytest.raises(h2.exceptions.CheckpointError):
            h2.connection.H2Connection.restore_checkpoint(unknown_version)

    def test_rejects_malformed_container_payload(self) -> None:
        checkpoint = h2.connection.H2Connection().export_checkpoint()

        malformed_json = b"{"
        digest = hashlib.sha256(malformed_json).digest()
        malformed_json = h2.checkpoint.CHECKPOINT_MAGIC + struct.pack(">BQ32s", h2.checkpoint.CHECKPOINT_VERSION, 1, digest) + malformed_json
        with pytest.raises(h2.exceptions.CheckpointError, match="payload"):
            h2.connection.H2Connection.restore_checkpoint(malformed_json)

        payload = self._payload(checkpoint)
        payload["format"] = "unknown"
        with pytest.raises(h2.exceptions.CheckpointError, match="format"):
            h2.connection.H2Connection.restore_checkpoint(self._container(payload))

        payload = self._payload(checkpoint)
        payload["version"] = 2
        with pytest.raises(h2.exceptions.CheckpointError, match="payload version"):
            h2.connection.H2Connection.restore_checkpoint(self._container(payload))

        payload = self._payload(checkpoint)
        payload["extra"] = True
        with pytest.raises(h2.exceptions.CheckpointError, match="sections"):
            h2.connection.H2Connection.restore_checkpoint(self._container(payload))

    def test_rejects_inconsistent_connection_state(self, frame_factory: helpers.FrameFactory) -> None:
        connection = _server_connection()
        connection.receive_data(frame_factory.preamble())
        connection.receive_data(
            frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1).serialize(),
        )
        valid = self._payload(connection.export_checkpoint())

        mutations = [
            ("connection", "max_outbound_frame_size", 16385),
            ("connection", "max_inbound_frame_size", 16385),
            ("hpack_encoder", "max", 4095),
            ("hpack_decoder_max", None, None),
            ("hpack_decoder_header_list", None, None),
            ("connection_window", None, None),
            ("stream_frame_size", None, None),
            ("stream_window", None, None),
        ]
        for section, key, value in mutations:
            payload = json.loads(json.dumps(valid))
            if section == "connection":
                payload["connection"][key] = value
            elif section == "hpack_encoder":
                payload["hpack"]["encoder"]["table"][key] = value
            elif section == "hpack_decoder_max":
                payload["hpack"]["decoder"]["max_allowed_table_size"] = 4097
            elif section == "hpack_decoder_header_list":
                payload["hpack"]["decoder"]["max_header_list_size"] = 1
            elif section == "connection_window":
                payload["connection"]["inbound_window"]["max"] = 0
                payload["connection"]["inbound_window"]["current"] = 0
            elif section == "stream_frame_size":
                payload["streams"][0]["max_outbound_frame_size"] = 16385
            elif section == "stream_window":
                payload["streams"][0]["inbound_window"]["max"] = 65534
                payload["streams"][0]["inbound_window"]["current"] = 65534
            with pytest.raises(h2.exceptions.CheckpointError):
                h2.connection.H2Connection.restore_checkpoint(self._container(payload))

    def test_wraps_unexpected_frame_buffer_parsing_error(self, frame_factory: helpers.FrameFactory) -> None:
        connection = _server_connection()
        connection.receive_data(frame_factory.preamble())
        headers = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        payload = self._payload(connection.export_checkpoint())
        invalid_frame = bytearray(headers.serialize())
        invalid_frame[3] = 8
        payload["frame_buffer"]["header_frames"] = [
            base64.b64encode(bytes(invalid_frame)).decode(),
        ]
        with pytest.raises(h2.exceptions.CheckpointError, match="Invalid buffered header frame"):
            h2.connection.H2Connection.restore_checkpoint(self._container(payload))

    def test_rejects_corrupt_length_and_checksum(self) -> None:
        checkpoint = bytearray(h2.connection.H2Connection().export_checkpoint())
        correct_length = len(checkpoint) - 49
        checkpoint[9:17] = struct.pack(">Q", correct_length + 1)

        with pytest.raises(h2.exceptions.CheckpointError, match="length"):
            h2.connection.H2Connection.restore_checkpoint(bytes(checkpoint))

        checkpoint[9:17] = struct.pack(">Q", correct_length)
        checkpoint[48] ^= 1
        with pytest.raises(h2.exceptions.CheckpointError, match="checksum"):
            h2.connection.H2Connection.restore_checkpoint(bytes(checkpoint))

    def test_rejects_duplicate_stream_id(self) -> None:
        connection = _server_connection()
        connection.receive_data(helpers.FrameFactory().preamble())
        headers = helpers.FrameFactory().build_headers_frame(
            REQUEST_HEADERS,
            stream_id=1,
        )
        connection.receive_data(headers.serialize())
        payload = self._payload(connection.export_checkpoint())
        payload["streams"].append(payload["streams"][0])

        corrupt = self._container(payload)

        with pytest.raises(h2.exceptions.CheckpointError, match="Duplicate stream"):
            h2.connection.H2Connection.restore_checkpoint(corrupt)

    def test_events_and_output_match_at_every_byte_boundary(
        self,
        frame_factory: helpers.FrameFactory,
    ) -> None:
        client = h2.connection.H2Connection()
        client.initiate_connection()
        client.send_headers(1, REQUEST_HEADERS)
        client.send_data(1, b"abc")
        client.update_settings({4: 100000, 5: 20000})
        client.ping(b"12345678")
        wire = client.data_to_send()

        expected = _server_connection()
        expected_events = [_event_key(event) for event in expected.receive_data(wire)]
        expected_output = expected.data_to_send()

        for cut in range(len(wire) + 1):
            prefix_connection = _server_connection()
            prefix_events = prefix_connection.receive_data(wire[:cut])
            prefix_output = prefix_connection.data_to_send()

            restored = h2.connection.H2Connection.restore_checkpoint(
                prefix_connection.export_checkpoint(),
            )
            suffix_events = restored.receive_data(wire[cut:])
            restored_output = prefix_output + restored.data_to_send()

            assert [_event_key(event) for event in [*prefix_events, *suffix_events]] == expected_events
            assert restored_output == expected_output

    def test_half_headers_continuation_and_settings_ack_boundaries(
        self,
        frame_factory: helpers.FrameFactory,
    ) -> None:
        first = frame_factory.build_headers_frame(
            REQUEST_HEADERS,
            stream_id=1,
        )
        first.flags.discard("END_HEADERS")
        split_at = len(first.data) // 2
        continuation_data = first.data[split_at:]
        first.data = first.data[:split_at]
        continuation = ContinuationFrame(1)
        continuation.data = continuation_data
        continuation.flags.add("END_HEADERS")
        request = first.serialize() + continuation.serialize()

        remote_settings = frame_factory.build_settings_frame({4: 50000})
        wire = frame_factory.preamble() + request + remote_settings.serialize()

        ack = frame_factory.build_settings_frame({}, ack=True).serialize()
        complete_incoming = wire + ack

        def prepared_server() -> h2.connection.H2Connection:
            connection = _server_connection()
            connection.initiate_connection()
            connection.update_settings({4: 100000})
            return connection

        expected = prepared_server()
        expected_output = expected.data_to_send()
        expected_events = [_event_key(event) for event in expected.receive_data(complete_incoming)]
        expected_output += expected.data_to_send()

        for cut in range(len(complete_incoming) + 1):
            prefix_connection = prepared_server()
            prefix_output = prefix_connection.data_to_send()
            prefix_events = prefix_connection.receive_data(complete_incoming[:cut])
            prefix_output += prefix_connection.data_to_send()
            restored = h2.connection.H2Connection.restore_checkpoint(
                prefix_connection.export_checkpoint(),
            )
            suffix_events = restored.receive_data(complete_incoming[cut:])

            assert [_event_key(event) for event in [*prefix_events, *suffix_events]] == expected_events
            assert prefix_output + restored.data_to_send() == expected_output

    @staticmethod
    def _payload(checkpoint: bytes) -> dict[str, object]:
        return json.loads(checkpoint[49:].decode("utf-8"))

    @staticmethod
    def _container(payload: dict[str, object]) -> bytes:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(encoded).digest()
        return h2.checkpoint.CHECKPOINT_MAGIC + struct.pack(">BQ32s", h2.checkpoint.CHECKPOINT_VERSION, len(encoded), digest) + encoded
