"""
Tests for RFC 9218 PRIORITY_UPDATE support: the Priority Field Value parser,
frame serialization, connection-level send/receive handling, early updates
and interaction with the RFC 7540 priority signals.
"""
from __future__ import annotations

import pytest

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.priority_update
import h2.settings
from h2.priority_update import (
    DisplayString,
    ParsedPriorityFieldValue,
    PriorityFieldError,
    PriorityUpdateFrame,
    StructuredFieldItem,
    Token,
    parse_priority_field_value,
    serialize_priority_field_value,
)

from hyperframe.exceptions import InvalidDataError


class TestPriorityFieldValueParser:
    """Parser for the subset of Structured Fields used by RFC 9218."""

    @pytest.mark.parametrize(("raw", "urgency", "incremental"), [
        (b"u=0", 0, False),
        (b"u=7", 7, False),
        (b"u=3", 3, False),
        (b"u=3, i", 3, True),
        (b"u=2, i=?1", 2, True),
        (b"u=2, i=?0", 2, False),
        (b"3", 3, False),
        (b"0", 0, False),
        (b"  u=1 , i  ", 1, True),
    ])
    def test_valid_values(self, raw, urgency, incremental) -> None:
        result = parse_priority_field_value(raw)
        assert result.urgency == urgency
        assert result.incremental == incremental
        assert result.unknown_parameters == {}

    @pytest.mark.parametrize("raw", [
        b"u=8",
        b"u=-1",
        b"u=99",
        b"u=?1",
        b'u="3"',
        b"u=1.5",
        b"i=1",
        b"i=\"yes\"",
    ])
    def test_invalid_members_fall_back_to_defaults(self, raw) -> None:
        # Per RFC 9218 section 4.1 invalid member values are ignored in favour
        # of the defaults; the field itself parses as Structured Fields.
        assert parse_priority_field_value(raw) == ParsedPriorityFieldValue()

    @pytest.mark.parametrize("raw", [
        b"",
        b"1.5",          # top-level shorthand must be an integer
        b"u=3,",         # trailing comma
        b"u=3,,i",       # empty member
        b"u=3 i",        # missing comma
        b"x=~",          # invalid bare item
        b'x="abc',       # unterminated string
        b"u=3;x=1;x=2",  # duplicate parameter
        b"u=3, u=4",     # duplicate member
        b"1234567890123456",  # integer too long
        b"u=3, 4 trailing",
    ])
    def test_invalid_structured_fields_raise(self, raw) -> None:
        with pytest.raises(PriorityFieldError):
            parse_priority_field_value(raw)

    def test_unknown_members_are_preserved(self) -> None:
        raw = (
            b'u=2, i, tok=foo;q=?1, str="bar", bytes=:aGVsbG8=:,'
            b'flag, dec=1.50, inner=("a" "b");x=1, disp=%"hi there%41"'
        )
        result = parse_priority_field_value(raw)

        assert result.urgency == 2
        assert result.incremental is True

        unknown = result.unknown_parameters
        assert unknown["tok"] == StructuredFieldItem(
            Token("foo"), {"q": StructuredFieldItem(True)},
        )
        assert unknown["str"].value == "bar"
        assert unknown["bytes"].value == b"hello"
        assert unknown["flag"] == StructuredFieldItem(True)
        assert unknown["dec"].value == 1.5
        assert isinstance(unknown["inner"].value, list)
        assert unknown["inner"].value[0].value == "a"
        assert unknown["inner"].parameters["x"].value == 1
        assert unknown["disp"].value == DisplayString("hi thereA")

    def test_member_order_is_preserved(self) -> None:
        result = parse_priority_field_value(b"a=1, z=2, m=3")
        assert list(result.unknown_parameters) == ["a", "z", "m"]

    def test_accepts_str_input(self) -> None:
        assert parse_priority_field_value("u=1, i").urgency == 1

    def test_shorthand_parameters_are_preserved(self) -> None:
        result = parse_priority_field_value(b"3;rel")
        assert result.urgency == 3
        assert result.unknown_parameters["rel"].value is True

    @pytest.mark.parametrize("raw", [
        b"?1",             # bare boolean
        b'"str"',          # bare string
        b":aGVs:",         # bare byte sequence
        b"@1234",          # bare date
        b'%"x"',           # bare display string
        b"(",             # unterminated inner list
        b'("a" 1)',        # missing SP inside inner list
        b'(1,2)',          # comma instead of SP inside inner list
        b"x=(1 2~)",       # invalid separator inside inner list
        b"x=?",            # truncated boolean
        b"x=?2",           # invalid boolean
        b"x=-",            # number without digits
        b"x=1.",           # decimal without fraction
        b"x=1.1234",       # too many fraction digits
        b"x=12345678901234.0",  # too many integer digits
        b'x="\\"',         # invalid string escape
        b'x="\x01"',       # control byte in string
        b'x="\\x"',        # bad escaped character
        b"x=:~",           # invalid byte sequence
        b"x=:%",           # invalid base64
        b"x=:",            # empty truncated byte sequence
        b"x=:@@:",         # non-base64 byte inside byte sequence
        b"x=:aGVs",         # byte sequence missing closing colon
        b"x=:aGV=b:",       # invalid base64 padding
        b"x=%x",           # display string missing quote
        b"x=%;",           # display string truncated
        b"x=%\"\x01\"",   # control byte in display string
        b"x=%",            # display string without opening quote
        b'x=%"a\xff"',     # non-UTF-8 display string
        b"x=%\"%zz\"",   # invalid percent encoding
        b"x=%\"%\"",    # truncated percent encoding
        b"1x=1",           # invalid key (digit start)
        b"u=1, 1=2",       # invalid dictionary key
    ])
    def test_more_invalid_or_bare_values(self, raw) -> None:
        with pytest.raises(PriorityFieldError):
            parse_priority_field_value(raw)

    @pytest.mark.parametrize(("raw", "expected_type", "expected_value"), [
        (b"x=?1", bool, True),
        (b"x=?0", bool, False),
        (b"x=@-42", float, -42.0),
        (b"x=@-1.5", float, -1.5),
        (b"x=:aGVs:", bytes, b"hel"),
        (b"x=123456789012345", int, 123456789012345),
        (b"x=-123456789012345", int, -123456789012345),
    ])
    def test_bare_item_types(self, raw, expected_type, expected_value) -> None:
        result = parse_priority_field_value(raw)
        item = result.unknown_parameters["x"]
        assert isinstance(item.value, expected_type)
        assert item.value == expected_value

    def test_wrapper_classes(self) -> None:
        token = Token("abc")
        assert token == Token("abc")
        assert token != "abc"
        assert hash(token) == hash(Token("abc"))
        assert repr(token) == "Token('abc')"

        display = DisplayString("x")
        assert display == DisplayString("x")
        assert display != "x"
        assert hash(display) == hash(DisplayString("x"))
        assert repr(display) == "DisplayString('x')"

    @pytest.mark.parametrize(("urgency", "incremental", "expected"), [
        (0, False, b"u=0"),
        (3, False, b"u=3"),
        (7, True, b"u=7, i"),
    ])
    def test_serializer(self, urgency, incremental, expected) -> None:
        assert serialize_priority_field_value(
            urgency, incremental,
        ) == expected

    @pytest.mark.parametrize("urgency", [-1, 8, 100, True, "3", 3.0])
    def test_serializer_rejects_bad_urgency(self, urgency) -> None:
        with pytest.raises(ValueError):
            serialize_priority_field_value(urgency, False)

    def test_serializer_rejects_bad_incremental(self) -> None:
        with pytest.raises(ValueError):
            serialize_priority_field_value(3, 1)


class TestPriorityUpdateFrame:
    """Frame body serialization and parsing."""

    def test_roundtrip(self) -> None:
        f = PriorityUpdateFrame(stream_id=0)
        f.prioritized_stream_id = 17
        f.priority_field_value = b"u=1, i"

        data = f.serialize()

        frame = PriorityUpdateFrame(0)
        frame.parse_body(memoryview(data[9:]))
        assert frame.prioritized_stream_id == 17
        assert frame.priority_field_value == b"u=1, i"

    def test_r_bit_is_ignored(self) -> None:
        # The R bit is a reserved bit and must be ignored on receipt.
        body = b"\x80\x00\x00\x05" + b"u=3"
        frame = PriorityUpdateFrame(0)
        frame.parse_body(memoryview(body))
        assert frame.prioritized_stream_id == 5

    @pytest.mark.parametrize("body", [b"", b"\x00", b"\x00\x00", b"\x00\x00\x00"])
    def test_body_shorter_than_four_bytes_is_invalid(self, body) -> None:
        frame = PriorityUpdateFrame(0)
        with pytest.raises(InvalidDataError):
            frame.parse_body(memoryview(body))


def _new_rfc9218_connection(client_side: bool) -> h2.connection.H2Connection:
    config = h2.config.H2Configuration(client_side=client_side)
    connection = h2.connection.H2Connection(config=config)
    connection.initiate_connection()
    connection.update_settings({
        h2.settings.SettingCodes.NO_RFC7540_PRIORITIES: 1,
    })
    return connection


def _establish_rfc9218() -> tuple[h2.connection.H2Connection, h2.connection.H2Connection]:
    """Bring up a client/server pair with setting 9 enabled on both sides."""
    client = _new_rfc9218_connection(client_side=True)
    server = _new_rfc9218_connection(client_side=False)

    # Feed the client's preamble and SETTINGS to the server, then exchange
    # the server's SETTINGS and the SETTINGS ACKs on both sides.
    server.receive_data(client.data_to_send())
    client.receive_data(server.data_to_send())
    server.receive_data(client.data_to_send())
    client.receive_data(server.data_to_send())
    return client, server


def _feed_in_chunks(connection: h2.connection.H2Connection, data: bytes, chunk_size: int = 3):
    events = []
    for index in range(0, len(data), chunk_size):
        events.extend(connection.receive_data(data[index:index + chunk_size]))
    return events


REQUEST_HEADERS = [
    (":method", "GET"),
    (":path", "/"),
    (":authority", "example.com"),
    (":scheme", "https"),
]


class TestConnectionPriorityUpdate:
    """End-to-end behaviour over two real h2 connections."""

    def test_send_and_receive_through_pair(self) -> None:
        client, server = _establish_rfc9218()

        client.send_headers(stream_id=1, headers=REQUEST_HEADERS)
        server.receive_data(client.data_to_send())

        client.send_priority_update(stream_id=1, urgency=1, incremental=True)
        events = server.receive_data(client.data_to_send())

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, h2.events.PriorityUpdateReceived)
        assert event.stream_id == 1
        assert event.urgency == 1
        assert event.incremental is True
        assert event.unknown_parameters == {}

    def test_server_may_send_to_client(self) -> None:
        client, server = _establish_rfc9218()

        client.send_headers(stream_id=1, headers=REQUEST_HEADERS)
        server.receive_data(client.data_to_send())

        server.send_priority_update(stream_id=1, urgency=0)
        events = client.receive_data(server.data_to_send())

        assert len(events) == 1
        assert isinstance(events[0], h2.events.PriorityUpdateReceived)
        assert events[0].stream_id == 1
        assert events[0].urgency == 0
        assert events[0].incremental is False

    def test_segmented_bytes(self) -> None:
        client, server = _establish_rfc9218()

        client.send_headers(stream_id=1, headers=REQUEST_HEADERS)
        server.receive_data(client.data_to_send())

        client.send_priority_update(stream_id=1, urgency=5, incremental=True)
        data = client.data_to_send()

        events = _feed_in_chunks(server, data, chunk_size=1)
        assert len(events) == 1
        assert isinstance(events[0], h2.events.PriorityUpdateReceived)
        assert events[0].stream_id == 1

    def test_update_before_stream_is_opened(self) -> None:
        client, server = _establish_rfc9218()

        # Update arrives before any HEADERS frame opens stream 3.
        client.send_priority_update(stream_id=3, urgency=0, incremental=True)
        events = server.receive_data(client.data_to_send())
        assert events == []

        # The early update is delivered when the stream is opened.
        client.send_headers(stream_id=3, headers=REQUEST_HEADERS)
        events = server.receive_data(client.data_to_send())
        event_types = [type(e) for e in events]
        assert event_types == [
            h2.events.RequestReceived,
            h2.events.PriorityUpdateReceived,
        ]
        update = events[1]
        assert update.stream_id == 3
        assert update.urgency == 0
        assert update.incremental is True

    def test_multiple_updates_overwrite_before_open(self) -> None:
        client, server = _establish_rfc9218()

        client.send_priority_update(stream_id=9, urgency=0, incremental=False)
        server.receive_data(client.data_to_send())
        client.send_priority_update(stream_id=9, urgency=7, incremental=True)
        server.receive_data(client.data_to_send())
        client.send_priority_update(stream_id=9, urgency=2)
        events = server.receive_data(client.data_to_send())
        assert events == []

        client.send_headers(stream_id=9, headers=REQUEST_HEADERS)
        events = server.receive_data(client.data_to_send())

        updates = [e for e in events if isinstance(
            e, h2.events.PriorityUpdateReceived,
        )]
        assert len(updates) == 1
        assert updates[0].urgency == 2
        assert updates[0].incremental is False
        assert server._pending_priority_updates == {}

    def test_updates_on_open_stream_emit_immediately(self) -> None:
        client, server = _establish_rfc9218()

        client.send_headers(stream_id=1, headers=REQUEST_HEADERS)
        server.receive_data(client.data_to_send())

        client.send_priority_update(stream_id=1, urgency=6, incremental=True)
        events = server.receive_data(client.data_to_send())
        assert len(events) == 1
        assert isinstance(events[0], h2.events.PriorityUpdateReceived)
        assert events[0].urgency == 6

    def test_update_for_closed_stream_is_dropped(self) -> None:
        client, server = _establish_rfc9218()

        client.send_headers(stream_id=1, headers=REQUEST_HEADERS)
        server.receive_data(client.data_to_send())
        # Reset the stream: this fully closes it on the server side.
        server.reset_stream(stream_id=1)
        client.receive_data(server.data_to_send())
        assert server.open_inbound_streams == 0
        assert 1 in server._closed_streams

        client.send_priority_update(stream_id=1, urgency=0)
        events = server.receive_data(client.data_to_send())
        assert events == []
        assert 1 not in server._pending_priority_updates

    def test_goaway_releases_pending_updates(self) -> None:
        client, server = _establish_rfc9218()

        client.send_priority_update(stream_id=3, urgency=0)
        server.receive_data(client.data_to_send())
        assert 3 in server._pending_priority_updates

        client.close_connection()
        server.receive_data(client.data_to_send())
        assert server._pending_priority_updates == {}

    def test_pending_update_delivered_with_push_promise(self, frame_factory) -> None:
        client, server = _establish_rfc9218()

        # Open a client-initiated request so the server may push a stream.
        client.send_headers(stream_id=1, headers=REQUEST_HEADERS)
        server.receive_data(client.data_to_send())
        # Enable push on the client (server defaults to pushing).
        client.local_settings

        # The server learns of an early update for the promised even stream
        # before the PUSH_PROMISE arrives.
        server.send_priority_update(stream_id=4, urgency=0, incremental=True)
        events = client.receive_data(server.data_to_send())
        assert events == []
        assert 4 in client._pending_priority_updates

        push = frame_factory.build_push_promise_frame(
            stream_id=1,
            promised_stream_id=4,
            headers=REQUEST_HEADERS,
        )
        events = client.receive_data(push.serialize())
        event_types = [type(e) for e in events]
        assert h2.events.PriorityUpdateReceived in event_types
        update = next(
            e for e in events
            if isinstance(e, h2.events.PriorityUpdateReceived)
        )
        assert update.stream_id == 4
        assert update.urgency == 0
        assert update.incremental is True
        assert client._pending_priority_updates == {}

    def test_pending_updates_are_bounded(self) -> None:
        client, server = _establish_rfc9218()

        limit = h2.connection.H2Connection.MAX_PENDING_PRIORITY_UPDATES
        for stream_id in range(1, limit + 6):
            client.send_priority_update(stream_id=stream_id, urgency=1)
            server.receive_data(client.data_to_send())

        pending = server._pending_priority_updates
        assert len(pending) == limit
        # The oldest retained updates are evicted first (FIFO eviction).
        assert 1 not in pending
        assert 2 not in pending
        assert 3 not in pending
        assert 4 not in pending
        assert 5 not in pending
        assert 6 in pending
        assert (limit + 5) in pending

    def test_old_priority_tree_coexists_separately(self) -> None:
        """RFC 7540 PRIORITY and RFC 9218 PRIORITY_UPDATE remain independent."""
        client, server = _establish_rfc9218()

        # An old-style PRIORITY frame is still delivered as the tree event.
        from hyperframe.frame import PriorityFrame
        f = PriorityFrame(stream_id=5)
        f.depends_on = 0
        f.stream_weight = 15
        f.exclusive = False
        events = server.receive_data(f.serialize())
        assert len(events) == 1
        assert isinstance(events[0], h2.events.PriorityUpdated)
        assert events[0].weight == 16

        # The new signal never mutates any dependency-tree state.
        client.send_headers(stream_id=5, headers=REQUEST_HEADERS)
        server.receive_data(client.data_to_send())
        client.send_priority_update(stream_id=5, urgency=0)
        events = server.receive_data(client.data_to_send())
        assert len(events) == 1
        assert isinstance(events[0], h2.events.PriorityUpdateReceived)
        assert not hasattr(events[0], "depends_on")

        # The old tree event is unaffected by the new signal.
        events = server.receive_data(PriorityFrame(5).serialize())
        assert isinstance(events[0], h2.events.PriorityUpdated)

    def test_unknown_parameters_delivered_to_application(self) -> None:
        client, server = _establish_rfc9218()

        client.send_headers(stream_id=3, headers=REQUEST_HEADERS)
        server.receive_data(client.data_to_send())

        frame = PriorityUpdateFrame(stream_id=0)
        frame.prioritized_stream_id = 3
        frame.priority_field_value = b'u=1, i, ext="x";p=?0'
        client._prepare_for_sending([frame])
        events = server.receive_data(client.data_to_send())

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, h2.events.PriorityUpdateReceived)
        assert event.urgency == 1
        assert event.incremental is True
        assert event.unknown_parameters["ext"].value == "x"
        assert event.unknown_parameters["ext"].parameters["p"].value is False


class TestPriorityUpdateValidation:
    """Connection-layer validation per RFC 9218 section 4.2."""

    def test_cannot_send_before_setting_is_advertised(self, frame_factory) -> None:
        config = h2.config.H2Configuration(client_side=True)
        client = h2.connection.H2Connection(config=config)
        client.initiate_connection()

        # The client has not received the server's SETTINGS yet, so it must
        # not emit PRIORITY_UPDATE.
        with pytest.raises(h2.exceptions.ProtocolError):
            client.send_priority_update(stream_id=1, urgency=0)

        # A peer that never advertised the setting also rejects the frame.
        server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        # Build the frame without going through the client's own send guard.
        frame = PriorityUpdateFrame(stream_id=0)
        frame.prioritized_stream_id = 1
        frame.priority_field_value = b"u=0"
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(frame.serialize())

    def test_cannot_receive_before_setting_is_advertised(self, frame_factory) -> None:
        server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        server.clear_outbound_data_buffer()

        f = frame_factory.build_priority_update_frame(stream_id=1)
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(f.serialize())

        # A GOAWAY is queued when the connection is terminated.
        assert server.data_to_send()

    @pytest.mark.parametrize("stream_id", [0, 2**31, -1, "x", True])
    def test_send_validates_target_stream_id(self, stream_id) -> None:
        client, _server = _establish_rfc9218()
        with pytest.raises((h2.exceptions.ProtocolError, TypeError)):
            client.send_priority_update(stream_id=stream_id)

    def test_non_zero_header_stream_id_is_protocol_error(self, frame_factory) -> None:
        _client, server = _establish_rfc9218()
        server.clear_outbound_data_buffer()

        # Hand-craft a type-16 frame with a non-zero header stream ID.
        f = frame_factory.build_priority_update_frame(stream_id=1)
        raw = bytearray(f.serialize())
        raw[8] = 1  # stream identifier byte
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(bytes(raw))

    def test_r_bit_in_target_stream_id_is_ignored(self, frame_factory) -> None:
        _client, server = _establish_rfc9218()
        server.clear_outbound_data_buffer()

        f = frame_factory.build_priority_update_frame(stream_id=1)
        raw = bytearray(f.serialize())
        raw[9] = 0x80  # set the reserved R bit in the target stream ID
        events = server.receive_data(bytes(raw))

        assert len(events) == 0
        pending = server._pending_priority_updates
        assert 1 in pending
        assert pending[1].stream_id == 1

    def test_send_or_receive_forbidden_after_goaway(self) -> None:
        client, server = _establish_rfc9218()

        client.close_connection()
        server.receive_data(client.data_to_send())

        with pytest.raises(h2.exceptions.ProtocolError):
            server.send_priority_update(stream_id=1, urgency=0)

    def test_invalid_setting_value_on_the_wire_terminates_connection(
        self, frame_factory,
    ) -> None:
        server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        server.clear_outbound_data_buffer()

        f = frame_factory.build_settings_frame({
            h2.settings.SettingCodes.NO_RFC7540_PRIORITIES: 2,
        })
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(f.serialize())

        goaway = bytes(server.data_to_send())
        # Frame type 0x07 (GOAWAY), error code PROTOCOL_ERROR (0x1).
        assert goaway[3] == 0x07

    def test_target_stream_id_zero_is_protocol_error(self, frame_factory) -> None:
        _client, server = _establish_rfc9218()
        server.clear_outbound_data_buffer()

        f = frame_factory.build_priority_update_frame(stream_id=0)
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(f.serialize())

    @pytest.mark.parametrize("field_value", [
        b"",            # missing Priority Field Value
        b"1.5",         # top-level decimal is not valid here
        b"u=3,",        # malformed dictionary
        b"not sf!",
    ])
    def test_invalid_field_value_is_protocol_error(
        self, frame_factory, field_value,
    ) -> None:
        _client, server = _establish_rfc9218()
        server.clear_outbound_data_buffer()

        f = frame_factory.build_priority_update_frame(
            stream_id=1, priority_field_value=field_value,
        )
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(f.serialize())

    @pytest.mark.parametrize("field_value", [b"u=99", b'i="3"', b"i=1"])
    def test_semantically_invalid_members_use_defaults(
        self, frame_factory, field_value,
    ) -> None:
        _client, server = _establish_rfc9218()
        server.clear_outbound_data_buffer()

        f = frame_factory.build_priority_update_frame(
            stream_id=11, priority_field_value=field_value,
        )
        # Stream 11 has not been established, so the normalised update is
        # retained for delivery when the stream opens.
        assert server.receive_data(f.serialize()) == []
        stored = server._pending_priority_updates[11]
        assert stored.urgency == h2.priority_update.DEFAULT_URGENCY
        assert stored.incremental is False

    def test_truncated_frame_is_protocol_error(self) -> None:
        _client, server = _establish_rfc9218()

        f = PriorityUpdateFrame(stream_id=0)
        f.prioritized_stream_id = 1
        f.priority_field_value = b"u=3"
        raw = f.serialize()
        # A partial frame simply waits for the rest of its body.
        assert server.receive_data(raw[:11]) == []
        # Deliver a body shorter than the advertised length: the frame header
        # promised a body of 4+ bytes, so this truncation violates framing.
        short_header = raw[:9]
        short_header = b"\x00\x00\x02\x10\x00" + raw[5:9]
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(short_header + b"\x00\x00")
