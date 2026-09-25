"""
Tests for RFC 9218 PRIORITY_UPDATE frames and the extensible priority scheme.
"""
from __future__ import annotations

import hyperframe.frame
import pytest

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
import h2.frame
import h2.priority


def pv(urgency=3, incremental=False, unknown_parameters=None):
    """
    Shorthand for building an expected PriorityValue.
    """
    return h2.priority.PriorityValue(
        urgency=urgency,
        incremental=incremental,
        unknown_parameters=unknown_parameters or {},
    )


class TestParsePriorityFieldValue:
    """
    Tests for the Structured Fields parsing of priority field values.
    """

    @pytest.mark.parametrize(("field_value", "expected"), [
        # Empty values and simple, well-formed values.
        (b"", pv()),
        (b"u=1", pv(urgency=1)),
        (b"u=0", pv(urgency=0)),
        (b"u=7", pv(urgency=7)),
        (b"i=?1", pv(incremental=True)),
        (b"i=?0", pv()),
        (b"i", pv(incremental=True)),
        (b"u=4, i=?1", pv(urgency=4, incremental=True)),
        (b"u=2, x=1, i=?1", pv(urgency=2, incremental=True, unknown_parameters={"x": 1})),
        # Known parameters with out-of-range or wrongly-typed values are
        # ignored, falling back to the RFC 9218 defaults.
        (b"u=8", pv()),
        (b"u=-1", pv()),
        (b"u=3.5", pv()),
        (b'u="3"', pv()),
        (b"u=?1", pv()),
        (b"u", pv()),
        (b"i=1", pv()),
        (b'i="yes"', pv()),
        # Duplicate keys: the first occurrence wins.
        (b"u=1, u=5", pv(urgency=1)),
        (b"u=1, u=8", pv(urgency=1)),
        # Unknown parameters are preserved, whatever their type.
        (b"x=1", pv(unknown_parameters={"x": 1})),
        (b"foo=?0", pv(unknown_parameters={"foo": False})),
        (b"bar=:aGVsbG8=:", pv(unknown_parameters={"bar": b"hello"})),
        (b'baz="qux"', pv(unknown_parameters={"baz": "qux"})),
        (b"tok=abc/1:x", pv(unknown_parameters={"tok": "abc/1:x"})),
        (b"dec=1.5", pv(unknown_parameters={"dec": 1.5})),
        (b"neg=-5", pv(unknown_parameters={"neg": -5})),
        (b"lst=(1 2)", pv(unknown_parameters={"lst": [1, 2]})),
        (b"lst=()", pv(unknown_parameters={"lst": []})),
        (b"lst=(1;p=2 3)", pv(unknown_parameters={"lst": [1, 3]})),
        (b"star=*", pv(unknown_parameters={"star": "*"})),
        # Parameters on dictionary members are validated and discarded.
        (b"x=1;x=2", pv(unknown_parameters={"x": 1})),
        (b"u=1;x=2", pv(urgency=1)),
        (b"x;p=1", pv(unknown_parameters={"x": True})),
        # String escapes and optional whitespace around commas.
        (b'esc="a\\"b\\\\c"', pv(unknown_parameters={"esc": 'a"b\\c'})),
        (b"u=1\t, x=2", pv(urgency=1, unknown_parameters={"x": 2})),
    ])
    def test_parse_valid_values(self, field_value, expected) -> None:
        """
        Well-formed field values are parsed according to RFC 8941/9218.
        """
        assert h2.priority.parse_priority_field_value(field_value) == expected

    @pytest.mark.parametrize("field_value", [
        b"\xff\xfe",
        b"u==",
        b"u=",
        b"u=1,",
        b",u=1",
        b"u=1 x=2",
        b"###",
        b"1x=2",
        b"U=1",
        b"u =1",
        b"u=1;",
        b"x=1;P=2",
        b"x=%",
        b'x="unterminated',
        b'x="a\x7f"',
        b'x="a\\z"',
        b'x="a\\',
        b"x=:!!!:",
        b"x=:aGVsbG8",
        b"x=?2",
        b"x=?",
        b"x=-",
        b"x=1234567890123456",
        b"x=1234567890123.5",
        b"x=1.",
        b"x=1.5678",
        b"x=(1 2",
        b"x=(1,2)",
    ])
    def test_parse_invalid_values_fall_back_to_defaults(self, field_value) -> None:
        """
        Field values that are not valid Structured Fields Dictionaries are
        treated as though no priority had been signalled at all.
        """
        assert h2.priority.parse_priority_field_value(field_value) == pv()

    @pytest.mark.parametrize(("urgency", "incremental", "expected"), [
        (None, None, b""),
        (None, False, b""),
        (0, None, b"u=0"),
        (7, None, b"u=7"),
        (None, True, b"i=?1"),
        (2, True, b"u=2, i=?1"),
        (5, False, b"u=5"),
    ])
    def test_serialize(self, urgency, incremental, expected) -> None:
        """
        Serializing produces valid Structured Fields Dictionaries, omitting
        parameters that should take their default values.
        """
        assert h2.priority.serialize_priority_field_value(urgency, incremental) == expected

    @pytest.mark.parametrize(("urgency", "incremental"), [
        (None, None),
        (None, True),
        (0, None),
        (7, False),
        (3, True),
    ])
    def test_serialize_round_trip(self, urgency, incremental) -> None:
        """
        Serialized values parse back to the same urgency and incremental
        flag (or their defaults).
        """
        value = h2.priority.parse_priority_field_value(
            h2.priority.serialize_priority_field_value(urgency, incremental),
        )
        assert value.urgency == (urgency if urgency is not None else 3)
        assert value.incremental == bool(incremental)
        assert value.unknown_parameters == {}
        assert value.unknown_parameters == {}


class TestPriorityUpdateFrame:
    """
    Tests for the wire format of the PRIORITY_UPDATE frame itself.
    """

    def test_frame_round_trip(self) -> None:
        """
        A serialized PRIORITY_UPDATE frame parses back to the same content.
        """
        f = h2.frame.PriorityUpdateFrame(stream_id=0)
        f.prioritized_element_id = 27
        f.field_value = b"u=0, i=?1"

        data = f.serialize()
        assert data[3] == 0x10  # The frame type byte.

        parsed, length = hyperframe.frame.Frame.parse_frame_header(memoryview(data)[:9])
        assert isinstance(parsed, h2.frame.PriorityUpdateFrame)
        parsed.parse_body(memoryview(data[9:9 + length]))
        assert parsed.stream_id == 0
        assert parsed.prioritized_element_id == 27
        assert parsed.field_value == b"u=0, i=?1"

    def test_frame_defaults(self) -> None:
        """
        Freshly built frames have sensible default values.
        """
        f = h2.frame.PriorityUpdateFrame(stream_id=0)
        assert f.prioritized_element_id == 0
        assert f.field_value == b""

    def test_frame_repr(self) -> None:
        """
        The frame repr shows the prioritized element ID and field value.
        """
        f = h2.frame.PriorityUpdateFrame(stream_id=0)
        f.prioritized_element_id = 3
        f.field_value = b"u=1"
        assert "prioritized_element_id=3" in repr(f)
        assert "u=1" in repr(f)

    def test_parse_short_body(self) -> None:
        """
        Bodies shorter than 4 bytes cannot hold a prioritized element ID.
        """
        f = h2.frame.PriorityUpdateFrame(stream_id=0)
        with pytest.raises(hyperframe.exceptions.InvalidFrameError):
            f.parse_body(memoryview(b"abc"))

    def test_reserved_bit_is_ignored(self) -> None:
        """
        The reserved bit of the prioritized element ID field is ignored.
        """
        f = h2.frame.PriorityUpdateFrame(stream_id=0)
        f.parse_body(memoryview(b"\x80\x00\x00\x05u=1"))
        assert f.prioritized_element_id == 5
        assert f.field_value == b"u=1"
        assert f.field_value == b"u=1"


class TestReceivePriorityUpdate:
    """
    Tests for receiving PRIORITY_UPDATE frames.
    """

    example_request_headers = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]
    server_config = h2.config.H2Configuration(client_side=False)
    client_config = h2.config.H2Configuration(client_side=True)

    def server_connection(self, frame_factory):
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()
        return c

    def test_receive_on_open_stream(self, frame_factory) -> None:
        """
        A PRIORITY_UPDATE for an open stream emits a PriorityUpdateReceived
        event carrying the parsed parameters.
        """
        c = self.server_connection(frame_factory)
        f = frame_factory.build_headers_frame(self.example_request_headers, stream_id=1)
        c.receive_data(f.serialize())
        c.clear_outbound_data_buffer()

        f = frame_factory.build_priority_update_frame(1, b"u=0, i=?1")
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        assert not c.data_to_send()

        event = events[0]
        assert isinstance(event, h2.events.PriorityUpdateReceived)
        assert event.stream_id == 1
        assert event.urgency == 0
        assert event.incremental is True
        assert event.unknown_parameters == {}

    def test_unknown_parameters_are_preserved(self, frame_factory) -> None:
        """
        Unrecognized parameters in the field value are surfaced to the
        application verbatim.
        """
        c = self.server_connection(frame_factory)
        f = frame_factory.build_headers_frame(self.example_request_headers, stream_id=1)
        c.receive_data(f.serialize())
        c.clear_outbound_data_buffer()

        f = frame_factory.build_priority_update_frame(1, b'u=2, x=1, note="hi"')
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        event = events[0]
        assert event.urgency == 2
        assert event.incremental is False
        assert event.unknown_parameters == {"x": 1, "note": "hi"}

    def test_invalid_field_value_uses_defaults(self, frame_factory) -> None:
        """
        A field value that fails to parse yields the RFC 9218 defaults.
        """
        c = self.server_connection(frame_factory)
        f = frame_factory.build_headers_frame(self.example_request_headers, stream_id=1)
        c.receive_data(f.serialize())
        c.clear_outbound_data_buffer()

        f = frame_factory.build_priority_update_frame(1, b"u=99, i=?1")
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        event = events[0]
        assert event.urgency == 3
        assert event.incremental is True

    def test_event_repr(self, frame_factory) -> None:
        """
        The event has a useful repr.
        """
        c = self.server_connection(frame_factory)
        f = frame_factory.build_headers_frame(self.example_request_headers, stream_id=1)
        c.receive_data(f.serialize())
        c.clear_outbound_data_buffer()

        f = frame_factory.build_priority_update_frame(1, b"u=1")
        events = c.receive_data(f.serialize())

        assert repr(events[0]) == (
            "<PriorityUpdateReceived stream_id:1, urgency:1, "
            "incremental:False, unknown_parameters:{}>"
        )

    def test_update_before_headers_is_buffered(self, frame_factory) -> None:
        """
        A PRIORITY_UPDATE that arrives before the HEADERS of its stream is
        buffered, and emitted once the stream appears.
        """
        c = self.server_connection(frame_factory)

        f = frame_factory.build_priority_update_frame(3, b"u=1, i=?1")
        events = c.receive_data(f.serialize())
        assert events == []

        f = frame_factory.build_headers_frame(self.example_request_headers, stream_id=3)
        events = c.receive_data(f.serialize())

        assert len(events) == 2
        assert isinstance(events[0], h2.events.RequestReceived)
        assert isinstance(events[1], h2.events.PriorityUpdateReceived)
        assert events[1].stream_id == 3
        assert events[1].urgency == 1
        assert events[1].incremental is True

    def test_consecutive_updates(self, frame_factory) -> None:
        """
        Consecutive PRIORITY_UPDATE frames each emit their own event, in
        order.
        """
        c = self.server_connection(frame_factory)
        f = frame_factory.build_headers_frame(self.example_request_headers, stream_id=1)
        c.receive_data(f.serialize())
        c.clear_outbound_data_buffer()

        f1 = frame_factory.build_priority_update_frame(1, b"u=0")
        f2 = frame_factory.build_priority_update_frame(1, b"u=7, i=?1")
        events = c.receive_data(f1.serialize() + f2.serialize())

        assert len(events) == 2
        assert events[0].urgency == 0
        assert events[0].incremental is False
        assert events[1].urgency == 7
        assert events[1].incremental is True

    def test_buffered_updates_are_last_one_wins(self, frame_factory) -> None:
        """
        Only the most recent buffered update is emitted when the stream
        appears: earlier ones are superseded.
        """
        c = self.server_connection(frame_factory)

        f1 = frame_factory.build_priority_update_frame(1, b"u=0")
        f2 = frame_factory.build_priority_update_frame(1, b"u=6")
        assert c.receive_data(f1.serialize() + f2.serialize()) == []

        f = frame_factory.build_headers_frame(self.example_request_headers, stream_id=1)
        events = c.receive_data(f.serialize())

        assert len(events) == 2
        assert isinstance(events[1], h2.events.PriorityUpdateReceived)
        assert events[1].urgency == 6

    def test_update_for_closed_stream(self, frame_factory) -> None:
        """
        A PRIORITY_UPDATE for a stream that has already closed is emitted
        immediately, not buffered.
        """
        c = self.server_connection(frame_factory)
        f = frame_factory.build_headers_frame(
            self.example_request_headers, stream_id=1, flags=["END_STREAM"],
        )
        c.receive_data(f.serialize())
        c.send_headers(1, [(":status", "200")], end_stream=True)
        c.clear_outbound_data_buffer()

        # Force the closed stream to be cleaned up into the closed stream
        # registry.
        assert c.open_inbound_streams == 0
        assert 1 not in c.streams

        f = frame_factory.build_priority_update_frame(1, b"u=2")
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        assert isinstance(events[0], h2.events.PriorityUpdateReceived)
        assert events[0].stream_id == 1
        assert events[0].urgency == 2

    def test_update_for_idle_stream_below_highest(self, frame_factory) -> None:
        """
        A PRIORITY_UPDATE for a stream ID that can no longer be opened (it
        is below the highest stream ID seen) is emitted immediately.
        """
        c = self.server_connection(frame_factory)
        f = frame_factory.build_headers_frame(self.example_request_headers, stream_id=5)
        c.receive_data(f.serialize())
        c.clear_outbound_data_buffer()

        # Stream 1 was never opened and can never be opened now.
        f = frame_factory.build_priority_update_frame(1, b"u=4")
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        assert isinstance(events[0], h2.events.PriorityUpdateReceived)
        assert events[0].stream_id == 1

    def test_pending_updates_are_bounded(self, frame_factory) -> None:
        """
        The buffer of updates waiting for their streams is bounded, so a
        peer cannot exhaust memory by sending updates for streams that
        never arrive.
        """
        c = self.server_connection(frame_factory)

        limit = c.MAX_PENDING_PRIORITY_UPDATES
        for stream_id in range(1, 2 * (limit + 10), 2):
            f = frame_factory.build_priority_update_frame(stream_id, b"u=1")
            assert c.receive_data(f.serialize()) == []

        assert len(c._pending_priority_updates) == limit

        # The oldest updates were evicted: their streams get no event.
        f = frame_factory.build_headers_frame(self.example_request_headers, stream_id=1)
        events = c.receive_data(f.serialize())
        assert len(events) == 1
        assert isinstance(events[0], h2.events.RequestReceived)
        assert len(events) == 1
        assert isinstance(events[0], h2.events.RequestReceived)

    def test_frame_on_nonzero_stream_is_connection_error(self, frame_factory) -> None:
        """
        PRIORITY_UPDATE frames MUST be sent on stream 0.
        """
        c = self.server_connection(frame_factory)

        f = frame_factory.build_priority_update_frame(1, b"u=1", stream_id=1)
        with pytest.raises(h2.exceptions.ProtocolError):
            c.receive_data(f.serialize())

        expected_frame = frame_factory.build_goaway_frame(
            last_stream_id=0, error_code=h2.errors.ErrorCodes.PROTOCOL_ERROR,
        )
        assert c.data_to_send() == expected_frame.serialize()

    def test_zero_prioritized_element_id_is_connection_error(self, frame_factory) -> None:
        """
        A prioritized element ID of 0 is invalid.
        """
        c = self.server_connection(frame_factory)

        f = frame_factory.build_priority_update_frame(0, b"u=1")
        with pytest.raises(h2.exceptions.ProtocolError):
            c.receive_data(f.serialize())

        expected_frame = frame_factory.build_goaway_frame(
            last_stream_id=0, error_code=h2.errors.ErrorCodes.PROTOCOL_ERROR,
        )
        assert c.data_to_send() == expected_frame.serialize()

    def test_server_rejects_updates_for_server_streams(self, frame_factory) -> None:
        """
        A server cannot accept PRIORITY_UPDATE frames that refer to
        server-initiated (even) stream IDs: clients may only reprioritize
        their own requests.
        """
        c = self.server_connection(frame_factory)

        f = frame_factory.build_priority_update_frame(2, b"u=1")
        with pytest.raises(h2.exceptions.ProtocolError):
            c.receive_data(f.serialize())

        expected_frame = frame_factory.build_goaway_frame(
            last_stream_id=0, error_code=h2.errors.ErrorCodes.PROTOCOL_ERROR,
        )
        assert c.data_to_send() == expected_frame.serialize()

    def test_client_rejects_updates_for_client_streams(self, frame_factory) -> None:
        """
        A client cannot accept PRIORITY_UPDATE frames that refer to
        client-initiated (odd) stream IDs: servers may only reprioritize
        pushed streams.
        """
        c = h2.connection.H2Connection(config=self.client_config)
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_priority_update_frame(1, b"u=1")
        with pytest.raises(h2.exceptions.ProtocolError):
            c.receive_data(f.serialize())

        expected_frame = frame_factory.build_goaway_frame(
            last_stream_id=0, error_code=h2.errors.ErrorCodes.PROTOCOL_ERROR,
        )
        assert c.data_to_send() == expected_frame.serialize()

    def test_short_frame_is_connection_error(self, frame_factory) -> None:
        """
        A PRIORITY_UPDATE frame with a body shorter than 4 bytes is a
        FRAME_SIZE_ERROR.
        """
        c = self.server_connection(frame_factory)

        # A PRIORITY_UPDATE frame (type 0x10) on stream 0 with a 3-byte body.
        data = b"\x00\x00\x03\x10\x00\x00\x00\x00\x00" + b"abc"
        with pytest.raises(h2.exceptions.FrameDataMissingError):
            c.receive_data(data)

        expected_frame = frame_factory.build_goaway_frame(
            last_stream_id=0, error_code=h2.errors.ErrorCodes.FRAME_SIZE_ERROR,
        )
        assert c.data_to_send() == expected_frame.serialize()

    def test_client_receives_push_stream_updates(self, frame_factory) -> None:
        """
        A client accepts PRIORITY_UPDATE frames for pushed (even) streams,
        buffering them until the PUSH_PROMISE arrives.
        """
        c = h2.connection.H2Connection(config=self.client_config)
        c.initiate_connection()
        c.send_headers(1, self.example_request_headers, end_stream=True)
        c.clear_outbound_data_buffer()

        # The update for the pushed stream arrives before the PUSH_PROMISE.
        f = frame_factory.build_priority_update_frame(2, b"u=0, i=?1")
        assert c.receive_data(f.serialize()) == []

        f = frame_factory.build_push_promise_frame(
            stream_id=1,
            promised_stream_id=2,
            headers=self.example_request_headers,
        )
        events = c.receive_data(f.serialize())

        assert len(events) == 2
        assert isinstance(events[0], h2.events.PushedStreamReceived)
        assert isinstance(events[1], h2.events.PriorityUpdateReceived)
        assert events[1].stream_id == 2
        assert events[1].urgency == 0
        assert events[1].incremental is True
        assert events[1].urgency == 0
        assert events[1].incremental is True


class TestSendPriorityUpdate:
    """
    Tests for sending PRIORITY_UPDATE frames.
    """

    server_config = h2.config.H2Configuration(client_side=False)

    def parse_sent_frame(self, c):
        data = c.data_to_send()
        frame, length = hyperframe.frame.Frame.parse_frame_header(memoryview(data)[:9])
        assert isinstance(frame, h2.frame.PriorityUpdateFrame)
        frame.parse_body(memoryview(data[9:9 + length]))
        return frame

    @pytest.mark.parametrize(("urgency", "incremental", "field_value"), [
        (None, None, b""),
        (0, True, b"u=0, i=?1"),
        (7, None, b"u=7"),
        (None, True, b"i=?1"),
        (3, False, b"u=3"),
    ])
    def test_client_sends_priority_update(self, urgency, incremental, field_value) -> None:
        """
        The client emits well-formed PRIORITY_UPDATE frames on stream 0.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        c.send_priority_update(1, urgency=urgency, incremental=incremental)

        frame = self.parse_sent_frame(c)
        assert frame.stream_id == 0
        assert frame.prioritized_element_id == 1
        assert frame.field_value == field_value

    def test_server_sends_priority_update_for_push_stream(self) -> None:
        """
        Servers may send PRIORITY_UPDATE frames for pushed (even) streams.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        c.send_priority_update(2, urgency=5, incremental=True)

        frame = self.parse_sent_frame(c)
        assert frame.prioritized_element_id == 2
        assert frame.field_value == b"u=5, i=?1"

    @pytest.mark.parametrize("stream_id", [0, -1, 2, 4, 2**31])
    def test_client_rejects_invalid_stream_ids(self, stream_id) -> None:
        """
        Clients may only send updates for client-initiated (odd) streams.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        with pytest.raises(h2.exceptions.ProtocolError):
            c.send_priority_update(stream_id, urgency=1)
        assert not c.data_to_send()

    @pytest.mark.parametrize("stream_id", [1, 3])
    def test_server_rejects_request_streams(self, stream_id) -> None:
        """
        Servers may only send updates for pushed (even) streams.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        with pytest.raises(h2.exceptions.ProtocolError):
            c.send_priority_update(stream_id, urgency=1)
        assert not c.data_to_send()

    @pytest.mark.parametrize("urgency", [-1, 8, 100, "1", 3.5, True, False])
    def test_rejects_invalid_urgency(self, urgency) -> None:
        """
        The urgency must be an integer between 0 and 7.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        with pytest.raises(ValueError, match="Invalid urgency"):
            c.send_priority_update(1, urgency=urgency)
        assert not c.data_to_send()
        with pytest.raises(ValueError, match="Invalid urgency"):
            c.send_priority_update(1, urgency=urgency)
        assert not c.data_to_send()


def pump(src, dst, chunk_size):
    """
    Move all pending data from one connection to the other, feeding it to
    the receiver in small chunks to simulate fragmented network reads.
    Returns the events emitted by the receiver.
    """
    data = src.data_to_send()
    events = []
    for i in range(0, len(data), chunk_size):
        events.extend(dst.receive_data(data[i:i + chunk_size]))
    return events


class TestPriorityUpdateExchange:
    """
    Tests that run two H2Connection objects against each other, exchanging
    PRIORITY_UPDATE frames chopped into small pieces.
    """

    server_config = h2.config.H2Configuration(client_side=False)

    request_headers = [
        (":method", "GET"),
        (":path", "/"),
        (":authority", "example.com"),
        (":scheme", "https"),
    ]
    response_headers = [
        (":status", "200"),
        ("server", "pytest-h2"),
    ]

    @pytest.fixture(autouse=True)
    def connections(self):
        self.client = h2.connection.H2Connection()
        self.server = h2.connection.H2Connection(config=self.server_config)
        self.client.initiate_connection()
        self.server.initiate_connection()
        pump(self.client, self.server, chunk_size=3)
        pump(self.server, self.client, chunk_size=3)
        self.client.clear_outbound_data_buffer()
        self.server.clear_outbound_data_buffer()

    @pytest.mark.parametrize("chunk_size", [1, 3])
    def test_exchange_open_stream(self, chunk_size) -> None:
        """
        The server receives the target stream and parsed parameters, even
        when the frames arrive chopped into tiny pieces.
        """
        self.client.send_headers(1, self.request_headers, end_stream=True)
        pump(self.client, self.server, chunk_size)

        self.client.send_priority_update(1, urgency=0, incremental=True)
        events = pump(self.client, self.server, chunk_size)

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, h2.events.PriorityUpdateReceived)
        assert event.stream_id == 1
        assert event.urgency == 0
        assert event.incremental is True
        assert event.unknown_parameters == {}

    @pytest.mark.parametrize("chunk_size", [1, 3])
    def test_exchange_early_arrival(self, chunk_size) -> None:
        """
        An update that crosses the wire before its stream's HEADERS is
        delivered once the stream appears.
        """
        self.client.send_priority_update(3, urgency=1, incremental=True)
        events = pump(self.client, self.server, chunk_size)
        assert events == []

        self.client.send_headers(3, self.request_headers, end_stream=True)
        events = pump(self.client, self.server, chunk_size)

        assert len(events) == 3
        assert isinstance(events[0], h2.events.RequestReceived)
        assert isinstance(events[1], h2.events.StreamEnded)
        update = events[2]
        assert isinstance(update, h2.events.PriorityUpdateReceived)
        assert update.stream_id == 3
        assert update.urgency == 1
        assert update.incremental is True

    @pytest.mark.parametrize("chunk_size", [1, 3])
    def test_exchange_consecutive_updates(self, chunk_size) -> None:
        """
        Consecutive updates for the same stream each produce an event.
        """
        self.client.send_headers(1, self.request_headers, end_stream=True)
        pump(self.client, self.server, chunk_size)

        self.client.send_priority_update(1, urgency=2)
        self.client.send_priority_update(1, urgency=4, incremental=True)
        self.client.send_priority_update(1, urgency=6)
        events = pump(self.client, self.server, chunk_size)

        assert len(events) == 3
        assert [e.urgency for e in events] == [2, 4, 6]
        assert [e.incremental for e in events] == [False, True, False]
        assert all(e.stream_id == 1 for e in events)

    @pytest.mark.parametrize("chunk_size", [1, 3])
    def test_exchange_closed_stream(self, chunk_size) -> None:
        """
        Updates for streams that have already closed are still delivered.
        """
        self.client.send_headers(1, self.request_headers, end_stream=True)
        pump(self.client, self.server, chunk_size)
        self.server.send_headers(1, self.response_headers, end_stream=True)
        pump(self.server, self.client, chunk_size)
        self.client.clear_outbound_data_buffer()
        self.server.clear_outbound_data_buffer()

        self.client.send_priority_update(1, urgency=5)
        events = pump(self.client, self.server, chunk_size)

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, h2.events.PriorityUpdateReceived)
        assert event.stream_id == 1
        assert event.urgency == 5
        assert isinstance(event, h2.events.PriorityUpdateReceived)
        assert event.stream_id == 1
        assert event.urgency == 5


class TestPrioritySchemesCoexist:
    """
    The RFC 7540 dependency-tree priority signaling (PRIORITY frames and
    HEADERS priority flags) keeps working alongside RFC 9218
    PRIORITY_UPDATE frames, and the two schemes do not share state.
    """

    example_request_headers = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]
    server_config = h2.config.H2Configuration(client_side=False)

    def test_headers_priority_and_priority_update(self, frame_factory) -> None:
        """
        A HEADERS frame with priority information produces a PriorityUpdated
        event, and a following PRIORITY_UPDATE frame produces a distinct
        PriorityUpdateReceived event with its own fields.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()

        f = frame_factory.build_headers_frame(
            headers=self.example_request_headers,
            stream_id=1,
            flags=["PRIORITY"],
            stream_weight=15,
            depends_on=0,
            exclusive=False,
        )
        events = c.receive_data(f.serialize())

        assert len(events) == 2
        assert isinstance(events[0], h2.events.RequestReceived)
        assert isinstance(events[1], h2.events.PriorityUpdated)
        assert events[1].weight == 16

        f = frame_factory.build_priority_update_frame(1, b"u=2, i=?1")
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, h2.events.PriorityUpdateReceived)
        assert not isinstance(event, h2.events.PriorityUpdated)
        assert event.urgency == 2
        assert event.incremental is True
        # The new event does not reuse the old priority tree fields.
        assert not hasattr(event, "weight")
        assert not hasattr(event, "depends_on")

    def test_priority_frame_and_priority_update(self, frame_factory) -> None:
        """
        Old-style PRIORITY frames and new-style PRIORITY_UPDATE frames can
        be received on the same connection without interfering.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()

        f = frame_factory.build_headers_frame(self.example_request_headers, stream_id=1)
        c.receive_data(f.serialize())
        c.clear_outbound_data_buffer()

        old = frame_factory.build_priority_frame(stream_id=1, weight=31)
        new = frame_factory.build_priority_update_frame(1, b"u=6")
        events = c.receive_data(old.serialize() + new.serialize())

        assert len(events) == 2
        assert isinstance(events[0], h2.events.PriorityUpdated)
        assert events[0].weight == 32
        assert isinstance(events[1], h2.events.PriorityUpdateReceived)
        assert events[1].urgency == 6

    def test_prioritize_method_still_uses_old_scheme(self) -> None:
        """
        The prioritize method keeps emitting RFC 7540 PRIORITY frames.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        c.prioritize(1, weight=32)

        data = c.data_to_send()
        frame, length = hyperframe.frame.Frame.parse_frame_header(memoryview(data)[:9])
        assert isinstance(frame, hyperframe.frame.PriorityFrame)
        assert not isinstance(frame, h2.frame.PriorityUpdateFrame)
