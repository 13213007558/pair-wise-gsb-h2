"""
Tests for the RFC 9218 PRIORITY_UPDATE frame support.
"""
from __future__ import annotations

import pytest

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
from h2.priority import Priority


class TestPriorityUpdateFrames:
    """
    Tests for sending and receiving RFC 9218 PRIORITY_UPDATE frames.
    """

    example_request_headers = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]
    client_config = h2.config.H2Configuration(client_side=True)
    server_config = h2.config.H2Configuration(client_side=False)

    def _client_server_pair(self):
        """
        Build an interconnected client/server pair of H2Connections with
        the preamble and SETTINGS already exchanged.
        """
        client = h2.connection.H2Connection(config=self.client_config)
        server = h2.connection.H2Connection(config=self.server_config)
        client.initiate_connection()
        server.initiate_connection()
        server.receive_data(client.data_to_send())
        client.receive_data(server.data_to_send())
        client.clear_outbound_data_buffer()
        server.clear_outbound_data_buffer()
        return client, server

    @staticmethod
    def _feed_chopped(conn, data, chunk_size=3):
        """
        Feed data to a connection in small chunks, collecting all events.
        """
        events = []
        for i in range(0, len(data), chunk_size):
            events.extend(conn.receive_data(data[i:i + chunk_size]))
        return events

    def test_roundtrip_fragmented_frames(self) -> None:
        """
        A client can send a PRIORITY_UPDATE frame that the server receives,
        even when the frame bytes arrive chopped into small pieces. The
        event carries the target stream and the parsed parameters.
        """
        client, server = self._client_server_pair()

        client.send_headers(1, self.example_request_headers)
        client.send_priority_update(
            1, Priority(urgency=0, incremental=True,
                        extra_parameters={"foo": "bar"}),
        )
        events = self._feed_chopped(server, client.data_to_send())

        update_events = [
            e for e in events
            if isinstance(e, h2.events.PriorityUpdateReceived)
        ]
        assert len(update_events) == 1
        event = update_events[0]
        assert event.stream_id == 1
        assert event.priority.urgency == 0
        assert event.priority.incremental is True
        assert event.priority.extra_parameters == {"foo": "bar"}

    def test_update_arriving_before_headers_is_buffered(self) -> None:
        """
        A PRIORITY_UPDATE that arrives before the HEADERS of the stream it
        targets is buffered and flushed, in order, when the stream appears.
        """
        client, server = self._client_server_pair()

        client.send_priority_update(3, Priority(urgency=7))
        client.send_priority_update(1, Priority(urgency=1))
        client.send_headers(3, self.example_request_headers)
        events = self._feed_chopped(server, client.data_to_send())

        update_events = [
            e for e in events
            if isinstance(e, h2.events.PriorityUpdateReceived)
        ]
        # The update for stream 3 was sent first, but is only emitted once
        # stream 3 exists. The update for stream 1 targets a stream that
        # never arrives, so it stays buffered.
        assert len(update_events) == 1
        assert update_events[0].stream_id == 3
        assert update_events[0].priority.urgency == 7

        # The buffered event comes after the RequestReceived for stream 3.
        request_index = next(
            i for i, e in enumerate(events)
            if isinstance(e, h2.events.RequestReceived)
        )
        update_index = events.index(update_events[0])
        assert update_index > request_index

    def test_consecutive_updates_are_all_delivered_in_order(self) -> None:
        """
        Multiple PRIORITY_UPDATE frames for the same stream each produce an
        event, in arrival order.
        """
        client, server = self._client_server_pair()

        client.send_headers(1, self.example_request_headers)
        client.send_priority_update(1, Priority(urgency=5))
        client.send_priority_update(1, Priority(urgency=2, incremental=True))
        client.send_priority_update(1, Priority(urgency=0))
        events = self._feed_chopped(server, client.data_to_send())

        update_events = [
            e for e in events
            if isinstance(e, h2.events.PriorityUpdateReceived)
        ]
        assert [e.priority.urgency for e in update_events] == [5, 2, 0]
        assert [e.priority.incremental for e in update_events] == [
            False, True, False,
        ]
        assert all(e.stream_id == 1 for e in update_events)

    def test_update_for_closed_stream_is_delivered(self) -> None:
        """
        A PRIORITY_UPDATE for a stream that has already closed still
        produces an event and does not error.
        """
        client, server = self._client_server_pair()

        client.send_headers(1, self.example_request_headers, end_stream=True)
        server.receive_data(client.data_to_send())
        server.send_headers(1, [(":status", "200")], end_stream=True)
        client.receive_data(server.data_to_send())
        server.clear_outbound_data_buffer()
        client.clear_outbound_data_buffer()

        client.send_priority_update(1, Priority(urgency=6))
        events = self._feed_chopped(server, client.data_to_send())

        update_events = [
            e for e in events
            if isinstance(e, h2.events.PriorityUpdateReceived)
        ]
        assert len(update_events) == 1
        assert update_events[0].stream_id == 1
        assert update_events[0].priority.urgency == 6

    def test_old_and_new_priority_schemes_are_independent(self) -> None:
        """
        RFC 7540 PRIORITY frames and RFC 9218 PRIORITY_UPDATE frames can be
        used on the same connection, and write to separate state: the old
        PriorityUpdated event carries tree data, the new event carries the
        parsed field value.
        """
        client, server = self._client_server_pair()

        client.send_headers(1, self.example_request_headers)
        client.prioritize(1, weight=200, depends_on=0, exclusive=False)
        client.send_priority_update(1, Priority(urgency=4, incremental=True))
        events = self._feed_chopped(server, client.data_to_send())

        old_events = [
            e for e in events if isinstance(e, h2.events.PriorityUpdated)
        ]
        new_events = [
            e for e in events
            if isinstance(e, h2.events.PriorityUpdateReceived)
        ]
        assert len(old_events) == 1
        assert old_events[0].weight == 200
        assert not hasattr(old_events[0], "priority")
        assert len(new_events) == 1
        assert new_events[0].priority.urgency == 4
        assert new_events[0].priority.incremental is True
        assert not hasattr(new_events[0], "weight")

    def test_serialized_frame_layout(self, frame_factory) -> None:
        """
        The sent frame has type 0x10, stream ID zero, and a body of the
        prioritized element ID followed by the field value.
        """
        client = h2.connection.H2Connection(config=self.client_config)
        client.initiate_connection()
        client.clear_outbound_data_buffer()

        client.send_priority_update(5, Priority(urgency=2, incremental=True))
        data = client.data_to_send()

        expected = (
            frame_factory.build_priority_update_frame(5, b"u=2, i=?1")
            .serialize()
        )
        assert data == expected

    def test_servers_cannot_send_priority_update(self) -> None:
        """
        Servers are not allowed to send PRIORITY_UPDATE frames.
        """
        server = h2.connection.H2Connection(config=self.server_config)
        server.initiate_connection()

        with pytest.raises(h2.exceptions.RFC1122Error):
            server.send_priority_update(1, Priority())

    @pytest.mark.parametrize("stream_id", [0, 2, 4, -1, 2**31])
    def test_clients_validate_target_stream_id(self, stream_id) -> None:
        """
        Clients can only send PRIORITY_UPDATE for client-initiated (odd,
        in-range) stream IDs.
        """
        client = h2.connection.H2Connection(config=self.client_config)
        client.initiate_connection()

        with pytest.raises(h2.exceptions.ProtocolError):
            client.send_priority_update(stream_id, Priority())

    def test_clients_reject_received_priority_update(self, frame_factory) -> None:
        """
        A client receiving a PRIORITY_UPDATE frame treats it as a connection
        error of type PROTOCOL_ERROR.
        """
        client = h2.connection.H2Connection(config=self.client_config)
        client.initiate_connection()
        client.clear_outbound_data_buffer()

        f = frame_factory.build_priority_update_frame(1, b"u=1")
        with pytest.raises(h2.exceptions.ProtocolError):
            client.receive_data(f.serialize())

        expected = frame_factory.build_goaway_frame(
            last_stream_id=0,
            error_code=h2.errors.ErrorCodes.PROTOCOL_ERROR,
        )
        assert client.data_to_send() == expected.serialize()

    def test_priority_update_on_nonzero_stream_is_error(self, frame_factory) -> None:
        """
        A PRIORITY_UPDATE frame received on a stream other than stream zero
        is a connection error of type PROTOCOL_ERROR.
        """
        server = h2.connection.H2Connection(config=self.server_config)
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        server.clear_outbound_data_buffer()

        f = frame_factory.build_priority_update_frame(1, b"u=1", stream_id=1)
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(f.serialize())

        expected = frame_factory.build_goaway_frame(
            last_stream_id=0,
            error_code=h2.errors.ErrorCodes.PROTOCOL_ERROR,
        )
        assert server.data_to_send() == expected.serialize()

    @pytest.mark.parametrize("prioritized_stream_id", [0, 2, 4])
    def test_invalid_prioritized_stream_id_is_error(
        self, frame_factory, prioritized_stream_id,
    ) -> None:
        """
        A PRIORITY_UPDATE frame that does not reference a client-initiated
        request stream is a connection error of type PROTOCOL_ERROR.
        """
        server = h2.connection.H2Connection(config=self.server_config)
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        server.clear_outbound_data_buffer()

        f = frame_factory.build_priority_update_frame(
            prioritized_stream_id, b"u=1",
        )
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(f.serialize())

    def test_short_frame_body_is_error(self, frame_factory) -> None:
        """
        A PRIORITY_UPDATE frame whose body cannot hold a prioritized
        element ID is a connection error of type PROTOCOL_ERROR.
        """
        server = h2.connection.H2Connection(config=self.server_config)
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        server.clear_outbound_data_buffer()

        f = frame_factory.build_priority_update_frame(1, b"")
        f.body = b"\x00\x00\x00"
        f.body_len = 3
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(f.serialize())

    def test_unparseable_field_value_is_discarded(self, frame_factory) -> None:
        """
        A PRIORITY_UPDATE frame with a field value that is not a valid
        Structured Fields Dictionary is discarded without an event.
        """
        server = h2.connection.H2Connection(config=self.server_config)
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        server.clear_outbound_data_buffer()

        f = frame_factory.build_priority_update_frame(1, b"u=1, u=2")
        events = server.receive_data(f.serialize())
        assert events == []

    def test_buffered_updates_are_bounded(self, frame_factory) -> None:
        """
        The buffer of updates for not-yet-opened streams is bounded, so a
        peer cannot consume unbounded memory.
        """
        server = h2.connection.H2Connection(config=self.server_config)
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        server.clear_outbound_data_buffer()

        limit = h2.connection.H2Connection.MAX_BUFFERED_PRIORITY_UPDATES
        for i in range(limit * 2):
            stream_id = 2 * i + 1
            f = frame_factory.build_priority_update_frame(stream_id, b"u=1")
            assert server.receive_data(f.serialize()) == []

        assert len(server._buffered_priority_updates) <= limit


class TestPriorityValueParsing:
    """
    Tests for parsing and serializing RFC 9218 priority field values.
    """

    @pytest.mark.parametrize("data,expected", [
        (b"u=3", (3, False)),
        (b"u=0, i=?1", (0, True)),
        (b"u=7, i=?0", (7, False)),
        (b"u=1, i", (1, True)),
        (b"i", (3, True)),
        (b"", (3, False)),
        # Known parameters with invalid values fall back to defaults.
        (b"u=8", (3, False)),
        (b"u=-1", (3, False)),
        (b"u=?1", (3, False)),
        (b"u=2.5", (3, False)),
        (b'u="1"', (3, False)),
        (b"i=1", (3, False)),
        (b"i=u", (3, False)),
        (b"u=2, i=?2", None),
    ])
    def test_parse_known_parameters(self, data, expected) -> None:
        priority = Priority.parse(data)
        if expected is None:
            assert priority is None
        else:
            assert priority is not None
            assert (priority.urgency, priority.incremental) == expected

    def test_unknown_parameters_are_preserved(self) -> None:
        priority = Priority.parse(
            b'u=2, x=5, y=?0, z=token, s="a b", b=:aGVsbG8=:, f=1.5',
        )
        assert priority is not None
        assert priority.urgency == 2
        assert priority.extra_parameters == {
            "x": 5,
            "y": False,
            "z": "token",
            "s": "a b",
            "b": b"hello",
            "f": 1.5,
        }

    @pytest.mark.parametrize("data", [
        b"u=1, u=2",       # duplicate key
        b"u=1,",           # trailing comma
        b"u =1",           # whitespace around =
        b"U=1",            # uppercase key
        b"??",             # garbage
        b"u=1 i=?1",       # missing comma
        b"u=9999999999999999",  # integer too long
        b"\xff\xfe",      # not ASCII
    ])
    def test_invalid_dictionaries_fail_to_parse(self, data) -> None:
        assert Priority.parse(data) is None

    @pytest.mark.parametrize("priority,expected", [
        (Priority(), b"u=3"),
        (Priority(urgency=0, incremental=True), b"u=0, i=?1"),
        (Priority(urgency=7), b"u=7"),
        (
            Priority(urgency=2, extra_parameters={"x": 1, "y": False}),
            b"u=2, x=1, y=?0",
        ),
        (
            Priority(extra_parameters={"t": "tok", "s": "a b", "b": b"hi"}),
            b'u=3, t=tok, s="a b", b=:aGk=:',
        ),
    ])
    def test_serialize(self, priority, expected) -> None:
        assert priority.serialize() == expected

    def test_serialize_rejects_out_of_range_urgency(self) -> None:
        with pytest.raises(ValueError, match="urgency"):
            Priority(urgency=8).serialize()

    def test_roundtrip(self) -> None:
        original = Priority(
            urgency=1,
            incremental=True,
            extra_parameters={"foo": "bar", "n": 42, "flag": True},
        )
        assert Priority.parse(original.serialize()) == original
