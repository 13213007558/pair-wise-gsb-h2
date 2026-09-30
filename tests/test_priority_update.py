"""
Tests for the RFC 9218 extensible prioritization scheme: the PRIORITY_UPDATE
frame, its parsing, validation, and the events emitted for it.
"""
from __future__ import annotations

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.priority
import h2.settings
import pytest


def feed_in_chunks(connection, data, chunk_size=3):
    """
    Feed data to a connection in small fragments, as if it arrived in
    several TCP segments, and collect all emitted events.
    """
    events = []
    for i in range(0, len(data), chunk_size):
        events.extend(connection.receive_data(data[i:i + chunk_size]))
    return events


class TestPriorityFieldValueParsing:
    """
    Unit tests for the tolerant structured-field-dictionary parser.
    """

    @pytest.mark.parametrize(("field_value", "urgency", "incremental"), [
        (b"u=0", 0, False),
        (b"u=7", 7, False),
        (b"i=?1", 3, True),
        (b"i=?0", 3, False),
        (b"u=5, i=?1", 5, True),
        (b"i=?1, u=2", 2, True),
        (b"", 3, False),
        # Invalid or out-of-range values fall back to the defaults.
        (b"u=8", 3, False),
        (b"u=-1", 3, False),
        (b"u=?1", 3, False),
        (b"u", 3, False),
        (b"i=1", 3, False),
        (b"i=u", 3, False),
        # Structurally invalid field values are not errors: defaults apply.
        (b"this is not a dictionary", 3, False),
        (b"u=1, u=2", 3, False),
        (b'foo="unterminated', 3, False),
        (b"u=1,,i=?1", 3, False),
        (b")", 3, False),
        (b"foo=(a", 3, False),
        (b"\xff\xfe\x00", 3, False),
        # Trailing parameters are tolerated: the value itself still parses.
        (b"u=1;", 1, False),
    ])
    def test_parsing_known_parameters(self, field_value, urgency, incremental) -> None:
        parsed_urgency, parsed_incremental, unknown = (
            h2.priority.parse_priority_field_value(field_value)
        )
        assert parsed_urgency == urgency
        assert parsed_incremental == incremental
        assert unknown == {}

    def test_unknown_parameters_are_preserved(self) -> None:
        _, _, unknown = h2.priority.parse_priority_field_value(
            b'u=1, foo=bar, x=?1, bare, lst=(a b), s="quoted, string"',
        )
        assert unknown == {
            "foo": "bar",
            "x": "?1",
            "bare": None,
            "lst": "(a b)",
            "s": '"quoted, string"',
        }

    def test_member_parameters_do_not_confuse_known_keys(self) -> None:
        urgency, incremental, unknown = h2.priority.parse_priority_field_value(
            b"u=4;extra=1, i=?1",
        )
        assert urgency == 4
        assert incremental is True
        assert unknown == {}

    def test_quoted_string_with_escapes_and_semicolons(self) -> None:
        _, _, unknown = h2.priority.parse_priority_field_value(
            b'x="a\\"b;c";p=1, y="z"',
        )
        assert unknown == {"x": '"a\\"b;c"', "y": '"z"'}

    @pytest.mark.parametrize(("urgency", "incremental", "expected"), [
        (None, None, b""),
        (None, False, b""),
        (0, True, b"u=0, i=?1"),
        (7, None, b"u=7"),
        (None, True, b"i=?1"),
    ])
    def test_building_field_values(self, urgency, incremental, expected) -> None:
        assert h2.priority.build_priority_field_value(
            urgency, incremental=incremental,
        ) == expected

    def test_built_values_round_trip(self) -> None:
        field_value = h2.priority.build_priority_field_value(6, incremental=True)
        assert h2.priority.parse_priority_field_value(field_value) == (
            6, True, {},
        )


class TestPriorityUpdateFrame:
    """
    Tests for the wire format of the PRIORITY_UPDATE frame itself.
    """

    def test_frame_round_trip(self) -> None:
        f = h2.priority.PriorityUpdateFrame(stream_id=0)
        f.prioritized_stream_id = 15
        f.field_value = b"u=3, i=?1"

        data = f.serialize()
        # 9-byte header, type 0x10, no flags, stream 0.
        assert data[3] == 0x10
        assert data[4] == 0
        assert int.from_bytes(data[5:9], "big") == 0

        g = h2.priority.PriorityUpdateFrame()
        g.parse_flags(data[4])
        g.parse_body(memoryview(data[9:]))
        assert g.prioritized_stream_id == 15
        assert g.field_value == b"u=3, i=?1"

    def test_frame_reserved_bit_of_element_id_is_masked(self) -> None:
        f = h2.priority.PriorityUpdateFrame()
        f.parse_flags(0)
        f.parse_body(memoryview(b"\x80\x00\x00\x2au=1"))
        assert f.prioritized_stream_id == 42
        assert f.field_value == b"u=1"


class TestPriorityUpdateConnection:
    """
    Connection-level tests, using two h2 connections (a client and a
    server) that feed each other data in small fragments.
    """

    example_request_headers = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]

    def connection_pair(self):
        client = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True),
        )
        server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        client.initiate_connection()
        server.initiate_connection()
        server.receive_data(client.data_to_send())
        client.receive_data(server.data_to_send())
        client.clear_outbound_data_buffer()
        server.clear_outbound_data_buffer()
        return client, server

    def open_stream(self, client, server, stream_id=1):
        client.send_headers(
            stream_id, self.example_request_headers, end_stream=True,
        )
        return feed_in_chunks(server, client.data_to_send())

    def test_update_for_open_stream_emits_event_immediately(self) -> None:
        client, server = self.connection_pair()
        self.open_stream(client, server)

        client.send_priority_update(1, urgency=0, incremental=True)
        events = feed_in_chunks(server, client.data_to_send())

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, h2.events.PriorityUpdateReceived)
        assert event.stream_id == 1
        assert event.urgency == 0
        assert event.incremental is True
        assert event.unknown_parameters == {}
        assert event.field_value == b"u=0, i=?1"
        # No state is retained for a stream that already exists.
        assert not server._pending_priority_updates

    def test_event_repr(self) -> None:
        client, server = self.connection_pair()
        self.open_stream(client, server)

        client.send_priority_update(1, urgency=0, incremental=True)
        events = feed_in_chunks(server, client.data_to_send())

        assert repr(events[0]) == (
            "<PriorityUpdateReceived stream_id:1, urgency:0, "
            "incremental:True>"
        )

    def test_update_before_stream_open_is_deferred_until_open(self) -> None:
        client, server = self.connection_pair()

        client.send_priority_update(1, urgency=2, incremental=True)
        events = feed_in_chunks(server, client.data_to_send())
        assert events == []
        assert 1 in server._pending_priority_updates

        events = self.open_stream(client, server)
        assert isinstance(events[0], h2.events.RequestReceived)
        update = events[-1]
        assert isinstance(update, h2.events.PriorityUpdateReceived)
        assert update.stream_id == 1
        assert update.urgency == 2
        assert update.incremental is True
        # The retained state is released once the stream opens.
        assert not server._pending_priority_updates

    def test_repeated_updates_for_idle_stream_only_latest_is_kept(self) -> None:
        client, server = self.connection_pair()

        client.send_priority_update(1, urgency=7)
        client.send_priority_update(1, urgency=1, incremental=True)
        client.send_priority_update(1, urgency=4)
        events = feed_in_chunks(server, client.data_to_send())
        assert events == []

        events = self.open_stream(client, server)
        updates = [
            e for e in events
            if isinstance(e, h2.events.PriorityUpdateReceived)
        ]
        assert len(updates) == 1
        assert updates[0].urgency == 4
        assert updates[0].incremental is False
        assert not server._pending_priority_updates

    def test_invalid_field_value_yields_default_parameters(self) -> None:
        client, server = self.connection_pair()
        self.open_stream(client, server)

        frame = h2.priority.PriorityUpdateFrame(stream_id=0)
        frame.prioritized_stream_id = 1
        frame.field_value = b"this is not a valid dictionary"
        events = feed_in_chunks(server, frame.serialize())

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, h2.events.PriorityUpdateReceived)
        assert event.urgency == 3
        assert event.incremental is False
        # The raw value is preserved for the application to inspect.
        assert event.field_value == b"this is not a valid dictionary"

    def test_unknown_parameters_are_preserved_in_event(self) -> None:
        client, server = self.connection_pair()
        self.open_stream(client, server)

        frame = h2.priority.PriorityUpdateFrame(stream_id=0)
        frame.prioritized_stream_id = 1
        frame.field_value = b"u=1, foo=bar, experimental"
        events = feed_in_chunks(server, frame.serialize())

        assert len(events) == 1
        event = events[0]
        assert event.urgency == 1
        assert event.unknown_parameters == {"foo": "bar", "experimental": None}

    def test_legacy_priority_and_priority_update_coexist(self) -> None:
        """
        The RFC 7540 dependency-tree priority and the RFC 9218 priority
        update are independent schemes: both can be used on the same
        connection, and neither is translated into the other.
        """
        client, server = self.connection_pair()
        self.open_stream(client, server)

        client.prioritize(1, weight=42, depends_on=0, exclusive=False)
        client.send_priority_update(1, urgency=5, incremental=True)
        events = feed_in_chunks(server, client.data_to_send())

        assert len(events) == 2
        legacy = events[0]
        assert isinstance(legacy, h2.events.PriorityUpdated)
        assert legacy.stream_id == 1
        assert legacy.weight == 42
        update = events[1]
        assert isinstance(update, h2.events.PriorityUpdateReceived)
        assert update.stream_id == 1
        assert update.urgency == 5
        assert update.incremental is True

    def test_application_can_schedule_from_events_only(self) -> None:
        """
        An application that only subscribes to PriorityUpdateReceived
        events can derive a scheduling order, without h2 doing any
        scheduling itself.
        """
        client, server = self.connection_pair()

        # The client opens three streams and reprioritizes them, both
        # before and after they are opened.
        client.send_priority_update(5, urgency=0)
        client.send_headers(1, self.example_request_headers, end_stream=True)
        client.send_headers(3, self.example_request_headers, end_stream=True)
        client.send_priority_update(1, urgency=7)
        client.send_priority_update(3, urgency=2, incremental=True)
        client.send_headers(5, self.example_request_headers, end_stream=True)
        events = feed_in_chunks(server, client.data_to_send())

        updates = [
            e for e in events
            if isinstance(e, h2.events.PriorityUpdateReceived)
        ]
        schedule = sorted(updates, key=lambda e: (e.urgency, e.stream_id))
        assert [(e.stream_id, e.urgency) for e in schedule] == [
            (5, 0),
            (3, 2),
            (1, 7),
        ]

    def test_update_for_closed_stream_emits_event_without_state(self) -> None:
        client, server = self.connection_pair()
        self.open_stream(client, server)

        # The server ends its side of the stream, fully closing it.
        server.send_headers(
            1, [(":status", "200"), ("server", "pytest-h2")], end_stream=True,
        )
        feed_in_chunks(client, server.data_to_send())
        # Force the cleanup pass that forgets closed streams.
        assert server.open_inbound_streams == 0
        assert 1 not in server.streams

        client.send_priority_update(1, urgency=1)
        events = feed_in_chunks(server, client.data_to_send())

        assert len(events) == 1
        assert isinstance(events[0], h2.events.PriorityUpdateReceived)
        assert events[0].stream_id == 1
        # No state is retained for a closed stream.
        assert not server._pending_priority_updates

    def test_pending_update_released_when_stream_implicitly_closed(self) -> None:
        client, server = self.connection_pair()

        # An update for stream 1, but stream 3 is opened first: stream 1
        # can now never be opened, so the retained update must be dropped.
        client.send_priority_update(1, urgency=0)
        feed_in_chunks(server, client.data_to_send())
        assert 1 in server._pending_priority_updates

        self.open_stream(client, server, stream_id=3)
        assert not server._pending_priority_updates

        # A further update for the implicitly-closed stream 1 is delivered
        # immediately, and still retains no state.
        client.send_priority_update(1, urgency=2)
        events = feed_in_chunks(server, client.data_to_send())
        assert len(events) == 1
        assert isinstance(events[0], h2.events.PriorityUpdateReceived)
        assert events[0].urgency == 2
        assert not server._pending_priority_updates

    def test_pending_updates_are_bounded(self) -> None:
        client, server = self.connection_pair()

        limit = server.MAX_PENDING_PRIORITY_UPDATES
        for stream_id in range(1, 2 * (limit + 10), 2):
            client.send_priority_update(stream_id, urgency=1)
        feed_in_chunks(server, client.data_to_send(), chunk_size=4096)

        assert len(server._pending_priority_updates) == limit
        # The oldest updates were evicted.
        assert 1 not in server._pending_priority_updates


class TestPriorityUpdateValidation:
    """
    Tests for the RFC 9218 validation rules, on both send and receive paths.
    """

    example_request_headers = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]

    def connection_pair(self):
        client = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True),
        )
        server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        client.initiate_connection()
        server.initiate_connection()
        server.receive_data(client.data_to_send())
        client.receive_data(server.data_to_send())
        client.clear_outbound_data_buffer()
        server.clear_outbound_data_buffer()
        return client, server

    @pytest.mark.parametrize("urgency", [-1, 8, 100])
    def test_sending_invalid_urgency_is_rejected(self, urgency) -> None:
        client, _ = self.connection_pair()
        with pytest.raises(h2.exceptions.ProtocolError):
            client.send_priority_update(1, urgency=urgency)

    def test_sending_for_stream_zero_is_rejected(self) -> None:
        client, _ = self.connection_pair()
        with pytest.raises(h2.exceptions.ProtocolError):
            client.send_priority_update(0, urgency=1)

    def test_client_cannot_prioritize_push_streams(self) -> None:
        client, _ = self.connection_pair()
        with pytest.raises(h2.exceptions.ProtocolError):
            client.send_priority_update(2, urgency=1)

    def test_server_cannot_prioritize_request_streams(self) -> None:
        _, server = self.connection_pair()
        with pytest.raises(h2.exceptions.ProtocolError):
            server.send_priority_update(1, urgency=1)

    def test_frame_on_nonzero_stream_is_connection_error(self, frame_factory) -> None:
        _, server = self.connection_pair()
        frame = frame_factory.build_priority_update_frame(
            prioritized_stream_id=1, field_value=b"u=1", stream_id=1,
        )
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(frame.serialize())

    def test_frame_for_element_zero_is_connection_error(self, frame_factory) -> None:
        _, server = self.connection_pair()
        frame = frame_factory.build_priority_update_frame(
            prioritized_stream_id=0, field_value=b"u=1",
        )
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(frame.serialize())

    def test_frame_with_short_payload_is_connection_error(self, frame_factory) -> None:
        _, server = self.connection_pair()
        frame = frame_factory.build_priority_update_frame(
            prioritized_stream_id=1,
        )
        # Truncate the payload to fewer than 4 bytes.
        frame.field_value = b""
        data = bytearray(frame.serialize())
        data[0:3] = (2).to_bytes(3, "big")
        del data[11:]
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(bytes(data))

    def test_update_for_own_streams_is_connection_error(self, frame_factory) -> None:
        """
        A server must only receive updates for client-initiated (request)
        streams: an update naming a server-initiated stream is a connection
        error.
        """
        _, server = self.connection_pair()
        frame = frame_factory.build_priority_update_frame(
            prioritized_stream_id=2, field_value=b"u=1",
        )
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(frame.serialize())

    def test_client_rejects_update_for_request_stream(self, frame_factory) -> None:
        """
        A client must only receive updates for server-initiated (push)
        streams.
        """
        client, _ = self.connection_pair()
        frame = frame_factory.build_priority_update_frame(
            prioritized_stream_id=1, field_value=b"u=1",
        )
        with pytest.raises(h2.exceptions.ProtocolError):
            client.receive_data(frame.serialize())

    def test_server_can_update_push_stream(self, frame_factory) -> None:
        """
        Servers may send PRIORITY_UPDATE frames for push streams. The
        client defers the event until the push promise arrives.
        """
        client, server = self.connection_pair()

        client.send_headers(1, self.example_request_headers, end_stream=True)
        feed_in_chunks(server, client.data_to_send())

        server.send_priority_update(2, urgency=6, incremental=True)
        events = feed_in_chunks(client, server.data_to_send())
        assert events == []
        assert 2 in client._pending_priority_updates

        server.push_stream(
            1, 2,
            [(":authority", "example.com"), (":path", "/style.css"),
             (":scheme", "https"), (":method", "GET")],
        )
        events = feed_in_chunks(client, server.data_to_send())
        update = events[-1]
        assert isinstance(update, h2.events.PriorityUpdateReceived)
        assert update.stream_id == 2
        assert update.urgency == 6
        assert update.incremental is True
        assert not client._pending_priority_updates


class TestNoRfc7540PrioritiesSetting:
    """
    Tests for the connection-level SETTINGS_NO_RFC7540_PRIORITIES flag
    defined by RFC 9218 section 3.
    """

    def test_setting_accepts_zero_and_one(self) -> None:
        s = h2.settings.Settings(client=True)
        s[h2.settings.SettingCodes.NO_RFC7540_PRIORITIES] = 0
        s[h2.settings.SettingCodes.NO_RFC7540_PRIORITIES] = 1

    def test_setting_rejects_other_values(self) -> None:
        s = h2.settings.Settings(client=True)
        with pytest.raises(h2.exceptions.InvalidSettingsValueError):
            s[h2.settings.SettingCodes.NO_RFC7540_PRIORITIES] = 2

    def test_receiving_invalid_value_is_connection_error(self, frame_factory) -> None:
        server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        server.clear_outbound_data_buffer()

        frame = frame_factory.build_settings_frame(
            {h2.settings.SettingCodes.NO_RFC7540_PRIORITIES: 7},
        )
        with pytest.raises(h2.exceptions.InvalidSettingsValueError):
            server.receive_data(frame.serialize())

    def test_receiving_valid_value_emits_remote_settings_changed(self, frame_factory) -> None:
        server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        server.clear_outbound_data_buffer()

        frame = frame_factory.build_settings_frame(
            {h2.settings.SettingCodes.NO_RFC7540_PRIORITIES: 1},
        )
        events = server.receive_data(frame.serialize())

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, h2.events.RemoteSettingsChanged)
        changed = event.changed_settings[
            h2.settings.SettingCodes.NO_RFC7540_PRIORITIES
        ]
        assert changed.new_value == 1
