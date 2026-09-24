"""
Test the RFC 8336 ORIGIN frame support.
"""
from __future__ import annotations

import pytest

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions


class TestRFC8336Client:
    """
    Tests that the client supports receiving the RFC 8336 ORIGIN frame.
    """

    example_origins = [
        b"https://example.com",
        b"https://www.example.com:8443",
        b"https://[2001:db8::1]",
    ]

    def test_receiving_origin_frame(self, frame_factory) -> None:
        """
        An ORIGIN frame received on stream zero fires an OriginReceived
        event carrying the origins from the frame, and updates the
        connection's Origin Set.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_origin_frame(origins=self.example_origins)
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        event = events[0]

        assert isinstance(event, h2.events.OriginReceived)
        assert event.origins == self.example_origins
        assert c.origin_set == frozenset(self.example_origins)

        # No data gets sent.
        assert not c.data_to_send()

    def test_origin_set_is_none_before_any_origin_frame(self, frame_factory) -> None:
        """
        Before any ORIGIN frame is received, the Origin Set is None, which
        is distinct from the empty set.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()

        assert c.origin_set is None

    def test_empty_origin_frame_is_not_none(self, frame_factory) -> None:
        """
        An ORIGIN frame carrying no origins clears the Origin Set: the set
        becomes empty, which must not be conflated with "no ORIGIN frame
        received yet".
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()

        f = frame_factory.build_origin_frame(origins=[])
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        event = events[0]

        assert isinstance(event, h2.events.OriginReceived)
        assert event.origins == []
        assert c.origin_set is not None
        assert c.origin_set == frozenset()

    def test_origin_frames_replace_the_origin_set(self, frame_factory) -> None:
        """
        Each ORIGIN frame replaces the Origin Set wholesale: the set is not
        cumulative across frames.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()

        f = frame_factory.build_origin_frame(
            origins=[b"https://example.com", b"https://www.example.com"],
        )
        events = c.receive_data(f.serialize())
        assert events[0].origins == [b"https://example.com", b"https://www.example.com"]
        assert c.origin_set == frozenset([b"https://example.com", b"https://www.example.com"])

        # A second frame replaces the set entirely: the first frame's
        # origins are gone.
        f = frame_factory.build_origin_frame(origins=[b"https://other.example.com"])
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        assert events[0].origins == [b"https://other.example.com"]
        assert c.origin_set == frozenset([b"https://other.example.com"])

        # An empty frame clears the set.
        f = frame_factory.build_origin_frame(origins=[])
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        assert events[0].origins == []
        assert c.origin_set == frozenset()

    @pytest.mark.parametrize("chunk_size", [1, 3, 7])
    def test_receiving_fragmented_origin_frame(self, frame_factory, chunk_size) -> None:
        """
        An ORIGIN frame that arrives split across multiple chunks of data
        is reassembled and processed once complete.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_origin_frame(origins=self.example_origins)
        data = f.serialize()

        events = []
        for i in range(0, len(data), chunk_size):
            events.extend(c.receive_data(data[i:i + chunk_size]))

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, h2.events.OriginReceived)
        assert event.origins == self.example_origins
        assert c.origin_set == frozenset(self.example_origins)

    def test_duplicate_origins(self, frame_factory) -> None:
        """
        Duplicate origins in a frame are preserved in the event exactly as
        sent, but collapse in the connection's Origin Set.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()

        origins = [b"https://example.com", b"https://example.com", b"https://www.example.com"]
        f = frame_factory.build_origin_frame(origins=origins)
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        assert events[0].origins == origins
        assert c.origin_set == frozenset([b"https://example.com", b"https://www.example.com"])

    @pytest.mark.parametrize("invalid_origin", [
        b"",
        b"example.com",
        b"example.com:8443",
        b"https://",
        b"https://example.com:notaport",
        b"https://exam ple.com",
        b"https://example.com/path",
        b"https://user@example.com",
        b"https://2001:db8::1",
        b"https://[2001:db8::1",
        b"https://ex\xc3\xa4mple.com",
        b"//example.com",
    ])
    def test_invalid_origins_are_ignored(self, frame_factory, invalid_origin) -> None:
        """
        Origins in the frame that are not valid origin serializations are
        ignored: they appear neither in the event nor in the Origin Set.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()

        f = frame_factory.build_origin_frame(
            origins=[b"https://example.com", invalid_origin],
        )
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        assert events[0].origins == [b"https://example.com"]
        assert c.origin_set == frozenset([b"https://example.com"])

    @pytest.mark.parametrize("origin", [
        b"https://example.com",
        b"http://example.com",
        b"https://example.com:8443",
        b"https://EXAMPLE.com",
        b"https://[2001:db8::1]",
        b"https://[2001:db8::1]:8443",
        b"https://127.0.0.1:8080",
    ])
    def test_origin_structure_is_preserved(self, frame_factory, origin) -> None:
        """
        The scheme, host, explicit port, and IPv6 literal of each origin
        are preserved byte-for-byte.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()

        f = frame_factory.build_origin_frame(origins=[origin])
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        assert events[0].origins == [origin]
        assert c.origin_set == frozenset([origin])

    def test_origin_frame_on_nonzero_stream_is_ignored(self, frame_factory) -> None:
        """
        RFC 8336 section 2.3: an ORIGIN frame received on any stream other
        than stream 0 MUST be ignored.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_origin_frame(
            origins=[b"https://example.com"], stream_id=1,
        )
        events = c.receive_data(f.serialize())

        assert not events
        assert c.origin_set is None
        assert not c.data_to_send()

    def test_malformed_origin_frame(self, frame_factory) -> None:
        """
        An ORIGIN frame whose length-prefixed origins overrun the frame
        body is a connection error.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        # Build a frame body whose only origin claims to be 16 bytes long,
        # but only 2 bytes of data follow.
        body = b"\x00\x10ab"
        header = len(body).to_bytes(3, "big") + b"\x0c\x00\x00\x00\x00\x00"

        with pytest.raises(h2.exceptions.FrameDataMissingError) as e:
            c.receive_data(header + body)

        assert e.value.error_code == h2.errors.ErrorCodes.FRAME_SIZE_ERROR

    def test_origin_received_event_repr(self, frame_factory) -> None:
        """
        The OriginReceived event has a readable representation.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()

        f = frame_factory.build_origin_frame(origins=[b"https://example.com"])
        events = c.receive_data(f.serialize())

        assert repr(events[0]) == "<OriginReceived origins:['https://example.com']>"


class TestRFC8336Server:
    """
    Tests that the server supports sending the RFC 8336 ORIGIN frame.
    """

    server_config = h2.config.H2Configuration(client_side=False)

    def test_sending_origin_frame(self, frame_factory) -> None:
        """
        A server can send an ORIGIN frame advertising a set of origins.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()

        origins = [b"https://example.com", b"https://www.example.com:8443"]
        c.send_origin(origins)

        f = frame_factory.build_origin_frame(origins=origins)
        assert c.data_to_send() == f.serialize()

    def test_sending_origin_frame_with_str_origins(self, frame_factory) -> None:
        """
        Origins may be provided as text strings, which are encoded to
        ASCII.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()

        c.send_origin(["https://example.com"])

        f = frame_factory.build_origin_frame(origins=[b"https://example.com"])
        assert c.data_to_send() == f.serialize()

    def test_sending_empty_origin_frame(self, frame_factory) -> None:
        """
        A server can send an empty ORIGIN frame to clear the Origin Set.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()

        c.send_origin([])

        f = frame_factory.build_origin_frame(origins=[])
        assert c.data_to_send() == f.serialize()

    @pytest.mark.parametrize("invalid_origin", [
        b"example.com",
        b"https://exam ple.com",
        "https://ex\xe4mple.com",
        42,
    ])
    def test_sending_invalid_origin_rejected(self, frame_factory, invalid_origin) -> None:
        """
        Origins that are not valid ASCII origin serializations are
        rejected when sending.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()

        with pytest.raises(ValueError, match="Origin"):
            c.send_origin([invalid_origin])

        assert not c.data_to_send()

    def test_client_cannot_send_origin(self, frame_factory) -> None:
        """
        RFC 8336 section 2.3: clients MUST NOT send ORIGIN frames.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        with pytest.raises(h2.exceptions.ProtocolError, match="Clients MUST NOT send ORIGIN frames"):
            c.send_origin([b"https://example.com"])

        assert not c.data_to_send()

    def test_server_receiving_origin_frame_is_connection_error(self, frame_factory) -> None:
        """
        RFC 8336 section 2.3: servers MUST treat the receipt of an ORIGIN
        frame as a connection error of type PROTOCOL_ERROR.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()

        f = frame_factory.build_origin_frame(origins=[b"https://example.com"])

        with pytest.raises(h2.exceptions.ProtocolError, match="must not receive ORIGIN"):
            c.receive_data(f.serialize())

        assert c.data_to_send()
        assert c.origin_set is None

    def test_full_origin_exchange(self, frame_factory) -> None:
        """
        A server can advertise origins to a client, which observes both
        the per-frame origins and the current Origin Set, across multiple
        exchanges.
        """
        server = h2.connection.H2Connection(config=self.server_config)
        client = h2.connection.H2Connection()
        server.initiate_connection()
        client.initiate_connection()

        client.receive_data(server.data_to_send())
        server.receive_data(client.data_to_send())

        assert client.origin_set is None

        server.send_origin([b"https://example.com", b"https://[::1]:8443"])
        events = client.receive_data(server.data_to_send())

        origin_events = [e for e in events if isinstance(e, h2.events.OriginReceived)]
        assert len(origin_events) == 1
        assert origin_events[0].origins == [b"https://example.com", b"https://[::1]:8443"]
        assert client.origin_set == frozenset([b"https://example.com", b"https://[::1]:8443"])

        # A second advertisement replaces the first.
        server.send_origin([b"https://www.example.com"])
        events = client.receive_data(server.data_to_send())

        origin_events = [e for e in events if isinstance(e, h2.events.OriginReceived)]
        assert len(origin_events) == 1
        assert origin_events[0].origins == [b"https://www.example.com"]
        assert client.origin_set == frozenset([b"https://www.example.com"])
