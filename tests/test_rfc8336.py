"""
Test the RFC 8336 ORIGIN frame support.
"""
from __future__ import annotations

import pytest

import h2.config
import h2.connection
import h2.events
import h2.exceptions


def _server_connection() -> h2.connection.H2Connection:
    config = h2.config.H2Configuration(client_side=False)
    return h2.connection.H2Connection(config=config)


class TestRFC8336Client:
    """
    Tests that the client supports receiving the RFC 8336 ORIGIN frame.
    """

    example_origins = [
        b"https://example.com",
        b"https://www.example.com:8443",
        b"https://[::1]:8443",
    ]

    def test_receiving_origin_frame(self, frame_factory) -> None:
        """
        An ORIGIN frame received on stream zero provides both the origins
        in the frame and the full advertised set.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_origin_frame(self.example_origins)
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        event = events[0]

        assert isinstance(event, h2.events.OriginReceived)
        assert event.origins == self.example_origins
        assert event.origin_set == frozenset(self.example_origins)
        assert c.origin_set == frozenset(self.example_origins)

        # No data gets sent.
        assert not c.data_to_send()

    def test_origin_set_is_none_before_any_origin_frame(self) -> None:
        """
        Before any ORIGIN frame is received, the advertised set is None,
        which is distinct from an empty set.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()

        assert c.origin_set is None

    def test_empty_origin_frame_initializes_empty_set(self, frame_factory) -> None:
        """
        An ORIGIN frame with an empty payload initializes the advertised
        set to the empty set, which is not the same as never having
        received an ORIGIN frame.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_origin_frame([])
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        event = events[0]

        assert isinstance(event, h2.events.OriginReceived)
        assert event.origins == []
        assert event.origin_set == frozenset()
        assert c.origin_set == frozenset()
        assert c.origin_set is not None

    def test_origin_frame_fragmented_delivery(self, frame_factory) -> None:
        """
        An ORIGIN frame delivered byte-by-byte is reassembled correctly.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_origin_frame(self.example_origins)
        data = f.serialize()

        events = []
        for byte in data:
            events.extend(c.receive_data(bytes([byte])))

        assert len(events) == 1
        assert events[0].origins == self.example_origins
        assert c.origin_set == frozenset(self.example_origins)

    def test_origin_frames_accumulate(self, frame_factory) -> None:
        """
        Each ORIGIN frame adds to the advertised set: the event carries the
        origins of its own frame, while the connection tracks the union.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        first = frame_factory.build_origin_frame([b"https://example.com"])
        second = frame_factory.build_origin_frame(
            [b"https://other.example", b"https://example.com:8443"],
        )

        first_events = c.receive_data(first.serialize())
        second_events = c.receive_data(second.serialize())

        assert first_events[0].origins == [b"https://example.com"]
        assert first_events[0].origin_set == frozenset(
            [b"https://example.com"],
        )
        assert second_events[0].origins == [
            b"https://other.example",
            b"https://example.com:8443",
        ]
        assert second_events[0].origin_set == frozenset([
            b"https://example.com",
            b"https://other.example",
            b"https://example.com:8443",
        ])
        assert c.origin_set == second_events[0].origin_set

    def test_duplicate_origins_are_deduplicated(self, frame_factory) -> None:
        """
        Duplicate origins, both within a frame and across frames, appear
        only once in the advertised set.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_origin_frame(
            [b"https://example.com", b"https://example.com"],
        )
        c.receive_data(f.serialize())
        c.receive_data(f.serialize())

        assert c.origin_set == frozenset([b"https://example.com"])

    @pytest.mark.parametrize(
        "invalid_origin",
        [
            b"",
            b"example.com",
            b"https://",
            b"https://example.com:",
            b"https://example.com:notaport",
            b"https://example.com:99999",
            b"https://user@example.com",
            b"https://example.com/path",
            b"https://exa mple.com",
            b"://example.com",
            b"https://[::1",
            b"https://[::1]junk",
        ],
    )
    def test_invalid_origins_are_ignored(self, frame_factory, invalid_origin) -> None:
        """
        Origins that are not valid origin serializations are ignored, as
        required by RFC 8336.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_origin_frame(
            [invalid_origin, b"https://valid.example"],
        )
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        assert events[0].origins == [b"https://valid.example"]
        assert c.origin_set == frozenset([b"https://valid.example"])

    @pytest.mark.parametrize(
        "valid_origin",
        [
            b"https://example.com",
            b"https://example.com:8443",
            b"https://[::1]",
            b"https://[2001:db8::1]:8443",
            b"https://EXAMPLE.com",
            b"http://example.com:80",
        ],
    )
    def test_valid_origins_are_preserved(self, frame_factory, valid_origin) -> None:
        """
        Scheme, host, explicit port and IPv6 authority are preserved
        byte-for-byte.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_origin_frame([valid_origin])
        events = c.receive_data(f.serialize())

        assert events[0].origins == [valid_origin]
        assert c.origin_set == frozenset([valid_origin])

    def test_origin_frame_on_stream_is_connection_error(self, frame_factory) -> None:
        """
        An ORIGIN frame received on any stream other than stream zero is a
        connection error of type PROTOCOL_ERROR.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_origin_frame(
            [b"https://example.com"], stream_id=1,
        )

        with pytest.raises(h2.exceptions.ProtocolError):
            c.receive_data(f.serialize())

        # The connection is terminated with a GOAWAY frame.
        assert c.data_to_send()

    @pytest.mark.parametrize(
        "body",
        [
            b"\x00",  # truncated length prefix
            b"\x00\x10https://example.com",  # origin longer than payload
            b"\x00\x05https://example.com",  # trailing garbage after origin
        ],
    )
    def test_malformed_origin_payload_is_connection_error(
        self, frame_factory, body,
    ) -> None:
        """
        An ORIGIN frame whose payload is not a sequence of length-prefixed
        origins is a connection error of type PROTOCOL_ERROR.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_origin_frame([])
        f.body = body
        f.body_len = len(body)

        with pytest.raises(h2.exceptions.ProtocolError):
            c.receive_data(f.serialize())

        assert c.data_to_send()

    def test_origin_received_repr(self, frame_factory) -> None:
        """
        The OriginReceived event has a useful repr.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_origin_frame([b"https://example.com"])
        events = c.receive_data(f.serialize())

        assert repr(events[0]) == (
            "<OriginReceived origins:['https://example.com'], "
            "origin_set:['https://example.com']>"
        )


class TestRFC8336Server:
    """
    Tests that the server supports sending the RFC 8336 ORIGIN frame.
    """

    def test_send_origin_roundtrip(self, frame_factory) -> None:
        """
        Origins sent by the server are received by the client intact.
        """
        server = _server_connection()
        client = h2.connection.H2Connection()

        server.initiate_connection()
        client.initiate_connection()
        client.receive_data(server.data_to_send())

        origins = [
            b"https://example.com",
            b"https://example.com:8443",
            b"https://[2001:db8::1]",
        ]
        server.send_origin(origins)

        events = client.receive_data(server.data_to_send())

        assert len(events) == 1
        assert isinstance(events[0], h2.events.OriginReceived)
        assert events[0].origins == origins
        assert client.origin_set == frozenset(origins)

    def test_send_empty_origin(self) -> None:
        """
        A server can send an ORIGIN frame with no origins.
        """
        server = _server_connection()
        client = h2.connection.H2Connection()

        server.initiate_connection()
        client.initiate_connection()
        client.receive_data(server.data_to_send())

        server.send_origin([])

        events = client.receive_data(server.data_to_send())

        assert len(events) == 1
        assert events[0].origins == []
        assert client.origin_set == frozenset()

    def test_send_origin_before_any_stream(self) -> None:
        """
        A server can send an ORIGIN frame immediately after the connection
        preface, before any stream is opened.
        """
        server = _server_connection()
        server.initiate_connection()
        server.clear_outbound_data_buffer()

        server.send_origin([b"https://example.com"])

        assert server.data_to_send()

    def test_client_cannot_send_origin(self) -> None:
        """
        ORIGIN frames are sent by servers only: clients are forbidden.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()

        with pytest.raises(h2.exceptions.ProtocolError):
            c.send_origin([b"https://example.com"])

    def test_send_origin_requires_bytes(self) -> None:
        """
        Origins must be bytestrings.
        """
        server = _server_connection()
        server.initiate_connection()

        with pytest.raises(ValueError, match="bytestring"):
            server.send_origin(["https://example.com"])

    def test_server_ignores_received_origin_frame(self, frame_factory) -> None:
        """
        A server that receives an ORIGIN frame ignores it, like any other
        unknown extension frame.
        """
        server = _server_connection()
        server.initiate_connection()
        server.clear_outbound_data_buffer()

        f = frame_factory.build_origin_frame([b"https://example.com"])
        events = server.receive_data(frame_factory.preamble() + f.serialize())

        assert not events
        assert server.origin_set is None
        assert not server.data_to_send()

    def test_multiple_origin_frames_sent(self) -> None:
        """
        A server can send several ORIGIN frames over the connection
        lifetime; the client accumulates all of them.
        """
        server = _server_connection()
        client = h2.connection.H2Connection()

        server.initiate_connection()
        client.initiate_connection()
        client.receive_data(server.data_to_send())

        server.send_origin([b"https://example.com"])
        server.send_origin([b"https://other.example"])

        events = client.receive_data(server.data_to_send())

        assert len(events) == 2
        assert events[0].origins == [b"https://example.com"]
        assert events[1].origins == [b"https://other.example"]
        assert client.origin_set == frozenset([
            b"https://example.com",
            b"https://other.example",
        ])
