"""
Test the RFC 8336 ORIGIN frame support.
"""
from __future__ import annotations

import struct

import pytest
from hyperframe.frame import ExtensionFrame, Frame

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
from h2.origin import (
    InvalidOrigin,
    Origin,
    OriginParseError,
    normalize_origin,
    parse_origin_entry,
)


def origin_body(*entries: bytes) -> bytes:
    """
    Build an ORIGIN frame payload from raw origin entries.
    """
    return b"".join(struct.pack("!H", len(entry)) + entry for entry in entries)


class TestOriginNormalization:
    """
    Origins are normalized to their canonical RFC 6454 form.
    """

    @pytest.mark.parametrize(("text", "expected"), [
        ("https://example.com", Origin("https", "example.com", None)),
        ("HTTPS://Example.COM", Origin("https", "example.com", None)),
        ("https://example.com:443", Origin("https", "example.com", None)),
        ("https://example.com:444", Origin("https", "example.com", 444)),
        ("http://example.com:80", Origin("http", "example.com", None)),
        ("http://example.com:8080", Origin("http", "example.com", 8080)),
        ("wss://example.com:443", Origin("wss", "example.com", None)),
        ("ftp://example.com:21", Origin("ftp", "example.com", 21)),
        ("https://127.0.0.1", Origin("https", "127.0.0.1", None)),
        ("https://example.com:0443", Origin("https", "example.com", None)),
    ])
    def test_normalize_basic(self, text, expected) -> None:
        assert normalize_origin(text) == expected

    @pytest.mark.parametrize("text", [
        "https://bücher.de",
        "https://Bücher.de",
        "https://xn--bcher-kva.de",
        "https://XN--BCHER-KVA.de",
    ])
    def test_normalize_idna(self, text) -> None:
        """
        U-labels and A-labels normalize to the same punycode form.
        """
        assert normalize_origin(text) == Origin("https", "xn--bcher-kva.de", None)

    @pytest.mark.parametrize(("text", "expected"), [
        ("https://[2001:0DB8:0000:0000:0000:0000:0000:0001]",
         Origin("https", "2001:db8::1", None)),
        ("https://[::1]:8443", Origin("https", "::1", 8443)),
        ("https://[2001:db8::1]:443", Origin("https", "2001:db8::1", None)),
    ])
    def test_normalize_ipv6(self, text, expected) -> None:
        assert normalize_origin(text) == expected

    @pytest.mark.parametrize("text", [
        "https://bücher.de",
        "https://[2001:db8::1]:8443",
        "http://example.com:8080",
        "https://example.com",
    ])
    def test_str_roundtrip(self, text) -> None:
        origin = normalize_origin(text)
        assert normalize_origin(str(origin)) == origin

    @pytest.mark.parametrize("text", [
        "example.com",
        "https://",
        "https://example.com/path",
        "https://example.com?query",
        "https://user@example.com",
        "://example.com",
        "1https://example.com",
        "https://exa mple.com",
        "https://exam_ple.com",
        "https://:8080",
        "https://example.com:",
        "https://example.com:abc",
        "https://example.com:65536",
        "https://example.com:-1",
        "https://2001:db8::1",
        "https://[2001:db8::1",
        "https://[2001:db8::1]x",
        "https://[2001:db8::1]:",
        "https://[fe80::1%eth0]",
        "https://[not-an-ip]",
        "https://example.com.",
        "https://example..com",
        "https://" + "a" * 64 + ".com",
        "https://" + ".".join(["a" * 63] * 5),
        "https://-example.com",
        "https://example-.com",
    ])
    def test_invalid_origins_rejected(self, text) -> None:
        with pytest.raises(OriginParseError):
            normalize_origin(text)

    def test_non_ascii_wire_entry_rejected(self) -> None:
        """
        On the wire, origins must be ASCII: raw UTF-8 U-labels are invalid.
        """
        with pytest.raises(OriginParseError):
            parse_origin_entry("https://bücher.de".encode())

    def test_empty_entry_rejected(self) -> None:
        with pytest.raises(OriginParseError):
            parse_origin_entry(b"")


class TestRFC8336Client:
    """
    Tests that the client supports receiving the RFC 8336 ORIGIN frame.
    """

    client_config = h2.config.H2Configuration(client_side=True)
    server_config = h2.config.H2Configuration(client_side=False)

    def make_client(self):
        c = h2.connection.H2Connection(config=self.client_config)
        c.initiate_connection()
        c.clear_outbound_data_buffer()
        return c

    def test_receiving_origin_frame(self, frame_factory) -> None:
        """
        An ORIGIN frame on stream 0 fires OriginReceived and populates the
        connection's Origin Set.
        """
        c = self.make_client()

        body = origin_body(b"https://example.com", b"https://example.org:8443")
        f = frame_factory.build_origin_frame(stream_id=0, body=body)
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, h2.events.OriginReceived)
        assert event.origins == [
            Origin("https", "example.com", None),
            Origin("https", "example.org", 8443),
        ]
        assert event.invalid_origins == []

        assert c.origin_set == (
            Origin("https", "example.com", None),
            Origin("https", "example.org", 8443),
        )

        # No data gets sent.
        assert not c.data_to_send()

    def test_origin_frames_accumulate(self, frame_factory) -> None:
        """
        Origins from successive ORIGIN frames are added to the Origin Set.
        """
        c = self.make_client()

        f1 = frame_factory.build_origin_frame(body=origin_body(b"https://example.com"))
        f2 = frame_factory.build_origin_frame(body=origin_body(b"https://example.org"))
        events = c.receive_data(f1.serialize() + f2.serialize())

        assert len(events) == 2
        assert all(isinstance(e, h2.events.OriginReceived) for e in events)
        assert c.origin_set == (
            Origin("https", "example.com", None),
            Origin("https", "example.org", None),
        )

    def test_duplicate_origins_are_collapsed(self, frame_factory) -> None:
        """
        Duplicate declarations, including ones that only differ before
        normalization, appear in the Origin Set only once.
        """
        c = self.make_client()

        body = origin_body(
            b"https://example.com",
            b"HTTPS://EXAMPLE.COM",
            b"https://example.com:443",
        )
        f = frame_factory.build_origin_frame(body=body)
        c.receive_data(f.serialize())

        f2 = frame_factory.build_origin_frame(body=origin_body(b"https://example.com"))
        c.receive_data(f2.serialize())

        assert c.origin_set == (Origin("https", "example.com", None),)

    def test_idna_duplicates_are_collapsed(self, frame_factory) -> None:
        """
        The U-label and A-label forms of the same name are one origin.
        """
        c = self.make_client()

        body = origin_body(b"https://xn--bcher-kva.de", b"https://XN--BCHER-KVA.de")
        f = frame_factory.build_origin_frame(body=body)
        events = c.receive_data(f.serialize())

        assert events[0].origins == [Origin("https", "xn--bcher-kva.de", None)] * 2
        assert c.origin_set == (Origin("https", "xn--bcher-kva.de", None),)

    def test_empty_origin_frame(self, frame_factory) -> None:
        """
        An ORIGIN frame with no entries is legal and changes nothing.
        """
        c = self.make_client()

        f = frame_factory.build_origin_frame(body=b"")
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        assert events[0].origins == []
        assert events[0].invalid_origins == []
        assert c.origin_set == ()

    def test_invalid_entries_are_reported_and_skipped(self, frame_factory) -> None:
        """
        Origin-Entry fields that are not valid origins are ignored, but
        reported on the event with enough detail to diagnose them. Valid
        entries in the same frame are still applied.
        """
        c = self.make_client()

        body = origin_body(
            b"https://example.com",
            b"not-an-origin",
            b"https://exa mple.com",
            "https://bücher.de".encode(),
            b"https://example.com:99999",
        )
        f = frame_factory.build_origin_frame(body=body)
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        event = events[0]
        assert event.origins == [Origin("https", "example.com", None)]
        assert len(event.invalid_origins) == 4
        assert [i.raw for i in event.invalid_origins] == [
            b"not-an-origin",
            b"https://exa mple.com",
            "https://bücher.de".encode(),
            b"https://example.com:99999",
        ]
        assert all(isinstance(i, InvalidOrigin) for i in event.invalid_origins)
        assert all(i.reason for i in event.invalid_origins)

        assert c.origin_set == (Origin("https", "example.com", None),)

    def test_origin_frame_split_across_reads(self, frame_factory) -> None:
        """
        An ORIGIN frame delivered in several TCP segments is reassembled
        before it is processed.
        """
        c = self.make_client()

        body = origin_body(b"https://example.com", b"https://[2001:db8::1]:8443")
        data = frame_factory.build_origin_frame(body=body).serialize()

        events = []
        for i in range(len(data)):
            events.extend(c.receive_data(data[i:i + 1]))

        assert len(events) == 1
        assert events[0].origins == [
            Origin("https", "example.com", None),
            Origin("https", "2001:db8::1", 8443),
        ]
        assert c.origin_set == tuple(events[0].origins)

    def test_origin_frame_split_with_other_frames(self, frame_factory) -> None:
        """
        A partial ORIGIN frame does not block or corrupt adjacent frames.
        """
        c = self.make_client()

        origin = frame_factory.build_origin_frame(body=origin_body(b"https://example.com")).serialize()
        ping = frame_factory.build_ping_frame(b"12345678").serialize()

        events = c.receive_data(origin[:5])
        assert events == []

        events = c.receive_data(origin[5:] + ping)
        assert len(events) == 2
        assert isinstance(events[0], h2.events.OriginReceived)
        assert isinstance(events[1], h2.events.PingReceived)

    def test_origin_frame_flags_ignored(self, frame_factory) -> None:
        """
        The ORIGIN frame defines no flags: unknown flag bits are ignored.
        """
        c = self.make_client()

        f = frame_factory.build_origin_frame(body=origin_body(b"https://example.com"), flag_byte=0xFF)
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        assert events[0].origins == [Origin("https", "example.com", None)]


class TestRFC8336Errors:
    """
    Protocol-mandated error handling for invalid ORIGIN frames.
    """

    client_config = h2.config.H2Configuration(client_side=True)
    server_config = h2.config.H2Configuration(client_side=False)

    def make_client(self):
        c = h2.connection.H2Connection(config=self.client_config)
        c.initiate_connection()
        c.clear_outbound_data_buffer()
        return c

    def make_server(self, frame_factory):
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()
        return c

    def assert_connection_torn_down(self, c, frame_factory) -> None:
        """
        A connection error queues a GOAWAY with PROTOCOL_ERROR.
        """
        expected_frame = frame_factory.build_goaway_frame(
            last_stream_id=0, error_code=h2.errors.ErrorCodes.PROTOCOL_ERROR,
        )
        assert c.data_to_send() == expected_frame.serialize()

    def test_origin_frame_on_stream(self, frame_factory) -> None:
        """
        An ORIGIN frame on any stream other than stream 0 is a connection
        error of type PROTOCOL_ERROR.
        """
        c = self.make_client()

        f = frame_factory.build_origin_frame(stream_id=1, body=origin_body(b"https://example.com"))
        with pytest.raises(h2.exceptions.ProtocolError):
            c.receive_data(f.serialize())

        self.assert_connection_torn_down(c, frame_factory)
        assert c.origin_set == ()

    def test_server_receiving_origin_frame(self, frame_factory) -> None:
        """
        Clients must not send ORIGIN frames: a server receiving one treats
        it as a connection error of type PROTOCOL_ERROR.
        """
        c = self.make_server(frame_factory)

        f = frame_factory.build_origin_frame(stream_id=0, body=origin_body(b"https://example.com"))
        with pytest.raises(h2.exceptions.ProtocolError):
            c.receive_data(f.serialize())

        self.assert_connection_torn_down(c, frame_factory)
        assert c.origin_set == ()

    @pytest.mark.parametrize("body", [
        # A lone trailing byte: too short for an Origin-Len.
        origin_body(b"https://example.com") + b"\x00",
        # Origin-Len larger than the remaining payload.
        origin_body(b"https://example.com") + b"\x00\x20https://short",
        # Origin-Len with no entry at all.
        b"\x00\x10",
    ])
    def test_truncated_origin_frame(self, frame_factory, body) -> None:
        """
        A structurally truncated ORIGIN frame is a connection error of type
        PROTOCOL_ERROR, and the Origin Set is left completely untouched:
        the connection is torn down rather than continuing with a
        partially-applied update.
        """
        c = self.make_client()

        f = frame_factory.build_origin_frame(stream_id=0, body=body)
        with pytest.raises(h2.exceptions.ProtocolError):
            c.receive_data(f.serialize())

        self.assert_connection_torn_down(c, frame_factory)
        assert c.origin_set == ()

        # The connection does not accept further ORIGIN frames either.
        good = frame_factory.build_origin_frame(body=origin_body(b"https://example.org"))
        with pytest.raises(h2.exceptions.ProtocolError):
            c.receive_data(good.serialize())
        assert c.origin_set == ()

    def test_truncated_frame_does_not_update_existing_set(self, frame_factory) -> None:
        """
        A malformed frame after valid ones leaves the earlier Origin Set
        intact.
        """
        c = self.make_client()

        good = frame_factory.build_origin_frame(body=origin_body(b"https://example.com"))
        c.receive_data(good.serialize())
        assert c.origin_set == (Origin("https", "example.com", None),)

        bad = frame_factory.build_origin_frame(
            body=origin_body(b"https://example.org") + b"\x00\xff",
        )
        with pytest.raises(h2.exceptions.ProtocolError):
            c.receive_data(bad.serialize())

        self.assert_connection_torn_down(c, frame_factory)
        assert c.origin_set == (Origin("https", "example.com", None),)

    def test_client_cannot_send_origin(self) -> None:
        """
        Clients must not send ORIGIN frames.
        """
        c = h2.connection.H2Connection(config=self.client_config)
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        with pytest.raises(h2.exceptions.ProtocolError):
            c.send_origin(["https://example.com"])

        assert not c.data_to_send()

    def test_unknown_extension_frames_still_ignored(self, frame_factory) -> None:
        """
        Extension frames of other types still fire UnknownFrameReceived.
        """
        c = self.make_client()

        f = ExtensionFrame(type=0xF0, stream_id=0, body=b"whatever")
        f.body_len = len(f.body)
        events = c.receive_data(f.serialize())
        assert len(events) == 1
        assert isinstance(events[0], h2.events.UnknownFrameReceived)
        assert c.origin_set == ()


class TestRFC8336Server:
    """
    Tests that the server can declare origins with send_origin.
    """

    client_config = h2.config.H2Configuration(client_side=True)
    server_config = h2.config.H2Configuration(client_side=False)

    def make_connected_pair(self):
        server = h2.connection.H2Connection(config=self.server_config)
        client = h2.connection.H2Connection(config=self.client_config)
        server.initiate_connection()
        client.initiate_connection()
        client.receive_data(server.data_to_send())
        server.receive_data(client.data_to_send())
        client.clear_outbound_data_buffer()
        server.clear_outbound_data_buffer()
        return server, client

    def test_send_origin_roundtrip(self) -> None:
        """
        Origins sent by the server are received, normalized, and added to
        the client's Origin Set.
        """
        server, client = self.make_connected_pair()

        server.send_origin([
            "https://example.com",
            "https://bücher.de",
            Origin("https", "2001:db8::1", 8443),
            "http://example.org:8080",
        ])
        events = client.receive_data(server.data_to_send())

        events = [e for e in events if isinstance(e, h2.events.OriginReceived)]
        assert len(events) == 1
        expected = (
            Origin("https", "example.com", None),
            Origin("https", "xn--bcher-kva.de", None),
            Origin("https", "2001:db8::1", 8443),
            Origin("http", "example.org", 8080),
        )
        assert tuple(events[0].origins) == expected
        assert client.origin_set == expected

    def test_send_origin_on_wire(self, frame_factory) -> None:
        """
        The emitted frame is a well-formed ORIGIN frame on stream 0.
        """
        server, client = self.make_connected_pair()

        server.send_origin(["https://example.com"])
        data = server.data_to_send()

        expected = frame_factory.build_origin_frame(
            stream_id=0, body=origin_body(b"https://example.com"),
        )
        assert data == expected.serialize()

    def test_send_origin_empty(self) -> None:
        """
        Sending no origins emits a single empty ORIGIN frame.
        """
        server, client = self.make_connected_pair()

        server.send_origin([])
        events = client.receive_data(server.data_to_send())

        events = [e for e in events if isinstance(e, h2.events.OriginReceived)]
        assert len(events) == 1
        assert events[0].origins == []
        assert client.origin_set == ()

    def test_send_origin_invalid(self) -> None:
        """
        Invalid origins are rejected before anything is sent.
        """
        server, client = self.make_connected_pair()

        with pytest.raises(OriginParseError):
            server.send_origin(["not an origin"])

        assert not server.data_to_send()

    def test_send_origin_entry_exceeding_frame_size(self) -> None:
        """
        A single origin entry larger than the maximum frame size cannot
        be sent.
        """
        server, client = self.make_connected_pair()

        huge_scheme = "a" * (server.max_outbound_frame_size + 1)
        with pytest.raises(ValueError, match="exceeds the maximum frame size"):
            server.send_origin([huge_scheme + "://example.com"])

        assert not server.data_to_send()

    def test_origin_received_repr(self) -> None:
        """
        The OriginReceived event has a useful repr.
        """
        server, client = self.make_connected_pair()

        server.send_origin(["https://example.com"])
        events = client.receive_data(server.data_to_send())
        event = next(e for e in events if isinstance(e, h2.events.OriginReceived))

        assert repr(event) == (
            "<OriginReceived origins:['https://example.com'], invalid_origins:[]>"
        )

    def test_send_origin_splits_large_frames(self) -> None:
        """
        Origin sets larger than one maximum-size frame are split across
        several ORIGIN frames, each within the peer's max frame size.
        """
        server, client = self.make_connected_pair()

        origins = [
            "https://" + ("a" * 50) + str(i) + ".example.com"
            for i in range(400)
        ]
        server.send_origin(origins)
        data = server.data_to_send()

        # Walk the serialized frames: every one must be an ORIGIN frame
        # within the maximum frame size.
        count = 0
        remaining = data
        while remaining:
            frame, length = Frame.parse_frame_header(memoryview(remaining[:9]))
            assert frame.type == 0x0C
            assert frame.stream_id == 0
            assert length <= server.max_outbound_frame_size
            remaining = remaining[9 + length:]
            count += 1
        assert count > 1

        events = client.receive_data(data)
        events = [e for e in events if isinstance(e, h2.events.OriginReceived)]
        assert len(events) == count
        assert client.origin_set == tuple(normalize_origin(o) for o in origins)
