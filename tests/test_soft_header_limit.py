"""
Tests for the application-level soft header list size limit.

The soft limit (H2Configuration.soft_header_list_size) rejects individual
streams whose decompressed header list exceeds the configured size, while
leaving the connection (and the HPACK dynamic table) intact for all other
streams. The connection-level hard limit enforced by the HPACK decoder
continues to terminate the connection when breached.
"""

from __future__ import annotations

import hyperframe
import pytest

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions

# The decompressed size of the base request headers below, computed as
# defined in RFC 7541 Section 4.1: sum of name and value lengths plus 32
# bytes of overhead per field.
#
#     :authority: example.com -> 10 + 11 + 32 = 53
#     :path: /                  ->  5 +  1 + 32 = 38
#     :scheme: https            ->  7 +  5 + 32 = 44
#     :method: GET              ->  7 +  3 + 32 = 42
#                                   total         177
BASE_REQUEST_SIZE = 177
SOFT_LIMIT = 250


class TestSoftHeaderListSizeLimit:
    """
    Tests for the per-stream soft header list size limit.
    """

    base_request_headers = [
        (b":authority", b"example.com"),
        (b":path", b"/"),
        (b":scheme", b"https"),
        (b":method", b"GET"),
    ]

    # Base headers plus a small indexed field and a large padding field:
    # 177 + (5 + 3 + 32) + (5 + 64 + 32) = 318 > SOFT_LIMIT.
    oversized_request_headers = [
        (b":authority", b"example.com"),
        (b":path", b"/"),
        (b":scheme", b"https"),
        (b":method", b"GET"),
        (b"x-tag", b"abc"),
        (b"x-pad", b"v" * 64),
    ]

    # A legal follow-up request that reuses the indexed field inserted
    # into the HPACK dynamic table by the oversized request:
    # 177 + (5 + 3 + 32) = 217 <= SOFT_LIMIT.
    followup_request_headers = [
        (b":authority", b"example.com"),
        (b":path", b"/"),
        (b":scheme", b"https"),
        (b":method", b"GET"),
        (b"x-tag", b"abc"),
    ]

    example_response_headers = [
        (b":status", b"200"),
    ]

    def _server_connection(self) -> h2.connection.H2Connection:
        config = h2.config.H2Configuration(
            client_side=False,
            soft_header_list_size=SOFT_LIMIT,
        )
        c = h2.connection.H2Connection(config=config)
        c.initiate_connection()
        c.clear_outbound_data_buffer()
        return c

    def _client_connection(self) -> h2.connection.H2Connection:
        config = h2.config.H2Configuration(
            client_side=True,
            soft_header_list_size=SOFT_LIMIT,
        )
        c = h2.connection.H2Connection(config=config)
        c.initiate_connection()
        c.send_headers(stream_id=1, headers=self.base_request_headers)
        c.clear_outbound_data_buffer()
        return c

    def test_request_under_soft_limit_is_accepted(self, frame_factory) -> None:
        """
        A request whose header list is smaller than the soft limit is
        processed entirely normally.
        """
        c = self._server_connection()
        c.receive_data(frame_factory.preamble())

        f = frame_factory.build_headers_frame(
            self.base_request_headers,
            flags=["END_STREAM"],
        )
        events = c.receive_data(f.serialize())

        assert isinstance(events[0], h2.events.RequestReceived)
        assert events[0].headers == self.base_request_headers
        assert c.data_to_send() == b""

    def test_request_at_soft_limit_is_accepted(self, frame_factory) -> None:
        """
        A header list whose size is exactly the soft limit is not rejected:
        only lists that exceed the limit are.
        """
        headers = [*self.base_request_headers, (b"x-fill", b"f" * 35)]
        assert sum(len(n) + len(v) + 32 for n, v in headers) == SOFT_LIMIT

        c = self._server_connection()
        c.receive_data(frame_factory.preamble())

        f = frame_factory.build_headers_frame(headers, flags=["END_STREAM"])
        events = c.receive_data(f.serialize())

        assert isinstance(events[0], h2.events.RequestReceived)
        assert events[0].headers == headers

    def test_request_over_soft_limit_is_reset(self, frame_factory) -> None:
        """
        A request whose header list exceeds the soft limit is rejected: no
        RequestReceived event is emitted, the headers never reach the
        application, and the stream is reset while the connection stays up.
        """
        c = self._server_connection()
        c.receive_data(frame_factory.preamble())

        f = frame_factory.build_headers_frame(
            self.oversized_request_headers,
            flags=["END_STREAM"],
        )
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, h2.events.StreamReset)
        assert event.stream_id == 1
        assert event.error_code == h2.errors.ErrorCodes.REFUSED_STREAM
        assert event.remote_reset is False
        assert not hasattr(event, "headers")

        expected = frame_factory.build_rst_stream_frame(
            1,
            h2.errors.ErrorCodes.REFUSED_STREAM,
        )
        assert c.data_to_send() == expected.serialize()

        # The connection is still usable: a subsequent legal request on a
        # new stream is processed normally.
        c.clear_outbound_data_buffer()
        f = frame_factory.build_headers_frame(
            self.followup_request_headers,
            flags=["END_STREAM"],
            stream_id=3,
        )
        events = c.receive_data(f.serialize())

        assert isinstance(events[0], h2.events.RequestReceived)
        assert events[0].stream_id == 3
        assert events[0].headers == self.followup_request_headers

    def test_continuation_block_over_soft_limit_is_fully_consumed(self, frame_factory) -> None:
        """
        A header block split across HEADERS and CONTINUATION frames that
        exceeds the soft limit is consumed in full (keeping the HPACK
        dynamic table in sync) before the stream is reset.
        """
        c = self._server_connection()
        c.receive_data(frame_factory.preamble())

        encoded = frame_factory.encoder.encode(self.oversized_request_headers)
        split = len(encoded) // 2

        headers_frame = hyperframe.frame.HeadersFrame(1)
        headers_frame.data = encoded[:split]
        headers_frame.flags.add("END_STREAM")
        continuation_frame = frame_factory.build_continuation_frame(
            encoded[split:],
            flags=["END_HEADERS"],
            stream_id=1,
        )

        events = c.receive_data(
            headers_frame.serialize() + continuation_frame.serialize(),
        )

        assert len(events) == 1
        assert isinstance(events[0], h2.events.StreamReset)
        assert events[0].stream_id == 1

        expected = frame_factory.build_rst_stream_frame(
            1,
            h2.errors.ErrorCodes.REFUSED_STREAM,
        )
        assert c.data_to_send() == expected.serialize()

        # The follow-up request references dynamic table entries inserted
        # by the rejected header block: it must still decode correctly.
        c.clear_outbound_data_buffer()
        f = frame_factory.build_headers_frame(
            self.followup_request_headers,
            flags=["END_STREAM"],
            stream_id=3,
        )
        events = c.receive_data(f.serialize())

        assert isinstance(events[0], h2.events.RequestReceived)
        assert events[0].headers == self.followup_request_headers

    def test_rejected_block_keeps_hpack_table_in_sync(self, frame_factory) -> None:
        """
        The follow-up request is encoded by the peer against a dynamic
        table that contains entries inserted by the rejected header block.
        If h2 had skipped decoding the rejected block, decoding this
        request would fail with a connection error.
        """
        c = self._server_connection()
        c.receive_data(frame_factory.preamble())

        f = frame_factory.build_headers_frame(
            self.oversized_request_headers,
            flags=["END_STREAM"],
        )
        c.receive_data(f.serialize())
        c.clear_outbound_data_buffer()

        # Sanity check: the peer's encoder really does emit an indexed
        # representation for the follow-up request, i.e. the encoded block
        # is much smaller than the decompressed header list.
        encoded_followup = frame_factory.encoder.encode(
            self.followup_request_headers,
        )
        assert len(encoded_followup) < 32

        followup_frame = hyperframe.frame.HeadersFrame(3)
        followup_frame.data = encoded_followup
        followup_frame.flags.add("END_HEADERS")
        followup_frame.flags.add("END_STREAM")
        events = c.receive_data(followup_frame.serialize())

        assert isinstance(events[0], h2.events.RequestReceived)
        assert events[0].headers == self.followup_request_headers

    def test_trailers_over_soft_limit_are_reset(self, frame_factory) -> None:
        """
        Trailers whose header list exceeds the soft limit are dropped: the
        application sees neither TrailersReceived nor the rejected fields,
        and the stream is reset without killing the connection.
        """
        c = self._server_connection()
        c.receive_data(frame_factory.preamble())

        f = frame_factory.build_headers_frame(self.base_request_headers)
        events = c.receive_data(f.serialize())
        assert len(events) == 1
        assert isinstance(events[0], h2.events.RequestReceived)
        c.clear_outbound_data_buffer()

        # 13 + 250 + 32 = 295 > SOFT_LIMIT.
        trailers = [(b"x-trailer-pad", b"t" * 250)]
        f = frame_factory.build_headers_frame(
            trailers,
            flags=["END_STREAM"],
            stream_id=1,
        )
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, h2.events.StreamReset)
        assert event.stream_id == 1
        assert event.error_code == h2.errors.ErrorCodes.REFUSED_STREAM
        assert event.remote_reset is False

        expected = frame_factory.build_rst_stream_frame(
            1,
            h2.errors.ErrorCodes.REFUSED_STREAM,
        )
        assert c.data_to_send() == expected.serialize()

        # Other streams are unaffected.
        c.clear_outbound_data_buffer()
        f = frame_factory.build_headers_frame(
            self.followup_request_headers,
            flags=["END_STREAM"],
            stream_id=3,
        )
        events = c.receive_data(f.serialize())

        assert isinstance(events[0], h2.events.RequestReceived)
        assert events[0].stream_id == 3

    def test_push_promise_over_soft_limit_is_refused(self, frame_factory) -> None:
        """
        A PUSH_PROMISE whose header list exceeds the soft limit refuses
        only the promised stream: no PushedStreamReceived event fires and
        the parent stream remains usable.
        """
        c = self._client_connection()

        f = frame_factory.build_push_promise_frame(
            stream_id=1,
            promised_stream_id=2,
            headers=self.oversized_request_headers,
            flags=["END_HEADERS"],
        )
        events = c.receive_data(f.serialize())

        assert not any(isinstance(e, h2.events.PushedStreamReceived) for e in events)

        expected = frame_factory.build_rst_stream_frame(
            2,
            h2.errors.ErrorCodes.REFUSED_STREAM,
        )
        assert c.data_to_send() == expected.serialize()

        # The parent stream is still open and can receive its response.
        f = frame_factory.build_headers_frame(
            self.example_response_headers,
            flags=["END_STREAM"],
            stream_id=1,
        )
        events = c.receive_data(f.serialize())

        assert any(isinstance(e, h2.events.ResponseReceived) for e in events)

    def test_hard_limit_still_terminates_connection(self, frame_factory) -> None:
        """
        The connection-level hard limit is unaffected by the soft limit: a
        header list that exceeds the HPACK decoder's max_header_list_size
        remains a connection error.
        """
        c = self._server_connection()
        c.decoder.max_header_list_size = SOFT_LIMIT + 50
        c.receive_data(frame_factory.preamble())

        f = frame_factory.build_headers_frame(
            self.oversized_request_headers,
            flags=["END_STREAM"],
        )

        with pytest.raises(h2.exceptions.DenialOfServiceError):
            c.receive_data(f.serialize())

        # A GOAWAY frame is emitted for the connection error.
        data = c.data_to_send()
        assert data[3] == 0x7  # GOAWAY frame type

    def test_no_soft_limit_by_default(self, frame_factory) -> None:
        """
        Without an explicit soft limit, oversized header lists are accepted
        as long as they stay below the connection-level hard limit.
        """
        config = h2.config.H2Configuration(client_side=False)
        c = h2.connection.H2Connection(config=config)
        c.initiate_connection()
        c.clear_outbound_data_buffer()
        c.receive_data(frame_factory.preamble())

        f = frame_factory.build_headers_frame(
            self.oversized_request_headers,
            flags=["END_STREAM"],
        )
        events = c.receive_data(f.serialize())

        assert isinstance(events[0], h2.events.RequestReceived)
        assert c.data_to_send() == b""


class TestSoftHeaderListSizeConfig:
    """
    Validation of the soft_header_list_size configuration option.
    """

    @pytest.mark.parametrize("value", [0, 1, 1024, None])
    def test_valid_values(self, value) -> None:
        config = h2.config.H2Configuration(soft_header_list_size=value)
        assert config.soft_header_list_size == value

    @pytest.mark.parametrize("value", ["1024", 1.5, True, False, object()])
    def test_invalid_types(self, value) -> None:
        with pytest.raises(ValueError, match="must be an int or None"):
            h2.config.H2Configuration(soft_header_list_size=value)

    def test_negative_value(self) -> None:
        with pytest.raises(ValueError, match="cannot be negative"):
            h2.config.H2Configuration(soft_header_list_size=-1)

    def test_defaults_to_none(self) -> None:
        config = h2.config.H2Configuration()
        assert config.soft_header_list_size is None
