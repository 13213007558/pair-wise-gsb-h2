"""
Tests for the optional connection-level request admission budget.

These tests use a small budget capacity and a fixed (fake) clock to verify
that the budget counts newly created request streams, that trailers,
CONTINUATION frames, and retransmitted frames do not consume fresh credit,
that the budget refills at the configured rate, and that exhaustion
terminates the connection with a GOAWAY frame before the request reaches
the application.
"""
from __future__ import annotations

import pytest
from hyperframe.frame import GoAwayFrame, HeadersFrame

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions


class FakeClock:
    """
    A monotonic clock whose time only advances when told to.
    """

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestRequestBudget:
    """
    Tests for the connection-level request admission budget.
    """

    example_request_headers = [
        (b":authority", b"example.com"),
        (b":path", b"/"),
        (b":scheme", b"https"),
        (b":method", b"GET"),
    ]
    example_trailer_headers = [
        (b"x-trailer", b"done"),
    ]

    def _make_server(self, capacity=None, refill_rate=0.0, clock=None):
        config = h2.config.H2Configuration(
            client_side=False,
            request_budget_capacity=capacity,
            request_budget_refill_rate=refill_rate,
            budget_clock=clock,
        )
        c = h2.connection.H2Connection(config=config)
        c.initiate_connection()
        return c

    def _receive_request(self, conn, frame_factory, stream_id, end_stream=True):
        flags = ["END_STREAM"] if end_stream else []
        f = frame_factory.build_headers_frame(
            self.example_request_headers, flags=flags, stream_id=stream_id,
        )
        return conn.receive_data(f.serialize())

    def _expected_goaway(self, last_stream_id):
        f = GoAwayFrame(0)
        f.last_stream_id = last_stream_id
        f.error_code = h2.errors.ErrorCodes.ENHANCE_YOUR_CALM
        return f.serialize()

    def test_concurrent_requests_within_capacity_are_delivered(
            self, frame_factory) -> None:
        """
        Concurrent requests that fit in the budget are all delivered.
        """
        clock = FakeClock()
        c = self._make_server(capacity=3, clock=clock)
        c.receive_data(frame_factory.preamble())

        events = []
        for stream_id in (1, 3, 5):
            events.extend(self._receive_request(c, frame_factory, stream_id))

        received = [e for e in events if isinstance(e, h2.events.RequestReceived)]
        assert len(received) == 3
        assert [e.stream_id for e in received] == [1, 3, 5]

    def test_headers_rst_stream_loop_exhausts_budget(self, frame_factory) -> None:
        """
        A peer that resets each stream immediately keeps the concurrent
        stream count low, but the budget still runs out and the connection
        is terminated with GOAWAY/ENHANCE_YOUR_CALM.
        """
        clock = FakeClock()
        c = self._make_server(capacity=2, clock=clock)
        c.receive_data(frame_factory.preamble())

        events = []
        for stream_id in (1, 3):
            events.extend(self._receive_request(c, frame_factory, stream_id))
            rst = frame_factory.build_rst_stream_frame(stream_id)
            events.extend(c.receive_data(rst.serialize()))

        received = [e for e in events if isinstance(e, h2.events.RequestReceived)]
        assert len(received) == 2
        resets = [e for e in events if isinstance(e, h2.events.StreamReset)]
        assert len(resets) == 2

        # The third new request stream is refused before delivery.
        c.clear_outbound_data_buffer()
        f = frame_factory.build_headers_frame(
            self.example_request_headers, flags=["END_STREAM"], stream_id=5,
        )
        with pytest.raises(h2.exceptions.RequestBudgetExhaustedError):
            c.receive_data(f.serialize())

        assert c.data_to_send() == self._expected_goaway(last_stream_id=3)
        assert 5 not in c.streams
        assert c.highest_inbound_stream_id == 3

    def test_exhaustion_skips_buffered_requests(self, frame_factory) -> None:
        """
        When the budget runs out partway through a buffer, the remaining
        buffered requests are not delivered to the application.
        """
        clock = FakeClock()
        c = self._make_server(capacity=1, clock=clock)
        c.receive_data(frame_factory.preamble())

        events = self._receive_request(c, frame_factory, 1)
        assert len([e for e in events
                    if isinstance(e, h2.events.RequestReceived)]) == 1

        c.clear_outbound_data_buffer()
        f3 = frame_factory.build_headers_frame(
            self.example_request_headers, flags=["END_STREAM"], stream_id=3,
        )
        f5 = frame_factory.build_headers_frame(
            self.example_request_headers, flags=["END_STREAM"], stream_id=5,
        )
        with pytest.raises(h2.exceptions.RequestBudgetExhaustedError):
            c.receive_data(f3.serialize() + f5.serialize())

        # Neither buffered request stream was created or delivered.
        assert 3 not in c.streams
        assert 5 not in c.streams
        assert c.highest_inbound_stream_id == 1
        assert c.data_to_send() == self._expected_goaway(last_stream_id=1)

    def test_budget_refills_at_configured_rate(self, frame_factory) -> None:
        """
        The budget refills over time at the configured rate, up to the
        configured capacity.
        """
        clock = FakeClock()
        c = self._make_server(capacity=1, refill_rate=2.0, clock=clock)
        c.receive_data(frame_factory.preamble())

        events = self._receive_request(c, frame_factory, 1)
        assert len([e for e in events
                    if isinstance(e, h2.events.RequestReceived)]) == 1

        # Half a second refills exactly one token: the next request is
        # allowed, and the one after that (only 0.5 tokens refilled) is not.
        clock.advance(0.5)
        events = self._receive_request(c, frame_factory, 3)
        assert len([e for e in events
                    if isinstance(e, h2.events.RequestReceived)]) == 1

        clock.advance(0.25)
        c.clear_outbound_data_buffer()
        f = frame_factory.build_headers_frame(
            self.example_request_headers, flags=["END_STREAM"], stream_id=5,
        )
        with pytest.raises(h2.exceptions.RequestBudgetExhaustedError):
            c.receive_data(f.serialize())

        assert c.data_to_send() == self._expected_goaway(last_stream_id=3)

    def test_trailers_do_not_consume_budget(self, frame_factory) -> None:
        """
        Trailer HEADERS frames on an existing stream do not consume credit.
        """
        clock = FakeClock()
        c = self._make_server(capacity=1, clock=clock)
        c.receive_data(frame_factory.preamble())

        events = self._receive_request(
            c, frame_factory, 1, end_stream=False,
        )
        assert len([e for e in events
                    if isinstance(e, h2.events.RequestReceived)]) == 1

        trailers = frame_factory.build_headers_frame(
            self.example_trailer_headers, flags=["END_STREAM"], stream_id=1,
        )
        events = c.receive_data(trailers.serialize())
        assert len([e for e in events
                    if isinstance(e, h2.events.TrailersReceived)]) == 1

        # The single token was consumed by the request, not the trailers:
        # the next new stream is refused.
        c.clear_outbound_data_buffer()
        f = frame_factory.build_headers_frame(
            self.example_request_headers, flags=["END_STREAM"], stream_id=3,
        )
        with pytest.raises(h2.exceptions.RequestBudgetExhaustedError):
            c.receive_data(f.serialize())

        assert c.data_to_send() == self._expected_goaway(last_stream_id=1)

    def test_continuation_frames_do_not_consume_budget(self, frame_factory) -> None:
        """
        A header block split across HEADERS and CONTINUATION frames consumes
        exactly one token.
        """
        clock = FakeClock()
        c = self._make_server(capacity=1, clock=clock)
        c.receive_data(frame_factory.preamble())

        header_block = frame_factory.encoder.encode(
            self.example_request_headers,
        )
        f = HeadersFrame(1)
        f.data = header_block[:5]
        f.flags = {"END_STREAM"}
        cont = frame_factory.build_continuation_frame(
            header_block[5:], flags=["END_HEADERS"], stream_id=1,
        )
        events = c.receive_data(f.serialize() + cont.serialize())
        assert len([e for e in events
                    if isinstance(e, h2.events.RequestReceived)]) == 1

        # Only one token was consumed by the whole header block.
        c.clear_outbound_data_buffer()
        f = frame_factory.build_headers_frame(
            self.example_request_headers, flags=["END_STREAM"], stream_id=3,
        )
        with pytest.raises(h2.exceptions.RequestBudgetExhaustedError):
            c.receive_data(f.serialize())

        assert c.data_to_send() == self._expected_goaway(last_stream_id=1)

    def test_retransmitted_frames_do_not_consume_budget(
            self, frame_factory) -> None:
        """
        Frames retransmitted on reset streams reference old stream IDs and
        do not consume fresh credit.
        """
        clock = FakeClock()
        c = self._make_server(capacity=2, clock=clock)
        c.receive_data(frame_factory.preamble())

        events = self._receive_request(c, frame_factory, 1)
        assert len([e for e in events
                    if isinstance(e, h2.events.RequestReceived)]) == 1

        rst = frame_factory.build_rst_stream_frame(1)
        c.receive_data(rst.serialize())

        # A retransmitted HEADERS frame on the reset stream is rejected with
        # a RST_STREAM response, but consumes no budget.
        c.clear_outbound_data_buffer()
        replay = frame_factory.build_headers_frame(
            self.example_request_headers, flags=["END_STREAM"], stream_id=1,
        )
        events = c.receive_data(replay.serialize())
        assert not [e for e in events
                    if isinstance(e, h2.events.RequestReceived)]
        expected_rst = frame_factory.build_rst_stream_frame(
            1, h2.errors.ErrorCodes.STREAM_CLOSED,
        )
        assert c.data_to_send() == expected_rst.serialize()

        # The remaining token is still available for a genuinely new stream.
        events = self._receive_request(c, frame_factory, 3)
        assert len([e for e in events
                    if isinstance(e, h2.events.RequestReceived)]) == 1

        c.clear_outbound_data_buffer()
        f = frame_factory.build_headers_frame(
            self.example_request_headers, flags=["END_STREAM"], stream_id=5,
        )
        with pytest.raises(h2.exceptions.RequestBudgetExhaustedError):
            c.receive_data(f.serialize())

        assert c.data_to_send() == self._expected_goaway(last_stream_id=3)

    def test_budget_disabled_by_default(self, frame_factory) -> None:
        """
        Without configuration, no budget is enforced and the original
        behaviour is preserved.
        """
        c = self._make_server()
        c.receive_data(frame_factory.preamble())

        events = []
        for i in range(10):
            stream_id = (2 * i) + 1
            events.extend(self._receive_request(c, frame_factory, stream_id))
            rst = frame_factory.build_rst_stream_frame(stream_id)
            events.extend(c.receive_data(rst.serialize()))

        received = [e for e in events if isinstance(e, h2.events.RequestReceived)]
        assert len(received) == 10

    def test_client_side_budget_is_rejected(self) -> None:
        """
        Request budgets only apply to server-side connections.
        """
        config = h2.config.H2Configuration(
            client_side=True,
            request_budget_capacity=1,
        )
        with pytest.raises(ValueError, match="server-side"):
            h2.connection.H2Connection(config=config)

    @pytest.mark.parametrize("capacity", [-1, 1.5, "10", True])
    def test_invalid_budget_capacity(self, capacity) -> None:
        with pytest.raises(ValueError, match="request_budget_capacity"):
            h2.config.H2Configuration(
                client_side=False,
                request_budget_capacity=capacity,
            )

    @pytest.mark.parametrize("refill_rate", [-1.0, "fast"])
    def test_invalid_budget_refill_rate(self, refill_rate) -> None:
        with pytest.raises(ValueError, match="request_budget_refill_rate"):
            h2.config.H2Configuration(
                client_side=False,
                request_budget_refill_rate=refill_rate,
            )

    def test_invalid_budget_clock(self) -> None:
        with pytest.raises(ValueError, match="budget_clock"):
            h2.config.H2Configuration(
                client_side=False,
                budget_clock=42,
            )
