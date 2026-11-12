"""
Regression tests for HTTP/2 flow control accounting around stream reset and
stream/connection closure boundaries.

The concern these tests guard against is the bookkeeping of flow controlled
bytes once a stream has been cancelled (RST_STREAM) or closed (END_STREAM):

* bytes that were delivered to us but had not been acknowledged when the
  stream was reset must still be returned to the *connection* window exactly
  once, and must never be returned to the dead stream;
* DATA frames that arrive late on a reset stream are refused, but their
  flow controlled length still consumes connection-level credit, so the
  connection window has to be reimbursed or every other stream on the
  connection eventually stalls;
* the same bytes must never be reimbursed twice, which would hand the peer
  extra, unearned credit.

The expected values in this module are computed from a hand-maintained byte
ledger and from the protocol rules of RFC 7540 (the frame definitions, the
connection-vs-stream window split, and the closed-state error handling in
section 5.1). They are deliberately not copied from the internal counters of
the implementation under test. Wire frames emitted by the connection are
decoded back with hyperframe and checked against that ledger.
"""

from __future__ import annotations

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
import h2.settings
import pytest
from hyperframe.frame import Frame, GoAwayFrame, RstStreamFrame, WindowUpdateFrame

from .helpers import FrameFactory

REQUEST_HEADERS = [
    (b":authority", b"example.com"),
    (b":path", b"/"),
    (b":scheme", b"https"),
    (b":method", b"POST"),
]
RESPONSE_HEADERS = [
    (b":status", b"200"),
    (b"server", b"fake-serv/0.1.0"),
]

# Hand-computable window sizes. The per-stream value is advertised through a
# real SETTINGS/ACK exchange; the connection value is fixed by test scaffolding
# because RFC 7540 provides no on-the-wire mechanism to shrink the connection
# window (only WINDOW_UPDATE can enlarge it).
SMALL_WINDOW = 100
DEFAULT_WINDOW = 65535


def decode_frames(data: bytes) -> list[Frame]:
    """
    Decode raw wire bytes back into a list of hyperframe frames so that tests
    can assert on what was actually emitted rather than on internal state.
    """
    frames: list[Frame] = []
    buffer = memoryview(data)
    offset = 0
    while offset < len(buffer):
        frame, body_length = Frame.parse_frame_header(buffer[offset : offset + 9])
        frame.parse_body(buffer[offset + 9 : offset + 9 + body_length])
        frames.append(frame)
        offset += 9 + body_length
    return frames


class WindowLedger:
    """
    A protocol-level byte ledger for a single receiver-side flow control
    window (the connection window or one stream window).

    It mirrors only what the wire protocol guarantees: every received flow
    controlled byte shrinks the window, every WINDOW_UPDATE frame enlarges it
    by its increment, and an empty (zero) window must be reopened before any
    further DATA can legally be received on it.
    """

    def __init__(self, initial_size: int) -> None:
        self.initial_size = initial_size
        self.window = initial_size
        self.received = 0
        self.returned = 0

    def consume(self, flow_controlled_length: int) -> None:
        self.window -= flow_controlled_length
        self.received += flow_controlled_length

    def repay(self, increment: int) -> None:
        self.window += increment
        self.returned += increment

    @property
    def outstanding(self) -> int:
        """Flow controlled bytes received but not yet returned."""
        return self.received - self.returned


class ServerHarness:
    """
    Drives a server-side H2Connection together with an independent byte
    ledger. Every DATA frame fed to the connection is recorded in the ledgers
    before the implementation sees it, and every frame the implementation
    emits is replayed against the connection ledger.
    """

    def __init__(self, frame_factory: FrameFactory, initial_window: int = SMALL_WINDOW) -> None:
        self.factory = frame_factory
        self.config = h2.config.H2Configuration(client_side=False)
        self.conn = h2.connection.H2Connection(config=self.config)
        self.conn.initiate_connection()
        self.conn.receive_data(frame_factory.preamble())
        # Consume the server's initial SETTINGS frame.
        self.conn.data_to_send()

        self.conn_ledger = WindowLedger(SMALL_WINDOW)
        self.stream_ledgers: dict[int, WindowLedger] = {}

        if initial_window != DEFAULT_WINDOW:
            self.set_initial_window_size(initial_window)
        # The connection window cannot be shrunk on the wire, so the test
        # fixture sizes it directly to match the small hand-computed ledger.
        self._resize_connection_window(SMALL_WINDOW)

    def set_initial_window_size(self, value: int) -> None:
        self.conn.update_settings(
            {h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: value},
        )
        ack = self.factory.build_settings_frame({}, ack=True)
        self.conn.receive_data(ack.serialize())
        self.conn.data_to_send()

    def _resize_connection_window(self, value: int) -> None:
        manager = self.conn._inbound_flow_control_window_manager
        manager.max_window_size = value
        manager.current_window_size = value
        manager._bytes_processed = 0

    def open_request(self, stream_id: int) -> None:
        headers_frame = self.factory.build_headers_frame(
            REQUEST_HEADERS,
            stream_id=stream_id,
        )
        self.conn.receive_data(headers_frame.serialize())
        self.conn.data_to_send()
        self.stream_ledgers[stream_id] = WindowLedger(SMALL_WINDOW)

    def receive_data_events(
        self,
        stream_id: int,
        data: bytes,
    ) -> list[h2.events.Event]:
        """Feed a DATA frame and return the events delivered to the app."""
        frame = self.factory.build_data_frame(data, stream_id=stream_id)
        length = frame.flow_controlled_length
        self.conn_ledger.consume(length)
        self.stream_ledgers.setdefault(stream_id, WindowLedger(SMALL_WINDOW))
        self.stream_ledgers[stream_id].consume(length)
        events = self.conn.receive_data(frame.serialize())
        self._replay_emitted_frames()
        return events

    def receive_data_frames(
        self,
        stream_id: int,
        data: bytes,
        padding_len: int = 0,
    ) -> list[Frame]:
        """
        Feed a DATA frame to the connection and return the wire frames the
        connection emitted in response (RST_STREAM, WINDOW_UPDATE, ...).
        """
        frame = self.factory.build_data_frame(
            data,
            stream_id=stream_id,
            padding_len=padding_len,
        )
        length = frame.flow_controlled_length
        # Record the debt against the protocol ledgers first.
        self.conn_ledger.consume(length)
        self.stream_ledgers.setdefault(stream_id, WindowLedger(SMALL_WINDOW))
        self.stream_ledgers[stream_id].consume(length)
        self.conn.receive_data(frame.serialize())
        return self._replay_emitted_frames()

    def receive_rst_stream(self, stream_id: int) -> list[h2.events.Event]:
        frame = self.factory.build_rst_stream_frame(stream_id)
        events = self.conn.receive_data(frame.serialize())
        self.conn.data_to_send()
        return events

    def local_reset(self, stream_id: int, error_code: h2.errors.ErrorCodes) -> None:
        self.conn.reset_stream(stream_id, error_code)
        self.conn.data_to_send()

    def cleanup_closed_streams(self) -> None:
        # Counting open streams is what triggers lazy removal of closed
        # stream objects in the public API.
        self.conn.open_inbound_streams

    def acknowledge(self, stream_id: int, size: int) -> list[Frame]:
        self.conn.acknowledge_received_data(size, stream_id)
        return self._replay_emitted_frames()

    def drain(self) -> list[Frame]:
        return self._replay_emitted_frames()

    def _replay_emitted_frames(self) -> list[Frame]:
        frames = decode_frames(self.conn.data_to_send())
        for frame in frames:
            if isinstance(frame, WindowUpdateFrame):
                if frame.stream_id == 0:
                    self.conn_ledger.repay(frame.window_increment)
                else:
                    self.stream_ledgers.setdefault(
                        frame.stream_id,
                        WindowLedger(SMALL_WINDOW),
                    ).repay(frame.window_increment)
        return frames

    def assert_ledger_matches_windows(self) -> None:
        """
        The independently maintained ledger must agree with the windows the
        implementation reports through its public API.
        """
        assert self.conn.inbound_flow_control_window == self.conn_ledger.window
        for stream_id, ledger in self.stream_ledgers.items():
            if stream_id in self.conn.streams:
                assert self.conn.remote_flow_control_window(stream_id) == min(self.conn_ledger.window, ledger.window)


def frame_specs(frames: list[Frame]) -> list[tuple[type, int, int]]:
    """
    Reduce frames to (type, stream_id, payload) tuples so tests can express
    exact expectations without serialising matching frames themselves.
    """
    specs = []
    for frame in frames:
        if isinstance(frame, WindowUpdateFrame):
            payload = frame.window_increment
        elif isinstance(frame, RstStreamFrame | GoAwayFrame):
            payload = frame.error_code
        else:
            payload = 0
        specs.append((type(frame), frame.stream_id, payload))
    return specs


class TestResetFlowControlBoundaries:
    """
    Flow control accounting when streams are reset.
    """

    @pytest.mark.parametrize("force_cleanup", [False, True])
    def test_data_delivered_before_reset_is_returned_to_connection_only(
        self,
        frame_factory,
        force_cleanup,
    ) -> None:
        """
        Bytes delivered on a stream before it is reset are still owed to the
        connection window. When acknowledged after the reset they produce a
        connection WINDOW_UPDATE but never a stream WINDOW_UPDATE for the
        dead stream.
        """
        harness = ServerHarness(frame_factory)
        harness.open_request(1)
        harness.open_request(3)

        delivered = 60
        harness.receive_data_frames(1, b"x" * delivered)
        harness.receive_rst_stream(1)
        if force_cleanup:
            harness.cleanup_closed_streams()
        assert 1 not in harness.conn.streams or harness.conn.streams[1].closed

        frames = harness.acknowledge(1, delivered)

        # Exactly one connection-level update for the pre-reset bytes; the
        # reset stream must receive no per-stream update.
        assert frame_specs(frames) == [
            (WindowUpdateFrame, 0, delivered),
        ]
        assert harness.conn_ledger.outstanding == 0
        assert harness.stream_ledgers[1].outstanding == delivered
        harness.assert_ledger_matches_windows()

    @pytest.mark.parametrize("padding_len", [0, 9])
    def test_late_data_on_reset_stream_is_refunded_once_and_reset(
        self,
        frame_factory,
        padding_len,
    ) -> None:
        """
        DATA arriving on a stream that was reset remotely is refused with a
        RST_STREAM. Its full flow controlled length (including padding and
        the padding length byte) is charged to and then reimbursed on the
        connection window, exactly once, with no stream WINDOW_UPDATE.
        """
        harness = ServerHarness(frame_factory)
        harness.open_request(1)
        harness.open_request(3)
        harness.receive_rst_stream(1)
        harness.cleanup_closed_streams()
        assert 1 not in harness.conn.streams

        # First frame stays below the half-window batching threshold, so only
        # a RST_STREAM is emitted even though the debt is already recorded.
        small_body = b"y" * 10
        small_length = len(small_body) + padding_len + (1 if padding_len else 0)
        emitted = harness.receive_data_frames(1, small_body, padding_len=padding_len)
        assert frame_specs(emitted) == [
            (RstStreamFrame, 1, h2.errors.ErrorCodes.STREAM_CLOSED),
        ]
        assert harness.conn_ledger.received == small_length
        assert harness.conn_ledger.returned == 0

        # A second, unpadded frame pushes the accumulated debt over half the
        # window, at which point one connection WINDOW_UPDATE repays the whole
        # debt and the RST_STREAM is still sent for the stream.
        second_body = b"z" * 40
        emitted = harness.receive_data_frames(1, second_body)
        total_length = small_length + len(second_body)
        assert frame_specs(emitted) == [
            (WindowUpdateFrame, 0, total_length),
            (RstStreamFrame, 1, h2.errors.ErrorCodes.STREAM_CLOSED),
        ]

        # Every received flow byte returned exactly once; none to the stream.
        assert harness.conn_ledger.received == total_length
        assert harness.conn_ledger.returned == total_length
        assert harness.conn_ledger.window == SMALL_WINDOW
        assert harness.stream_ledgers[1].returned == 0
        # The healthy stream's own window is untouched by the refusals.
        assert harness.stream_ledgers[3].window == SMALL_WINDOW
        harness.assert_ledger_matches_windows()

    def test_late_data_accumulates_then_single_refund(self, frame_factory) -> None:
        """
        Several small late DATA frames on a reset stream accrue connection
        debt and trigger a single batched WINDOW_UPDATE for the accumulated
        bytes rather than one update per frame.
        """
        harness = ServerHarness(frame_factory)
        harness.open_request(1)
        harness.receive_rst_stream(1)
        harness.cleanup_closed_streams()

        # Small late DATA frames accrue connection debt without repaying it
        # until the half-window batching threshold (50 of 100 bytes) is hit.
        first = harness.receive_data_frames(1, b"a" * 20)
        assert frame_specs(first) == [
            (RstStreamFrame, 1, h2.errors.ErrorCodes.STREAM_CLOSED),
        ]
        second = harness.receive_data_frames(1, b"b" * 20)
        assert frame_specs(second) == [
            (RstStreamFrame, 1, h2.errors.ErrorCodes.STREAM_CLOSED),
        ]
        # The third frame crosses 50 accumulated bytes: one WINDOW_UPDATE
        # repays the whole 50-byte debt in a single frame, not one per DATA.
        third = harness.receive_data_frames(1, b"c" * 10)
        assert frame_specs(third) == [
            (WindowUpdateFrame, 0, 50),
            (RstStreamFrame, 1, h2.errors.ErrorCodes.STREAM_CLOSED),
        ]

        assert harness.conn_ledger.received == 50
        assert harness.conn_ledger.returned == 50
        assert harness.conn_ledger.window == SMALL_WINDOW
        harness.assert_ledger_matches_windows()

    @pytest.mark.parametrize(
        "local_reset",
        [False, True],
        ids=["remote_reset", "local_reset"],
    )
    def test_refused_data_does_not_starve_healthy_stream(
        self,
        frame_factory,
        local_reset,
    ) -> None:
        """
        After late DATA on a cancelled stream is refused and its connection
        credit returned, a concurrent healthy stream keeps moving: its own
        DATA is accepted and acknowledged with both connection and stream
        WINDOW_UPDATE frames.
        """
        harness = ServerHarness(frame_factory)
        harness.open_request(1)  # cancelled stream
        harness.open_request(3)  # healthy stream

        if local_reset:
            harness.local_reset(1, h2.errors.ErrorCodes.INTERNAL_ERROR)
        else:
            harness.receive_rst_stream(1)
        harness.cleanup_closed_streams()

        # 50 bytes of late, refused data on stream 1: crosses the batching
        # threshold so the connection is reimbursed immediately.
        emitted = harness.receive_data_frames(1, b"z" * 50)
        assert frame_specs(emitted) == [
            (WindowUpdateFrame, 0, 50),
            (RstStreamFrame, 1, h2.errors.ErrorCodes.STREAM_CLOSED),
        ]
        assert harness.conn_ledger.window == SMALL_WINDOW

        # The healthy stream can now consume the full connection window. Its
        # DATA is accepted as a DataReceived event, not refused.
        events = harness.receive_data_events(3, b"h" * 60)
        assert len(events) == 1
        assert isinstance(events[0], h2.events.DataReceived)
        assert events[0].stream_id == 3

        # Acknowledging it returns credit on both windows, exactly once each.
        frames = harness.acknowledge(3, 60)
        assert frame_specs(frames) == [
            (WindowUpdateFrame, 0, 60),
            (WindowUpdateFrame, 3, 60),
        ]
        assert harness.stream_ledgers[3].outstanding == 0
        assert harness.conn_ledger.outstanding == 0
        harness.assert_ledger_matches_windows()

    def test_connection_window_near_zero_late_data_keeps_peer_moving(
        self,
        frame_factory,
    ) -> None:
        """
        Driven entirely over the wire with the default 65535-byte connection
        window: a healthy stream drains the connection window down to a small
        remainder. A late DATA frame on a reset stream that consumes the last
        of the window would deadlock every stream unless the implementation
        returns that credit. The returned space must then be reusable by the
        healthy stream.
        """
        factory = frame_factory
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        conn.initiate_connection()
        conn.receive_data(factory.preamble())
        conn.update_settings(
            {h2.settings.SettingCodes.MAX_FRAME_SIZE: DEFAULT_WINDOW},
        )
        conn.receive_data(factory.build_settings_frame({}, ack=True).serialize())
        conn.data_to_send()

        conn.receive_data(
            factory.build_headers_frame(REQUEST_HEADERS, stream_id=1).serialize(),
        )
        conn.receive_data(
            factory.build_headers_frame(REQUEST_HEADERS, stream_id=3).serialize(),
        )
        conn.data_to_send()

        # Drain all but 1025 bytes of the connection window on the healthy
        # stream, using the real default-window accounting.
        consumed = DEFAULT_WINDOW - 1025
        conn.receive_data(
            factory.build_data_frame(b"a" * consumed, stream_id=3).serialize(),
        )
        assert conn.inbound_flow_control_window == 1025

        conn.receive_data(factory.build_rst_stream_frame(1).serialize())
        conn.data_to_send()

        # Late DATA exactly empties the remaining connection window. At a
        # zero window the window manager must emit a connection WINDOW_UPDATE
        # alongside the RST_STREAM.
        conn.receive_data(
            factory.build_data_frame(b"b" * 1025, stream_id=1).serialize(),
        )
        emitted = decode_frames(conn.data_to_send())
        assert frame_specs(emitted) == [
            (WindowUpdateFrame, 0, 1025),
            (RstStreamFrame, 1, h2.errors.ErrorCodes.STREAM_CLOSED),
        ]
        assert conn.inbound_flow_control_window == 1025

        # The healthy stream can spend the returned space immediately.
        conn.receive_data(
            factory.build_data_frame(b"c" * 1025, stream_id=3).serialize(),
        )
        assert conn.inbound_flow_control_window == 0
        assert conn.remote_flow_control_window(3) == 0

    def test_late_data_exceeding_connection_window_is_connection_error(
        self,
        frame_factory,
    ) -> None:
        """
        If a late DATA frame on a reset stream is larger than the remaining
        connection window, the peer has violated flow control: this is a
        connection error, not a stream error, so GOAWAY (FLOW_CONTROL_ERROR)
        is emitted and no RST_STREAM is sent.
        """
        factory = frame_factory
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        conn.initiate_connection()
        conn.receive_data(factory.preamble())
        conn.update_settings(
            {h2.settings.SettingCodes.MAX_FRAME_SIZE: DEFAULT_WINDOW},
        )
        conn.receive_data(factory.build_settings_frame({}, ack=True).serialize())
        conn.data_to_send()

        conn.receive_data(
            factory.build_headers_frame(REQUEST_HEADERS, stream_id=1).serialize(),
        )
        conn.receive_data(
            factory.build_headers_frame(REQUEST_HEADERS, stream_id=3).serialize(),
        )
        conn.data_to_send()
        conn.receive_data(
            factory.build_data_frame(b"a" * (DEFAULT_WINDOW - 35), stream_id=3).serialize(),
        )
        conn.receive_data(factory.build_rst_stream_frame(1).serialize())
        conn.data_to_send()
        assert conn.inbound_flow_control_window == 35

        with pytest.raises(h2.exceptions.FlowControlError) as exc_info:
            conn.receive_data(
                factory.build_data_frame(b"b" * 40, stream_id=1).serialize(),
            )
        assert exc_info.value.error_code == h2.errors.ErrorCodes.FLOW_CONTROL_ERROR

        emitted = decode_frames(conn.data_to_send())
        assert frame_specs(emitted) == [
            (GoAwayFrame, 0, h2.errors.ErrorCodes.FLOW_CONTROL_ERROR),
        ]


class TestEndStreamClosureDistinction:
    """
    END_STREAM closure must not be handled like RST_STREAM closure.
    """

    @pytest.mark.parametrize("force_cleanup", [False, True])
    def test_headers_after_end_stream_are_connection_error(
        self,
        frame_factory,
        force_cleanup,
    ) -> None:
        """
        A non-DATA frame (HEADERS) on a stream closed by END_STREAM is a
        connection error (GOAWAY STREAM_CLOSED) per RFC 7540 section 5.1.
        The same frame on a reset stream would instead be answered with a
        RST_STREAM, proving the two close reasons are not conflated.
        """
        # END_STREAM closure: connection error, no RST_STREAM.
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        conn.initiate_connection()
        conn.receive_data(frame_factory.preamble())
        conn.data_to_send()
        conn.receive_data(
            frame_factory.build_headers_frame(
                REQUEST_HEADERS,
                flags=["END_STREAM"],
                stream_id=1,
            ).serialize(),
        )
        conn.send_headers(1, RESPONSE_HEADERS, end_stream=True)
        if force_cleanup:
            conn.open_inbound_streams
        conn.data_to_send()

        with pytest.raises(h2.exceptions.ProtocolError) as exc_info:
            conn.receive_data(
                frame_factory.build_headers_frame(
                    REQUEST_HEADERS,
                    stream_id=1,
                ).serialize(),
            )
        assert exc_info.value.error_code == h2.errors.ErrorCodes.STREAM_CLOSED
        emitted = decode_frames(conn.data_to_send())
        assert frame_specs(emitted) == [
            (GoAwayFrame, 0, h2.errors.ErrorCodes.STREAM_CLOSED),
        ]

        # Reset closure of an equivalent stream: stream error, RST_STREAM and
        # no GOAWAY.
        frame_factory.refresh_encoder()
        reset_conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        reset_conn.initiate_connection()
        reset_conn.receive_data(frame_factory.preamble())
        reset_conn.data_to_send()
        reset_conn.receive_data(
            frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1).serialize(),
        )
        reset_conn.receive_data(
            frame_factory.build_rst_stream_frame(1).serialize(),
        )
        if force_cleanup:
            reset_conn.open_inbound_streams
        reset_conn.data_to_send()

        events = reset_conn.receive_data(
            frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1).serialize(),
        )
        assert not events
        emitted = decode_frames(reset_conn.data_to_send())
        assert frame_specs(emitted) == [
            (RstStreamFrame, 1, h2.errors.ErrorCodes.STREAM_CLOSED),
        ]

    def test_data_after_end_stream_still_preserves_connection_window(
        self,
        frame_factory,
    ) -> None:
        """
        DATA on an END_STREAM-closed stream is also refused, but unlike other
        frame types it carries flow controlled bytes. The implementation
        answers with a RST_STREAM (stream error) while still reimbursing the
        connection window, so the accounting invariant - every received flow
        controlled byte is returned exactly once - holds.
        """
        harness = ServerHarness(frame_factory)
        harness.open_request(1)
        # Close the inbound stream cleanly with END_STREAM and respond in kind.
        harness.conn.receive_data(
            frame_factory.build_data_frame(
                b"",
                flags=["END_STREAM"],
                stream_id=1,
            ).serialize(),
        )
        harness.conn.send_headers(1, RESPONSE_HEADERS, end_stream=True)
        harness.cleanup_closed_streams()
        harness.drain()

        # A late, padded DATA frame (10 body + 4 pad + 1 length = 15 bytes).
        emitted = harness.receive_data_frames(1, b"q" * 10, padding_len=4)
        assert frame_specs(emitted) == [
            (RstStreamFrame, 1, h2.errors.ErrorCodes.STREAM_CLOSED),
        ]
        # Debt recorded on the connection ledger and not yet repaid because it
        # is below the batching threshold; crucially never repaid twice.
        assert harness.conn_ledger.received == 15
        assert harness.conn_ledger.returned == 0


class TestNegativeWindowFromSettings:
    """
    SETTINGS_INITIAL_WINDOW_SIZE changes may leave a stream window negative;
    that state is legal per RFC 7540 section 6.9.2 and must be preserved.
    """

    def test_negative_window_is_legal_and_recovers_on_ack(
        self,
        frame_factory,
    ) -> None:
        """
        Shrinking the initial window below what a stream has already consumed
        leaves its window negative without an error. Acknowledging the
        outstanding data returns the stream to exactly the new initial window,
        via a stream WINDOW_UPDATE, while new streams open at the new size.
        """
        harness = ServerHarness(frame_factory, initial_window=64)
        # SETTINGS only adjust stream windows, so the connection ledger keeps
        # its protocol default; per-stream ledgers use the advertised window.
        harness.conn_ledger = WindowLedger(DEFAULT_WINDOW)
        harness.stream_ledgers.clear()

        harness.open_request(1)
        harness.stream_ledgers[1] = WindowLedger(64)
        harness.receive_data_frames(1, b"x" * 40)
        assert harness.stream_ledgers[1].window == 24

        old_window, new_window = 64, 10
        harness.set_initial_window_size(new_window)
        # Ledger arithmetic: the 24 bytes of remaining credit move by the
        # advertised initial-window delta (new - old = -54).
        expected_negative = (old_window - 40) + (new_window - old_window)
        assert harness.conn.remote_flow_control_window(1) == expected_negative
        assert expected_negative < 0
        # Reflect the same SETTINGS delta in the independent stream ledger.
        harness.stream_ledgers[1].window += new_window - old_window
        assert harness.stream_ledgers[1].window == expected_negative

        # A brand new stream starts at the new window size.
        harness.open_request(3)
        assert harness.conn.remote_flow_control_window(3) == new_window

        # Acknowledging the 40 outstanding bytes restores stream 1 to 10.
        frames = harness.acknowledge(1, 40)
        assert frame_specs(frames) == [
            (WindowUpdateFrame, 1, 40),
        ]
        assert harness.conn.remote_flow_control_window(1) == new_window
        assert harness.stream_ledgers[1].outstanding == 0

    def test_sending_data_while_window_negative_tears_down_connection(
        self,
        frame_factory,
    ) -> None:
        """
        A negative stream window means no further DATA may be received on it
        until credit returns. Doing so is a FLOW_CONTROL_ERROR connection
        error signalled with GOAWAY.
        """
        harness = ServerHarness(frame_factory, initial_window=64)
        harness.conn_ledger = WindowLedger(DEFAULT_WINDOW)
        harness.stream_ledgers.clear()

        harness.open_request(1)
        harness.stream_ledgers[1] = WindowLedger(64)
        harness.receive_data_frames(1, b"x" * 40)
        harness.set_initial_window_size(10)
        assert harness.conn.remote_flow_control_window(1) < 0
        harness.drain()

        with pytest.raises(h2.exceptions.FlowControlError) as exc_info:
            harness.receive_data_frames(1, b"y")
        assert exc_info.value.error_code == h2.errors.ErrorCodes.FLOW_CONTROL_ERROR

        # The offending byte was never accepted, so the ledger keeps its debt;
        # the connection tears down with a single GOAWAY, no RST_STREAM.
        emitted = harness.drain()
        assert frame_specs(emitted) == [
            (GoAwayFrame, 0, h2.errors.ErrorCodes.FLOW_CONTROL_ERROR),
        ]


class TestNoDoubleReturnInvariant:
    """
    Cross-cutting invariants that catch both missing and duplicated refunds.
    """

    def test_total_refunds_never_exceed_total_received(self, frame_factory) -> None:
        """
        Across a mix of pre-reset acknowledged data and several late DATA
        frames, the sum of connection WINDOW_UPDATE increments can never
        exceed the flow controlled bytes received, and every byte is either
        still outstanding or returned exactly once.
        """
        harness = ServerHarness(frame_factory)
        harness.open_request(1)
        harness.open_request(3)

        # 20 bytes delivered before the reset, acknowledged afterwards. Below
        # the batching threshold, so no frame is emitted yet.
        harness.receive_data_frames(1, b"a" * 20)
        harness.receive_rst_stream(1)
        harness.cleanup_closed_streams()
        harness.acknowledge(1, 20)

        # Late DATA in small chunks, some padded. Each is refused with a
        # RST_STREAM; the connection debt accrues and is repaid in batches.
        harness.receive_data_frames(1, b"b" * 10)
        harness.receive_data_frames(1, b"c" * 10, padding_len=4)  # 15 flow bytes
        harness.receive_data_frames(1, b"d" * 15)

        total_received = 20 + 10 + 15 + 15
        assert harness.conn_ledger.received == total_received
        # Conservation: returned credit plus outstanding debt equals received.
        assert harness.conn_ledger.returned <= total_received
        assert harness.conn_ledger.returned + harness.conn_ledger.outstanding == total_received
        # Nothing was ever credited back to the dead stream.
        assert harness.stream_ledgers[1].returned == 0

        # Acknowledge the remaining debt on the reset stream. The connection
        # manager still holds the pre-reset 20 bytes plus any chunks that did
        # not cross the batching threshold; acknowledging the full outstanding
        # amount must close the ledger without ever overshooting it.
        remaining = harness.conn_ledger.outstanding
        harness.acknowledge(1, remaining)
        assert harness.conn_ledger.returned == total_received
        assert harness.conn_ledger.outstanding == 0
        assert harness.conn_ledger.window == SMALL_WINDOW
        harness.assert_ledger_matches_windows()

    def test_reset_stream_emits_no_window_update_for_unacked_data(
        self,
        frame_factory,
    ) -> None:
        """
        Receiving a RST_STREAM itself emits nothing: the stream's unacked
        bytes stay charged until the application acknowledges them, at which
        point only the connection window is updated and the dead stream gets
        no WINDOW_UPDATE.
        """
        delivered = 60
        harness = ServerHarness(frame_factory)
        harness.open_request(1)
        harness.receive_data_frames(1, b"x" * delivered)

        events = harness.receive_rst_stream(1)
        assert len(events) == 1
        assert isinstance(events[0], h2.events.StreamReset)
        assert events[0].error_code == h2.errors.ErrorCodes.NO_ERROR
        assert harness.drain() == []

        # Acknowledging after the reset returns the bytes to the connection
        # window only; there must be no stream-level WINDOW_UPDATE.
        frames = harness.acknowledge(1, delivered)
        assert frame_specs(frames) == [(WindowUpdateFrame, 0, delivered)]
        assert harness.stream_ledgers[1].returned == 0
        assert harness.conn_ledger.outstanding == 0
