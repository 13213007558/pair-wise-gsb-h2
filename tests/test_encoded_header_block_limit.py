"""
Tests for the configurable limit on the size of an encoded (still compressed)
HTTP/2 header block, measured before HPACK decompression.

The limit counts only HPACK bytes: padding, the padding length field, HEADERS
priority data and the PUSH_PROMISE promised stream ID are excluded. All
buffering stays in the kilobyte range; protection against large payloads is
asserted through the ``header_block_peak_size`` high-water mark rather than by
constructing huge inputs.
"""
from __future__ import annotations

import pytest
from hyperframe.frame import (
    ContinuationFrame,
    GoAwayFrame,
    HeadersFrame,
    PushPromiseFrame,
)

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
import h2.frame_buffer
import h2.settings

REQUEST_HEADERS = [
    (b":authority", b"example.com"),
    (b":path", b"/"),
    (b":scheme", b"https"),
    (b":method", b"GET"),
]


def make_server(limit):
    config = h2.config.H2Configuration(
        client_side=False,
        max_encoded_header_block_size=limit,
    )
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    conn.receive_data(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    conn.clear_outbound_data_buffer()
    return conn


def make_client(limit):
    config = h2.config.H2Configuration(
        client_side=True,
        max_encoded_header_block_size=limit,
    )
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    conn.clear_outbound_data_buffer()
    return conn


def make_raw_buffer(limit):
    buffer = h2.frame_buffer.FrameBuffer(
        max_encoded_header_block_size=limit,
    )
    buffer.max_frame_size = 2**24
    return buffer


def drain(buffer):
    return list(buffer)


def parse_goaway(data):
    frame, length = GoAwayFrame.parse_frame_header(memoryview(data[:9]))
    frame.parse_body(memoryview(data[9:9 + length]))
    return frame


def assert_connection_terminated(conn):
    frame = parse_goaway(conn.data_to_send())
    assert frame.error_code == h2.errors.ErrorCodes.PROTOCOL_ERROR
    assert conn.state_machine.state == h2.connection.ConnectionState.CLOSED
    # The partially accumulated header block must have been released.
    assert conn.incoming_buffer._headers_buffer == []
    assert conn.incoming_buffer._header_block_size == 0


class TestConfiguration:
    def test_default_limit(self) -> None:
        config = h2.config.H2Configuration()
        assert config.max_encoded_header_block_size == 2**16

    @pytest.mark.parametrize("value", [0, 1, 2**16, 2**32 - 1])
    def test_accepts_non_negative_integers(self, value) -> None:
        config = h2.config.H2Configuration(
            max_encoded_header_block_size=value,
        )
        assert config.max_encoded_header_block_size == value

    @pytest.mark.parametrize("value", [-1, -2**16])
    def test_rejects_negative_integers(self, value) -> None:
        with pytest.raises(ValueError):
            h2.config.H2Configuration(max_encoded_header_block_size=value)

    @pytest.mark.parametrize("value", [True, False, "100", 1.5, None, b"100"])
    def test_rejects_non_integer_values(self, value) -> None:
        with pytest.raises(ValueError):
            h2.config.H2Configuration(max_encoded_header_block_size=value)

    def test_attribute_assignment_is_validated(self) -> None:
        config = h2.config.H2Configuration()
        config.max_encoded_header_block_size = 10
        assert config.max_encoded_header_block_size == 10
        with pytest.raises(ValueError):
            config.max_encoded_header_block_size = -1
        with pytest.raises(ValueError):
            config.max_encoded_header_block_size = "10"

    def test_zero_disables_the_limit(self) -> None:
        buffer = make_raw_buffer(0)
        frame = HeadersFrame(stream_id=1)
        frame.data = b"\x82" * 4096
        frame.flags.add("END_HEADERS")
        buffer.add_data(frame.serialize())
        drain(buffer)
        # No size error, and the full size is still recorded for inspection.
        assert buffer.header_block_peak_size == 4096


class TestExactLimitBoundaries:
    def test_block_exactly_at_the_limit_is_accepted(
        self, frame_factory,
    ) -> None:
        block = frame_factory.encoder.encode(REQUEST_HEADERS)
        conn = make_server(len(block))

        frame = HeadersFrame(stream_id=1)
        frame.data = block
        frame.flags.add("END_HEADERS")
        frame.flags.add("END_STREAM")

        events = conn.receive_data(frame.serialize())
        assert any(
            isinstance(event, h2.events.RequestReceived) for event in events
        )
        assert conn.incoming_buffer.header_block_peak_size == len(block)

    def test_block_one_byte_over_the_limit_is_rejected(
        self, frame_factory,
    ) -> None:
        block = frame_factory.encoder.encode(REQUEST_HEADERS)
        conn = make_server(len(block) - 1)

        frame = HeadersFrame(stream_id=1)
        frame.data = block
        frame.flags.add("END_HEADERS")
        frame.flags.add("END_STREAM")

        with pytest.raises(h2.exceptions.HeaderBlockTooLargeError) as exc:
            conn.receive_data(frame.serialize())

        assert exc.value.encoded_size == len(block)
        assert exc.value.max_size == len(block) - 1
        assert exc.value.stream_id == 1
        assert_connection_terminated(conn)

    def test_no_header_event_is_delivered_on_rejection(
        self, frame_factory,
    ) -> None:
        block = frame_factory.encoder.encode(REQUEST_HEADERS)
        conn = make_server(len(block) - 1)

        frame = HeadersFrame(stream_id=1)
        frame.data = block
        frame.flags.add("END_HEADERS")

        with pytest.raises(h2.exceptions.HeaderBlockTooLargeError):
            conn.receive_data(frame.serialize())

        # The rejection happens inside the frame buffer, before any frame is
        # dispatched to the state machine, so no partial event can exist.
        assert conn.incoming_buffer._headers_buffer == []


class TestFragmentedFrames:
    def test_split_frame_header_keeps_buffering(
        self, frame_factory,
    ) -> None:
        block = frame_factory.encoder.encode(REQUEST_HEADERS)
        conn = make_server(len(block))

        frame = HeadersFrame(stream_id=1)
        frame.data = block
        frame.flags.add("END_HEADERS")
        frame.flags.add("END_STREAM")
        serialized = frame.serialize()

        # Feed the nine-byte header a few bytes at a time, then the body.
        conn.receive_data(serialized[:3])
        conn.receive_data(serialized[3:9])
        assert len(conn.incoming_buffer._data) == 9
        events = conn.receive_data(serialized[9:])

        assert any(
            isinstance(event, h2.events.RequestReceived) for event in events
        )
        assert conn.incoming_buffer.header_block_peak_size == len(block)

    def test_legal_incomplete_frame_waits_for_its_body(self) -> None:
        buffer = make_raw_buffer(1000)
        frame = HeadersFrame(stream_id=1)
        frame.data = b"\x82" * 100
        frame.flags.add("END_HEADERS")
        serialized = frame.serialize()

        # Only the nine-byte header arrives: the frame claims a 100-byte body
        # but is otherwise legal, so it stays buffered rather than erroring.
        buffer.add_data(serialized[:9])
        assert list(iter(buffer)) == []
        assert len(buffer._data) == 9

        buffer.add_data(serialized[9:])
        assert list(iter(buffer))[0].data == frame.data
        assert buffer.header_block_peak_size == 100

    def test_oversize_frame_rejected_from_header_alone(self) -> None:
        buffer = make_raw_buffer(10)
        frame = HeadersFrame(stream_id=1)
        frame.data = b"\x82" * 100
        frame.flags.add("END_HEADERS")
        serialized = frame.serialize()

        # The header already proves the 100-byte HPACK fragment exceeds the
        # 10-byte budget, so it fails without waiting for the body.
        buffer.add_data(serialized[:9])
        with pytest.raises(h2.exceptions.HeaderBlockTooLargeError) as exc:
            list(iter(buffer))

        assert exc.value.encoded_size == 100
        assert exc.value.max_size == 10
        assert len(buffer._data) == 9
        assert buffer.header_block_peak_size == 0

    def test_early_rejection_releases_an_open_block(self) -> None:
        buffer = make_raw_buffer(100)

        head = HeadersFrame(stream_id=1)
        head.data = b"\x82" * 60  # opens a block without END_HEADERS
        buffer.add_data(head.serialize())
        list(iter(buffer))
        assert len(buffer._headers_buffer) == 1

        continuation = ContinuationFrame(stream_id=1)
        continuation.data = b"\x82" * 100
        # Feed only the nine-byte header: it already guarantees overflow.
        buffer.add_data(continuation.serialize()[:9])

        with pytest.raises(h2.exceptions.HeaderBlockTooLargeError) as exc:
            list(iter(buffer))

        assert exc.value.encoded_size == 160
        # The in-progress block is released even though only the offending
        # frame's header had been received.
        assert buffer._headers_buffer == []
        assert buffer._header_block_size == 0

    def test_padded_frame_defers_early_check_until_body_arrives(self) -> None:
        buffer = make_raw_buffer(10)
        frame = HeadersFrame(stream_id=1)
        frame.data = b"\x82" * 5  # HPACK fragment fits the 10-byte budget
        frame.pad_length = 100
        frame.flags.add("PADDED")
        frame.flags.add("END_HEADERS")
        serialized = frame.serialize()

        # The padding size is unknowable from the header, so the partial frame
        # stays buffered instead of being rejected on a false oversize.
        buffer.add_data(serialized[:9])
        assert list(iter(buffer)) == []

        buffer.add_data(serialized[9:])
        assert list(iter(buffer))[0].data == frame.data
        assert buffer.header_block_peak_size == 5

    def test_continuation_accumulates_hpack_bytes_only(
        self, frame_factory,
    ) -> None:
        block = frame_factory.encoder.encode(REQUEST_HEADERS)
        conn = make_server(len(block))

        head = HeadersFrame(stream_id=1)
        head.data = block[:6]
        conn.receive_data(head.serialize())

        continuation = ContinuationFrame(stream_id=1)
        continuation.data = block[6:]
        continuation.flags.add("END_HEADERS")
        events = conn.receive_data(continuation.serialize())

        assert any(
            isinstance(event, h2.events.RequestReceived) for event in events
        )
        assert conn.incoming_buffer.header_block_peak_size == len(block)

    def test_continuation_crossing_the_limit_is_rejected(self) -> None:
        buffer = make_raw_buffer(12)

        head = HeadersFrame(stream_id=1)
        head.data = b"abcdef"
        buffer.add_data(head.serialize())
        drain(buffer)
        assert buffer._header_block_size == 6

        continuation = ContinuationFrame(stream_id=1)
        continuation.data = b"ghijklm"
        continuation.flags.add("END_HEADERS")
        buffer.add_data(continuation.serialize())

        with pytest.raises(h2.exceptions.HeaderBlockTooLargeError) as exc:
            drain(buffer)

        assert exc.value.encoded_size == 13
        assert exc.value.max_size == 12
        assert buffer._headers_buffer == []
        assert buffer._header_block_size == 0
        assert buffer.header_block_peak_size == 13


class TestPaddingAndPriority:
    def test_padding_bytes_are_excluded(self, frame_factory) -> None:
        block = frame_factory.encoder.encode(REQUEST_HEADERS)
        conn = make_server(len(block))

        frame = HeadersFrame(stream_id=1)
        frame.data = block
        frame.flags.add("END_HEADERS")
        frame.flags.add("END_STREAM")
        frame.flags.add("PADDED")
        frame.pad_length = 200

        events = conn.receive_data(frame.serialize())
        assert any(
            isinstance(event, h2.events.RequestReceived) for event in events
        )
        # The peak counts HPACK bytes only, never the padding or its length
        # byte.
        assert conn.incoming_buffer.header_block_peak_size == len(block)

    def test_padding_does_not_hide_an_oversize_block(
        self, frame_factory,
    ) -> None:
        block = frame_factory.encoder.encode(REQUEST_HEADERS)
        conn = make_server(len(block) - 1)

        frame = HeadersFrame(stream_id=1)
        frame.data = block
        frame.flags.add("END_HEADERS")
        frame.flags.add("PADDED")
        frame.pad_length = 200

        with pytest.raises(h2.exceptions.HeaderBlockTooLargeError) as exc:
            conn.receive_data(frame.serialize())

        assert exc.value.encoded_size == len(block)

    def test_priority_bytes_are_excluded(self, frame_factory) -> None:
        block = frame_factory.encoder.encode(REQUEST_HEADERS)
        conn = make_server(len(block))

        frame = HeadersFrame(stream_id=1)
        frame.data = block
        frame.flags.add("END_HEADERS")
        frame.flags.add("END_STREAM")
        frame.flags.add("PRIORITY")
        frame.depends_on = 0
        frame.stream_weight = 15
        frame.exclusive = False

        events = conn.receive_data(frame.serialize())
        assert any(
            isinstance(event, h2.events.RequestReceived) for event in events
        )
        assert conn.incoming_buffer.header_block_peak_size == len(block)

    def test_padding_and_priority_combined_are_excluded(
        self, frame_factory,
    ) -> None:
        block = frame_factory.encoder.encode(REQUEST_HEADERS)
        conn = make_server(len(block))

        frame = HeadersFrame(stream_id=1)
        frame.data = block
        frame.flags.add("END_HEADERS")
        frame.flags.add("END_STREAM")
        frame.flags.add("PADDED")
        frame.flags.add("PRIORITY")
        frame.pad_length = 50
        frame.depends_on = 0
        frame.stream_weight = 7
        frame.exclusive = False

        events = conn.receive_data(frame.serialize())
        assert any(
            isinstance(event, h2.events.RequestReceived) for event in events
        )
        assert conn.incoming_buffer.header_block_peak_size == len(block)


class TestPushPromise:
    def test_promised_stream_id_is_excluded(self, frame_factory) -> None:
        block = frame_factory.encoder.encode(REQUEST_HEADERS)
        conn = make_client(len(block))
        conn.send_headers(1, REQUEST_HEADERS)
        conn.clear_outbound_data_buffer()

        frame = PushPromiseFrame(stream_id=1)
        frame.promised_stream_id = 2
        frame.data = block
        frame.flags.add("END_HEADERS")

        events = conn.receive_data(frame.serialize())
        assert any(
            isinstance(event, h2.events.PushedStreamReceived)
            for event in events
        )
        assert conn.incoming_buffer.header_block_peak_size == len(block)

    def test_oversize_push_promise_is_rejected(self, frame_factory) -> None:
        block = frame_factory.encoder.encode(REQUEST_HEADERS)
        conn = make_client(len(block) - 1)
        conn.send_headers(1, REQUEST_HEADERS)
        conn.clear_outbound_data_buffer()

        frame = PushPromiseFrame(stream_id=1)
        frame.promised_stream_id = 2
        frame.data = block
        frame.flags.add("END_HEADERS")

        with pytest.raises(h2.exceptions.HeaderBlockTooLargeError) as exc:
            conn.receive_data(frame.serialize())

        assert exc.value.encoded_size == len(block)
        assert exc.value.stream_id == 1

    def test_padded_push_promise_excludes_padding(
        self, frame_factory,
    ) -> None:
        block = frame_factory.encoder.encode(REQUEST_HEADERS)
        conn = make_client(len(block))
        conn.send_headers(1, REQUEST_HEADERS)
        conn.clear_outbound_data_buffer()

        frame = PushPromiseFrame(stream_id=1)
        frame.promised_stream_id = 2
        frame.data = block
        frame.flags.add("END_HEADERS")
        frame.flags.add("PADDED")
        frame.pad_length = 100

        events = conn.receive_data(frame.serialize())
        assert any(
            isinstance(event, h2.events.PushedStreamReceived)
            for event in events
        )
        assert conn.incoming_buffer.header_block_peak_size == len(block)


class TestErrorDistinction:
    def _buffer_continuation_block(self, buffer, fragment_count):
        head = HeadersFrame(stream_id=1)
        head.data = b"x"
        buffer.add_data(head.serialize())
        drain(buffer)

        for _ in range(fragment_count - 1):
            continuation = ContinuationFrame(stream_id=1)
            continuation.data = b"y"
            buffer.add_data(continuation.serialize())
            drain(buffer)

    def test_too_many_frames_is_a_distinct_error(self) -> None:
        buffer = make_raw_buffer(0)  # byte budget disabled
        self._buffer_continuation_block(
            buffer, h2.frame_buffer.CONTINUATION_BACKLOG,
        )
        assert len(buffer._headers_buffer) == 64

        overflow = ContinuationFrame(stream_id=1)
        overflow.data = b"z"
        overflow.flags.add("END_HEADERS")
        buffer.add_data(overflow.serialize())

        with pytest.raises(
            h2.exceptions.TooManyContinuationFramesError,
        ) as exc:
            drain(buffer)

        assert exc.value.frame_count == 65
        assert exc.value.max_frames == 64
        assert isinstance(exc.value, h2.exceptions.ProtocolError)
        assert not isinstance(exc.value, h2.exceptions.HeaderBlockTooLargeError)
        assert buffer._headers_buffer == []

    def test_continuation_dos_still_raises_protocol_error(self) -> None:
        # Backwards-compatible guarantee for callers catching ProtocolError.
        buffer = make_raw_buffer(0)
        self._buffer_continuation_block(
            buffer, h2.frame_buffer.CONTINUATION_BACKLOG,
        )

        overflow = ContinuationFrame(stream_id=1)
        overflow.data = b"z"
        overflow.flags.add("END_HEADERS")
        buffer.add_data(overflow.serialize())

        with pytest.raises(h2.exceptions.ProtocolError):
            drain(buffer)

    def test_hpack_decompression_failure_is_distinct(self) -> None:
        # Disable the encoded-size check so only HPACK decompression can fire.
        conn = make_server(0)
        conn.local_settings[h2.settings.SettingCodes.MAX_FRAME_SIZE] = 2**20
        conn.max_inbound_frame_size = 2**20
        conn.incoming_buffer.max_frame_size = 2**20

        frame = HeadersFrame(stream_id=1)
        frame.data = (
            bytes([0x00, 0x7e])
            + (70000).to_bytes(4, "big")
            + b"k"
            + b"v" * 70000
        )
        frame.flags.add("END_HEADERS")

        with pytest.raises(h2.exceptions.DenialOfServiceError) as exc:
            conn.receive_data(frame.serialize())

        assert not isinstance(
            exc.value, h2.exceptions.HeaderBlockTooLargeError,
        )
        assert exc.value.error_code == h2.errors.ErrorCodes.ENHANCE_YOUR_CALM


class TestRecoveryAndBoundaries:
    def test_legal_request_after_failure_finds_a_closed_connection(
        self, frame_factory,
    ) -> None:
        block = frame_factory.encoder.encode(REQUEST_HEADERS)
        conn = make_server(len(block) - 1)

        bad = HeadersFrame(stream_id=1)
        bad.data = block
        bad.flags.add("END_HEADERS")
        with pytest.raises(h2.exceptions.HeaderBlockTooLargeError):
            conn.receive_data(bad.serialize())

        good = HeadersFrame(stream_id=3)
        good.data = block
        good.flags.add("END_HEADERS")
        good.flags.add("END_STREAM")
        with pytest.raises(h2.exceptions.ProtocolError):
            conn.receive_data(good.serialize())

    def test_config_change_does_not_split_an_in_progress_block(self) -> None:
        buffer = make_raw_buffer(100)

        head = HeadersFrame(stream_id=1)
        head.data = b"\x82" * 60  # no END_HEADERS: the block stays open
        buffer.add_data(head.serialize())
        drain(buffer)

        # Shrink the budget while the block is still accumulating. The open
        # block must keep using the snapshot taken when it started.
        buffer.max_encoded_header_block_size = 10
        assert buffer._header_block_limit == 100

        continuation = ContinuationFrame(stream_id=1)
        continuation.data = b"\x82" * 50
        continuation.flags.add("END_HEADERS")
        buffer.add_data(continuation.serialize())

        with pytest.raises(h2.exceptions.HeaderBlockTooLargeError) as exc:
            drain(buffer)

        assert exc.value.max_size == 100
        assert exc.value.encoded_size == 110

    def test_config_change_applies_at_the_next_block_boundary(self) -> None:
        buffer = make_raw_buffer(100)

        first = HeadersFrame(stream_id=1)
        first.data = b"\x82" * 50
        first.flags.add("END_HEADERS")
        buffer.add_data(first.serialize())
        drain(buffer)

        buffer.max_encoded_header_block_size = 10

        second = HeadersFrame(stream_id=3)
        second.data = b"\x82" * 50
        second.flags.add("END_HEADERS")
        buffer.add_data(second.serialize())

        with pytest.raises(h2.exceptions.HeaderBlockTooLargeError) as exc:
            drain(buffer)

        assert exc.value.max_size == 10

    def test_connection_propagates_config_to_the_frame_buffer(
        self, frame_factory,
    ) -> None:
        conn = make_server(100)
        assert conn.incoming_buffer.max_encoded_header_block_size == 100

        block = frame_factory.encoder.encode(REQUEST_HEADERS)
        head = HeadersFrame(stream_id=1)
        head.data = block
        # Keep the block open so the limit snapshot must remain at 100 even
        # after the configuration attribute is shrunk mid-block.
        conn.receive_data(head.serialize())

        conn.config.max_encoded_header_block_size = 5
        # The new value reaches the frame buffer on the next data delivery.
        conn.receive_data(b"")
        assert conn.incoming_buffer.max_encoded_header_block_size == 5
        assert conn.incoming_buffer._header_block_limit == 100

        continuation = ContinuationFrame(stream_id=1)
        continuation.data = b""
        continuation.flags.add("END_HEADERS")

        # Total HPACK size is only len(block), well within the original 100,
        # so the block completes successfully under the frozen snapshot.
        events = conn.receive_data(continuation.serialize())
        assert any(
            isinstance(event, h2.events.RequestReceived) for event in events
        )

    def test_peak_tracks_largest_block_without_huge_inputs(self) -> None:
        buffer = make_raw_buffer(1000)
        sizes = (100, 250, 30)

        for stream_id, size in zip((1, 3, 5), sizes, strict=True):
            frame = HeadersFrame(stream_id=stream_id)
            frame.data = b"\x82" * size
            frame.flags.add("END_HEADERS")
            buffer.add_data(frame.serialize())
            # Drain each block on its own so its completion resets the running
            # block size while the high-water mark is retained.
            assert list(iter(buffer))

        # The high-water mark tracks HPACK fragment bytes (the frame payload),
        # not the nine-byte frame headers, and is directly inspectable without
        # constructing any large input.
        assert buffer.header_block_peak_size == max(sizes)
        assert buffer._header_block_size == 0
