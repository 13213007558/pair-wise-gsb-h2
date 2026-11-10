"""
Tests that verify logic local to exceptions.
"""
from __future__ import annotations

import h2.exceptions


class TestExceptions:
    def test_stream_id_too_low_prints_properly(self) -> None:
        x = h2.exceptions.StreamIDTooLowError(5, 10)

        assert str(x) == "StreamIDTooLowError: 5 is lower than 10"

    def test_header_block_too_large_error_attributes(self) -> None:
        error = h2.exceptions.HeaderBlockTooLargeError(
            stream_id=7, encoded_size=101, max_size=100,
        )

        assert error.stream_id == 7
        assert error.encoded_size == 101
        assert error.max_size == 100
        assert isinstance(error, h2.exceptions.ProtocolError)
        assert str(error) == (
            "Encoded header block of 101 bytes on stream 7 exceeds limit of "
            "100 bytes"
        )

    def test_too_many_continuation_frames_error_attributes(self) -> None:
        error = h2.exceptions.TooManyContinuationFramesError(
            stream_id=9, frame_count=65, max_frames=64,
        )

        assert error.stream_id == 9
        assert error.frame_count == 65
        assert error.max_frames == 64
        assert isinstance(error, h2.exceptions.ProtocolError)
        assert not isinstance(
            error, h2.exceptions.HeaderBlockTooLargeError,
        )
        assert str(error) == (
            "Header block on stream 9 used 65 frames, exceeding the limit of "
            "64 frames"
        )
