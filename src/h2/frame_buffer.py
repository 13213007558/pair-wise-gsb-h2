"""
h2/frame_buffer
~~~~~~~~~~~~~~~

A data structure that provides a way to iterate over a byte buffer in terms of
frames.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from hyperframe.exceptions import InvalidDataError, InvalidFrameError
from hyperframe.frame import ContinuationFrame, Frame, HeadersFrame, PushPromiseFrame

from .config import H2Configuration
from .exceptions import (
    FrameDataMissingError,
    FrameTooLargeError,
    HeaderBlockTooLargeError,
    ProtocolError,
    TooManyContinuationFramesError,
)

if TYPE_CHECKING:  # pragma: no cover
    from ._typing import Buffer

# To avoid a DOS attack based on sending loads of continuation frames, we limit
# the maximum number we're prepared to receive. In this case, we'll set the
# limit to 64, which means the largest encoded header block we can receive by
# default is 262144 bytes long, and the largest possible *at all* is 1073741760
# bytes long.
#
# This value seems reasonable for now, but in future we may want to evaluate
# making it configurable.
CONTINUATION_BACKLOG = 64

# Non-HPACK overhead inside a frame body, derivable from the 9-byte frame
# header alone. These are the bytes that must never be counted towards the
# encoded header block size.
_PRIORITY_DATA_LENGTH = 5
_PROMISED_STREAM_ID_LENGTH = 4


class FrameBuffer:
    """
    A buffer data structure for HTTP/2 data that allows iteration in terms of
    H2 frames.
    """

    def __init__(
        self,
        server: bool = False,
        max_encoded_header_block_size: int = (
            H2Configuration.DEFAULT_MAX_ENCODED_HEADER_BLOCK_SIZE
        ),
        max_continuation_frames: int = CONTINUATION_BACKLOG,
    ) -> None:
        self._data = bytearray()
        self.max_frame_size = 0
        self._preamble = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" if server else b""
        self._preamble_len = len(self._preamble)
        self._headers_buffer: list[HeadersFrame | ContinuationFrame | PushPromiseFrame] = []

        #: Maximum number of HPACK-encoded bytes accepted for one header block.
        #: A value of ``0`` disables the check. The value in force when a
        #: header block starts is frozen for the whole block.
        self.max_encoded_header_block_size = max_encoded_header_block_size

        #: Maximum number of frames (the opening frame plus CONTINUATIONs)
        #: buffered for a single header block.
        self.max_continuation_frames = max_continuation_frames

        # HPACK bytes accumulated for the header block currently in progress,
        # alongside the limit snapshot that applies to it. These only ever
        # count actual header block fragments: padding, the padding length
        # field, priority data and the PUSH_PROMISE promised stream ID are
        # excluded because hyperframe strips them into separate attributes.
        self._header_block_size = 0
        self._header_block_limit = self.max_encoded_header_block_size

        #: High-water mark of ``_header_block_size`` across all header blocks
        #: processed by this buffer. This is a verifiable count of the peak
        #: encoded-header buffering, including blocks that were later rejected.
        self.header_block_peak_size = 0

    def add_data(self, data: Buffer) -> None:
        """
        Add more data to the frame buffer.

        :param data: A bytestring containing the byte buffer.
        """
        data_view = memoryview(data)

        if self._preamble_len:
            data_len = len(data_view)
            of_which_preamble = min(self._preamble_len, data_len)

            if self._preamble[:of_which_preamble] != data_view[:of_which_preamble]:
                msg = "Invalid HTTP/2 preamble."
                raise ProtocolError(msg)

            data_view = data_view[of_which_preamble:]
            self._preamble_len -= of_which_preamble
            self._preamble = self._preamble[of_which_preamble:]

        self._data += data_view

    def _validate_frame_length(self, length: int) -> None:
        """
        Confirm that the frame is an appropriate length.
        """
        if length > self.max_frame_size:
            msg = f"Received overlong frame: length {length}, max {self.max_frame_size}"
            raise FrameTooLargeError(msg)

    def _reset_header_buffer(self) -> None:
        """
        Release any header block currently being accumulated, discarding the
        buffered frames and the running byte count.
        """
        self._headers_buffer.clear()
        self._header_block_size = 0

    def _record_header_fragment(self, frame: Frame) -> None:
        """
        Account for the HPACK bytes of one fully parsed header-bearing frame
        and enforce the per-block byte budget using the exact fragment size.
        """
        fragment_size = len(frame.data)
        self._header_block_size += fragment_size
        if self._header_block_size > self.header_block_peak_size:
            self.header_block_peak_size = self._header_block_size

        limit = self._header_block_limit
        if limit and self._header_block_size > limit:
            raise HeaderBlockTooLargeError(
                frame.stream_id,
                self._header_block_size,
                limit,
            )

    def _max_fragment_length(self, frame: Frame, length: int) -> int | None:
        """
        Exact HPACK fragment length, derived from only the 9-byte frame
        header, for frames whose non-HPACK overhead is fixed by the header.
        Returns ``None`` for frames that do not carry a header block
        fragment, or whose fragment length cannot be known until the body is
        parsed because a padding length byte sits inside the body.
        """
        if isinstance(frame, ContinuationFrame):
            # CONTINUATION frames have no padding or priority fields: their
            # whole body is a header block fragment.
            return length
        if isinstance(frame, HeadersFrame):
            # With PADDED set, the padding length (and therefore the size of
            # the HPACK fragment) is only known once the body arrives, so an
            # early check could produce false positives. The exact check after
            # body parsing still enforces the budget.
            if "PADDED" in frame.flags:
                return None
            overhead = _PRIORITY_DATA_LENGTH if "PRIORITY" in frame.flags else 0
            return length - overhead
        if isinstance(frame, PushPromiseFrame):
            if "PADDED" in frame.flags:
                return None
            return length - _PROMISED_STREAM_ID_LENGTH
        return None

    def _early_validate_header_frame(self, frame: Frame, length: int) -> None:
        """
        Validate a header-bearing frame as soon as its 9-byte header is known,
        without waiting for its body to arrive. Frames whose HPACK fragment
        size is fixed by the header can be rejected immediately when even that
        exact fragment would overflow the block budget. Padded frames defer to
        the exact post-parse check because their padding lives in the body.
        """
        fragment_length = self._max_fragment_length(frame, length)
        if fragment_length is None or fragment_length < 0:
            # Not a header frame whose size is knowable from the header, or a
            # body too short to hold its mandatory non-HPACK fields. The
            # latter is malformed and gets rejected when its body is parsed.
            return

        # The limit snapshot for a new block is taken in
        # ``_update_header_buffer`` once the opening frame has been fully
        # parsed. When only its nine-byte header has been seen so far (and no
        # block is open yet) fall back to the currently configured value,
        # which is exactly what the snapshot will be once it is taken.
        if self._headers_buffer:
            limit = self._header_block_limit
        else:
            limit = self.max_encoded_header_block_size

        if limit and self._header_block_size + fragment_length > limit:
            projected_size = self._header_block_size + fragment_length
            raise HeaderBlockTooLargeError(
                frame.stream_id,
                projected_size,
                limit,
            )

    def _update_header_buffer(self, f: Frame | None) -> Frame | None:
        """
        Updates the internal header buffer. Returns a frame that should replace
        the current one. May throw exceptions if this frame is invalid.
        """
        # Check if we're in the middle of a headers block. If we are, this
        # frame *must* be a CONTINUATION frame with the same stream ID as the
        # leading HEADERS or PUSH_PROMISE frame. Anything else is a
        # ProtocolError. If the frame *is* valid, append it to the header
        # buffer.
        if self._headers_buffer:
            stream_id = self._headers_buffer[0].stream_id
            valid_frame = (
                f is not None and
                isinstance(f, ContinuationFrame) and
                f.stream_id == stream_id
            )
            if not valid_frame:
                msg = "Invalid frame during header block."
                raise ProtocolError(msg)
            assert isinstance(f, ContinuationFrame)

            # The body is fully parsed, so apply the exact byte budget before
            # retaining the frame. Accounting first means a rejected frame is
            # never left behind in the buffer when the block is released.
            self._record_header_fragment(f)

            # Enforce the frame-count cap before retaining the frame, so an
            # over-limit frame never joins the buffer that gets discarded.
            if len(self._headers_buffer) >= self.max_continuation_frames:
                raise TooManyContinuationFramesError(
                    stream_id,
                    len(self._headers_buffer) + 1,
                    self.max_continuation_frames,
                )

            # Append the frame to the buffer.
            self._headers_buffer.append(f)

            # If this is the end of the header block, then we want to build a
            # mutant HEADERS frame that's massive. Use the original one we got,
            # then set END_HEADERS and set its data appropriately. If it's not
            # the end of the block, lose the current frame: we can't yield it.
            if "END_HEADERS" in f.flags:
                f = self._headers_buffer[0]
                f.flags.add("END_HEADERS")
                f.data = b"".join(x.data for x in self._headers_buffer)
                self._reset_header_buffer()
            else:
                f = None
        elif (isinstance(f, (HeadersFrame, PushPromiseFrame)) and
                "END_HEADERS" not in f.flags):
            # This is the start of a headers block! Save the frame off and then
            # act like we didn't receive one.
            self._header_block_limit = self.max_encoded_header_block_size
            self._record_header_fragment(f)
            self._headers_buffer.append(f)
            f = None
        elif isinstance(f, (HeadersFrame, PushPromiseFrame)):
            # A complete, single-frame header block. Account for its fragment
            # against the budget, but do not buffer anything; the running
            # block count is finished, so release it immediately.
            self._header_block_limit = self.max_encoded_header_block_size
            self._record_header_fragment(f)
            self._header_block_size = 0

        return f

    # The methods below support the iterator protocol.
    def __iter__(self) -> FrameBuffer:
        return self

    def __next__(self) -> Frame:
        # First, check that we have enough data to successfully parse the
        # next frame header. If not, bail. Otherwise, parse it.
        if len(self._data) < 9:
            raise StopIteration

        try:
            f, length = Frame.parse_frame_header(memoryview(self._data[:9]))
        except (InvalidDataError, InvalidFrameError) as err:  # pragma: no cover
            msg = f"Received frame with invalid header: {err!s}"
            raise ProtocolError(msg) from err

        # Next, check that we have enough length to parse the frame body. If
        # not, bail, leaving the frame header data in the buffer for next time.
        # A partial header or an incomplete but otherwise legal frame must
        # remain buffered rather than being reported as an error.
        if len(self._data) < length + 9:
            # A header-bearing frame whose projected HPACK fragment would
            # overflow the block budget is provably illegal from the 9-byte
            # header alone, so reject it immediately instead of waiting for
            # the whole (potentially huge) body to be buffered. Truncated
            # frames of every other kind stay buffered and are revisited once
            # more data arrives. Any failure releases the block already in
            # progress, since it can never be completed or delivered.
            try:
                self._early_validate_header_frame(f, length)
            except BaseException:
                self._reset_header_buffer()
                raise
            raise StopIteration

        # The full frame is present and its length is now final. The frame
        # length is rejected before any body bytes are parsed.
        self._validate_frame_length(length)

        # Try to parse the frame body
        try:
            f.parse_body(memoryview(self._data[9:9+length]))
        except InvalidDataError as err:
            msg = "Received frame with non-compliant data"
            raise ProtocolError(msg) from err
        except InvalidFrameError as err:
            msg = "Frame data missing or invalid"
            raise FrameDataMissingError(msg) from err

        # At this point, as we know we'll use or discard the entire frame, we
        # can update the data.
        # Deleting the consumed prefix mutates the bytearray in place instead
        # of copying the remaining bytes into a new object, as slicing would.
        # ``del s[i:j]`` is documented for mutable sequences in
        # https://docs.python.org/3/library/stdtypes.html#mutable-sequence-types
        # and CPython's bytearray tracks an internal offset (``ob_start`` in
        # Objects/bytearrayobject.c) that makes repeated deletes from the
        # front amortized O(1) per byte rather than O(len) per frame.
        del self._data[:9+length]

        # Pass the frame through the header buffer. Any failure means the
        # partially accumulated header block can never be delivered, so
        # release it rather than leaving stale fragments behind.
        try:
            new_frame = self._update_header_buffer(f)
        except BaseException:
            self._reset_header_buffer()
            raise

        # If we got a frame we didn't understand or shouldn't yield, rather
        # than return None it'd be better if we just tried to get the next
        # frame in the sequence instead. Recurse back into ourselves to do
        # that. This is safe because the amount of work we have to do here is
        # strictly bounded by the length of the buffer.
        return new_frame if new_frame is not None else self.__next__()
