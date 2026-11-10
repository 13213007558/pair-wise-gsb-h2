"""
h2/exceptions
~~~~~~~~~~~~~

Exceptions for the HTTP/2 module.
"""
from __future__ import annotations

from .errors import ErrorCodes


class H2Error(Exception):
    """
    The base class for all exceptions for the HTTP/2 module.
    """


class ProtocolError(H2Error):
    """
    An action was attempted in violation of the HTTP/2 protocol.
    """

    #: The error code corresponds to this kind of Protocol Error.
    error_code = ErrorCodes.PROTOCOL_ERROR


class FrameTooLargeError(ProtocolError):
    """
    The frame that we tried to send or that we received was too large.
    """

    #: The error code corresponds to this kind of Protocol Error.
    error_code = ErrorCodes.FRAME_SIZE_ERROR


class FrameDataMissingError(ProtocolError):
    """
    The frame that we received is missing some data.

    .. versionadded:: 2.0.0
    """

    #: The error code corresponds to this kind of Protocol Error.
    error_code = ErrorCodes.FRAME_SIZE_ERROR


class HeaderBlockTooLargeError(ProtocolError):
    """
    The remote peer sent an HPACK-encoded header block whose size, measured
    before decompression and excluding non-HPACK bytes such as padding or
    priority data, exceeded the configured
    ``max_encoded_header_block_size`` limit.

    No partial header event is delivered: the in-progress header block is
    discarded and the connection is terminated.

    .. versionadded:: 4.5.0
    """

    #: The error code corresponds to this kind of Protocol Error.
    error_code = ErrorCodes.PROTOCOL_ERROR

    def __init__(self, stream_id: int, encoded_size: int, max_size: int) -> None:
        #: The ID of the stream whose header block exceeded the limit.
        self.stream_id = stream_id

        #: The encoded size, in bytes, accumulated when the limit was hit.
        self.encoded_size = encoded_size

        #: The configured limit, in bytes.
        self.max_size = max_size
        super().__init__(
            f"Encoded header block of {encoded_size} bytes on stream "
            f"{stream_id} exceeds limit of {max_size} bytes",
        )


class TooManyContinuationFramesError(ProtocolError):
    """
    The remote peer sent more CONTINUATION frames for a single header block
    than the implementation is prepared to buffer.

    No partial header event is delivered: the in-progress header block is
    discarded and the connection is terminated.

    .. versionadded:: 4.5.0
    """

    #: The error code corresponds to this kind of Protocol Error.
    error_code = ErrorCodes.PROTOCOL_ERROR

    def __init__(self, stream_id: int, frame_count: int, max_frames: int) -> None:
        #: The ID of the stream whose header block had too many frames.
        self.stream_id = stream_id

        #: The number of header-bearing frames accumulated when rejected.
        self.frame_count = frame_count

        #: The maximum number of header-bearing frames permitted per block.
        self.max_frames = max_frames
        super().__init__(
            f"Header block on stream {stream_id} used {frame_count} frames, "
            f"exceeding the limit of {max_frames} frames",
        )


class TooManyStreamsError(ProtocolError):
    """
    An attempt was made to open a stream that would lead to too many concurrent
    streams.
    """



class FlowControlError(ProtocolError):
    """
    An attempted action violates flow control constraints.
    """

    #: The error code corresponds to this kind of Protocol Error.
    error_code = ErrorCodes.FLOW_CONTROL_ERROR


class StreamIDTooLowError(ProtocolError):
    """
    An attempt was made to open a stream that had an ID that is lower than the
    highest ID we have seen on this connection.
    """

    def __init__(self, stream_id: int, max_stream_id: int) -> None:
        #: The ID of the stream that we attempted to open.
        self.stream_id = stream_id

        #: The current highest-seen stream ID.
        self.max_stream_id = max_stream_id

    def __str__(self) -> str:
        return f"StreamIDTooLowError: {self.stream_id} is lower than {self.max_stream_id}"


class NoAvailableStreamIDError(ProtocolError):
    """
    There are no available stream IDs left to the connection. All stream IDs
    have been exhausted.

    .. versionadded:: 2.0.0
    """



class NoSuchStreamError(ProtocolError):
    """
    A stream-specific action referenced a stream that does not exist.

    .. versionchanged:: 2.0.0
       Became a subclass of :class:`ProtocolError
       <h2.exceptions.ProtocolError>`
    """

    def __init__(self, stream_id: int) -> None:
        #: The stream ID corresponds to the non-existent stream.
        self.stream_id = stream_id


class StreamClosedError(NoSuchStreamError):
    """
    A more specific form of
    :class:`NoSuchStreamError <h2.exceptions.NoSuchStreamError>`. Indicates
    that the stream has since been closed, and that all state relating to that
    stream has been removed.
    """

    def __init__(self, stream_id: int) -> None:
        #: The stream ID corresponds to the nonexistent stream.
        self.stream_id = stream_id

        #: The relevant HTTP/2 error code.
        self.error_code = ErrorCodes.STREAM_CLOSED

        # Any events that internal code may need to fire. Not relevant to
        # external users that may receive a StreamClosedError.
        self._events = []  # type: ignore


class InvalidSettingsValueError(ProtocolError, ValueError):
    """
    An attempt was made to set an invalid Settings value.

    .. versionadded:: 2.0.0
    """

    def __init__(self, msg: str, error_code: ErrorCodes) -> None:
        super().__init__(msg)
        self.error_code = error_code


class InvalidBodyLengthError(ProtocolError):
    """
    The remote peer sent more or less data that the Content-Length header
    indicated.

    .. versionadded:: 2.0.0
    """

    def __init__(self, expected: int, actual: int) -> None:
        self.expected_length = expected
        self.actual_length = actual

    def __str__(self) -> str:
        return f"InvalidBodyLengthError: Expected {self.expected_length} bytes, received {self.actual_length}"


class UnsupportedFrameError(ProtocolError):
    """
    The remote peer sent a frame that is unsupported in this context.

    .. versionadded:: 2.1.0

    .. versionchanged:: 4.0.0
       Removed deprecated KeyError parent class.
    """



class RFC1122Error(H2Error):
    """
    Emitted when users attempt to do something that is literally allowed by the
    relevant RFC, but is sufficiently ill-defined that it's unwise to allow
    users to actually do it.

    While there is some disagreement about whether or not we should be liberal
    in what accept, it is a truth universally acknowledged that we should be
    conservative in what emit.

    .. versionadded:: 2.4.0
    """

    # shazow says I'm going to regret naming the exception this way. If that
    # turns out to be true, TELL HIM NOTHING.


class DenialOfServiceError(ProtocolError):
    """
    Emitted when the remote peer exhibits a behaviour that is likely to be an
    attempt to perform a Denial of Service attack on the implementation. This
    is a form of ProtocolError that carries a different error code, and allows
    more easy detection of this kind of behaviour.

    .. versionadded:: 2.5.0
    """

    #: The error code corresponds to this kind of
    #: :class:`ProtocolError <h2.exceptions.ProtocolError>`
    error_code = ErrorCodes.ENHANCE_YOUR_CALM
