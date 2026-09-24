"""
h2/frame
~~~~~~~~

Additional HTTP/2 frame types that are not provided by hyperframe.
"""
from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Any

from hyperframe.exceptions import InvalidFrameError
from hyperframe.frame import (
    _STREAM_ASSOC_EITHER,
    FRAMES,
    Frame,
)

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Iterable

_STRUCT_H = struct.Struct(">H")


class OriginFrame(Frame):
    """
    The ORIGIN frame is used by a server to indicate which origins (and thus
    which hosts) it considers this connection authoritative for. This frame
    is standardised as part of RFC 8336.

    The frame payload is a sequence of length-prefixed origins. This class
    only parses and serializes that structure: it does not validate that the
    origins themselves are well-formed.

    .. versionadded:: 4.5.0
    """

    #: The type byte for ORIGIN frames.
    type = 0x0C

    # RFC 8336 requires that ORIGIN frames received on a stream other than
    # stream 0 are ignored, rather than treated as an error, so the stream
    # association cannot be enforced when parsing.
    stream_association = _STREAM_ASSOC_EITHER

    def __init__(self, stream_id: int = 0, origins: Iterable[bytes] = (), **kwargs: Any) -> None:
        super().__init__(stream_id, **kwargs)

        #: The origins contained in this frame, in wire order.
        self.origins = list(origins)

    def _body_repr(self) -> str:
        return f"origins={self.origins!r}"

    def serialize_body(self) -> bytes:
        return b"".join(
            _STRUCT_H.pack(len(origin)) + origin for origin in self.origins
        )

    def parse_body(self, data: memoryview) -> None:
        self.body_len = len(data)

        origins = []
        while data:
            if len(data) < _STRUCT_H.size:
                msg = "Invalid ORIGIN frame body."
                raise InvalidFrameError(msg)
            (origin_len,) = _STRUCT_H.unpack(data[:_STRUCT_H.size])
            if len(data) < _STRUCT_H.size + origin_len:
                msg = "Invalid ORIGIN frame body."
                raise InvalidFrameError(msg)
            origins.append(
                data[_STRUCT_H.size:_STRUCT_H.size + origin_len].tobytes(),
            )
            data = data[_STRUCT_H.size + origin_len:]

        self.origins = origins


# Teach hyperframe's frame registry about the ORIGIN frame so that it is
# parsed as a first-class frame instead of an opaque extension frame.
FRAMES[OriginFrame.type] = OriginFrame
