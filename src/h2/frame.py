"""
h2/frame
~~~~~~~~

Additional HTTP/2 frame types that are not provided by hyperframe.

Currently this contains only the PRIORITY_UPDATE frame defined by RFC 9218.
The frame class is registered with hyperframe's frame table at import time
so that the regular frame parsing machinery produces these frames directly.
"""

from __future__ import annotations

import struct
from typing import Any

from hyperframe.exceptions import InvalidFrameError
from hyperframe.frame import FRAMES, Frame

#: The type byte of the PRIORITY_UPDATE frame, as defined by RFC 9218 § 7.1.
PRIORITY_UPDATE_FRAME_TYPE = 0x10


class PriorityUpdateFrame(Frame):
    """
    The PRIORITY_UPDATE frame (type=0x10) carries the sender-advised priority
    of a stream using the extensible prioritization scheme defined in
    RFC 9218. It is always sent on the connection control stream (stream 0)
    and identifies the stream it applies to via the Prioritized Element ID
    field in its payload.

    .. versionadded:: 4.5.0
    """

    #: The type byte defined for PRIORITY_UPDATE frames.
    type = PRIORITY_UPDATE_FRAME_TYPE

    # The PRIORITY_UPDATE frame is a connection-level frame: it MUST be sent
    # on stream 0. That requirement is enforced by the connection state
    # machine, which can raise a more useful error, so either association is
    # accepted at this layer.
    stream_association = "either"

    def __init__(self, stream_id: int, **kwargs: Any) -> None:
        super().__init__(stream_id, **kwargs)

        #: The stream ID of the request or push stream whose priority is
        #: being updated. RFC 9218 calls this the Prioritized Element ID.
        self.prioritized_element_id = 0

        #: The serialized Priority Field Value: an RFC 8941 Structured Fields
        #: Dictionary, exactly as it appears in the Priority header field.
        self.field_value = b""

    def _body_repr(self) -> str:
        return f"prioritized_element_id={self.prioritized_element_id}, field_value={self.field_value!r}"

    def serialize_body(self) -> bytes:
        return (
            struct.pack(
                "!L",
                self.prioritized_element_id & 0x7FFFFFFF,
            )
            + self.field_value
        )

    def parse_body(self, data: memoryview) -> None:
        if len(data) < 4:
            msg = f"PRIORITY_UPDATE must have at least 4 byte body: received {len(data)}"
            raise InvalidFrameError(msg)

        self.prioritized_element_id = struct.unpack("!L", data[:4])[0] & 0x7FFFFFFF
        self.field_value = data[4:].tobytes()
        self.body_len = len(data)


# Register the frame with hyperframe so that Frame.parse_frame_header builds
# PriorityUpdateFrame objects instead of generic ExtensionFrame objects.
FRAMES[PRIORITY_UPDATE_FRAME_TYPE] = PriorityUpdateFrame
