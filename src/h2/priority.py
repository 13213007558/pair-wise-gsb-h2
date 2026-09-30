"""
h2/priority
~~~~~~~~~~~

Implementation of the RFC 9218 extensible prioritization scheme: the
PRIORITY_UPDATE frame and parsing of the HTTP priority field value.

This module only deals with conveying priority *signals* between peers. It
deliberately does not implement any kind of scheduling: that is left to the
application using h2.
"""
from __future__ import annotations

import re
import struct

from hyperframe.frame import ExtensionFrame

#: The frame type code of the PRIORITY_UPDATE frame, defined in RFC 9218
#: section 6.
PRIORITY_UPDATE_FRAME_TYPE = 0x10

#: The default urgency of a request, used when the urgency parameter is
#: absent or invalid. Defined in RFC 9218 section 4.1.
DEFAULT_URGENCY = 3

#: The lowest (most urgent) value the urgency parameter can take.
MIN_URGENCY = 0

#: The highest (least urgent) value the urgency parameter can take.
MAX_URGENCY = 7

# An RFC 8941 dictionary key.
_KEY_RE = re.compile(r"[a-z*][a-z0-9_.*-]*")

# An RFC 8941 integer.
_INTEGER_RE = re.compile(r"-?[0-9]+")


class PriorityUpdateFrame(ExtensionFrame):
    """
    The PRIORITY_UPDATE frame, defined in RFC 9218 section 6.

    This frame is sent on stream 0 and carries, for a given prioritized
    element (a request or push stream), a new priority expressed as an HTTP
    priority field value: a structured field dictionary containing the
    ``u`` (urgency) and ``i`` (incremental) parameters, plus any unknown
    parameters the peer chose to include.

    hyperframe does not know this frame type, so h2 maintains its own frame
    class here. On the wire it is indistinguishable from a generic extension
    frame of type 0x10.

    .. versionadded:: 4.5.0
    """

    def __init__(self, stream_id: int = 0, **kwargs: object) -> None:
        super().__init__(
            type=PRIORITY_UPDATE_FRAME_TYPE,
            stream_id=stream_id,
            **kwargs,  # type: ignore[arg-type]
        )

        #: The stream ID of the element being reprioritized. This is the
        #: "Prioritized Element ID" from RFC 9218 section 6.
        self.prioritized_stream_id = 0

        #: The raw priority field value carried by the frame.
        self.field_value = b""

    def _body_repr(self) -> str:
        return (
            f"prioritized_stream_id={self.prioritized_stream_id}, "
            f"field_value={self.field_value!r}"
        )

    def parse_body(self, data: memoryview) -> None:
        super().parse_body(data)
        if self.body_len >= 4:
            self.prioritized_stream_id = (
                struct.unpack("!L", self.body[:4])[0] & 0x7FFFFFFF
            )
            self.field_value = self.body[4:]

    def serialize(self) -> bytes:
        self.body = (
            struct.pack("!L", self.prioritized_stream_id) + self.field_value
        )
        self.body_len = len(self.body)
        return super().serialize()


def build_priority_field_value(urgency: int | None, incremental: bool | None) -> bytes:
    """
    Serialize a priority field value from its structured parts. Parameters
    set to ``None`` (or ``incremental=False``, which is the default) are
    omitted, as permitted by RFC 9218 section 4.
    """
    parts = []
    if urgency is not None:
        parts.append(f"u={urgency}")
    if incremental:
        parts.append("i=?1")
    return ", ".join(parts).encode("ascii")


def parse_priority_field_value(data: bytes) -> tuple[int, bool, dict[str, str | None]]:
    """
    Parse an HTTP priority field value (an RFC 8941 structured field
    dictionary) into its known and unknown parameters.

    Returns a tuple of ``(urgency, incremental, unknown_parameters)`` where
    ``unknown_parameters`` maps unknown parameter keys to their raw,
    unparsed values (or ``None`` for bare keys), allowing applications to
    inspect parameters h2 does not understand.

    Following RFC 9218, this parser is tolerant: a field value that does not
    parse as a structured field dictionary yields the default parameters
    (urgency 3, not incremental), and individually invalid ``u``/``i``
    values are ignored in favour of their defaults. Parsing never raises.
    """
    urgency = DEFAULT_URGENCY
    incremental = False
    unknown: dict[str, str | None] = {}

    try:
        text = bytes(data).decode("ascii")
    except UnicodeDecodeError:
        return urgency, incremental, unknown

    if not text.strip(" \t"):
        # An empty dictionary is valid: all parameters take their defaults.
        return urgency, incremental, unknown

    members = _split_dictionary_members(text)
    if members is None:
        return DEFAULT_URGENCY, False, {}

    parameters = _parse_members(members)
    if parameters is None:
        return DEFAULT_URGENCY, False, {}

    for key, value in parameters:
        if key == "u":
            parsed_urgency = _parse_urgency(value)
            if parsed_urgency is not None:
                urgency = parsed_urgency
        elif key == "i":
            parsed_incremental = _parse_boolean(value)
            if parsed_incremental is not None:
                incremental = parsed_incremental
        else:
            unknown[key] = value

    return urgency, incremental, unknown


def _parse_members(members: list[str]) -> list[tuple[str, str | None]] | None:
    """
    Parse the members of a structured field dictionary into (key, raw
    value) pairs. Returns ``None`` if any member is structurally invalid.
    """
    seen_keys = set()
    parameters = []

    for member in members:
        stripped_member = member.strip(" \t")
        match = _KEY_RE.match(stripped_member) if stripped_member else None
        if match is None:
            return None
        key = match.group(0)

        # Duplicate keys are a parse error in RFC 8941.
        if key in seen_keys:
            return None
        seen_keys.add(key)

        valid, value = _member_value(stripped_member[match.end():])
        if not valid:
            return None
        parameters.append((key, value))

    return parameters


def _member_value(rest: str) -> tuple[bool, str | None]:
    """
    Extract the value from the part of a dictionary member that follows
    its key. Returns a (valid, value) tuple, where the value is ``None``
    for bare keys.
    """
    if rest.startswith("="):
        value = _read_member_value(rest[1:])
        return (value is not None), value

    if not rest or rest.startswith(";"):
        # A bare key, or a key with parameters we don't need to parse.
        return True, None

    return False, None


def _split_dictionary_members(text: str) -> list[str] | None:
    """
    Split a structured field dictionary into its members on top-level
    commas, respecting quoted strings and inner lists. Returns ``None`` if
    the value is structurally invalid (unbalanced quotes or parentheses).
    """
    members = []
    start = 0
    depth = 0
    index = 0

    while index < len(text):
        char = text[index]
        if char == '"':
            string_end = _find_string_end(text, index)
            if string_end is None:
                return None
            index = string_end
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return None
        elif char == "," and depth == 0:
            members.append(text[start:index])
            start = index + 1
        index += 1

    if depth != 0:
        return None

    members.append(text[start:])
    return members


def _find_string_end(text: str, start: int) -> int | None:
    """
    Return the index just past the closing quote of the quoted string
    opening at ``start``, or ``None`` if the string is unterminated.
    """
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
        elif char == '"':
            return index + 1
        else:
            index += 1
    return None


def _read_member_value(text: str) -> str | None:
    """
    Extract the raw member value following the "=" of a dictionary member,
    stopping at any member parameters (";..."). Returns ``None`` if no
    value is present.
    """
    in_string = False
    escaped = False

    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == ";":
            value = text[:index].strip(" \t")
            return value or None

    if in_string:
        # Unreachable: _split_dictionary_members guarantees balanced
        # quotes within each member.
        return None  # pragma: no cover

    value = text.strip(" \t")
    return value or None


def _parse_urgency(value: str | None) -> int | None:
    """
    Parse an urgency parameter value. Returns ``None`` if the value is not
    a valid urgency, in which case the default applies (RFC 9218
    section 4.1).
    """
    if value is None or _INTEGER_RE.fullmatch(value) is None:
        return None

    urgency = int(value)
    if not MIN_URGENCY <= urgency <= MAX_URGENCY:
        return None

    return urgency


def _parse_boolean(value: str | None) -> bool | None:
    """
    Parse an RFC 8941 boolean parameter value. Returns ``None`` if the
    value is not a valid boolean, in which case the default applies.
    """
    if value == "?1":
        return True
    if value == "?0":
        return False
    return None
