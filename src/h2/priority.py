"""
h2/priority
~~~~~~~~~~~

Implementation of the RFC 9218 (Extensible Prioritization Scheme for HTTP)
priority field value, used by the HTTP/2 PRIORITY_UPDATE frame.

The priority field value is a Structured Fields (RFC 8941) Dictionary. This
module provides a small, strict parser and serializer for the subset of
Structured Fields needed to represent those dictionaries, plus the
:class:`Priority` object that exposes the parsed ``urgency`` and
``incremental`` parameters to applications.

h2 does not implement a priority scheduler: it only parses, validates and
serializes these values so that applications can make their own scheduling
decisions.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable

#: The HTTP/2 frame type code for the PRIORITY_UPDATE frame (RFC 9218 § 7.1).
PRIORITY_UPDATE_FRAME_TYPE = 0x10

#: The default urgency, used when the ``u`` parameter is absent or invalid
#: (RFC 9218 § 4.1).
DEFAULT_URGENCY = 3

#: The default incrementality, used when the ``i`` parameter is absent or
#: invalid (RFC 9218 § 4.2).
DEFAULT_INCREMENTAL = False

_MIN_URGENCY = 0
_MAX_URGENCY = 7

# sf-key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )
_KEY_RE = re.compile(r"[a-z*][a-z0-9_\-.*]*")

# sf-token, used to decide whether a string can be emitted bare.
_TOKEN_RE = re.compile(r"[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*\Z")


@dataclass
class Priority:
    """
    A parsed RFC 9218 priority field value.

    This object carries the scheduling signals defined by RFC 9218. It is
    purely advisory: h2 does not act on it in any way.

    .. versionadded:: 4.5.0
    """

    #: The urgency of the response: an integer between 0 (most urgent) and 7
    #: (least urgent). Defaults to 3 when the peer omits the parameter or
    #: sends an invalid value, as required by RFC 9218 § 4.1.
    urgency: int = DEFAULT_URGENCY

    #: Whether the response can be delivered incrementally. Defaults to
    #: ``False`` when the peer omits the parameter or sends an invalid
    #: value, as required by RFC 9218 § 4.2.
    incremental: bool = DEFAULT_INCREMENTAL

    #: Any additional, unknown dictionary parameters sent by the peer. RFC
    #: 9218 allows these to be ignored, but h2 preserves them here so that
    #: applications can make use of extension parameters. Values are the
    #: parsed Structured Fields bare items: ``bool``, ``int``,
    #: ``float``, ``str`` (tokens and strings) or ``bytes`` (byte
    #: sequences).
    extra_parameters: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def parse(cls, data: bytes) -> Priority | None:
        """
        Parse a priority field value (as carried by the PRIORITY_UPDATE
        frame or the ``Priority`` header field) into a
        :class:`Priority`.

        Returns ``None`` if the value cannot be parsed as a Structured
        Fields Dictionary.
        """
        try:
            text = data.decode("ascii")
        except UnicodeDecodeError:
            return None

        members = _parse_dictionary(text)
        if members is None:
            return None

        urgency = members.pop("u", None)
        incremental = members.pop("i", None)

        return cls(
            urgency=(
                urgency
                if isinstance(urgency, int)
                and not isinstance(urgency, bool)
                and _MIN_URGENCY <= urgency <= _MAX_URGENCY
                else DEFAULT_URGENCY
            ),
            incremental=(
                incremental
                if isinstance(incremental, bool)
                else DEFAULT_INCREMENTAL
            ),
            extra_parameters=members,
        )

    def serialize(self) -> bytes:
        """
        Serialize this priority value into Structured Fields Dictionary
        form, suitable for use in a PRIORITY_UPDATE frame or a ``Priority``
        header field.
        """
        if not (_MIN_URGENCY <= self.urgency <= _MAX_URGENCY):
            msg = f"urgency must be between {_MIN_URGENCY} and {_MAX_URGENCY}"
            raise ValueError(msg)

        items = [f"u={self.urgency}"]
        if self.incremental:
            items.append("i=?1")
        for key, value in self.extra_parameters.items():
            items.append(f"{key}={_serialize_bare_item(value)}")

        return ", ".join(items).encode("ascii")

    def __bytes__(self) -> bytes:
        return self.serialize()


def _parse_dictionary(text: str) -> dict[str, Any] | None:
    """
    Parse an RFC 8941 sf-dictionary. Returns a mapping of keys to bare item
    values, or ``None`` if the input is not a valid dictionary. Item
    parameters (``;``-separated) are parsed and discarded.
    """
    members: dict[str, Any] = {}
    pos = 0
    length = len(text)

    while True:
        pos = _skip_ows(text, pos)
        if pos >= length:
            return members

        parsed_member = _parse_member(text, pos)
        if parsed_member is None:
            return None
        key, value, pos = parsed_member

        if key in members:
            # Duplicate dictionary keys are a parse error (RFC 8941 § 3.1.2).
            return None

        members[key] = value

        pos = _skip_ows(text, pos)
        if pos >= length:
            return members
        if text[pos] != ",":
            return None
        pos += 1
        if _skip_ows(text, pos) >= length:
            # A trailing comma is a parse error (RFC 8941 § 3.1.2).
            return None


def _parse_member(text: str, pos: int) -> tuple[str, Any, int] | None:
    """
    Parse a single dictionary member (key, optional value and any item
    parameters, which are discarded) starting at ``pos``. Returns the key,
    the value and the position after the member, or ``None`` on a parse
    error.
    """
    match = _KEY_RE.match(text, pos)
    if match is None:
        return None
    key = match.group(0)
    pos = match.end()

    value: Any = True
    if pos < len(text) and text[pos] == "=":
        parsed = _parse_bare_item(text, pos + 1)
        if parsed is None:
            return None
        value, pos = parsed

    # Discard any item parameters.
    while pos < len(text) and text[pos] == ";":
        parsed_param = _parse_parameter(text, pos)
        if parsed_param is None:
            return None
        pos = parsed_param

    return key, value, pos


def _parse_parameter(text: str, pos: int) -> int | None:
    """
    Parse a single item parameter starting at ``;``. Returns the position
    after the parameter, or ``None`` on a parse error.
    """
    pos = _skip_optional_spaces(text, pos + 1)
    match = _KEY_RE.match(text, pos)
    if match is None:
        return None
    pos = match.end()
    if pos < len(text) and text[pos] == "=":
        parsed = _parse_bare_item(text, pos + 1)
        if parsed is None:
            return None
        _, pos = parsed
    return pos


def _parse_bare_item(text: str, pos: int) -> tuple[Any, int] | None:
    """
    Parse an RFC 8941 bare item starting at ``pos``. Returns a tuple of
    the parsed value and the position after the item, or ``None`` on a
    parse error.
    """
    if pos >= len(text):
        return None

    char = text[pos]
    parser: Callable[[str, int], tuple[Any, int] | None] | None = None
    if char == "?":
        parser = _parse_boolean
    elif char == '"':
        parser = _parse_string
    elif char == ":":
        parser = _parse_byte_sequence
    elif char == "-" or char.isdigit():
        parser = _parse_number
    elif char.isalpha() or char == "*":
        parser = _parse_token

    if parser is None:
        return None
    return parser(text, pos)


def _parse_boolean(text: str, pos: int) -> tuple[bool, int] | None:
    if pos + 1 >= len(text) or text[pos + 1] not in "01":
        return None
    return text[pos + 1] == "1", pos + 2


def _parse_number(text: str, pos: int) -> tuple[int | float, int] | None:
    match = re.match(r"-?[0-9]+", text[pos:])
    if match is None:
        return None
    integer_part = match.group(0)
    end = pos + len(integer_part)

    if end < len(text) and text[end] == ".":
        fraction = re.match(r"[0-9]+", text[end + 1:])
        if fraction is None:
            return None
        fraction_part = fraction.group(0)
        if len(integer_part.lstrip("-")) > 12 or len(fraction_part) > 3:
            return None
        return (
            float(f"{integer_part}.{fraction_part}"),
            end + 1 + len(fraction_part),
        )

    if len(integer_part.lstrip("-")) > 15:
        return None
    return int(integer_part), end


def _parse_string(text: str, pos: int) -> tuple[str, int] | None:
    pos += 1
    chars: list[str] = []
    while pos < len(text):
        char = text[pos]
        if char == '"':
            return "".join(chars), pos + 1
        if char == "\\":
            pos += 1
            if pos >= len(text) or text[pos] not in '"\\':
                return None
            chars.append(text[pos])
        elif not (0x20 <= ord(char) <= 0x7E):
            return None
        else:
            chars.append(char)
        pos += 1
    return None


def _parse_token(text: str, pos: int) -> tuple[str, int] | None:
    match = re.match(r"[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*", text[pos:])
    if match is None:
        return None
    return match.group(0), pos + len(match.group(0))


def _parse_byte_sequence(text: str, pos: int) -> tuple[bytes, int] | None:
    end = text.find(":", pos + 1)
    if end == -1:
        return None
    encoded = text[pos + 1:end]
    if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", encoded):
        return None
    try:
        value = base64.b64decode(encoded, validate=True)
    except binascii.Error:
        return None
    return value, end + 1


def _serialize_bare_item(value: Any) -> str:
    if isinstance(value, bool):
        result = "?1" if value else "?0"
    elif isinstance(value, int):
        result = str(value)
    elif isinstance(value, float):
        result = _serialize_decimal(value)
    elif isinstance(value, str):
        result = value if _TOKEN_RE.match(value) else _quote_string(value)
    elif isinstance(value, bytes):
        result = ":" + base64.b64encode(value).decode("ascii") + ":"
    else:
        msg = (
            f"Cannot serialize value of type {type(value).__name__} "
            "as a Structured Fields item"
        )
        raise TypeError(msg)
    return result


def _serialize_decimal(value: float) -> str:
    if value == int(value) and abs(value) < 1e12:
        return f"{value:.1f}"
    return f"{value:.3f}".rstrip("0")


def _quote_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _skip_ows(text: str, pos: int) -> int:
    while pos < len(text) and text[pos] in " \t":
        pos += 1
    return pos


def _skip_optional_spaces(text: str, pos: int) -> int:
    while pos < len(text) and text[pos] == " ":
        pos += 1
    return pos
