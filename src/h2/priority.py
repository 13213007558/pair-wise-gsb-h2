"""
h2/priority
~~~~~~~~~~~

Parsing and serialization of RFC 9218 Priority Field Values.

The Priority Field Value carried by the PRIORITY_UPDATE frame (and by the
Priority HTTP header field) is an RFC 8941 Structured Fields Dictionary.
This module implements the subset of Structured Fields parsing needed to
handle those dictionaries, and the RFC 9218 logic that extracts the
u (urgency) and i (incremental) parameters from them.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from typing import Any

#: The lowest valid urgency value (most urgent), from RFC 9218 section 4.1.
MIN_URGENCY = 0

#: The highest valid urgency value (least urgent), from RFC 9218 section 4.1.
MAX_URGENCY = 7

#: The urgency used when none is signalled, from RFC 9218 section 4.1.
DEFAULT_URGENCY = 3

_DIGITS = frozenset("0123456789")
_ALPHA = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_KEY_START_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz*")
_KEY_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-.*")
_TCHARS = frozenset("!#$%&'*+-.^_|~") | _DIGITS | _ALPHA


@dataclass
class PriorityValue:
    """
    The parsed content of an RFC 9218 Priority Field Value.

    .. versionadded:: 4.5.0
    """

    #: The urgency: an integer between 0 and 7. Defaults to 3.
    urgency: int = DEFAULT_URGENCY

    #: Whether the response should be delivered incrementally.
    incremental: bool = False

    #: Any additional dictionary members that were present in the field
    #: value, preserved verbatim for the application to interpret.
    unknown_parameters: dict[str, Any] = field(default_factory=dict)


class _ParseError(Exception):
    """
    The field value is not a valid RFC 8941 Structured Fields Dictionary.
    """


def _skip_ows(data: str, pos: int) -> int:
    while pos < len(data) and data[pos] in (" ", "\t"):
        pos += 1
    return pos


def _skip_sp(data: str, pos: int) -> int:
    while pos < len(data) and data[pos] == " ":
        pos += 1
    return pos


def _parse_key(data: str, pos: int) -> tuple[str, int]:
    if pos >= len(data) or data[pos] not in _KEY_START_CHARS:
        raise _ParseError
    start = pos
    pos += 1
    while pos < len(data) and data[pos] in _KEY_CHARS:
        pos += 1
    return data[start:pos], pos


def _parse_number(data: str, pos: int) -> tuple[int | float, int]:
    start = pos
    if data[pos] == "-":
        pos += 1
    digits_start = pos
    while pos < len(data) and data[pos] in _DIGITS:
        pos += 1
    int_digits = pos - digits_start
    if int_digits == 0 or int_digits > 15:
        raise _ParseError
    if pos < len(data) and data[pos] == ".":
        if int_digits > 12:
            raise _ParseError
        pos += 1
        frac_start = pos
        while pos < len(data) and data[pos] in _DIGITS:
            pos += 1
        frac_digits = pos - frac_start
        if frac_digits == 0 or frac_digits > 3:
            raise _ParseError
        return float(data[start:pos]), pos
    return int(data[start:pos]), pos


def _parse_string(data: str, pos: int) -> tuple[str, int]:
    pos += 1  # Consume the opening DQUOTE.
    chars: list[str] = []
    while pos < len(data):
        char = data[pos]
        pos += 1
        if char == '"':
            return "".join(chars), pos
        if char == "\\":
            if pos >= len(data) or data[pos] not in ('"', "\\"):
                raise _ParseError
            chars.append(data[pos])
            pos += 1
            continue
        if not " " <= char <= "~":
            raise _ParseError
        chars.append(char)
    raise _ParseError
    raise _ParseError


def _parse_token(data: str, pos: int) -> tuple[str, int]:
    start = pos
    pos += 1  # The first character (ALPHA or "*") was checked by the caller.
    while pos < len(data) and (data[pos] in _TCHARS or data[pos] in ":/"):
        pos += 1
    return data[start:pos], pos


def _parse_byte_sequence(data: str, pos: int) -> tuple[bytes, int]:
    end = data.find(":", pos + 1)
    if end == -1:
        raise _ParseError
    try:
        value = base64.b64decode(data[pos + 1 : end], validate=True)
    except (binascii.Error, ValueError):
        raise _ParseError from None
    return value, end + 1


def _parse_boolean(data: str, pos: int) -> tuple[bool, int]:
    if pos + 1 >= len(data) or data[pos + 1] not in ("0", "1"):
        raise _ParseError
    return data[pos + 1] == "1", pos + 2


def _parse_bare_item(data: str, pos: int) -> tuple[Any, int]:
    if pos >= len(data):
        raise _ParseError
    char = data[pos]
    if char == '"':
        return _parse_string(data, pos)
    if char == ":":
        return _parse_byte_sequence(data, pos)
    if char == "?":
        return _parse_boolean(data, pos)
    if char == "-" or char in _DIGITS:
        return _parse_number(data, pos)
    if char in _ALPHA or char == "*":
        return _parse_token(data, pos)
    raise _ParseError
    raise _ParseError


def _parse_parameters(data: str, pos: int) -> int:
    # Parameters (RFC 8941 section 3.1.2) are parsed and validated, but
    # their content is not currently meaningful for priority values, so it
    # is discarded.
    while pos < len(data) and data[pos] == ";":
        pos = _skip_sp(data, pos + 1)
        _, pos = _parse_key(data, pos)
        if pos < len(data) and data[pos] == "=":
            _, pos = _parse_bare_item(data, pos + 1)
    return pos


def _parse_inner_list(data: str, pos: int) -> tuple[list[Any], int]:
    pos += 1  # Consume the "(".
    items: list[Any] = []
    while True:
        pos = _skip_sp(data, pos)
        if pos >= len(data):
            raise _ParseError
        if data[pos] == ")":
            return items, pos + 1
        item, pos = _parse_bare_item(data, pos)
        pos = _parse_parameters(data, pos)
        items.append(item)
        if pos >= len(data) or data[pos] not in (" ", ")"):
            raise _ParseError


def _parse_member(data: str, pos: int) -> tuple[str, Any, int]:
    key, pos = _parse_key(data, pos)
    value: Any = True
    if pos < len(data) and data[pos] == "=":
        if data[pos + 1 : pos + 2] == "(":
            value, pos = _parse_inner_list(data, pos + 1)
        else:
            value, pos = _parse_bare_item(data, pos + 1)
    pos = _parse_parameters(data, pos)
    return key, value, pos
    return key, value, pos


def _parse_dictionary(data: str) -> dict[str, Any]:
    members: dict[str, Any] = {}
    pos = 0
    while pos < len(data):
        key, value, pos = _parse_member(data, pos)
        # RFC 8941 requires dictionary keys to be unique. When a peer sends
        # duplicates anyway, keep the first occurrence and ignore the rest.
        if key not in members:
            members[key] = value
        pos = _skip_ows(data, pos)
        if pos >= len(data):
            break
        if data[pos] != ",":
            raise _ParseError
        pos = _skip_ows(data, pos + 1)
        if pos >= len(data):
            # A trailing comma with no following member.
            raise _ParseError
    return members
    raise _ParseError


def parse_priority_field_value(data: bytes) -> PriorityValue:
    """
    Parse an RFC 9218 Priority Field Value.

    Returns a PriorityValue holding the urgency, the incremental flag, and
    any unknown dictionary members. If the field value cannot be parsed as
    a Structured Fields Dictionary, or if the known parameters have values
    of the wrong type, the defaults mandated by RFC 9218 are used for the
    affected parameters.

    .. versionadded:: 4.5.0
    """
    try:
        members = _parse_dictionary(data.decode("ascii"))
    except (UnicodeDecodeError, _ParseError):
        return PriorityValue()

    urgency = members.get("u")
    if not isinstance(urgency, int) or isinstance(urgency, bool) or not MIN_URGENCY <= urgency <= MAX_URGENCY:
        urgency = DEFAULT_URGENCY

    incremental = members.get("i")
    if not isinstance(incremental, bool):
        incremental = False

    unknown_parameters = {key: value for key, value in members.items() if key not in ("u", "i")}
    return PriorityValue(
        urgency=urgency,
        incremental=incremental,
        unknown_parameters=unknown_parameters,
    )


def serialize_priority_field_value(urgency: int | None, incremental: bool | None) -> bytes:
    """
    Serialize an urgency and incremental flag into an RFC 8941 Structured
    Fields Dictionary, suitable for use as a Priority Field Value.
    Parameters that are None (or, for incremental, false) are omitted,
    which causes the recipient to apply the RFC 9218 defaults for them.

    .. versionadded:: 4.5.0
    """
    members = []
    if urgency is not None:
        members.append(f"u={urgency}")
    if incremental:
        members.append("i=?1")
    return ", ".join(members).encode("ascii")
