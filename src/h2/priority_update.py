"""
h2/priority_update
~~~~~~~~~~~~~~~~~

Support for the extensible HTTP/2 prioritisation scheme defined in
`RFC 9218 <https://www.rfc-editor.org/rfc/rfc9218>`_: Extensible
Prioritization Scheme for HTTP.

This module provides the :class:`PriorityUpdateFrame`, plus parsing and
serialization helpers for the ``Priority Field Value`` carried in the
``PRIORITY_UPDATE`` frame (and in the ``PRIORITY`` HTTP field).

h2 only conveys priority *intent* to the application: it deliberately does
not implement a scheduler and never converts the new priorities into RFC
7540 dependency tree state.
"""
from __future__ import annotations

import base64
import binascii
import struct
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from hyperframe.exceptions import InvalidDataError
from hyperframe.frame import Frame
from hyperframe.flags import Flag

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Mapping

#: The HTTP/2 frame type code for ``PRIORITY_UPDATE`` (RFC 9218 section 4.2).
PRIORITY_UPDATE_FRAME_TYPE = 0x10

#: The SETTINGS_NO_RFC7540_PRIORITIES setting identifier
#: (RFC 9218 section 4.2).
SETTINGS_NO_RFC7540_PRIORITIES = 0x09

#: Default urgency of a stream when none is given (RFC 9218 section 4.1).
DEFAULT_URGENCY = 3

#: Default incremental value when none is given (RFC 9218 section 4.1).
DEFAULT_INCREMENTAL = False


class PriorityFieldError(ValueError):
    """
    Raised when a ``Priority Field Value`` cannot be parsed as the subset of
    Structured Fields (RFC 8941) required by RFC 9218.
    """


class Token:
    """
    Represents an RFC 8941 Structured Fields token.

    Tokens are preserved verbatim when found in unrecognised Priority Field
    Value members or parameters.
    """

    __slots__ = ("value",)

    def __init__(self, value: str) -> None:
        self.value = value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Token):
            return NotImplemented
        return self.value == other.value

    def __hash__(self) -> int:
        return hash((Token, self.value))

    def __repr__(self) -> str:
        return f"Token({self.value!r})"


class DisplayString:
    """Represents an RFC 9711 Structured Fields display string."""

    __slots__ = ("value",)

    def __init__(self, value: str) -> None:
        self.value = value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DisplayString):
            return NotImplemented
        return self.value == other.value

    def __hash__(self) -> int:
        return hash((DisplayString, self.value))

    def __repr__(self) -> str:
        return f"DisplayString({self.value!r})"


@dataclass(frozen=True)
class StructuredFieldItem:
    """
    An RFC 8941 bare item together with its parameters.

    :param value: The bare item value: ``int``, ``float``, ``str``, bytes,
        :class:`Token`, :class:`DisplayString`, :data:`True`,
        :data:`False` or ``None`` (the RFC 9689 "null" extension type).
    :param parameters: The item parameters, in transmission order, mapping
        parameter keys to their :class:`StructuredFieldItem` values.
    """

    value: object
    parameters: Mapping[str, StructuredFieldItem] = field(
        default_factory=OrderedDict,
    )


@dataclass(frozen=True)
class ParsedPriorityFieldValue:
    """
    The parsed contents of a Priority Field Value (RFC 9218 section 4.1).

    :param urgency: The stream's urgency, normalised to an integer between
        ``0`` and ``7`` (an invalid or missing value falls back to the default
        of ``3``).
    :param incremental: Whether the stream prefers incremental delivery,
        normalised to a boolean (an invalid or missing value falls back to
        the default of ``False``).
    :param unknown_parameters: Any dictionary members other than
        ``urgency`` and ``incremental``, preserved in transmission order so
        that applications can inspect members defined by later extensions.
    """

    urgency: int = DEFAULT_URGENCY
    incremental: bool = DEFAULT_INCREMENTAL
    unknown_parameters: Mapping[str, StructuredFieldItem] = field(
        default_factory=OrderedDict,
    )


class PriorityUpdateFrame(Frame):
    """
    The ``PRIORITY_UPDATE`` frame defined by RFC 9218 section 4.2.

    The frame is a connection-level frame: its stream identifier in the
    frame header is always ``0x0``. Its body contains the 4-byte
    prioritized stream ID followed by the Priority Field Value.
    """

    defined_flags: list[Flag] = []

    type = PRIORITY_UPDATE_FRAME_TYPE

    stream_association = "no-stream"

    def __init__(self, stream_id: int = 0) -> None:
        super().__init__(stream_id)
        #: The ID of the stream whose priority is being updated.
        self.prioritized_stream_id = 0
        #: The raw, unparsed Priority Field Value.
        self.priority_field_value = b""

    def _body_repr(self) -> str:
        return (
            f"prioritized_stream_id={self.prioritized_stream_id}, "
            f"priority_field_value={self.priority_field_value!r}"
        )

    def serialize_body(self) -> bytes:
        return (
            struct.pack("!I", self.prioritized_stream_id & 0x7FFFFFFF)
            + self.priority_field_value
        )

    def parse_body(self, data: memoryview) -> None:
        if len(data) < 4:
            msg = (
                "PRIORITY_UPDATE frame body must be at least 4 octets: "
                f"actual length {len(data)}"
            )
            raise InvalidDataError(msg)
        raw_stream_id = struct.unpack("!I", data[:4])[0]
        # The R bit is ignored per RFC 9218 section 4.2.
        self.prioritized_stream_id = raw_stream_id & 0x7FFFFFFF
        self.body_len = len(data)
        self.priority_field_value = bytes(data[4:])


def serialize_priority_field_value(urgency: int, incremental: bool) -> bytes:
    """
    Serialize an RFC 9218 ``Priority Field Value`` containing the two members
    defined by RFC 9218 section 4.1 (``urgency`` is sent as ``u`` and
    ``incremental`` as ``i``).

    :param urgency: The stream urgency, an integer between ``0`` and ``7``.
    :param incremental: Whether the stream prefers incremental delivery.
    :raises ValueError: If ``urgency`` is not an integer in ``range(8)`` or
        ``incremental`` is not a boolean.
    """
    if isinstance(urgency, bool) or not isinstance(urgency, int):
        msg = f"Urgency must be an integer between 0 and 7, not {urgency!r}"
        raise ValueError(msg)
    if not 0 <= urgency <= 7:
        msg = f"Urgency must be an integer between 0 and 7, not {urgency!r}"
        raise ValueError(msg)
    if not isinstance(incremental, bool):
        msg = f"Incremental must be a boolean, not {incremental!r}"
        raise ValueError(msg)
    field_value = f"u={urgency}"
    if incremental:
        field_value += ", i"
    return field_value.encode("ascii")


# Byte values used by the RFC 8941 grammar.
_TAB = 0x09
_SP = 0x20
_STAR = 0x2A
_COLON = 0x3A
_SEMI = 0x3B
_LT = 0x3C
_EQ = 0x3D
_GT = 0x3E
_QUESTION = 0x3F
_AT = 0x40
_PERCENT = 0x25
_QUOTE = 0x22
_LPAREN = 0x28
_RPAREN = 0x29
_COMMA = 0x2C
_DASH = 0x2D
_DOT = 0x2E
_ZERO = 0x30
_NINE = 0x39
_ONE = 0x31
_BACKSLASH = 0x5C
_LOWER_A = 0x61
_LOWER_Z = 0x7A
_UPPER_A = 0x41
_UPPER_Z = 0x5A
_UNDERSCORE = 0x5F

_DIGIT = frozenset(range(_ZERO, _NINE + 1))
_ALPHA = frozenset(
    range(_LOWER_A, _LOWER_Z + 1),
).union(range(_UPPER_A, _UPPER_Z + 1))
_TOKEN_START = _ALPHA | {_STAR}
_TOKEN_CHARS = (
    _ALPHA
    | _DIGIT
    | {_STAR, _DASH, _DOT, _UNDERSCORE, _COLON, _PERCENT, _LT, _GT, _QUESTION}
)
_SF_KEY_START = _ALPHA | {_STAR}
_KEY_CHARS = _ALPHA | _DIGIT | {_UNDERSCORE, _DASH, _DOT, _STAR}
_BINARY_CHARS = _ALPHA | _DIGIT | {0x2B, 0x2F, _EQ}
_OWS = {_SP, _TAB}


class _StructuredFieldParser:
    """
    Recursive-descent parser for the Structured Fields grammar (RFC 8941),
    restricted to what a Priority Field Value (RFC 9218) may contain but
    preserving every legal bare-item and parameter type.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._index = 0

    def parse(self) -> StructuredFieldItem | OrderedDict[str, StructuredFieldItem]:
        """Parse an sf-integer or an sf-dictionary."""
        self._consume_ows()
        if self._at_end():
            self._error("empty Priority Field Value")
        first = self._data[self._index]
        if first in _SF_KEY_START:
            parsed: StructuredFieldItem | OrderedDict[str, StructuredFieldItem] = (
                self._parse_dictionary()
            )
        else:
            parsed = self._parse_integer_shorthand()
        self._consume_ows()
        if not self._at_end():
            self._error("trailing data after Priority Field Value")
        return parsed

    def _parse_integer_shorthand(self) -> StructuredFieldItem:
        item = self._parse_item()
        if isinstance(item.value, bool) or not isinstance(item.value, int):
            self._error(
                "top-level Priority Field Value must be an integer or a dictionary",
            )
        return item

    def _parse_dictionary(self) -> OrderedDict[str, StructuredFieldItem]:
        members: OrderedDict[str, StructuredFieldItem] = OrderedDict()
        while True:
            self._consume_ows()
            key = self._parse_key()
            if key in members:
                self._error(f"duplicate dictionary member {key!r}")
            if self._peek() == _EQ:
                self._index += 1
                members[key] = self._parse_member_value()
            else:
                members[key] = StructuredFieldItem(True)
            self._consume_ows()
            if self._at_end():
                return members
            if self._peek() != _COMMA:
                self._error("expected ',' between dictionary members")
            self._index += 1

    def _parse_member_value(self) -> StructuredFieldItem:
        if self._peek() == _LPAREN:
            return self._parse_inner_list()
        return self._parse_item()

    def _parse_parameter_value(self) -> StructuredFieldItem:
        if self._peek() == _QUESTION:
            return StructuredFieldItem(self._parse_boolean())
        return StructuredFieldItem(self._parse_bare_item())

    def _parse_inner_list(self) -> StructuredFieldItem:
        self._index += 1  # consume '('
        items: list[StructuredFieldItem] = []
        while True:
            self._consume_sp()
            if self._peek() == _RPAREN:
                self._index += 1
                return StructuredFieldItem(
                    items, self._parse_parameters(),
                )
            items.append(self._parse_item())
            if self._peek() == _SP:
                continue
            if self._peek() != _RPAREN:
                self._error("expected SP or ')' inside inner list")

    def _parse_item(self) -> StructuredFieldItem:
        value = self._parse_bare_item()
        return StructuredFieldItem(value, self._parse_parameters())

    def _parse_bare_item(self) -> object:
        byte = self._peek()
        if byte in _DIGIT or byte == _DASH:
            return self._parse_number()
        if byte == _QUOTE:
            return self._parse_string()
        if byte in _TOKEN_START:
            return self._parse_token()
        if byte == _COLON:
            return self._parse_byte_sequence()
        if byte == _QUESTION:
            return self._parse_boolean()
        if byte == _AT:
            return self._parse_date()
        if byte == _PERCENT:
            return self._parse_display_string()
        self._error("unexpected start of bare item")

    def _parse_number(self) -> int | float:
        sign = 1
        if self._peek() == _DASH:
            sign = -1
            self._index += 1
        digits = self._consume_digits()
        if not digits:
            self._error("number must contain at least one digit")
        if self._peek() == _DOT:
            self._index += 1
            fraction = self._consume_digits()
            if len(digits) > 12 or not 1 <= len(fraction) <= 3:
                self._error("decimal has too many integer or fraction digits")
            return sign * float(f"{digits.decode()}.{fraction.decode()}")
        if len(digits) > 15:
            self._error("integer must have at most 15 digits")
        return sign * int(digits.decode())

    def _parse_boolean(self) -> bool:
        self._index += 1  # consume '?'
        byte = self._read_byte()
        if byte == _ONE:
            return True
        if byte == _ZERO:
            return False
        self._error("boolean must be '?0' or '?1'")

    def _parse_string(self) -> str:
        self._index += 1  # consume opening quote
        output = bytearray()
        while True:
            byte = self._read_byte()
            if byte == _QUOTE:
                return output.decode("ascii")
            if byte == _BACKSLASH:
                escaped = self._read_byte()
                if escaped not in (_QUOTE, _BACKSLASH):
                    self._error("invalid string escape")
                output.append(escaped)
                continue
            if byte < 0x21 or byte > 0x7E:
                self._error("string contains VCHAR/SP range violation")
            output.append(byte)

    def _parse_token(self) -> Token:
        start = self._index
        self._read_byte()
        while self._peek() in _TOKEN_CHARS:
            self._index += 1
        return Token(self._data[start:self._index].decode("ascii"))

    def _parse_byte_sequence(self) -> bytes:
        self._index += 1  # consume opening colon
        start = self._index
        while True:
            byte = self._read_byte()
            if byte == _COLON:
                encoded = self._data[start:self._index - 1]
                try:
                    return base64.b64decode(encoded, validate=True)
                except (binascii.Error, ValueError) as err:
                    self._error(f"invalid byte sequence: {err}")
            if byte not in _BINARY_CHARS:
                self._error("invalid byte in byte sequence")

    def _parse_date(self) -> float:
        self._index += 1  # consume '@'
        return float(self._parse_number())

    def _parse_display_string(self) -> DisplayString:
        self._index += 1  # consume '%'
        if self._read_byte() != _QUOTE:
            self._error('display string must begin with %"')
        output = bytearray()
        while True:
            byte = self._read_byte()
            if byte == _QUOTE:
                try:
                    return DisplayString(output.decode("utf-8"))
                except UnicodeDecodeError as err:
                    self._error(str(err))
            if byte == _PERCENT:
                # RFC 9711 uses RFC 3986 percent-encoding: '%' followed by
                # exactly two hexadecimal digits.
                high = self._read_byte()
                low = self._read_byte()
                try:
                    output.append(int(bytes([high, low]).decode("ascii"), 16))
                except (ValueError, UnicodeDecodeError):
                    self._error("invalid percent-encoding in display string")
                continue
            if byte < 0x20 or byte == 0x7F:
                self._error("display string contains non-printable byte")
            output.append(byte)

    def _parse_parameters(self) -> OrderedDict[str, StructuredFieldItem]:
        parameters: OrderedDict[str, StructuredFieldItem] = OrderedDict()
        while self._peek() == _SEMI:
            self._index += 1
            self._consume_sp()
            key = self._parse_key()
            if key in parameters:
                self._error(f"duplicate parameter {key!r}")
            if self._peek() == _EQ:
                self._index += 1
                parameters[key] = self._parse_parameter_value()
            else:
                parameters[key] = StructuredFieldItem(True)
        return parameters

    def _parse_key(self) -> str:
        start = self._index
        first = self._read_byte()
        if first not in _SF_KEY_START:
            self._error("invalid key start")
        while self._peek() in _KEY_CHARS:
            self._index += 1
        return self._data[start:self._index].decode("ascii")

    def _consume_digits(self) -> bytes:
        start = self._index
        while self._peek() in _DIGIT:
            self._index += 1
        return self._data[start:self._index]

    def _consume_sp(self) -> None:
        while self._peek() == _SP:
            self._index += 1

    def _consume_ows(self) -> None:
        while self._peek() in _OWS:
            self._index += 1

    def _peek(self) -> int | None:
        if self._at_end():
            return None
        return self._data[self._index]

    def _read_byte(self) -> int:
        if self._at_end():
            self._error("unexpected end of Priority Field Value")
        byte = self._data[self._index]
        self._index += 1
        return byte

    def _at_end(self) -> bool:
        return self._index >= len(self._data)

    def _error(self, message: str) -> None:
        raise PriorityFieldError(message)


def parse_priority_field_value(
    data: bytes | str,
) -> ParsedPriorityFieldValue:
    """
    Parse a Priority Field Value as defined by RFC 9218 section 4.1.

    The value is either an sf-integer (shorthand for a dictionary containing
    just ``u``) or an sf-dictionary (RFC 8941). A value that is not
    syntactically valid Structured Fields raises
    :class:`PriorityFieldError`. An invalid ``u`` (``urgency``) or ``i``
    (``incremental``) member is ignored in favour of the RFC 9218 default;
    members that h2 does not understand are returned unchanged in
    :attr:`ParsedPriorityFieldValue.unknown_parameters`.
    """
    if isinstance(data, str):
        raw = data.encode("ascii")
    else:
        raw = bytes(data)

    parsed = _StructuredFieldParser(raw).parse()

    urgency = DEFAULT_URGENCY
    incremental = DEFAULT_INCREMENTAL
    unknown: OrderedDict[str, StructuredFieldItem] = OrderedDict()

    if isinstance(parsed, StructuredFieldItem):
        # parse() only reaches here with a bare-integer shorthand.
        urgency = parsed.value
        # The shorthand has no member name for its parameters, but RFC 8941
        # allows parameters on the integer: surface them as unknown members.
        for key, item in parsed.parameters.items():
            unknown[key] = item
    else:
        for key, item in parsed.items():
            if key == "u":
                urgency = _coerce_urgency(item)
            elif key == "i":
                incremental = _coerce_incremental(item)
            else:
                unknown[key] = item

    if not 0 <= urgency <= 7:
        urgency = DEFAULT_URGENCY

    return ParsedPriorityFieldValue(
        urgency=urgency,
        incremental=incremental,
        unknown_parameters=unknown,
    )


def _coerce_urgency(item: StructuredFieldItem) -> int:
    if isinstance(item.value, bool) or not isinstance(item.value, int):
        return DEFAULT_URGENCY
    return item.value


def _coerce_incremental(item: StructuredFieldItem) -> bool:
    if not isinstance(item.value, bool):
        return DEFAULT_INCREMENTAL
    return item.value
