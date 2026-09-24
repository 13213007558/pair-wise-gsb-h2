"""
h2/altsvc
~~~~~~~~~

A structured, parse-only view of the RFC 7838 Alternative Service field
value.

This module turns the raw ALTSVC field value carried by
h2.events.AlternativeServiceAvailable into directly inspectable objects:
the advertised protocol (ALPN), target host and port, ma (max-age),
persist, and any unknown extension parameters.

The parser follows the grammar from RFC 7838 Section 3:

    Alt-Svc       = clear / 1#alt-value
    clear         = %s"clear"             ; case-sensitive
    alt-value     = alternative *( OWS ";" OWS parameter )
    alternative   = protocol-id "=" alt-authority
    protocol-id   = token                 ; percent-encoding allowed
    alt-authority = quoted-string         ; containing [ uri-host ] ":" port
    parameter     = token "=" ( token / quoted-string )

Parsing is strictly local: it never resolves DNS names and never opens
connections. Malformed input does not raise: problems are collected as
AltSvcParseError diagnostics, and individually broken alternatives are
dropped without discarding the valid remainder of the field value.
"""
from __future__ import annotations

from dataclasses import dataclass, field

#: Characters allowed in a RFC 7230 token, which covers protocol-ids and
#: parameter names. % is included, which is what allows percent-encoding
#: inside protocol-ids.
_TOKEN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "!#$%&'*+-.^_`|~",
)

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

#: Optional whitespace around list and parameter separators.
_OWS = " \t"

_MAX_PORT = 65535


@dataclass(frozen=True)
class AltSvcParseError:
    """
    A single diagnostic produced while parsing an ALTSVC field value.

    Parsing never raises: every problem found in the field value is
    reported as one of these objects, and parsing of the remaining
    alternatives continues wherever possible.
    """

    #: A human-readable description of the problem.
    message: str

    #: The offset in the field value at which the problem was detected,
    #: if a specific location could be determined.
    position: int | None = None

    #: The offending fragment of the field value, if any.
    snippet: str = ""

    def __str__(self) -> str:
        location = (
            f" at position {self.position}"
            if self.position is not None
            else ""
        )
        fragment = f": {self.snippet!r}" if self.snippet else ""
        return f"{self.message}{location}{fragment}"


@dataclass(frozen=True)
class AlternativeService:
    """
    A single parsed alternative service advertisement.

    .. versionadded:: 4.5.0
    """

    #: The advertised protocol identifier (the ALPN token), with any
    #: percent-encoding decoded: for example h2 or h3.
    protocol: str

    #: The advertised target host. None means the field value named an
    #: empty host, which per RFC 7838 refers to the host of the origin
    #: the advertisement applies to. It is deliberately *not* resolved
    #: to localhost or any other concrete name.
    host: str | None

    #: The advertised target port.
    port: int

    #: All parameters attached to this alternative, including unknown
    #: extension parameters, keyed by parameter name. Values are the
    #: raw parameter values with any quoting removed.
    parameters: dict[str, str] = field(default_factory=dict)

    @property
    def max_age(self) -> int | None:
        """
        The ma (max-age) parameter as an integer, or None if the
        parameter is absent or was not a valid number.
        """
        raw = self.parameters.get("ma")
        if raw is None or not raw.isdigit():
            return None
        return int(raw)

    @property
    def persist(self) -> bool | None:
        """
        The persist parameter as a boolean, or None if the parameter is
        absent. Only the value 1 is defined by RFC 7838; anything else
        is reported as False here and as a parse diagnostic.
        """
        raw = self.parameters.get("persist")
        if raw is None:
            return None
        return raw == "1"


@dataclass(frozen=True)
class AltSvcFieldValue:
    """
    The structured result of parsing an ALTSVC field value.

    .. versionadded:: 4.5.0
    """

    #: True if the field value was exactly "clear", instructing the
    #: client to forget all alternatives for the origin.
    clear: bool = False

    #: The successfully parsed alternative service advertisements, in
    #: the order they appeared in the field value.
    alternatives: tuple[AlternativeService, ...] = ()

    #: Diagnostics for everything in the field value that did not
    #: conform to the RFC 7838 grammar. Empty when the field value
    #: parsed cleanly.
    errors: tuple[AltSvcParseError, ...] = ()


def parse_alt_svc_field_value(value: bytes | str | None) -> AltSvcFieldValue:
    """
    Parse an RFC 7838 Alternative Service field value into an
    AltSvcFieldValue.

    This function never raises and never performs I/O: malformed input
    is reported through AltSvcFieldValue.errors.
    """
    errors: list[AltSvcParseError] = []

    if value is None:
        errors.append(AltSvcParseError("missing ALTSVC field value"))
        return AltSvcFieldValue(errors=tuple(errors))

    if isinstance(value, bytes):
        try:
            text = value.decode("ascii")
        except UnicodeDecodeError:
            errors.append(
                AltSvcParseError(
                    "field value is not pure ASCII; "
                    "non-ASCII bytes were replaced",
                ),
            )
            text = value.decode("ascii", "replace")
    else:
        text = value

    stripped = text.strip(_OWS)
    if not stripped:
        errors.append(AltSvcParseError("empty ALTSVC field value", position=0))
        return AltSvcFieldValue(errors=tuple(errors))

    # "clear" is case-sensitive and must be the entire field value.
    if stripped == "clear":
        return AltSvcFieldValue(clear=True, errors=tuple(errors))

    alternatives: list[AlternativeService] = []
    for raw_segment, offset in _split_top_level(text, ",", errors):
        leading_ws = len(raw_segment) - len(raw_segment.lstrip(_OWS))
        segment = raw_segment.strip(_OWS)
        if not segment:
            errors.append(
                AltSvcParseError(
                    "empty alternative in list",
                    position=offset + leading_ws,
                ),
            )
            continue
        alternative = _parse_alt_value(segment, offset + leading_ws, errors)
        if alternative is not None:
            alternatives.append(alternative)

    return AltSvcFieldValue(
        alternatives=tuple(alternatives), errors=tuple(errors),
    )


def _split_top_level(
    text: str, delimiter: str, errors: list[AltSvcParseError],
) -> list[tuple[str, int]]:
    """
    Split text on delimiter characters that appear outside of
    quoted-strings, honouring backslash escapes. Returns each segment
    along with its offset in the original text.
    """
    parts: list[tuple[str, int]] = []
    start = 0
    in_quote = False
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
        elif in_quote:
            if char == "\\":
                escaped = True
            elif char == '"':
                in_quote = False
        elif char == '"':
            in_quote = True
        elif char == delimiter:
            parts.append((text[start:index], start))
            start = index + 1
    if in_quote:
        errors.append(
            AltSvcParseError(
                "unterminated quoted-string",
                position=start,
                snippet=text[start:],
            ),
        )
    parts.append((text[start:], start))
    return parts


def _parse_alt_value(
    segment: str, offset: int, errors: list[AltSvcParseError],
) -> AlternativeService | None:
    """
    Parse a single alt-value element. Returns None (after recording
    diagnostics) if the alternative is unusable.
    """
    eq_index = segment.find("=")
    if eq_index == -1:
        errors.append(
            AltSvcParseError(
                "alternative is missing '=' separator",
                position=offset,
                snippet=segment,
            ),
        )
        return None

    protocol = _parse_protocol_id(
        segment[:eq_index].strip(_OWS), offset, errors,
    )
    if protocol is None:
        return None

    remainder = segment[eq_index + 1:]
    parts = _split_top_level(remainder, ";", errors)

    authority_text, authority_offset = parts[0]
    authority_leading = len(authority_text) - len(authority_text.lstrip(_OWS))
    authority_text = authority_text.strip(_OWS)
    authority_offset += authority_leading
    authority = _parse_quoted_string(authority_text, authority_offset, errors)
    if authority is None:
        return None

    host_port = _parse_alt_authority(authority, authority_offset, errors)
    if host_port is None:
        return None
    host, port = host_port

    parameters = _parse_parameters(parts[1:], errors)
    if parameters is None:
        return None

    return AlternativeService(
        protocol=protocol, host=host, port=port, parameters=parameters,
    )


def _parse_protocol_id(
    token: str, offset: int, errors: list[AltSvcParseError],
) -> str | None:
    """
    Validate a protocol-id token and decode any percent-encoding it
    carries.
    """
    if not token:
        errors.append(AltSvcParseError("empty protocol-id", position=offset))
        return None

    for index, char in enumerate(token):
        if char not in _TOKEN_CHARS:
            errors.append(
                AltSvcParseError(
                    f"invalid character {char!r} in protocol-id",
                    position=offset + index,
                    snippet=token,
                ),
            )
            return None

    decoded: list[str] = []
    index = 0
    valid = True
    while index < len(token):
        char = token[index]
        if char == "%":
            hex_digits = token[index + 1:index + 3]
            if len(hex_digits) != 2 or any(
                digit not in _HEX_DIGITS for digit in hex_digits
            ):
                errors.append(
                    AltSvcParseError(
                        "invalid percent-encoding in protocol-id",
                        position=offset + index,
                        snippet=token[index:index + 3],
                    ),
                )
                valid = False
                decoded.append(char)
                index += 1
                continue
            decoded.append(chr(int(hex_digits, 16)))
            index += 3
        else:
            decoded.append(char)
            index += 1

    if not valid:
        return None
    return "".join(decoded)


def _parse_quoted_string(
    text: str, offset: int, errors: list[AltSvcParseError],
) -> str | None:
    """
    Parse a quoted-string, resolving quoted-pair escapes. The text must
    consist of exactly one quoted-string.
    """
    if len(text) < 2 or not text.startswith('"'):
        errors.append(
            AltSvcParseError(
                "expected a quoted-string",
                position=offset,
                snippet=text,
            ),
        )
        return None

    chars: list[str] = []
    index = 1
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 1
            if index >= len(text):
                errors.append(
                    AltSvcParseError(
                        "backslash escape at end of quoted-string",
                        position=offset + index - 1,
                        snippet=text,
                    ),
                )
                return None
            chars.append(text[index])
        elif char == '"':
            trailing = text[index + 1:].strip(_OWS)
            if trailing:
                errors.append(
                    AltSvcParseError(
                        "unexpected data after closing quote",
                        position=offset + index + 1,
                        snippet=trailing,
                    ),
                )
                return None
            return "".join(chars)
        else:
            chars.append(char)
        index += 1

    errors.append(
        AltSvcParseError(
            "unterminated quoted-string", position=offset, snippet=text,
        ),
    )
    return None


def _parse_alt_authority(
    authority: str, offset: int, errors: list[AltSvcParseError],
) -> tuple[str | None, int] | None:
    """
    Split the content of an alt-authority quoted-string into host and
    port. An empty host maps to None: the host of the origin is implied.
    """
    if authority.startswith("["):
        # An IPv6 (or future IP literal) address in brackets.
        closing = authority.find("]")
        if closing == -1:
            errors.append(
                AltSvcParseError(
                    "unterminated IP literal in alt-authority",
                    position=offset,
                    snippet=authority,
                ),
            )
            return None
        host: str | None = authority[1:closing]
        remainder = authority[closing + 1:]
        if not remainder.startswith(":"):
            errors.append(
                AltSvcParseError(
                    "missing port in alt-authority",
                    position=offset,
                    snippet=authority,
                ),
            )
            return None
        port_text = remainder[1:]
    else:
        host, separator, port_text = authority.rpartition(":")
        if not separator:
            errors.append(
                AltSvcParseError(
                    "missing port in alt-authority",
                    position=offset,
                    snippet=authority,
                ),
            )
            return None
        if not host:
            # An empty host refers to the host of the origin: represent
            # it as None rather than guessing a concrete name.
            host = None

    if not port_text or not port_text.isdigit():
        errors.append(
            AltSvcParseError(
                f"invalid port {port_text!r} in alt-authority",
                position=offset,
                snippet=authority,
            ),
        )
        return None

    port = int(port_text)
    if port > _MAX_PORT:
        errors.append(
            AltSvcParseError(
                f"port {port} out of range (0-{_MAX_PORT})",
                position=offset,
                snippet=authority,
            ),
        )
        return None

    return host, port


def _parse_parameters(
    parts: list[tuple[str, int]],
    errors: list[AltSvcParseError],
) -> dict[str, str] | None:
    """
    Parse the ;-separated parameters of one alternative. Unknown
    extension parameters are preserved verbatim. Returns None if any
    parameter is malformed beyond recovery.
    """
    parameters: dict[str, str] = {}
    seen_names: set[str] = set()

    for raw_part, raw_offset in parts:
        leading_ws = len(raw_part) - len(raw_part.lstrip(_OWS))
        part = raw_part.strip(_OWS)
        part_offset = raw_offset + leading_ws
        if not part:
            errors.append(
                AltSvcParseError(
                    "empty parameter", position=part_offset, snippet=raw_part,
                ),
            )
            return None

        eq_index = part.find("=")
        if eq_index == -1:
            errors.append(
                AltSvcParseError(
                    "parameter is missing '=' separator",
                    position=part_offset,
                    snippet=part,
                ),
            )
            return None

        name = part[:eq_index].strip(_OWS)
        value_text = part[eq_index + 1:].strip(_OWS)
        value_offset = part_offset + eq_index + 1

        if not name or any(char not in _TOKEN_CHARS for char in name):
            errors.append(
                AltSvcParseError(
                    f"invalid parameter name {name!r}",
                    position=part_offset,
                    snippet=part,
                ),
            )
            return None

        value = _parse_parameter_value(name, value_text, value_offset, errors)
        if value is None:
            return None

        lowered = name.lower()
        if lowered in seen_names:
            errors.append(
                AltSvcParseError(
                    f"duplicate parameter {name!r}; first occurrence wins",
                    position=part_offset,
                    snippet=part,
                ),
            )
            continue
        seen_names.add(lowered)
        parameters[name] = value

    # Validate the parameters RFC 7838 defines, without discarding them.
    ma = parameters.get("ma")
    if ma is not None and not ma.isdigit():
        errors.append(
            AltSvcParseError(
                f"invalid ma (max-age) value {ma!r}: expected digits",
                snippet=f"ma={ma}",
            ),
        )

    persist = parameters.get("persist")
    if persist is not None and persist != "1":
        errors.append(
            AltSvcParseError(
                f"invalid persist value {persist!r}: only '1' is defined",
                snippet=f"persist={persist}",
            ),
        )

    return parameters


def _parse_parameter_value(
    name: str,
    value_text: str,
    value_offset: int,
    errors: list[AltSvcParseError],
) -> str | None:
    """
    Parse a single parameter value, which is either a token or a
    quoted-string.
    """
    if value_text.startswith('"'):
        return _parse_quoted_string(value_text, value_offset, errors)
    if not value_text or any(char not in _TOKEN_CHARS for char in value_text):
        errors.append(
            AltSvcParseError(
                f"invalid value for parameter {name!r}",
                position=value_offset,
                snippet=value_text,
            ),
        )
        return None
    return value_text
