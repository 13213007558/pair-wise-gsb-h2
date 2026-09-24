"""
Parsing helpers for RFC 7838 Alternative Service field values.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Final


_DEFAULT_MAX_AGE: Final = 24 * 60 * 60

_TCHAR = frozenset(
    b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
)
_PROTOCOL_ID_CHAR = frozenset(
    b"-._~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
)
_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")


@dataclass(frozen=True, kw_only=True)
class AlternativeService:
    """A single candidate parsed from an RFC 7838 Alternative Service field."""

    alpn: bytes
    host: bytes | None
    port: int | None
    max_age: int | None
    persist: bool
    unknown_parameters: dict[bytes, bytes | None]
    raw: bytes
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        """Whether this candidate follows the RFC 7838 field grammar."""
        return not self.errors

    @property
    def protocol_id(self) -> bytes:
        """The percent-decoded ALPN protocol identifier."""
        return self.alpn


@dataclass(frozen=True, kw_only=True)
class ParsedAlternativeServices:
    """The structured contents of an RFC 7838 Alternative Service field."""

    clear: bool
    alternatives: list[AlternativeService]
    errors: list[str] = field(default_factory=list)

    @property
    def alternative_services(self) -> list[AlternativeService]:
        """Alias for :attr:`alternatives`."""
        return self.alternatives


def parse_alternative_services(field_value: bytes, origin: bytes | None = None) -> ParsedAlternativeServices:
    """Parse an RFC 7838 Alternative Service field value without doing I/O."""
    value = bytes(field_value)
    source_host, source_port = _parse_origin(origin) if origin is not None else (None, None)
    segments, segment_errors = _split_top_level(value, ord(","))
    errors = list(segment_errors)
    alternatives: list[AlternativeService] = []
    clear_segments: list[int] = []
    malformed_clear = False

    for index, segment in enumerate(segments, start=1):
        candidate = segment.strip()
        if not candidate:
            errors.append(f"alternative {index}: empty alternative service advertisement")
            continue

        if candidate.lower() == b"clear":
            clear_segments.append(index)
            continue

        alternative, candidate_errors, inherit_port = _parse_alternative(segment, candidate, index)
        if alternative.host is None and source_host is not None:
            alternative = replace(alternative, host=source_host)
        if inherit_port:
            alternative = replace(alternative, port=source_port)
        alternatives.append(alternative)
        errors.extend(candidate_errors)
        if alternative.alpn.lower() == b"clear":
            malformed_clear = True

    if clear_segments:
        if len(clear_segments) == 1 and len(segments) == 1:
            return ParsedAlternativeServices(clear=True, alternatives=[], errors=[])
        errors.append(
            "'clear' cannot be combined with other alternative service advertisements "
            f"or parameters (found at alternative(s): {', '.join(map(str, clear_segments))})",
        )
    elif malformed_clear:
        pass

    return ParsedAlternativeServices(clear=False, alternatives=alternatives, errors=errors)


def parse_alternative_service_field(field_value: bytes) -> ParsedAlternativeServices:
    """Compatibility-oriented alias for :func:`parse_alternative_services`."""
    return parse_alternative_services(field_value)


def _parse_alternative(
    raw: bytes,
    segment: bytes,
    index: int,
) -> tuple[AlternativeService, list[str], bool]:
    errors: list[str] = []

    parts, part_errors = _split_top_level(segment, ord(";"))
    errors.extend(part_errors)
    binding = parts[0].strip() if parts else b""
    alpn, host, port, inherit_port, binding_errors = _parse_binding(binding, index)
    errors.extend(binding_errors)
    parameters = _AlternativeParameters()
    for parameter_part in parts[1:]:
        parameter = parameter_part.strip()
        if not parameter:
            errors.append(f"alternative {index}: empty parameter")
            continue

        name, value_text, parameter_errors = _split_parameter(parameter, index)
        errors.extend(parameter_errors)
        if not name:
            continue

        errors.extend(_validate_token(name, index, "parameter name"))
        value, value_errors = _parse_parameter_value(value_text, name, index)
        errors.extend(value_errors)
        errors.extend(parameters.apply(name, value, index))

    return (
        AlternativeService(
            alpn=alpn,
            host=host,
            port=port,
            max_age=parameters.max_age,
            persist=parameters.persist,
            unknown_parameters=parameters.unknown,
            raw=raw,
            errors=errors,
        ),
        errors,
        inherit_port,
    )


class _AlternativeParameters:
    def __init__(self) -> None:
        self.seen_known: set[bytes] = set()
        self.max_age: int | None = _DEFAULT_MAX_AGE
        self.persist = False
        self.unknown: dict[bytes, bytes | None] = {}

    def apply(self, name: bytes, value: bytes | None, index: int) -> list[str]:
        normalized_name = name.lower()
        if normalized_name == b"ma":
            return self._set_max_age(value, index)
        if normalized_name == b"persist":
            return self._set_persist(value, index)
        if normalized_name in self.unknown:
            return [f"alternative {index}: duplicate parameter {name!r}"]
        self.unknown[normalized_name] = value
        return []

    def _set_max_age(self, value: bytes | None, index: int) -> list[str]:
        if b"ma" in self.seen_known:
            return [f"alternative {index}: duplicate parameter 'ma'"]
        self.seen_known.add(b"ma")
        self.max_age, errors = _parse_non_negative_integer(value, index, "ma")
        return errors

    def _set_persist(self, value: bytes | None, index: int) -> list[str]:
        if b"persist" in self.seen_known:
            return [f"alternative {index}: duplicate parameter 'persist'"]
        self.seen_known.add(b"persist")
        if value == b"1":
            self.persist = True
            return []
        return [f"alternative {index}: invalid value for parameter 'persist': {value!r}"]


def _parse_binding(binding: bytes, index: int) -> tuple[bytes, bytes | None, int | None, bool, list[str]]:
    if not binding:
        return (
            b"",
            None,
            None,
            False,
            [
                f"alternative {index}: missing protocol-id and alternative authority",
            ],
        )

    equals_at = binding.find(b"=")
    errors: list[str] = []
    if equals_at < 0:
        errors = [f"alternative {index}: missing alternative authority"]
        if binding.lower() == b"clear":
            errors.append(f"alternative {index}: malformed 'clear' directive")
        return b"", None, None, False, errors

    protocol = binding[:equals_at]
    authority_value = binding[equals_at + 1 :]
    alpn, protocol_errors = _percent_decode_protocol(protocol, index)
    errors.extend(protocol_errors)
    if alpn.lower() == b"clear":
        errors.append(f"alternative {index}: malformed 'clear' directive")

    if not authority_value.startswith(b'"'):
        errors.append(f"alternative {index}: alternative authority must be a quoted-string")
        return alpn, None, None, False, errors

    authority, authority_errors = _parse_quoted_string(
        authority_value,
        index,
        "alternative authority",
    )
    errors.extend(authority_errors)
    if authority is None:
        return alpn, None, None, False, errors

    host, port, inherit_port, host_errors = _parse_authority(authority, index)
    errors.extend(host_errors)
    return alpn, host, port, inherit_port, errors


def _parse_parameter_value(
    value_text: bytes | None,
    name: bytes,
    index: int,
) -> tuple[bytes | None, list[str]]:
    if value_text is None:
        return None, [f"alternative {index}: missing value for parameter {name!r}"]
    return _parse_quoted_or_token_value(value_text, index, f"parameter {name!r}")


def _split_parameter(parameter: bytes, index: int) -> tuple[bytes, bytes | None, list[str]]:
    equals_at = parameter.find(b"=")
    if equals_at < 0:
        return parameter, None, [f"alternative {index}: missing '=' in parameter {parameter!r}"]
    return parameter[:equals_at], parameter[equals_at + 1 :], []


def _percent_decode_protocol(value: bytes, index: int) -> tuple[bytes, list[str]]:
    errors = _validate_protocol_token(value, index)
    output = bytearray()
    i = 0
    while i < len(value):
        byte = value[i]
        if byte != 0x25:
            output.append(byte)
            i += 1
            continue

        if i + 2 >= len(value) or value[i + 1] not in _HEX_DIGITS or value[i + 2] not in _HEX_DIGITS:
            errors.append(f"alternative {index}: invalid percent encoding in protocol-id at offset {i}")
            output.append(byte)
            i += 1
            continue

        output.append(int(value[i + 1 : i + 3], 16))
        i += 3

    return bytes(output), errors


def _validate_protocol_token(value: bytes, index: int) -> list[str]:
    if not value:
        return [f"alternative {index}: empty protocol-id"]

    for offset, byte in enumerate(value):
        if byte in _PROTOCOL_ID_CHAR or byte == 0x25:
            continue
        return [f"alternative {index}: invalid byte {byte:#04x} in protocol-id at offset {offset}"]
    return []


def _validate_token(value: bytes, index: int, description: str) -> list[str]:
    if not value:
        return [f"alternative {index}: empty {description}"]
    for offset, byte in enumerate(value):
        if byte not in _TCHAR:
            return [f"alternative {index}: invalid byte {byte:#04x} in {description} at offset {offset}"]
    return []


def _parse_quoted_or_token_value(value: bytes, index: int, description: str) -> tuple[bytes | None, list[str]]:
    if not value:
        return None, [f"alternative {index}: empty {description}"]
    if value[0] == 0x22:
        return _parse_quoted_string(value, index, description)

    errors = []
    for offset, byte in enumerate(value):
        if byte not in _TCHAR:
            errors.append(
                f"alternative {index}: {description} must be a quoted-string; invalid byte {byte:#04x} at offset {offset}",
            )
            return value, errors
    return value, errors


def _parse_quoted_string(value: bytes, index: int, description: str) -> tuple[bytes | None, list[str]]:
    output = bytearray()
    i = 1
    while i < len(value):
        byte = value[i]
        if byte == 0x22:
            if i + 1 != len(value):
                return None, [
                    f"alternative {index}: invalid trailing data after quoted-string in {description} at offset {i + 1}",
                ]
            return bytes(output), []
        if byte == 0x5C:
            if i + 1 >= len(value):
                return None, [f"alternative {index}: unterminated escape in quoted-string in {description}"]
            escaped = value[i + 1]
            if escaped != 0x09 and not (0x20 <= escaped <= 0x7E) and escaped < 0x80:
                return None, [
                    f"alternative {index}: invalid escaped byte {escaped:#04x} in quoted-string in {description} at offset {i + 1}",
                ]
            output.append(escaped)
            i += 2
            continue
        if byte == 0x7F or (byte < 0x20 and byte != 0x09):
            return None, [
                f"alternative {index}: invalid control byte {byte:#04x} in quoted-string in {description} at offset {i}",
            ]
        output.append(byte)
        i += 1

    return None, [f"alternative {index}: unterminated quoted-string in {description}"]


def _parse_authority(
    authority: bytes,
    index: int,
) -> tuple[bytes | None, int | None, bool, list[str]]:
    if not authority:
        return None, None, True, []

    if b"@" in authority:
        return _authority_error(index, f"userinfo is not allowed in alternative authority {authority!r}")

    if authority.startswith(b"["):
        return _parse_ip_literal_authority(authority, index)

    if authority.count(b":") > 1:
        return _authority_error(index, f"IPv6 authority must use brackets: {authority!r}")

    host_text, separator, port_text = authority.partition(b":")
    if not separator:
        return host_text, None, True, []
    host: bytes | None = host_text or None

    port, errors = _parse_port(port_text, index)
    return host, port, False, errors


def _authority_error(
    index: int,
    message: str,
) -> tuple[bytes | None, int | None, bool, list[str]]:
    return None, None, False, [f"alternative {index}: {message}"]


def _parse_ip_literal_authority(
    authority: bytes,
    index: int,
) -> tuple[bytes | None, int | None, bool, list[str]]:
    closing = authority.find(b"]")
    if closing < 0:
        return _authority_error(index, f"missing closing bracket in IPv6 authority {authority!r}")

    host = authority[1:closing]
    remainder = authority[closing + 1 :]
    if not host:
        return _authority_error(index, f"empty IP literal in alternative authority {authority!r}")
    if not remainder:
        return host, None, True, []
    if not remainder.startswith(b":") or remainder.count(b":") != 1:
        return _authority_error(index, f"invalid authority after IP literal {authority!r}")

    port, errors = _parse_port(remainder[1:], index)
    return host, port, False, errors


def _parse_port(value: bytes, index: int) -> tuple[int | None, list[str]]:
    if not value or not value.isdigit():
        return None, [f"alternative {index}: invalid port {value!r}"]
    port = int(value)
    if port > 65535:
        return None, [f"alternative {index}: port {port} is outside the range 0-65535"]
    return port, []


def _parse_non_negative_integer(value: bytes | None, index: int, name: str) -> tuple[int | None, list[str]]:
    if value is None or not value.isdigit():
        return None, [f"alternative {index}: invalid value for parameter '{name}': {value!r}"]
    return int(value), []


def _parse_origin(origin: bytes) -> tuple[bytes | None, int | None]:
    value = bytes(origin)
    scheme_end = value.find(b"://")
    if scheme_end >= 0:
        value = value[scheme_end + 3 :]

    authority = value
    for delimiter in (b"/", b"?", b"#"):
        delimiter_at = authority.find(delimiter)
        if delimiter_at >= 0:
            authority = authority[:delimiter_at]

    if b"@" in authority:
        authority = authority.rsplit(b"@", 1)[1]

    if not authority:
        return None, None
    host, port, _, _ = _parse_authority(authority, 0)
    return host, port


def _split_top_level(value: bytes, delimiter: int) -> tuple[list[bytes], list[str]]:
    segments: list[bytes] = []
    errors: list[str] = []
    start = 0
    quoted = False
    i = 0

    while i < len(value):
        byte = value[i]
        if quoted:
            if byte == 0x5C:
                if i + 1 >= len(value):
                    errors.append(f"unterminated escape in quoted-string at offset {i}")
                    i = len(value)
                    break
                i += 2
                continue
            if byte == 0x22:
                quoted = False
        elif byte == 0x22:
            quoted = True
        elif byte == delimiter:
            segments.append(value[start:i])
            start = i + 1
        i += 1

    segments.append(value[start:])
    if quoted:
        errors.append("unterminated quoted-string")
    return segments, errors
