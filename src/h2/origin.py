"""
h2/origin
~~~~~~~~~

Tools for working with origins, as defined by RFC 6454, in the context of
the RFC 8336 ORIGIN frame.

This module provides parsing, normalization, and serialization of the
"ASCII serialization of an origin" (RFC 6454, Section 6.2) that the ORIGIN
frame carries in its Origin-Entry fields. Normalization lowercases the
scheme and host, converts internationalized domain names to their A-label
(punycode) form, compresses IPv6 literals, and drops ports that are the
default for the scheme.
"""
from __future__ import annotations

import ipaddress
import re
import struct
from dataclasses import dataclass

from .exceptions import ProtocolError

#: The HTTP/2 frame type assigned to the ORIGIN frame by RFC 8336.
ORIGIN_FRAME_TYPE = 0x0C

#: Well-known default ports. Origins that explicitly carry one of these
#: ports for the matching scheme are normalized to the port-less form.
_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
}

_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*\Z")
_LDH_LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\Z")

#: Characters that may never appear in the authority component of an origin.
_FORBIDDEN_AUTHORITY_CHARS = frozenset("/?#@\\")


class OriginParseError(ValueError):
    """
    An origin entry could not be parsed or normalized into a valid
    RFC 6454 origin.
    """


@dataclass(frozen=True)
class Origin:
    """
    A single origin, normalized as required by RFC 6454 and RFC 8336.

    The scheme and host are lowercase; internationalized domain names are
    represented in their A-label (punycode) form and IPv6 literals are
    compressed. The port is None when the origin uses the default port for
    its scheme (or names no port for a scheme without a known default).
    """

    scheme: str
    host: str
    port: int | None

    def __str__(self) -> str:
        host = "[" + self.host + "]" if ":" in self.host else self.host
        port = ":" + str(self.port) if self.port is not None else ""
        return self.scheme + "://" + host + port


@dataclass(frozen=True)
class InvalidOrigin:
    """
    Diagnostic information about an Origin-Entry that did not contain a
    valid origin. RFC 8336 requires such entries to be ignored; they are
    surfaced here so applications can diagnose misbehaving peers.
    """

    #: The raw bytes of the offending Origin-Entry.
    raw: bytes

    #: A human-readable explanation of why the entry was rejected.
    reason: str


def _normalize_host_label(label: str) -> str:
    """
    Normalize a single DNS label to its lowercase A-label form.
    """
    if not label:
        msg = "host contains an empty label"
        raise OriginParseError(msg)
    try:
        ascii_label = label.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as e:
        msg = "host label " + repr(label) + " is not a valid IDNA label"
        raise OriginParseError(msg) from e
    # Unreachable in practice: the IDNA codec rejects overlong labels
    # itself, but guard against codec behavior differences.
    if len(ascii_label) > 63:  # pragma: no cover
        msg = "host label " + repr(ascii_label) + " exceeds 63 octets"
        raise OriginParseError(msg)
    if not _LDH_LABEL_RE.match(ascii_label):
        msg = "host label " + repr(ascii_label) + " contains invalid characters"
        raise OriginParseError(msg)
    return ascii_label


def _normalize_host(host: str) -> str:
    """
    Normalize the host component of an origin.
    """
    if not host:
        msg = "host is empty"
        raise OriginParseError(msg)
    labels = [_normalize_host_label(label) for label in host.lower().split(".")]
    normalized = ".".join(labels)
    if len(normalized) > 253:
        msg = "host name exceeds 253 octets"
        raise OriginParseError(msg)
    return normalized


def _normalize_ipv6_literal(literal: str) -> str:
    """
    Normalize an IPv6 literal (without brackets) to its compressed form.
    """
    if "%" in literal:
        msg = "IPv6 zone identifiers are not allowed in origins"
        raise OriginParseError(msg)
    try:
        address = ipaddress.IPv6Address(literal)
    except ipaddress.AddressValueError as e:
        msg = "invalid IPv6 literal " + repr(literal)
        raise OriginParseError(msg) from e
    return address.compressed


def _normalize_port(port_text: str, scheme: str) -> int | None:
    """
    Normalize the port component of an origin.
    """
    if not port_text or not port_text.isdigit():
        msg = "invalid port " + repr(port_text)
        raise OriginParseError(msg)
    port = int(port_text)
    if port > 65535:
        msg = "port " + str(port) + " out of range"
        raise OriginParseError(msg)
    if _DEFAULT_PORTS.get(scheme) == port:
        return None
    return port


def normalize_origin(text: str) -> Origin:
    """
    Parse and normalize the unicode text serialization of an origin, as
    defined by RFC 6454 Section 6.2. Internationalized domain names may be
    given as U-labels and are normalized to their A-label form.

    :raises OriginParseError: if the text is not a valid origin.
    """
    scheme, separator, authority = text.partition("://")
    if not separator:
        msg = "origin is missing the '://' separator"
        raise OriginParseError(msg)
    if not scheme or not _SCHEME_RE.match(scheme):
        msg = "invalid scheme " + repr(scheme)
        raise OriginParseError(msg)
    scheme = scheme.lower()

    if not authority or any(c in _FORBIDDEN_AUTHORITY_CHARS for c in authority):
        msg = "invalid authority component " + repr(authority)
        raise OriginParseError(msg)

    if authority.startswith("["):
        closing = authority.find("]")
        if closing == -1:
            msg = "unterminated IPv6 literal"
            raise OriginParseError(msg)
        host = _normalize_ipv6_literal(authority[1:closing])
        remainder = authority[closing + 1:]
        if remainder and not remainder.startswith(":"):
            msg = "unexpected data after IPv6 literal: " + repr(remainder)
            raise OriginParseError(msg)
        port_text = remainder[1:]
        has_port = bool(remainder)
    else:
        if authority.count(":") > 1:
            msg = "IPv6 literals in origins must be enclosed in brackets"
            raise OriginParseError(msg)
        host_text, colon, port_text = authority.partition(":")
        host = _normalize_host(host_text)
        has_port = bool(colon)

    port = _normalize_port(port_text, scheme) if has_port else None

    return Origin(scheme=scheme, host=host, port=port)


def parse_origin_entry(data: bytes) -> Origin:
    """
    Parse a single Origin-Entry from an ORIGIN frame. The entry must be the
    ASCII serialization of an origin: entries containing non-ASCII octets
    (such as raw UTF-8 U-labels) are rejected.

    :raises OriginParseError: if the entry is not a valid origin.
    """
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as e:
        msg = "origin entry is not ASCII"
        raise OriginParseError(msg) from e
    return normalize_origin(text)


def parse_origin_frame_body(body: bytes) -> tuple[list[Origin], list[InvalidOrigin]]:
    """
    Parse the payload of an ORIGIN frame into a list of valid, normalized
    origins and a list of diagnostics for invalid entries.

    A frame whose Origin-Entry sequence is structurally malformed (for
    example, an Origin-Len that runs past the end of the frame payload) is
    a connection error of type PROTOCOL_ERROR per RFC 8336, so this
    function raises before returning anything: callers never see a
    partially-parsed frame.

    :raises ProtocolError: if the frame payload is truncated.
    """
    origins: list[Origin] = []
    invalid_origins: list[InvalidOrigin] = []

    offset = 0
    while offset < len(body):
        if len(body) - offset < 2:
            msg = "ORIGIN frame payload truncated in Origin-Len field"
            raise ProtocolError(msg)
        (entry_len,) = struct.unpack_from("!H", body, offset)
        offset += 2
        if len(body) - offset < entry_len:
            msg = "ORIGIN frame payload truncated in Origin-Entry"
            raise ProtocolError(msg)
        entry = bytes(body[offset:offset + entry_len])
        offset += entry_len

        try:
            origins.append(parse_origin_entry(entry))
        except OriginParseError as e:
            invalid_origins.append(InvalidOrigin(raw=entry, reason=str(e)))

    return origins, invalid_origins


def serialize_origin(origin: Origin) -> bytes:
    """
    Serialize a single origin into an Origin-Entry, including the two-octet
    Origin-Len prefix.
    """
    entry = str(origin).encode("ascii")
    return struct.pack("!H", len(entry)) + entry
