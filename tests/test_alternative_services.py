"""
Tests for RFC 7838 Alternative Service field parsing.
"""

from __future__ import annotations

from h2.alternative_services import parse_alternative_services


def test_parses_ipv6_known_and_unknown_parameters() -> None:
    """Parse IPv6, known parameters, escapes, and normalized unknown keys."""
    parsed = parse_alternative_services(
        b'h3="[2001:db8::1]:443"; ma=7200; persist=1; FOO="a,b;\\";c"',
        b"https://example.com:8443",
    )

    assert parsed.clear is False
    assert parsed.errors == []
    assert len(parsed.alternatives) == 1
    alternative = parsed.alternatives[0]

    assert alternative.valid is True
    assert alternative.alpn == b"h3"
    assert alternative.host == b"2001:db8::1"
    assert alternative.port == 443
    assert alternative.max_age == 7200
    assert alternative.persist is True
    assert alternative.unknown_parameters == {b"foo": b'a,b;";c'}


def test_empty_host_inherits_origin_host_and_port() -> None:
    """Use the origin host when the advertised authority host is empty."""
    parsed = parse_alternative_services(
        b'h2%2F3=":8000"',
        b"https://example.com:8443",
    )

    alternative = parsed.alternatives[0]
    assert alternative.alpn == b"h2/3"
    assert alternative.host == b"example.com"
    assert alternative.port == 8000


def test_empty_host_without_port_inherits_source_host_and_port() -> None:
    """Use both origin host and port for an empty quoted authority."""
    parsed = parse_alternative_services(b'h2=""', b"example.com:8443")

    alternative = parsed.alternatives[0]
    assert alternative.host == b"example.com"
    assert alternative.port == 8443


def test_clear_directive_has_no_alternatives() -> None:
    """Represent standalone clear as a directive rather than a candidate."""
    parsed = parse_alternative_services(b"clear", b"https://example.com")

    assert parsed.clear is True
    assert parsed.alternatives == []
    assert parsed.errors == []
    assert parsed.alternative_services == []


def test_multiple_alternatives_keep_quotes_in_effect_and_partial_errors() -> None:
    """Preserve valid candidates while recording candidate-specific errors."""
    parsed = parse_alternative_services(
        b'h2="[::1]:99999"; ma=bad; persist=1, h3=":8000"; ma=60; x="a,b"',
        b"example.com",
    )

    invalid, valid = parsed.alternatives
    assert invalid.alpn == b"h2"
    assert invalid.host == b"::1"
    assert invalid.port is None
    assert invalid.max_age is None
    assert invalid.persist is True
    assert "port 99999 is outside the range 0-65535" in invalid.errors[0]
    assert "invalid value for parameter 'ma'" in invalid.errors[1]

    assert valid.alpn == b"h3"
    assert valid.host == b"example.com"
    assert valid.port == 8000
    assert valid.max_age == 60
    assert valid.unknown_parameters == {b"x": b"a,b"}
    assert valid.errors == []
    assert parsed.errors == invalid.errors


def test_duplicate_and_unknown_parameters_get_specific_diagnostics() -> None:
    """Report duplicate known and unknown extension parameters."""
    parsed = parse_alternative_services(
        b'h2=":443"; ma=60; MA=61; foo=1; FOO=2',
        b"example.com",
    )

    alternative = parsed.alternatives[0]
    assert alternative.max_age == 60
    assert alternative.unknown_parameters == {b"foo": b"1"}
    assert any("duplicate parameter 'ma'" in error for error in alternative.errors)
    assert any("duplicate parameter b'FOO'" in error for error in alternative.errors)


def test_invalid_port_and_bare_ipv6_are_diagnosed() -> None:
    """Diagnose invalid numeric ports and unbracketed IPv6 literals."""
    parsed = parse_alternative_services(b'h2="example:notaport"', b"example.com")
    assert parsed.alternatives[0].errors == [
        "alternative 1: invalid port b'notaport'",
    ]

    parsed = parse_alternative_services(b'h2="2001:db8::1"', b"example.com")
    assert parsed.alternatives[0].errors == [
        "alternative 1: IPv6 authority must use brackets: b'2001:db8::1'",
    ]


def test_invalid_explicit_port_does_not_inherit_source_port() -> None:
    """Keep an invalid explicit port absent instead of substituting origin."""
    parsed = parse_alternative_services(b'h2="example:65536"', b"example.com:8443")

    alternative = parsed.alternatives[0]
    assert alternative.host == b"example"
    assert alternative.port is None
    assert alternative.errors == [
        "alternative 1: port 65536 is outside the range 0-65535",
    ]


def test_escaped_quote_does_not_terminate_quoted_string() -> None:
    """Honor quoted-pair escapes while finding field and parameter delimiters."""
    parsed = parse_alternative_services(
        b'h2="x:443"; ext="a\\"b,c;d"',
        b"example.com",
    )

    assert len(parsed.alternatives) == 1
    assert parsed.alternatives[0].unknown_parameters == {b"ext": b'a"b,c;d'}


def test_quoted_comma_does_not_split_alternative() -> None:
    """Keep commas and semicolons inside quoted strings as value data."""
    parsed = parse_alternative_services(b'h2="x:443"; extension="a,b,c;x"', b"example.com")

    assert len(parsed.alternatives) == 1
    assert parsed.alternatives[0].unknown_parameters == {
        b"extension": b"a,b,c;x",
    }


def test_clear_cannot_be_combined_with_another_advertisement() -> None:
    """Reject clear when it shares a field with another advertisement."""
    parsed = parse_alternative_services(b'clear, h2=":443"', b"example.com")

    assert parsed.clear is False
    assert len(parsed.alternatives) == 1
    assert any("'clear' cannot be combined" in error for error in parsed.errors)
