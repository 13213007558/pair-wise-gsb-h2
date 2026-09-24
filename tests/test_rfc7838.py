"""
Test the RFC 7838 ALTSVC support.
"""
from __future__ import annotations

import pytest

import h2.altsvc
import h2.config
import h2.connection
import h2.events
import h2.exceptions


class TestRFC7838Client:
    """
    Tests that the client supports receiving the RFC 7838 AltSvc frame.
    """

    example_request_headers = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]
    example_request_headers_bytes = [
        (b":authority", b"example.com"),
        (b":path", b"/"),
        (b":scheme", b"https"),
        (b":method", b"GET"),
    ]
    example_response_headers = [
        (":status", "200"),
        ("server", "fake-serv/0.1.0"),
    ]

    def test_receiving_altsvc_stream_zero(self, frame_factory) -> None:
        """
        An ALTSVC frame received on stream zero correctly transposes all the
        fields from the frames.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_alt_svc_frame(
            stream_id=0, origin=b"example.com", field=b'h2=":8000"; ma=60',
        )
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        event = events[0]

        assert isinstance(event, h2.events.AlternativeServiceAvailable)
        assert event.origin == b"example.com"
        assert event.field_value == b'h2=":8000"; ma=60'

        # No data gets sent.
        assert not c.data_to_send()

    def test_receiving_altsvc_stream_zero_no_origin(self, frame_factory) -> None:
        """
        An ALTSVC frame received on stream zero without an origin field is
        ignored.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_alt_svc_frame(
            stream_id=0, origin=b"", field=b'h2=":8000"; ma=60',
        )
        events = c.receive_data(f.serialize())

        assert not events
        assert not c.data_to_send()

    @pytest.mark.parametrize("request_headers", [example_request_headers, example_request_headers_bytes])
    def test_receiving_altsvc_on_stream(self, frame_factory, request_headers) -> None:
        """
        An ALTSVC frame received on a stream correctly transposes all the
        fields from the frame and attaches the expected origin.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.send_headers(stream_id=1, headers=request_headers)
        c.clear_outbound_data_buffer()

        f = frame_factory.build_alt_svc_frame(
            stream_id=1, origin=b"", field=b'h2=":8000"; ma=60',
        )
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        event = events[0]

        assert isinstance(event, h2.events.AlternativeServiceAvailable)
        assert event.origin == b"example.com"
        assert event.field_value == b'h2=":8000"; ma=60'

        # No data gets sent.
        assert not c.data_to_send()

    @pytest.mark.parametrize("request_headers", [example_request_headers, example_request_headers_bytes])
    def test_receiving_altsvc_on_stream_with_origin(self, frame_factory, request_headers) -> None:
        """
        An ALTSVC frame received on a stream with an origin field present gets
        ignored.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.send_headers(stream_id=1, headers=request_headers)
        c.clear_outbound_data_buffer()

        f = frame_factory.build_alt_svc_frame(
            stream_id=1, origin=b"example.com", field=b'h2=":8000"; ma=60',
        )
        events = c.receive_data(f.serialize())

        assert len(events) == 0
        assert not c.data_to_send()

    def test_receiving_altsvc_on_stream_not_yet_opened(self, frame_factory) -> None:
        """
        When an ALTSVC frame is received on a stream the client hasn't yet
        opened, the frame is ignored.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        # We'll test this twice, once on a client-initiated stream ID and once
        # on a server initiated one.
        f1 = frame_factory.build_alt_svc_frame(
            stream_id=1, origin=b"", field=b'h2=":8000"; ma=60',
        )
        f2 = frame_factory.build_alt_svc_frame(
            stream_id=2, origin=b"", field=b'h2=":8000"; ma=60',
        )
        events = c.receive_data(f1.serialize() + f2.serialize())

        assert len(events) == 0
        assert not c.data_to_send()

    def test_receiving_altsvc_before_sending_headers(self, frame_factory) -> None:
        """
        When an ALTSVC frame is received but the client hasn't sent headers yet
        it gets ignored.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()

        # We need to create the idle stream. We have to do it by calling
        # a private API. While this can't naturally happen in hyper-h2 (we
        # don't currently have a mechanism by which this could occur), it could
        # happen in the future and we defend against it.
        c._begin_new_stream(
            stream_id=1, allowed_ids=h2.connection.AllowedStreamIDs.ODD,
        )
        c.clear_outbound_data_buffer()

        f = frame_factory.build_alt_svc_frame(
            stream_id=1, origin=b"", field=b'h2=":8000"; ma=60',
        )
        events = c.receive_data(f.serialize())

        assert len(events) == 0
        assert not c.data_to_send()

    @pytest.mark.parametrize("request_headers", [example_request_headers, example_request_headers_bytes])
    def test_receiving_altsvc_after_receiving_headers(self, frame_factory, request_headers) -> None:
        """
        When an ALTSVC frame is received but the server has already sent
        headers it gets ignored.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.send_headers(stream_id=1, headers=request_headers)

        f = frame_factory.build_headers_frame(
            headers=self.example_response_headers,
        )
        c.receive_data(f.serialize())
        c.clear_outbound_data_buffer()

        f = frame_factory.build_alt_svc_frame(
            stream_id=1, origin=b"", field=b'h2=":8000"; ma=60',
        )
        events = c.receive_data(f.serialize())

        assert len(events) == 0
        assert not c.data_to_send()

    @pytest.mark.parametrize("request_headers", [example_request_headers, example_request_headers_bytes])
    def test_receiving_altsvc_on_closed_stream(self, frame_factory, request_headers) -> None:
        """
        When an ALTSVC frame is received on a closed stream, we ignore it.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.send_headers(
            stream_id=1, headers=request_headers, end_stream=True,
        )

        f = frame_factory.build_headers_frame(
            headers=self.example_response_headers,
            flags=["END_STREAM"],
        )
        c.receive_data(f.serialize())
        c.clear_outbound_data_buffer()

        f = frame_factory.build_alt_svc_frame(
            stream_id=1, origin=b"", field=b'h2=":8000"; ma=60',
        )
        events = c.receive_data(f.serialize())

        assert len(events) == 0
        assert not c.data_to_send()

    @pytest.mark.parametrize("request_headers", [example_request_headers, example_request_headers_bytes])
    def test_receiving_altsvc_on_pushed_stream(self, frame_factory, request_headers) -> None:
        """
        When an ALTSVC frame is received on a stream that the server pushed,
        the frame is accepted.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.send_headers(stream_id=1, headers=request_headers)

        f = frame_factory.build_push_promise_frame(
            stream_id=1,
            promised_stream_id=2,
            headers=request_headers,
        )
        c.receive_data(f.serialize())
        c.clear_outbound_data_buffer()

        f = frame_factory.build_alt_svc_frame(
            stream_id=2, origin=b"", field=b'h2=":8000"; ma=60',
        )
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        event = events[0]

        assert isinstance(event, h2.events.AlternativeServiceAvailable)
        assert event.origin == b"example.com"
        assert event.field_value == b'h2=":8000"; ma=60'

        # No data gets sent.
        assert not c.data_to_send()

    @pytest.mark.parametrize("request_headers", [example_request_headers, example_request_headers_bytes])
    def test_cannot_send_explicit_alternative_service(self, frame_factory, request_headers) -> None:
        """
        A client cannot send an explicit alternative service.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.send_headers(stream_id=1, headers=request_headers)
        c.clear_outbound_data_buffer()

        with pytest.raises(h2.exceptions.ProtocolError):
            c.advertise_alternative_service(
                field_value=b'h2=":8000"; ma=60',
                origin=b"example.com",
            )

    @pytest.mark.parametrize("request_headers", [example_request_headers, example_request_headers_bytes])
    def test_cannot_send_implicit_alternative_service(self, frame_factory, request_headers) -> None:
        """
        A client cannot send an implicit alternative service.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.send_headers(stream_id=1, headers=request_headers)
        c.clear_outbound_data_buffer()

        with pytest.raises(h2.exceptions.ProtocolError):
            c.advertise_alternative_service(
                field_value=b'h2=":8000"; ma=60',
                stream_id=1,
            )


class TestRFC7838Server:
    """
    Tests that the server supports sending the RFC 7838 AltSvc frame.
    """

    example_request_headers = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]
    example_request_headers_bytes = [
        (b":authority", b"example.com"),
        (b":path", b"/"),
        (b":scheme", b"https"),
        (b":method", b"GET"),
    ]
    example_response_headers = [
        (":status", "200"),
        ("server", "fake-serv/0.1.0"),
    ]

    server_config = h2.config.H2Configuration(client_side=False)

    def test_receiving_altsvc_as_server_stream_zero(self, frame_factory) -> None:
        """
        When an ALTSVC frame is received on stream zero and we are a server,
        we ignore it.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()

        f = frame_factory.build_alt_svc_frame(
            stream_id=0, origin=b"example.com", field=b'h2=":8000"; ma=60',
        )
        events = c.receive_data(f.serialize())

        assert len(events) == 0
        assert not c.data_to_send()

    @pytest.mark.parametrize("request_headers", [example_request_headers, example_request_headers_bytes])
    def test_receiving_altsvc_as_server_on_stream(self, frame_factory, request_headers) -> None:
        """
        When an ALTSVC frame is received on a stream and we are a server, we
        ignore it.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())

        f = frame_factory.build_headers_frame(
            headers=request_headers,
        )
        c.receive_data(f.serialize())
        c.clear_outbound_data_buffer()

        f = frame_factory.build_alt_svc_frame(
            stream_id=1, origin=b"", field=b'h2=":8000"; ma=60',
        )
        events = c.receive_data(f.serialize())

        assert len(events) == 0
        assert not c.data_to_send()

    def test_sending_explicit_alternative_service(self, frame_factory) -> None:
        """
        A server can send an explicit alternative service.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()

        c.advertise_alternative_service(
            field_value=b'h2=":8000"; ma=60',
            origin=b"example.com",
        )

        f = frame_factory.build_alt_svc_frame(
            stream_id=0, origin=b"example.com", field=b'h2=":8000"; ma=60',
        )
        assert c.data_to_send() == f.serialize()

    @pytest.mark.parametrize("request_headers", [example_request_headers, example_request_headers_bytes])
    def test_sending_implicit_alternative_service(self, frame_factory, request_headers) -> None:
        """
        A server can send an implicit alternative service.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())

        f = frame_factory.build_headers_frame(
            headers=request_headers,
        )
        c.receive_data(f.serialize())
        c.clear_outbound_data_buffer()

        c.advertise_alternative_service(
            field_value=b'h2=":8000"; ma=60',
            stream_id=1,
        )

        f = frame_factory.build_alt_svc_frame(
            stream_id=1, origin=b"", field=b'h2=":8000"; ma=60',
        )
        assert c.data_to_send() == f.serialize()

    def test_no_implicit_alternative_service_before_headers(self,
                                                            frame_factory) -> None:
        """
        If headers haven't been received yet, the server forbids sending an
        implicit alternative service.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()

        with pytest.raises(h2.exceptions.ProtocolError):
            c.advertise_alternative_service(
                field_value=b'h2=":8000"; ma=60',
                stream_id=1,
            )

    @pytest.mark.parametrize("request_headers", [example_request_headers, example_request_headers_bytes])
    def test_no_implicit_alternative_service_after_response(self,
                                                            frame_factory,
                                                            request_headers) -> None:
        """
        If the server has sent response headers, hyper-h2 forbids sending an
        implicit alternative service.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())

        f = frame_factory.build_headers_frame(
            headers=request_headers,
        )
        c.receive_data(f.serialize())
        c.send_headers(stream_id=1, headers=self.example_response_headers)
        c.clear_outbound_data_buffer()

        with pytest.raises(h2.exceptions.ProtocolError):
            c.advertise_alternative_service(
                field_value=b'h2=":8000"; ma=60',
                stream_id=1,
            )

    @pytest.mark.parametrize("request_headers", [example_request_headers, example_request_headers_bytes])
    def test_cannot_provide_origin_and_stream_id(self, frame_factory, request_headers) -> None:
        """
        The user cannot provide both the origin and stream_id arguments when
        advertising alternative services.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        f = frame_factory.build_headers_frame(
            headers=request_headers,
        )
        c.receive_data(f.serialize())

        with pytest.raises(ValueError):
            c.advertise_alternative_service(
                field_value=b'h2=":8000"; ma=60',
                origin=b"example.com",
                stream_id=1,
            )

    def test_cannot_provide_unicode_altsvc_field(self, frame_factory) -> None:
        """
        The user cannot provide the field value for alternative services as a
        unicode string.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())

        with pytest.raises(ValueError):
            c.advertise_alternative_service(
                field_value='h2=":8000"; ma=60',
                origin=b"example.com",
            )
class TestAltSvcFieldValueParsing:
    """
    Tests for the structured, parse-only view of the ALTSVC field value
    exposed via AlternativeServiceAvailable.parsed and h2.altsvc.
    """

    example_request_headers = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]

    def test_stream_zero_event_exposes_parsed_view(self, frame_factory) -> None:
        """
        A connection-level ALTSVC frame produces an event whose parsed view
        matches the raw field value, which is preserved unmodified.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        f = frame_factory.build_alt_svc_frame(
            stream_id=0,
            origin=b"example.com",
            field=b'h2=":8000"; ma=60; persist=1',
        )
        (event,) = c.receive_data(f.serialize())

        assert isinstance(event, h2.events.AlternativeServiceAvailable)
        assert event.origin == b"example.com"
        assert event.field_value == b'h2=":8000"; ma=60; persist=1'

        parsed = event.parsed
        assert not parsed.clear
        assert parsed.errors == ()
        assert len(parsed.alternatives) == 1

        alternative = parsed.alternatives[0]
        assert alternative.protocol == "h2"
        # An empty host means "the origin's host": it must not be turned
        # into localhost or any other concrete name.
        assert alternative.host is None
        assert alternative.port == 8000
        assert alternative.max_age == 60
        assert alternative.persist is True

    def test_stream_event_exposes_parsed_view(self, frame_factory) -> None:
        """
        A stream-level ALTSVC frame gets its origin from the stream's
        :authority and still exposes the structured view.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.send_headers(stream_id=1, headers=self.example_request_headers)
        c.clear_outbound_data_buffer()

        f = frame_factory.build_alt_svc_frame(
            stream_id=1, origin=b"", field=b'h3="alt.example.com:443"; ma=3600',
        )
        (event,) = c.receive_data(f.serialize())

        assert event.origin == b"example.com"
        assert event.field_value == b'h3="alt.example.com:443"; ma=3600'

        parsed = event.parsed
        assert parsed.errors == ()
        (alternative,) = parsed.alternatives
        assert alternative.protocol == "h3"
        assert alternative.host == "alt.example.com"
        assert alternative.port == 443
        assert alternative.max_age == 3600
        assert alternative.persist is None

    def test_clear_field_value(self) -> None:
        """
        The field value "clear" empties the alternative list for the origin.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(b"clear")

        assert parsed.clear
        assert parsed.alternatives == ()
        assert parsed.errors == ()

    def test_clear_is_case_sensitive(self) -> None:
        """
        RFC 7838 defines "clear" as case-sensitive: "CLEAR" is not clear and
        fails to parse as an alternative.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(b"CLEAR")

        assert not parsed.clear
        assert parsed.alternatives == ()
        assert len(parsed.errors) == 1

    def test_clear_cannot_be_combined_with_alternatives(self) -> None:
        """
        "clear" must be the entire field value: combining it with
        alternatives is a grammar error.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(b'clear, h2=":443"')

        assert not parsed.clear
        assert len(parsed.alternatives) == 1
        assert any("missing '='" in e.message for e in parsed.errors)

    def test_ipv6_alt_authority(self) -> None:
        """
        IPv6 literals in brackets are recognised as hosts.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(b'h2="[2001:db8::1]:8443"')

        assert parsed.errors == ()
        (alternative,) = parsed.alternatives
        assert alternative.host == "2001:db8::1"
        assert alternative.port == 8443

    def test_unterminated_ipv6_literal(self) -> None:
        """
        A missing closing bracket on an IP literal is a specific diagnostic.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(b'h2="[::1:443"')

        assert parsed.alternatives == ()
        assert any("IP literal" in e.message for e in parsed.errors)

    def test_percent_encoded_protocol_id(self) -> None:
        """
        Percent-encoding in the protocol-id is decoded.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(b'h3%2D1=":443"')

        assert parsed.errors == ()
        (alternative,) = parsed.alternatives
        assert alternative.protocol == "h3-1"

    def test_invalid_percent_encoding_in_protocol_id(self) -> None:
        """
        Bad percent-encoding in the protocol-id is a specific diagnostic and
        drops that alternative.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(b'h2%zz=":443"')

        assert parsed.alternatives == ()
        assert any("percent-encoding" in e.message for e in parsed.errors)

    def test_unknown_parameters_are_preserved(self) -> None:
        """
        Unknown extension parameters are kept verbatim alongside the known
        ones.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(
            b'h2=":443"; ma=60; x-unknown="some value"; other=token',
        )

        assert parsed.errors == ()
        (alternative,) = parsed.alternatives
        assert alternative.parameters == {
            "ma": "60",
            "x-unknown": "some value",
            "other": "token",
        }
        assert alternative.max_age == 60

    def test_comma_inside_quoted_string_does_not_split(self) -> None:
        """
        Commas inside quoted-strings must not split the alternative list.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(
            b'h2="a.example:443"; note="x,y", h3="b.example:8443"',
        )

        assert parsed.errors == ()
        assert len(parsed.alternatives) == 2
        assert parsed.alternatives[0].parameters["note"] == "x,y"
        assert parsed.alternatives[1].protocol == "h3"

    def test_quoted_string_escapes(self) -> None:
        """
        Quoted-pair escapes inside quoted-strings are resolved.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(
            b'h2=":443"; note="say \\"hi\\""',
        )

        assert parsed.errors == ()
        (alternative,) = parsed.alternatives
        assert alternative.parameters["note"] == 'say "hi"'

    def test_unterminated_quoted_string(self) -> None:
        """
        An unterminated quoted-string is diagnosed, not silently split.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(b'h2=":443; ma=60')

        assert parsed.alternatives == ()
        assert any("unterminated quoted-string" in e.message
                   for e in parsed.errors)

    def test_duplicate_parameters_are_diagnosed(self) -> None:
        """
        A repeated parameter name is a diagnostic; the first value wins.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(
            b'h2=":443"; ma=60; ma=30',
        )

        (alternative,) = parsed.alternatives
        assert alternative.max_age == 60
        assert any("duplicate parameter" in e.message
                   for e in parsed.errors)

    @pytest.mark.parametrize("field_value", [
        b'h2=":abc"',         # non-numeric port
        b'h2=":"',            # empty port
        b'h2=":70000"',       # out of range
        b'h2="example.com"',  # missing port entirely
    ])
    def test_invalid_ports_are_diagnosed(self, field_value) -> None:
        """
        Bad ports produce specific diagnostics and drop the alternative.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(field_value)

        assert parsed.alternatives == ()
        assert len(parsed.errors) == 1

    def test_partially_invalid_field_value(self) -> None:
        """
        A broken alternative does not discard the valid ones around it.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(
            b'h2=":not-a-port", h3=":443", h2=":99999"',
        )

        assert len(parsed.alternatives) == 1
        assert parsed.alternatives[0].protocol == "h3"
        assert len(parsed.errors) == 2

    def test_invalid_ma_and_persist_are_diagnosed(self) -> None:
        """
        Invalid values for the defined parameters are diagnosed but the
        alternative itself survives.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(
            b'h2=":443"; ma=soon; persist=2',
        )

        (alternative,) = parsed.alternatives
        assert alternative.max_age is None
        assert alternative.persist is False
        assert any("ma" in e.message for e in parsed.errors)
        assert any("persist" in e.message for e in parsed.errors)

    def test_empty_alternative_in_list(self) -> None:
        """
        Empty list entries (consecutive commas) are diagnosed and skipped.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(
            b'h2=":443", , h3=":80"',
        )

        assert len(parsed.alternatives) == 2
        assert any("empty alternative" in e.message
                   for e in parsed.errors)

    def test_empty_field_value(self) -> None:
        """
        An empty field value is a diagnostic, not a crash.
        """
        parsed = h2.altsvc.parse_alt_svc_field_value(b"")

        assert not parsed.clear
        assert parsed.alternatives == ()
        assert len(parsed.errors) == 1
