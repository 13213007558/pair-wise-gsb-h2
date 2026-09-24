"""
Tests that a locally-rejected send_headers call is atomic: a call that fails
before emitting any bytes must not consume a stream ID, must not add entries
to the HPACK dynamic table, and must not advance the state of an existing
stream.
"""
from __future__ import annotations

import pytest
from hpack import NeverIndexedHeaderTuple

import h2.config
import h2.connection
import h2.events
import h2.exceptions


def _dynamic_entries(conn):
    return list(conn.encoder.header_table.dynamic_entries)


class TestSendHeadersFailureIsAtomic:
    """
    A send_headers call that is rejected for local reasons (invalid priority
    arguments or an invalid header block) leaves no observable state behind.
    """

    example_request_headers = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
        ("user-agent", "someua/0.0.1"),
    ]
    server_config = h2.config.H2Configuration(client_side=False)

    invalid_header_blocks = [
        # Unknown pseudo-header.
        [(":authority", "example.com"), (":path", "/"), (":scheme", "https"),
         (":method", "GET"), (":bogus", "1")],
        # Pseudo-header after a regular header.
        [("user-agent", "someua/0.0.1"), (":authority", "example.com"),
         (":path", "/"), (":scheme", "https"), (":method", "GET")],
        # Missing mandatory pseudo-headers.
        [(":authority", "example.com")],
        # Forbidden TE header value.
        [(":authority", "example.com"), (":path", "/"), (":scheme", "https"),
         (":method", "GET"), ("te", "chunked")],
    ]

    @pytest.mark.parametrize("priority_kwargs", [
        {"priority_depends_on": 1},      # stream may not depend on itself
        {"priority_weight": 0},          # weight out of range
        {"priority_weight": 257},
        {"priority_weight": -15},
    ])
    def test_invalid_priority_leaves_no_state(self, priority_kwargs) -> None:
        """
        A send_headers call with invalid priority arguments is rejected
        without consuming the stream ID or touching the HPACK state, and the
        stream can immediately be retried with valid arguments.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        with pytest.raises(h2.exceptions.ProtocolError):
            c.send_headers(
                1, self.example_request_headers, **priority_kwargs,
            )

        assert 1 not in c.streams
        assert c.highest_outbound_stream_id == 0
        assert c.get_next_available_stream_id() == 1
        assert not _dynamic_entries(c)
        assert not c.data_to_send()

        # The retry is a fresh request, not trailers on a half-open stream.
        c.send_headers(1, self.example_request_headers, end_stream=True)
        self._assert_decodes_as_request(c.data_to_send())

    @pytest.mark.parametrize("headers", invalid_header_blocks)
    def test_invalid_headers_leave_no_state(self, headers) -> None:
        """
        A send_headers call with an invalid header block is rejected without
        consuming the stream ID or adding HPACK dynamic table entries.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        with pytest.raises(h2.exceptions.ProtocolError):
            c.send_headers(1, headers)

        assert 1 not in c.streams
        assert c.highest_outbound_stream_id == 0
        assert c.get_next_available_stream_id() == 1
        assert not _dynamic_entries(c)
        assert not c.data_to_send()

        c.send_headers(1, self.example_request_headers, end_stream=True)
        self._assert_decodes_as_request(c.data_to_send())

    def test_rejected_trailers_do_not_advance_stream_state(self) -> None:
        """
        A rejected trailer block (pseudo-header in trailers) does not advance
        the state of the existing open stream or pollute the dynamic table.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.send_headers(1, self.example_request_headers)
        c.clear_outbound_data_buffer()

        stream_state = c.streams[1].state_machine.state
        dynamic_entries = _dynamic_entries(c)

        trailers = [(":status", "200")]
        with pytest.raises(h2.exceptions.ProtocolError):
            c.send_headers(1, trailers, end_stream=True)

        assert c.streams[1].state_machine.state == stream_state
        assert _dynamic_entries(c) == dynamic_entries
        assert not c.data_to_send()

        # Legal trailers can still be sent afterwards.
        c.send_headers(1, [("x-trailer", "yes")], end_stream=True)
        assert c.data_to_send()

    def test_one_shot_iterable_headers(self) -> None:
        """
        Headers provided as a one-shot iterable work both for the rejected
        call and for the subsequent successful send.
        """
        headers = [
            *self.example_request_headers,
            NeverIndexedHeaderTuple("authorization", "secret"),
        ]

        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        with pytest.raises(h2.exceptions.ProtocolError):
            c.send_headers(1, (h for h in headers), priority_depends_on=1)

        c.send_headers(1, (h for h in headers), end_stream=True)
        received = self._assert_decodes_as_request(c.data_to_send())

        # The sensitive header arrives intact, and its never-index marker
        # kept it out of the encoder's dynamic table.
        assert (b"authorization", b"secret") in received
        assert all(
            name != b"authorization" for name, _ in _dynamic_entries(c)
        )

    def test_server_priority_rejection_leaves_no_state(self, frame_factory) -> None:
        """
        A server calling send_headers with priority arguments is rejected
        before any state is changed.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.receive_data(
            frame_factory.build_headers_frame(
                self.example_request_headers,
            ).serialize(),
        )
        c.clear_outbound_data_buffer()

        response_headers = [
            (":status", "200"),
            ("server", "pytest-h2"),
        ]
        with pytest.raises(h2.exceptions.RFC1122Error):
            c.send_headers(
                1, response_headers, priority_weight=16,
            )

        assert not c.streams[1].state_machine.headers_sent
        assert not _dynamic_entries(c)
        assert not c.data_to_send()

        c.send_headers(1, response_headers)
        assert c.data_to_send()

    def _assert_decodes_as_request(self, data):
        """
        Feed the outbound data of a client connection into an independent
        server-side connection and return the decoded request headers.
        """
        server = h2.connection.H2Connection(config=self.server_config)
        server.initiate_connection()
        events = server.receive_data(
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + data,
        )

        request_received = [
            e for e in events if isinstance(e, h2.events.RequestReceived)
        ]
        assert len(request_received) == 1
        assert request_received[0].stream_id == 1
        return request_received[0].headers
