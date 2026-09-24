"""
test_data_acknowledgment_tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tests for the optional token-based data acknowledgment mode, using two real
H2Connection objects talking to each other so that the emitted WINDOW_UPDATE
frames and their values can be verified end to end.
"""
from __future__ import annotations

import pytest

import h2.config
import h2.connection
import h2.events
import h2.settings


class TestDataAcknowledgmentTokens:
    """
    Tests of the token-based data acknowledgment mode.
    """

    example_request_headers = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]

    DEFAULT_FLOW_WINDOW = 65535

    def _make_pair(self, tokens=True):
        """
        Create a client and a server H2Connection, perform the connection
        handshake, raise the maximum frame size, and open stream 1.
        """
        client = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True),
        )
        server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(
                client_side=False,
                data_acknowledgment_tokens=tokens,
            ),
        )

        client.initiate_connection()
        server.initiate_connection()
        server.receive_data(client.data_to_send())
        client.receive_data(server.data_to_send())
        server.receive_data(client.data_to_send())

        # Allow DATA frames large enough to empty the flow control window
        # in a single frame.
        server.update_settings(
            {h2.settings.SettingCodes.MAX_FRAME_SIZE: self.DEFAULT_FLOW_WINDOW},
        )
        client.receive_data(server.data_to_send())
        server.receive_data(client.data_to_send())

        client.send_headers(1, self.example_request_headers)
        server.receive_data(client.data_to_send())
        server.clear_outbound_data_buffer()
        return client, server

    def _receive_data(self, client, server, data):
        """
        Send data from the client and return the server's DataReceived event.
        """
        client.send_data(1, data)
        events = server.receive_data(client.data_to_send())
        data_events = [
            e for e in events if isinstance(e, h2.events.DataReceived)
        ]
        assert len(data_events) == 1
        return data_events[0]

    @staticmethod
    def _window_updates(events):
        return [
            (e.stream_id, e.delta)
            for e in events
            if isinstance(e, h2.events.WindowUpdated)
        ]

    def test_partial_consumption_returns_windows_incrementally(self) -> None:
        """
        A token can be advanced in several partial steps: each step hands
        the acknowledged flow-controlled bytes back, and the total returned
        never exceeds the flow-controlled length of the data.
        """
        client, server = self._make_pair()

        event = self._receive_data(
            client, server, b"\x00" * self.DEFAULT_FLOW_WINDOW,
        )
        token = event.data_acknowledgment
        assert token is not None
        assert token.stream_id == 1
        assert token.data_length == self.DEFAULT_FLOW_WINDOW
        assert token.flow_controlled_length == self.DEFAULT_FLOW_WINDOW
        assert token.remaining == self.DEFAULT_FLOW_WINDOW
        assert not token.exhausted

        token.acknowledge(20000)
        assert token.remaining == 45535
        token.acknowledge(20000)
        assert token.remaining == 25535
        token.acknowledge()
        assert token.remaining == 0
        assert token.exhausted

        events = client.receive_data(server.data_to_send())
        assert self._window_updates(events) == [
            (0, 20000), (1, 20000),
            (0, 45535), (1, 45535),
        ]

    def test_padding_returned_when_content_fully_consumed(self,
                                                          frame_factory) -> None:
        """
        The flow-controlled length includes padding, but applications only
        acknowledge payload bytes: when the final payload byte is consumed
        the token hands back the padding as well.
        """
        client, server = self._make_pair()

        # 65400 payload bytes + 1 pad length byte + 134 padding bytes fills
        # the entire flow control window.
        data_frame = frame_factory.build_data_frame(
            b"\x00" * 65400, padding_len=134,
        )
        events = server.receive_data(data_frame.serialize())
        token = events[0].data_acknowledgment
        assert token.data_length == 65400
        assert token.flow_controlled_length == self.DEFAULT_FLOW_WINDOW

        server.acknowledge_data_token(token, 65400)
        assert token.exhausted

        events = client.receive_data(server.data_to_send())
        assert self._window_updates(events) == [
            (0, self.DEFAULT_FLOW_WINDOW), (1, self.DEFAULT_FLOW_WINDOW),
        ]

    def test_zero_length_data_with_padding(self, frame_factory) -> None:
        """
        A zero-length DATA frame with padding produces a token whose entire
        flow-controlled length is padding: acknowledging it (there is no
        payload to consume) returns the padding.
        """
        client, server = self._make_pair()

        # A zero-length DATA frame carrying 255 bytes of padding (the
        # largest possible), followed by an ordinary DATA frame that
        # empties the rest of the flow control window.
        padded_frame = frame_factory.build_data_frame(b"", padding_len=255)
        events = server.receive_data(padded_frame.serialize())
        token = events[0].data_acknowledgment
        assert token.data_length == 0
        assert token.flow_controlled_length == 256

        second_event = self._receive_data(
            client, server, b"\x00" * (self.DEFAULT_FLOW_WINDOW - 256),
        )

        token.acknowledge()
        assert token.exhausted
        # The padding alone is too small to emit a WINDOW_UPDATE for.
        assert not server.data_to_send()

        # Acknowledging the second frame hands back everything, including
        # the padding from the zero-length frame.
        second_event.data_acknowledgment.acknowledge()
        events = client.receive_data(server.data_to_send())
        assert self._window_updates(events) == [
            (0, self.DEFAULT_FLOW_WINDOW), (1, self.DEFAULT_FLOW_WINDOW),
        ]

    def test_reset_midway_returns_connection_window_only(self) -> None:
        """
        If the stream is reset while a token is partially consumed, the
        remaining acknowledgment still returns the connection-level window
        but must not emit a WINDOW_UPDATE for the closed stream.
        """
        client, server = self._make_pair()

        event = self._receive_data(
            client, server, b"\x00" * self.DEFAULT_FLOW_WINDOW,
        )
        token = event.data_acknowledgment

        token.acknowledge(32768)
        events = client.receive_data(server.data_to_send())
        assert self._window_updates(events) == [
            (0, 32768), (1, 32768),
        ]

        client.reset_stream(1)
        events = server.receive_data(client.data_to_send())
        assert any(isinstance(e, h2.events.StreamReset) for e in events)

        token.acknowledge()
        assert token.exhausted

        events = client.receive_data(server.data_to_send())
        assert self._window_updates(events) == [(0, 32767)]

    def test_exhausted_token_rejects_further_acknowledgment(self) -> None:
        """
        A token that has returned its full flow-controlled length cannot be
        acknowledged again, and the rejected attempt changes nothing.
        """
        client, server = self._make_pair()

        event = self._receive_data(client, server, b"some data")
        token = event.data_acknowledgment
        token.acknowledge()
        assert token.exhausted

        window = server.inbound_flow_control_window
        with pytest.raises(ValueError, match="already been fully acknowledged"):
            token.acknowledge()
        with pytest.raises(ValueError, match="already been fully acknowledged"):
            server.acknowledge_data_token(token, 1)

        assert server.inbound_flow_control_window == window
        assert not server.data_to_send()

    def test_acknowledging_more_than_remaining_is_rejected(self) -> None:
        """
        Acknowledging more payload bytes than remain on the token is
        rejected before any window is changed, and the token stays usable.
        """
        client, server = self._make_pair()

        event = self._receive_data(client, server, b"some data")
        token = event.data_acknowledgment
        token.acknowledge(4)

        window = server.inbound_flow_control_window
        with pytest.raises(ValueError, match="only 5 payload bytes remain"):
            token.acknowledge(6)
        with pytest.raises(ValueError, match="Cannot acknowledge negative"):
            token.acknowledge(-1)

        assert server.inbound_flow_control_window == window
        assert token.remaining == 5
        assert not token.exhausted

        token.acknowledge(5)
        assert token.exhausted

    def test_token_from_other_connection_is_rejected(self) -> None:
        """
        A token is bound to the connection that produced it: using it on a
        different connection is rejected before any window is changed.
        """
        client, server = self._make_pair()
        _, other_server = self._make_pair()

        event = self._receive_data(client, server, b"some data")
        token = event.data_acknowledgment

        window = server.inbound_flow_control_window
        other_window = other_server.inbound_flow_control_window
        with pytest.raises(ValueError, match="different connection"):
            other_server.acknowledge_data_token(token)

        assert server.inbound_flow_control_window == window
        assert other_server.inbound_flow_control_window == other_window
        assert token.remaining == len(b"some data")
        assert not server.data_to_send()
        assert not other_server.data_to_send()

    def test_manual_acknowledgment_rejected_in_token_mode(self) -> None:
        """
        With tokens enabled, the old acknowledge_received_data API must not
        be usable for the same data.
        """
        client, server = self._make_pair()

        self._receive_data(client, server, b"some data")
        with pytest.raises(RuntimeError, match="data_acknowledgment_tokens"):
            server.acknowledge_received_data(9, stream_id=1)
        assert not server.data_to_send()

    def test_token_acknowledgment_rejected_in_manual_mode(self) -> None:
        """
        Without tokens enabled, acknowledge_data_token is not available and
        DataReceived events carry no token.
        """
        client, server = self._make_pair(tokens=False)

        event = self._receive_data(client, server, b"some data")
        assert event.data_acknowledgment is None

        # The old API keeps working unchanged.
        server.acknowledge_received_data(
            event.flow_controlled_length, stream_id=1,
        )
