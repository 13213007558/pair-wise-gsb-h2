"""
Tests for the explicit connection draining API.

Draining (a graceful GOAWAY-based shutdown) is distinct from the immediate
``close_connection`` path: new inbound work is refused while the streams that
had already been accepted keep exchanging DATA, trailers and window updates
until they finish.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
import pytest
from hyperframe.frame import (
    DataFrame,
    Frame,
    GoAwayFrame,
    RstStreamFrame,
    WindowUpdateFrame,
)

if TYPE_CHECKING:
    from .helpers import FrameFactory

SERVER_CONFIG = h2.config.H2Configuration(client_side=False)
CLIENT_CONFIG = h2.config.H2Configuration(client_side=True)

REQUEST_HEADERS = [
    (":method", "GET"),
    (":path", "/"),
    (":authority", "example.com"),
    (":scheme", "https"),
]


def parse_frames(data: bytes) -> list[Frame]:
    """Split a serialized HTTP/2 byte string back into individual frames."""
    frames: list[Frame] = []
    while data:
        frame, length = Frame.parse_frame_header(memoryview(data)[:9])
        frame.parse_body(memoryview(data)[9:9 + length])
        frames.append(frame)
        data = data[9 + length:]
    return frames


def make_server(frame_factory: FrameFactory) -> h2.connection.H2Connection:
    """Build a server connection that has completed the initial handshake."""
    server = h2.connection.H2Connection(config=SERVER_CONFIG)
    server.initiate_connection()
    server.receive_data(frame_factory.preamble())
    server.data_to_send()
    return server


def _handshake_pair() -> tuple[h2.connection.H2Connection, h2.connection.H2Connection]:
    server = h2.connection.H2Connection(config=SERVER_CONFIG)
    client = h2.connection.H2Connection(config=CLIENT_CONFIG)
    server.initiate_connection()
    client.initiate_connection()
    client.receive_data(server.data_to_send())
    server.receive_data(client.data_to_send())
    server.data_to_send()
    client.data_to_send()
    return server, client


class TestDrainLifecycle:
    def test_drain_emits_goaway_and_enters_draining(self, frame_factory) -> None:
        server = make_server(frame_factory)
        request = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        server.receive_data(request.serialize())
        server.data_to_send()

        events = server.drain()

        assert events == []
        assert server.state_machine.state is h2.connection.ConnectionState.DRAINING
        assert server.drain_state is h2.connection.DrainState.DRAINING
        assert server.draining is True
        assert server.local_goaway_last_stream_id == 1

        frames = parse_frames(server.data_to_send())
        assert len(frames) == 1
        assert isinstance(frames[0], GoAwayFrame)
        assert frames[0].error_code == h2.errors.ErrorCodes.NO_ERROR
        assert frames[0].last_stream_id == 1

    def test_drain_without_streams_completes_immediately(self, frame_factory) -> None:
        server = make_server(frame_factory)

        events = server.drain()

        assert len(events) == 1
        assert isinstance(events[0], h2.events.DrainCompleted)
        assert events[0].last_stream_id == 0
        assert server.state_machine.state is h2.connection.ConnectionState.CLOSED
        assert server.drain_state is h2.connection.DrainState.DRAINED

    def test_drain_uses_highest_inbound_stream_by_default(self, frame_factory) -> None:
        server = make_server(frame_factory)
        request = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=7)
        server.receive_data(request.serialize())
        server.data_to_send()

        server.drain()

        frames = parse_frames(server.data_to_send())
        assert isinstance(frames[0], GoAwayFrame)
        assert frames[0].last_stream_id == 7
        assert server.local_goaway_last_stream_id == 7

    def test_drain_completes_when_last_accepted_stream_ends(self, frame_factory) -> None:
        server = make_server(frame_factory)
        request = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        server.receive_data(request.serialize())
        server.data_to_send()
        server.drain()
        server.data_to_send()

        # Respond fully, then the client ends its side of the stream.
        server.send_headers(1, [(":status", "200")], end_stream=True)
        server.data_to_send()
        end = DataFrame(1)
        end.flags.add("END_STREAM")

        events = server.receive_data(end.serialize())

        assert isinstance(events[-1], h2.events.DrainCompleted)
        assert events[-1].last_stream_id == 1
        assert server.state_machine.state is h2.connection.ConnectionState.CLOSED
        assert server.drain_state is h2.connection.DrainState.DRAINED

    def test_drain_completion_waits_for_parallel_streams(self, frame_factory) -> None:
        server = make_server(frame_factory)
        for stream_id in (1, 3, 5):
            request = frame_factory.build_headers_frame(
                REQUEST_HEADERS, stream_id=stream_id,
            )
            server.receive_data(request.serialize())
        server.data_to_send()
        server.drain()
        server.data_to_send()

        for stream_id in (1, 3):
            end = DataFrame(stream_id)
            end.flags.add("END_STREAM")
            events = server.receive_data(end.serialize())
            assert not any(
                isinstance(event, h2.events.DrainCompleted) for event in events
            )
            assert server.draining is True
            # The server still has to finish its own side of the stream.
            server.send_headers(stream_id, [(":status", "200")], end_stream=True)
            server.data_to_send()
            assert server.draining is True

        end = DataFrame(5)
        end.flags.add("END_STREAM")
        server.receive_data(end.serialize())
        assert server.draining is True
        server.send_headers(5, [(":status", "200")], end_stream=True)

        assert server.drain_state is h2.connection.DrainState.DRAINED
        assert server.state_machine.state is h2.connection.ConnectionState.CLOSED

    def test_drain_cannot_be_started_after_close(self, frame_factory) -> None:
        server = make_server(frame_factory)
        server.close_connection()

        with pytest.raises(h2.exceptions.ProtocolError):
            server.drain()

    def test_repeated_drain_can_only_tighten(self, frame_factory) -> None:
        server = make_server(frame_factory)
        for stream_id in (1, 9):
            request = frame_factory.build_headers_frame(
                REQUEST_HEADERS, stream_id=stream_id,
            )
            server.receive_data(request.serialize())
        server.data_to_send()

        server.drain(last_stream_id=9)
        server.drain(last_stream_id=5)
        server.drain(last_stream_id=5)

        assert server.local_goaway_last_stream_id == 5
        frames = parse_frames(server.data_to_send())
        assert [frame.last_stream_id for frame in frames] == [9, 5, 5]

        with pytest.raises(h2.exceptions.ProtocolError):
            server.drain(last_stream_id=9)

        assert server.local_goaway_last_stream_id == 5


class TestAcceptedStreamsKeepWorking:
    def _draining_server(
        self, frame_factory: FrameFactory, stream_ids: tuple[int, ...],
    ) -> h2.connection.H2Connection:
        server = make_server(frame_factory)
        for stream_id in stream_ids:
            request = frame_factory.build_headers_frame(
                REQUEST_HEADERS, stream_id=stream_id,
            )
            server.receive_data(request.serialize())
        server.data_to_send()
        server.drain()
        server.data_to_send()
        return server

    def test_data_trailers_and_window_updates_still_processed(self, frame_factory) -> None:
        server = self._draining_server(frame_factory, (1, 3))

        data = DataFrame(1)
        data.data = b"hello"
        trailers = frame_factory.build_headers_frame(
            [("x-trailer", "value")],
            flags=["END_STREAM"],
            stream_id=1,
        )
        window_update = WindowUpdateFrame(3)
        window_update.window_increment = 16

        events = server.receive_data(
            data.serialize() + trailers.serialize() + window_update.serialize(),
        )

        assert [type(event) for event in events] == [
            h2.events.DataReceived,
            h2.events.TrailersReceived,
            h2.events.StreamEnded,
            h2.events.WindowUpdated,
        ]
        assert server.draining is True

    def test_responses_can_still_be_sent(self, frame_factory) -> None:
        server = self._draining_server(frame_factory, (1,))

        server.send_headers(1, [(":status", "200")])
        server.send_data(1, b"body", end_stream=True)

        frames = parse_frames(server.data_to_send())
        assert len(frames) == 2

    def test_half_closed_stream_is_part_of_the_drain(self, frame_factory) -> None:
        server = make_server(frame_factory)
        request = frame_factory.build_headers_frame(
            REQUEST_HEADERS, flags=["END_STREAM"], stream_id=1,
        )
        server.receive_data(request.serialize())
        server.data_to_send()
        server.drain()
        server.data_to_send()
        assert server.draining is True

        completion = server.send_headers(1, [(":status", "204")], end_stream=True)
        assert server.receive_data(b"") == []

        assert server.drain_state is h2.connection.DrainState.DRAINED
        assert completion is None  # send_headers does not surface events


class TestNewWorkIsRefused:
    def test_new_request_is_refused_and_never_delivered(self, frame_factory) -> None:
        server = make_server(frame_factory)
        accepted = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        server.receive_data(accepted.serialize())
        server.data_to_send()
        server.drain()
        server.data_to_send()

        late = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=3)
        events = server.receive_data(late.serialize())

        assert events == []
        assert 3 not in server.streams

        frames = parse_frames(server.data_to_send())
        assert len(frames) == 1
        assert isinstance(frames[0], RstStreamFrame)
        assert frames[0].stream_id == 3
        assert frames[0].error_code == h2.errors.ErrorCodes.REFUSED_STREAM

    def test_request_inside_accepted_range_still_reaches_app(self, frame_factory) -> None:
        server = make_server(frame_factory)
        existing = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        server.receive_data(existing.serialize())
        server.data_to_send()
        server.drain(last_stream_id=5)
        server.data_to_send()

        # Stream 3 is below the advertised limit: it was technically in flight
        # when the GOAWAY was emitted and must still be accepted.
        in_flight = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=3)
        events = server.receive_data(in_flight.serialize())

        assert len(events) == 1
        assert isinstance(events[0], h2.events.RequestReceived)
        assert events[0].stream_id == 3
        assert server.data_to_send() == b""

    def test_data_on_refused_stream_resets_and_keeps_window_accounting(
        self, frame_factory,
    ) -> None:
        server = make_server(frame_factory)
        existing = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        server.receive_data(existing.serialize())
        server.data_to_send()
        server.drain(last_stream_id=1)
        server.data_to_send()

        late_request = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=3)
        server.receive_data(late_request.serialize())
        server.data_to_send()

        data = DataFrame(3)
        data.data = b"x" * 100
        events = server.receive_data(data.serialize())

        assert events == []
        frames = parse_frames(server.data_to_send())
        assert len(frames) == 1
        assert isinstance(frames[0], RstStreamFrame)
        assert frames[0].stream_id == 3
        assert frames[0].error_code == h2.errors.ErrorCodes.REFUSED_STREAM

    def test_push_promise_cannot_bypass_the_drain(self, frame_factory) -> None:
        # A client draining: the server must not be able to push new work past
        # the client's advertised GOAWAY range.
        client = h2.connection.H2Connection(config=CLIENT_CONFIG)
        client.initiate_connection()
        client.send_headers(1, REQUEST_HEADERS)
        client.data_to_send()
        client.drain(last_stream_id=0)
        client.data_to_send()

        push = frame_factory.build_push_promise_frame(
            stream_id=1,
            promised_stream_id=2,
            headers=REQUEST_HEADERS,
        )
        events = client.receive_data(push.serialize())

        assert events == []
        frames = parse_frames(client.data_to_send())
        assert len(frames) == 1
        assert isinstance(frames[0], RstStreamFrame)
        assert frames[0].stream_id == 2
        assert frames[0].error_code == h2.errors.ErrorCodes.REFUSED_STREAM

    def test_in_range_push_promise_is_still_accepted(self, frame_factory) -> None:
        # A push that was in flight when the GOAWAY was emitted (promised
        # stream ID within the advertised limit) is accepted normally.
        client = h2.connection.H2Connection(config=CLIENT_CONFIG)
        client.initiate_connection()
        client.send_headers(1, REQUEST_HEADERS)
        client.data_to_send()
        client.drain(last_stream_id=4)
        client.data_to_send()

        push = frame_factory.build_push_promise_frame(
            stream_id=1,
            promised_stream_id=2,
            headers=REQUEST_HEADERS,
        )
        events = client.receive_data(push.serialize())

        assert len(events) == 1
        assert isinstance(events[0], h2.events.PushedStreamReceived)
        assert events[0].pushed_stream_id == 2
        assert 2 in client.streams
        assert client.data_to_send() == b""

    def test_local_send_headers_forbidden_while_draining(self, frame_factory) -> None:
        client = h2.connection.H2Connection(config=CLIENT_CONFIG)
        client.initiate_connection()
        client.send_headers(1, REQUEST_HEADERS)
        client.data_to_send()
        client.drain()

        with pytest.raises(h2.exceptions.ProtocolError):
            client.send_headers(3, REQUEST_HEADERS)

    def test_local_push_forbidden_while_draining(self, frame_factory) -> None:
        server = make_server(frame_factory)
        request = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        server.receive_data(request.serialize())
        server.data_to_send()
        server.drain()

        with pytest.raises(h2.exceptions.ProtocolError):
            server.push_stream(
                stream_id=1,
                promised_stream_id=2,
                request_headers=REQUEST_HEADERS,
            )


class TestRemoteGoAway:
    def test_unaccepted_outbound_streams_are_identifiable(self) -> None:
        client = h2.connection.H2Connection(config=CLIENT_CONFIG)
        client.initiate_connection()
        client.send_headers(1, REQUEST_HEADERS, end_stream=True)
        client.send_headers(3, REQUEST_HEADERS, end_stream=True)
        client.send_headers(5, REQUEST_HEADERS, end_stream=True)
        client.data_to_send()

        goaway = GoAwayFrame(0)
        goaway.last_stream_id = 3
        goaway.error_code = h2.errors.ErrorCodes.NO_ERROR

        events = client.receive_data(goaway.serialize())

        assert isinstance(events[0], h2.events.ConnectionTerminated)
        assert isinstance(events[1], h2.events.StreamsNotAccepted)
        assert events[1].stream_ids == (5,)
        assert events[1].last_stream_id == 3
        assert client.unaccepted_outbound_streams == (5,)
        assert client.remote_goaway_last_stream_id == 3

    def test_no_event_when_everything_was_accepted(self) -> None:
        client = h2.connection.H2Connection(config=CLIENT_CONFIG)
        client.initiate_connection()
        client.send_headers(1, REQUEST_HEADERS, end_stream=True)
        client.data_to_send()

        goaway = GoAwayFrame(0)
        goaway.last_stream_id = 1

        events = client.receive_data(goaway.serialize())

        assert len(events) == 1
        assert isinstance(events[0], h2.events.ConnectionTerminated)
        assert client.unaccepted_outbound_streams == ()

    def test_multiple_remote_goaways_only_tighten(self) -> None:
        client = h2.connection.H2Connection(config=CLIENT_CONFIG)
        client.initiate_connection()
        for stream_id in (1, 3, 5, 7):
            client.send_headers(stream_id, REQUEST_HEADERS, end_stream=True)
        client.data_to_send()

        first = GoAwayFrame(0)
        first.last_stream_id = 5
        second = GoAwayFrame(0)
        second.last_stream_id = 1

        events = client.receive_data(first.serialize() + second.serialize())

        not_accepted = [
            event for event in events
            if isinstance(event, h2.events.StreamsNotAccepted)
        ]
        assert [event.stream_ids for event in not_accepted] == [(7,), (3, 5, 7)]
        assert client.remote_goaway_last_stream_id == 1

    def test_library_does_not_replay_refused_requests(self) -> None:
        client = h2.connection.H2Connection(config=CLIENT_CONFIG)
        client.initiate_connection()
        client.send_headers(1, REQUEST_HEADERS, end_stream=True)
        client.data_to_send()

        goaway = GoAwayFrame(0)
        goaway.last_stream_id = 0
        client.receive_data(goaway.serialize())

        # The outbound buffer is cleared and h2 does not synthesize a retry.
        assert client.data_to_send() == b""
        assert client.unaccepted_outbound_streams == (1,)

    def test_remote_goaway_during_local_drain_keeps_drain_alive(
        self, frame_factory,
    ) -> None:
        server = make_server(frame_factory)
        request = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        server.receive_data(request.serialize())
        server.data_to_send()
        server.drain()
        server.data_to_send()

        remote_goaway = GoAwayFrame(0)
        remote_goaway.last_stream_id = 0
        events = server.receive_data(remote_goaway.serialize())

        assert isinstance(events[0], h2.events.ConnectionTerminated)
        assert server.state_machine.state is h2.connection.ConnectionState.DRAINING
        assert server.draining is True

        # The accepted request can still be answered and the drain completes.
        end = DataFrame(1)
        end.flags.add("END_STREAM")
        server.receive_data(end.serialize())
        server.send_headers(1, [(":status", "200")], end_stream=True)

        assert server.drain_state is h2.connection.DrainState.DRAINED
        assert server.state_machine.state is h2.connection.ConnectionState.CLOSED


class TestForcedEnds:
    def test_force_close_aborts_drain_with_local_event(self, frame_factory) -> None:
        server = make_server(frame_factory)
        request = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        server.receive_data(request.serialize())
        server.data_to_send()
        server.drain()
        server.data_to_send()

        events = server.force_close(h2.errors.ErrorCodes.INTERNAL_ERROR)

        assert len(events) == 1
        assert isinstance(events[0], h2.events.ConnectionTerminated)
        assert events[0].remote_terminated is False
        assert events[0].error_code == h2.errors.ErrorCodes.INTERNAL_ERROR
        assert server.state_machine.state is h2.connection.ConnectionState.CLOSED
        assert server.drain_state is h2.connection.DrainState.ABORTED

        frames = parse_frames(server.data_to_send())
        assert frames[-1].error_code == h2.errors.ErrorCodes.INTERNAL_ERROR

    def test_force_close_rejected_after_close(self, frame_factory) -> None:
        server = make_server(frame_factory)
        server.force_close()

        with pytest.raises(h2.exceptions.ProtocolError):
            server.force_close()

    def test_close_connection_aborts_drain(self, frame_factory) -> None:
        server = make_server(frame_factory)
        request = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        server.receive_data(request.serialize())
        server.data_to_send()
        server.drain()

        server.close_connection()

        assert server.state_machine.state is h2.connection.ConnectionState.CLOSED
        assert server.drain_state is h2.connection.DrainState.ABORTED

    def test_protocol_error_terminates_drain(self, frame_factory) -> None:
        server = make_server(frame_factory)
        request = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        server.receive_data(request.serialize())
        server.data_to_send()
        server.drain()
        server.data_to_send()

        bad_window_update = WindowUpdateFrame(0)
        bad_window_update.window_increment = 0

        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(bad_window_update.serialize())

        assert server.state_machine.state is h2.connection.ConnectionState.CLOSED
        assert server.drain_state is h2.connection.DrainState.TERMINATED
        frames = parse_frames(server.data_to_send())
        assert frames[-1].error_code == h2.errors.ErrorCodes.PROTOCOL_ERROR

    def test_close_connection_still_works_standalone(self, frame_factory) -> None:
        server = make_server(frame_factory)
        server.close_connection(
            error_code=h2.errors.ErrorCodes.INTERNAL_ERROR,
            additional_data=b"boom",
        )

        assert server.state_machine.state is h2.connection.ConnectionState.CLOSED
        assert server.drain_state is h2.connection.DrainState.IDLE
        frames = parse_frames(server.data_to_send())
        assert len(frames) == 1
        assert frames[0].error_code == h2.errors.ErrorCodes.INTERNAL_ERROR
        assert frames[0].additional_data == b"boom"


class TestInMemoryConnectionPair:
    """
    End-to-end behaviour with two H2Connection instances exchanging frames in
    memory. After the server-side drain begins, late and in-flight frames are
    fed through the real wire parse path so the test exercises the same code
    as a production stack.
    """

    @staticmethod
    def _open_parallel_requests(
        server: h2.connection.H2Connection,
        client: h2.connection.H2Connection,
    ) -> None:
        # Three parallel requests; stream 5 is half-closed immediately.
        client.send_headers(1, REQUEST_HEADERS, end_stream=False)
        assert server.receive_data(client.data_to_send())
        client.send_headers(3, REQUEST_HEADERS, end_stream=False)
        assert server.receive_data(client.data_to_send())
        client.send_headers(5, REQUEST_HEADERS, end_stream=True)
        assert server.receive_data(client.data_to_send())

    @staticmethod
    def _assert_late_request_refused(
        server: h2.connection.H2Connection, frame_factory: FrameFactory,
    ) -> None:
        # A brand-new request arriving after the GOAWAY is refused, never
        # delivered to the application and never creates stream state.
        late = frame_factory.build_headers_frame(
            REQUEST_HEADERS, stream_id=7, flags=["END_STREAM"],
        )
        assert server.receive_data(late.serialize()) == []
        assert 7 not in server.streams
        refusal = parse_frames(server.data_to_send())
        assert len(refusal) == 1
        assert isinstance(refusal[0], RstStreamFrame)
        assert refusal[0].stream_id == 7
        assert refusal[0].error_code == h2.errors.ErrorCodes.REFUSED_STREAM

    @staticmethod
    def _finish_accepted_streams(
        server: h2.connection.H2Connection, frame_factory: FrameFactory,
    ) -> list[h2.events.Event]:
        # In-flight DATA, trailers and window updates on accepted streams work.
        data = DataFrame(1)
        data.data = b"chunk"
        trailers = frame_factory.build_headers_frame(
            [("x-trailer", "done")], flags=["END_STREAM"], stream_id=1,
        )
        events = server.receive_data(data.serialize() + trailers.serialize())
        assert [type(event) for event in events] == [
            h2.events.DataReceived,
            h2.events.TrailersReceived,
            h2.events.StreamEnded,
        ]
        server.increment_flow_control_window(32, stream_id=3)
        assert parse_frames(server.data_to_send())

        # Every accepted request gets a response.
        server.send_headers(1, [(":status", "200")], end_stream=True)
        server.send_headers(3, [(":status", "200")])
        server.send_data(3, b"payload", end_stream=True)
        server.send_headers(5, [(":status", "204")], end_stream=True)
        server.data_to_send()

        # Ending the last still-open accepted stream completes the drain.
        end_of_three = DataFrame(3)
        end_of_three.flags.add("END_STREAM")
        return server.receive_data(end_of_three.serialize())

    def test_full_drain_scenario(self, frame_factory) -> None:
        server, client = _handshake_pair()
        self._open_parallel_requests(server, client)

        # The gateway stops accepting new work.
        assert server.drain() == []
        goaway_frames = parse_frames(server.data_to_send())
        assert len(goaway_frames) == 1
        assert goaway_frames[0].last_stream_id == 5
        client.receive_data(goaway_frames[0].serialize())

        self._assert_late_request_refused(server, frame_factory)
        events = self._finish_accepted_streams(server, frame_factory)

        assert isinstance(events[-1], h2.events.DrainCompleted)
        assert events[-1].last_stream_id == 5
        assert server.drain_state is h2.connection.DrainState.DRAINED
        assert server.state_machine.state is h2.connection.ConnectionState.CLOSED

        # The final accounting clearly separates finished from refused work.
        assert sorted(server.streams) == [1, 3, 5]
        assert server.unaccepted_outbound_streams == ()
        assert 7 not in server.streams


class TestDrainingStreamReset:
    def test_rst_stream_still_allowed_while_draining(self, frame_factory) -> None:
        server = make_server(frame_factory)
        request = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        server.receive_data(request.serialize())
        server.data_to_send()
        server.drain()
        server.data_to_send()

        server.reset_stream(1, error_code=h2.errors.ErrorCodes.CANCEL)

        frames = parse_frames(server.data_to_send())
        assert len(frames) == 1
        assert isinstance(frames[0], RstStreamFrame)
        assert frames[0].stream_id == 1
        assert frames[0].error_code == h2.errors.ErrorCodes.CANCEL
        # Resetting the last accepted stream ends the drain.
        assert server.drain_state is h2.connection.DrainState.DRAINED
        assert server.state_machine.state is h2.connection.ConnectionState.CLOSED

    def test_remote_reset_during_drain_does_not_break_other_streams(
        self, frame_factory,
    ) -> None:
        server = make_server(frame_factory)
        for stream_id in (1, 3):
            request = frame_factory.build_headers_frame(
                REQUEST_HEADERS, stream_id=stream_id,
            )
            server.receive_data(request.serialize())
        server.data_to_send()
        server.drain()
        server.data_to_send()

        from hyperframe.frame import RstStreamFrame as RemoteRst
        reset = RemoteRst(1)
        reset.error_code = h2.errors.ErrorCodes.CANCEL
        events = server.receive_data(reset.serialize())

        assert isinstance(events[0], h2.events.StreamReset)
        assert server.draining is True
        assert 3 in server.streams
