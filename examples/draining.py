# -*- coding: utf-8 -*-
"""
Connection Draining
~~~~~~~~~~~~~~~~~~~

This example shows how a gateway takes an HTTP/2 connection offline without
losing the requests it had already accepted. It uses two in-memory
``H2Connection`` objects and exchanges serialized frames between them, so no
sockets or background threads are required.

The flow mirrors what a real gateway does:

1. Accept parallel requests as usual.
2. Call ``drain()`` to emit a GOAWAY and stop accepting new requests.
3. Keep processing DATA, trailers and window updates on accepted streams.
4. Refuse anything the peer opens past the GOAWAY ``last_stream_id``.
5. When every accepted stream has finished, observe ``DrainCompleted``.
6. If an upper-layer deadline fires first, call ``force_close()`` instead.

h2 never starts a timer and never replays refused requests: the application
owns both the deadline and any retry decisions.
"""
from __future__ import annotations

import h2.config
import h2.connection
import h2.errors
import h2.events
from hpack import Encoder
from hyperframe.frame import (
    DataFrame,
    Frame,
    GoAwayFrame,
    HeadersFrame,
    RstStreamFrame,
)

REQUEST_HEADERS = [
    (":method", "GET"),
    (":path", "/"),
    (":scheme", "https"),
    (":authority", "example.com"),
]


def parse_frames(data: bytes) -> list[Frame]:
    """Split a serialized HTTP/2 byte string into individual frames."""
    frames: list[Frame] = []
    while data:
        frame, length = Frame.parse_frame_header(memoryview(data)[:9])
        frame.parse_body(memoryview(data)[9:9 + length])
        frames.append(frame)
        data = data[9 + length:]
    return frames


def handshake() -> tuple[h2.connection.H2Connection, h2.connection.H2Connection]:
    """Return a server/client pair that has completed the HTTP/2 handshake."""
    server = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=False),
    )
    client = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True),
    )
    server.initiate_connection()
    client.initiate_connection()
    client.receive_data(server.data_to_send())
    server.receive_data(client.data_to_send())
    server.data_to_send()
    client.data_to_send()
    return server, client


def open_parallel_requests(
    server: h2.connection.H2Connection,
    client: h2.connection.H2Connection,
) -> None:
    """Open three parallel requests; stream 5 ends the request immediately."""
    client.send_headers(1, REQUEST_HEADERS, end_stream=False)
    server.receive_data(client.data_to_send())
    client.send_headers(3, REQUEST_HEADERS, end_stream=False)
    server.receive_data(client.data_to_send())
    client.send_headers(5, REQUEST_HEADERS, end_stream=True)
    server.receive_data(client.data_to_send())


def refuse_late_request(server: h2.connection.H2Connection) -> int:
    """Feed a request created after the GOAWAY and return its stream ID."""
    wire_encoder = Encoder()
    late = HeadersFrame(7)
    late.data = wire_encoder.encode(REQUEST_HEADERS)
    late.flags.add("END_HEADERS")
    late.flags.add("END_STREAM")

    assert server.receive_data(late.serialize()) == []
    refusal_frames = parse_frames(server.data_to_send())
    assert len(refusal_frames) == 1
    assert isinstance(refusal_frames[0], RstStreamFrame)
    assert refusal_frames[0].error_code == h2.errors.ErrorCodes.REFUSED_STREAM
    print(
        "late stream 7 refused with "
        f"{h2.errors.ErrorCodes(refusal_frames[0].error_code).name}",
    )
    return 7


def exercise_accepted_streams(
    server: h2.connection.H2Connection,
) -> None:
    """Show DATA, trailers and window updates keep flowing during the drain."""
    wire_encoder = Encoder()
    body = DataFrame(1)
    body.data = b"request body"
    trailers = HeadersFrame(1)
    trailers.data = wire_encoder.encode([("x-trailer", "done")])
    trailers.flags.add("END_HEADERS")
    trailers.flags.add("END_STREAM")
    events = server.receive_data(body.serialize() + trailers.serialize())
    print("stream 1 events:", ", ".join(type(event).__name__ for event in events))

    server.increment_flow_control_window(64, stream_id=3)
    assert parse_frames(server.data_to_send())


def finish_accepted_streams(server: h2.connection.H2Connection) -> list[int]:
    """Respond to every accepted request and return the completed stream IDs."""
    server.send_headers(1, [(":status", "200")], end_stream=True)
    assert server.draining is True
    server.send_headers(5, [(":status", "204")], end_stream=True)
    assert server.draining is True
    server.send_headers(3, [(":status", "200")])
    server.send_data(3, b"response body", end_stream=True)
    parse_frames(server.data_to_send())

    # Stream 3 remains open on the client side; ending it completes the drain.
    end_stream = DataFrame(3)
    end_stream.flags.add("END_STREAM")
    final_events = server.receive_data(end_stream.serialize())
    assert isinstance(final_events[-1], h2.events.DrainCompleted)
    return [1, 3, 5]


def main() -> None:
    """Run the end-to-end in-memory drain demonstration."""
    server, client = handshake()
    open_parallel_requests(server, client)

    # GOAWAY NO_ERROR: last_stream_id defaults to the highest accepted stream.
    assert server.drain() == []
    print(
        f"server state: {server.state_machine.state.name}, "
        f"drain: {server.drain_state.name}",
    )
    goaway_frames = parse_frames(server.data_to_send())
    assert len(goaway_frames) == 1
    client_events = client.receive_data(goaway_frames[0].serialize())
    print("client received:", ", ".join(type(event).__name__ for event in client_events))

    # A second GOAWAY may only tighten the accepted range.
    server.drain(last_stream_id=3)
    tightened = parse_frames(server.data_to_send())
    assert isinstance(tightened[0], GoAwayFrame)
    assert tightened[0].last_stream_id == 3
    print(
        "second GOAWAY tightened last_stream_id to "
        f"{server.local_goaway_last_stream_id}",
    )

    refused = [refuse_late_request(server)]
    exercise_accepted_streams(server)
    completed = finish_accepted_streams(server)

    assert server.drain_state is h2.connection.DrainState.DRAINED
    assert server.state_machine.state is h2.connection.ConnectionState.CLOSED
    print(
        f"server state: {server.state_machine.state.name}, "
        f"drain: {server.drain_state.name}",
    )
    print()
    print("Summary")
    print("-------")
    print("completed requests:     ", sorted(completed))
    print("never accepted requests:", sorted(refused))


if __name__ == "__main__":
    main()
