"""
h2/acknowledgment
~~~~~~~~~~~~~~~~~

Defines the token-based flow control acknowledgment credential.

When a connection is configured with ``data_acknowledgment_tokens`` enabled,
each :class:`DataReceived <h2.events.DataReceived>` event carries one of
these tokens, which the application uses to hand flow-controlled bytes back
to the remote peer as it consumes them.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .connection import H2Connection


class DataAcknowledgment:
    """
    A single-use credential for handing received flow-controlled bytes back
    to the remote peer.

    Each token is bound to exactly one :class:`DataReceived
    <h2.events.DataReceived>` event and to the connection that produced it.
    It tracks the total *flow-controlled* size of the data (that is,
    including any padding), and allows the application to acknowledge the
    payload incrementally as it is consumed.

    Applications acknowledge *payload* bytes only: once every payload byte
    has been acknowledged, the token automatically returns any padding that
    accompanied the data and becomes exhausted. A token can never return
    more than its total flow-controlled length, and an exhausted token
    rejects any further acknowledgment.

    .. versionadded:: 4.5.0
    """

    def __init__(self,
                 connection: H2Connection,
                 stream_id: int,
                 data_length: int,
                 flow_controlled_length: int) -> None:
        self._connection = connection
        self.stream_id = stream_id
        self.data_length = data_length
        self.flow_controlled_length = flow_controlled_length
        self._acknowledged = 0
        self._exhausted = False

    def __repr__(self) -> str:
        return (
            f"<DataAcknowledgment stream_id:{self.stream_id}, "
            f"remaining:{self.remaining}, "
            f"flow_controlled_length:{self.flow_controlled_length}>"
        )

    @property
    def remaining(self) -> int:
        """
        The number of payload bytes that have not yet been acknowledged.
        """
        return self.data_length - self._acknowledged

    @property
    def exhausted(self) -> bool:
        """
        Whether this token has returned its entire flow-controlled length.
        An exhausted token cannot be used again.
        """
        return self._exhausted

    def acknowledge(self, amount: int | None = None) -> None:
        """
        Acknowledge ``amount`` payload bytes of the associated data. If
        ``amount`` is not given, acknowledges all remaining payload bytes.

        This is a convenience wrapper around
        :meth:`acknowledge_data_token
        <h2.connection.H2Connection.acknowledge_data_token>`.
        """
        self._connection.acknowledge_data_token(self, amount)
