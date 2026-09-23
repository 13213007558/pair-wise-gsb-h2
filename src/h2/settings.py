"""
h2/settings
~~~~~~~~~~~

This module contains a HTTP/2 settings object. This object provides a simple
API for manipulating HTTP/2 settings, keeping track of both the current active
state of the settings and the unacknowledged future values of the settings.
"""
from __future__ import annotations

import collections
import enum
from collections.abc import Iterator, MutableMapping

from hyperframe.frame import SettingsFrame

from .errors import ErrorCodes
from .exceptions import InvalidSettingsValueError


class SettingCodes(enum.IntEnum):
    """
    All known HTTP/2 setting codes.

    .. versionadded:: 2.6.0
    """

    #: Allows the sender to inform the remote endpoint of the maximum size of
    #: the header compression table used to decode header blocks, in octets.
    HEADER_TABLE_SIZE = SettingsFrame.HEADER_TABLE_SIZE

    #: This setting can be used to disable server push. To disable server push
    #: on a client, set this to 0.
    ENABLE_PUSH = SettingsFrame.ENABLE_PUSH

    #: Indicates the maximum number of concurrent streams that the sender will
    #: allow.
    MAX_CONCURRENT_STREAMS = SettingsFrame.MAX_CONCURRENT_STREAMS

    #: Indicates the sender's initial window size (in octets) for stream-level
    #: flow control.
    INITIAL_WINDOW_SIZE = SettingsFrame.INITIAL_WINDOW_SIZE

    #: Indicates the size of the largest frame payload that the sender is
    #: willing to receive, in octets.
    MAX_FRAME_SIZE = SettingsFrame.MAX_FRAME_SIZE

    #: This advisory setting informs a peer of the maximum size of header list
    #: that the sender is prepared to accept, in octets.  The value is based on
    #: the uncompressed size of header fields, including the length of the name
    #: and value in octets plus an overhead of 32 octets for each header field.
    MAX_HEADER_LIST_SIZE = SettingsFrame.MAX_HEADER_LIST_SIZE

    #: This setting can be used to enable the connect protocol. To enable on a
    #: client set this to 1.
    ENABLE_CONNECT_PROTOCOL = SettingsFrame.ENABLE_CONNECT_PROTOCOL


def _setting_code_from_int(code: int) -> SettingCodes | int:
    """
    Given an integer setting code, returns either one of :class:`SettingCodes
    <h2.settings.SettingCodes>` or, if not present in the known set of codes,
    returns the integer directly.
    """
    try:
        return SettingCodes(code)
    except ValueError:
        return code


class ChangedSetting:

    def __init__(self, setting: SettingCodes | int, original_value: int | None, new_value: int) -> None:
        #: The setting code given. Either one of :class:`SettingCodes
        #: <h2.settings.SettingCodes>` or ``int``
        #:
        #: .. versionchanged:: 2.6.0
        self.setting = setting

        #: The original value before being changed.
        self.original_value = original_value

        #: The new value after being changed.
        self.new_value = new_value

    def __repr__(self) -> str:
        return (
            f"ChangedSetting(setting={self.setting!s}, original_value={self.original_value}, new_value={self.new_value})"
        )


class Settings(MutableMapping[SettingCodes | int, int]):
    """
    An object that encapsulates HTTP/2 settings state.

    HTTP/2 Settings are a complex beast. Each party, remote and local, has its
    own settings and a view of the other party's settings. When a settings
    frame is emitted by a peer it cannot assume that the new settings values
    are in place until the remote peer acknowledges the setting. In principle,
    multiple settings changes can be "in flight" at the same time, all with
    different values.

    This object encapsulates this mess. It provides a dict-like interface to
    settings, which return the *current* values of the settings in question.
    Additionally, it keeps track of the queue of proposed values: each
    SETTINGS frame that has been sent or received occupies exactly one slot
    in the queue, and each acknowledgement consumes exactly one slot,
    applying only the changes carried by that frame. On top of all that, it
    validates the values to
    make sure they're allowed, and raises :class:`InvalidSettingsValueError
    <h2.exceptions.InvalidSettingsValueError>` if they are not.

    Finally, this object understands what the default values of the HTTP/2
    settings are, and sets those defaults appropriately.

    .. versionchanged:: 2.2.0
       Added the ``initial_values`` parameter.

    .. versionchanged:: 2.5.0
       Added the ``max_header_list_size`` property.

    .. versionchanged:: 4.4.2
       Settings changes are now tracked per SETTINGS frame: a single
       acknowledgement applies only the changes from the oldest
       unacknowledged frame, instead of applying all outstanding changes at
       once.

    :param client: (optional) Whether these settings should be defaulted for a
        client implementation or a server implementation. Defaults to ``True``.
    :type client: ``bool``
    :param initial_values: (optional) Any initial values the user would like
        set, rather than RFC 7540's defaults.
    :type initial_vales: ``MutableMapping``
    """

    def __init__(self, client: bool = True, initial_values: dict[SettingCodes, int] | None = None) -> None:
        self._client = client

        # Backing object for the settings. This is a dictionary of
        # (setting: value) holding the current values of the settings.
        #
        # This contains the default values for HTTP/2.
        self._settings: dict[SettingCodes | int, int] = {
            SettingCodes.HEADER_TABLE_SIZE: 4096,
            SettingCodes.ENABLE_PUSH: int(client),
            SettingCodes.INITIAL_WINDOW_SIZE: 65535,
            SettingCodes.MAX_FRAME_SIZE: 16384,
            SettingCodes.ENABLE_CONNECT_PROTOCOL: 0,
        }

        # A queue of unacknowledged SETTINGS frames. Each entry corresponds
        # to exactly one SETTINGS frame that has been sent (or received) and
        # not yet acknowledged, and maps the settings carried by that frame
        # to their proposed new values. Each acknowledgement consumes
        # exactly one entry, so changes take effect in the order the frames
        # were sent. Empty SETTINGS frames occupy their own slot here.
        self._pending_settings: collections.deque[dict[SettingCodes | int, int]] = collections.deque()
        if initial_values is not None:
            for key, value in initial_values.items():
                invalid = _validate_setting(key, value)
                if invalid:
                    msg = f"Setting {key} has invalid value {value}"
                    raise InvalidSettingsValueError(
                        msg,
                        error_code=invalid,
                    )
                self._settings[key] = value

    def acknowledge(self) -> dict[SettingCodes | int, ChangedSetting]:
        """
        The settings have been acknowledged, either by the user (remote
        settings) or by the remote peer (local settings).

        Exactly one unacknowledged SETTINGS frame is consumed: only the
        changes carried by the oldest outstanding frame are applied. If no
        SETTINGS frame is awaiting acknowledgement, nothing changes.

        :returns: A dict of {setting: ChangedSetting} that were applied.
        """
        changed_settings: dict[SettingCodes | int, ChangedSetting] = {}

        if not self._pending_settings:
            return changed_settings

        pending_frame = self._pending_settings.popleft()
        for setting, new_value in pending_frame.items():
            original_value = self._settings.get(setting)
            changed_settings[setting] = ChangedSetting(
                setting, original_value, new_value,
            )
            self._settings[setting] = new_value

        return changed_settings

    # Provide easy-access to well known settings.
    @property
    def header_table_size(self) -> int:
        """
        The current value of the :data:`HEADER_TABLE_SIZE
        <h2.settings.SettingCodes.HEADER_TABLE_SIZE>` setting.
        """
        return self[SettingCodes.HEADER_TABLE_SIZE]

    @header_table_size.setter
    def header_table_size(self, value: int) -> None:
        self[SettingCodes.HEADER_TABLE_SIZE] = value

    @property
    def enable_push(self) -> int:
        """
        The current value of the :data:`ENABLE_PUSH
        <h2.settings.SettingCodes.ENABLE_PUSH>` setting.
        """
        return self[SettingCodes.ENABLE_PUSH]

    @enable_push.setter
    def enable_push(self, value: int) -> None:
        self[SettingCodes.ENABLE_PUSH] = value

    @property
    def initial_window_size(self) -> int:
        """
        The current value of the :data:`INITIAL_WINDOW_SIZE
        <h2.settings.SettingCodes.INITIAL_WINDOW_SIZE>` setting.
        """
        return self[SettingCodes.INITIAL_WINDOW_SIZE]

    @initial_window_size.setter
    def initial_window_size(self, value: int) -> None:
        self[SettingCodes.INITIAL_WINDOW_SIZE] = value

    @property
    def max_frame_size(self) -> int:
        """
        The current value of the :data:`MAX_FRAME_SIZE
        <h2.settings.SettingCodes.MAX_FRAME_SIZE>` setting.
        """
        return self[SettingCodes.MAX_FRAME_SIZE]

    @max_frame_size.setter
    def max_frame_size(self, value: int) -> None:
        self[SettingCodes.MAX_FRAME_SIZE] = value

    @property
    def max_concurrent_streams(self) -> int:
        """
        The current value of the :data:`MAX_CONCURRENT_STREAMS
        <h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS>` setting.
        """
        return self.get(SettingCodes.MAX_CONCURRENT_STREAMS, 2**32+1)

    @max_concurrent_streams.setter
    def max_concurrent_streams(self, value: int) -> None:
        self[SettingCodes.MAX_CONCURRENT_STREAMS] = value

    @property
    def max_header_list_size(self) -> int | None:
        """
        The current value of the :data:`MAX_HEADER_LIST_SIZE
        <h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE>` setting. If not set,
        returns ``None``, which means unlimited.

        .. versionadded:: 2.5.0
        """
        return self.get(SettingCodes.MAX_HEADER_LIST_SIZE, None)

    @max_header_list_size.setter
    def max_header_list_size(self, value: int) -> None:
        self[SettingCodes.MAX_HEADER_LIST_SIZE] = value

    @property
    def enable_connect_protocol(self) -> int:
        """
        The current value of the :data:`ENABLE_CONNECT_PROTOCOL
        <h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL>` setting.
        """
        return self[SettingCodes.ENABLE_CONNECT_PROTOCOL]

    @enable_connect_protocol.setter
    def enable_connect_protocol(self, value: int) -> None:
        self[SettingCodes.ENABLE_CONNECT_PROTOCOL] = value

    # Implement the MutableMapping API.
    def __getitem__(self, key: SettingCodes | int) -> int:
        return self._settings[key]

    def __setitem__(self, key: SettingCodes | int, value: int) -> None:
        invalid = _validate_setting(key, value)
        if invalid:
            msg = f"Setting {key} has invalid value {value}"
            raise InvalidSettingsValueError(
                msg,
                error_code=invalid,
            )

        # Individual item sets are added to the most recent unacknowledged
        # SETTINGS frame: if there is none, they start a new one.
        if not self._pending_settings:
            self._pending_settings.append({})
        self._pending_settings[-1][key] = value

    def update(self, new_settings: dict[SettingCodes | int, int]) -> None:  # type: ignore[override]
        """
        Apply a batch of new settings values as a single unit, corresponding
        to exactly one SETTINGS frame. The whole batch takes effect together
        when that frame is acknowledged. Empty batches are allowed: an empty
        SETTINGS frame still occupies its own acknowledgement slot.
        """
        for key, value in new_settings.items():
            invalid = _validate_setting(key, value)
            if invalid:
                msg = f"Setting {key} has invalid value {value}"
                raise InvalidSettingsValueError(
                    msg,
                    error_code=invalid,
                )

        self._pending_settings.append(dict(new_settings))

    def validate_received_setting(self, setting: SettingCodes | int, value: int) -> None:
        """
        Validate a setting received from the peer that owns this Settings
        object.

        Servers may advertise ``ENABLE_PUSH`` only as ``0`` in received
        SETTINGS frames.
        """
        invalid = _validate_setting(setting, value, client=self._client)

        if invalid != ErrorCodes.NO_ERROR:
            msg = f"Setting {setting} has invalid value {value}"
            raise InvalidSettingsValueError(
                msg,
                error_code=invalid,
            )

    def __delitem__(self, key: SettingCodes | int) -> None:
        del self._settings[key]
        for pending_frame in self._pending_settings:
            pending_frame.pop(key, None)

    def __iter__(self) -> Iterator[SettingCodes | int]:
        return self._settings.__iter__()

    def __len__(self) -> int:
        return len(self._settings)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Settings):
            return self._settings == other._settings and self._pending_settings == other._pending_settings
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        if isinstance(other, Settings):
            return not self == other
        return NotImplemented

    # be explicit that Settings is not providing a hash implementation
    # see https://docs.python.org/3/reference/datamodel.html#object.__hash__
    __hash__ = MutableMapping.__hash__


def _validate_setting(
    setting: SettingCodes | int,
    value: int,
    *,
    client: bool | None = None,
) -> ErrorCodes:
    """
    Confirms that a specific setting has a well-formed value. If the setting is
    invalid, returns an error code. Otherwise, returns 0 (NO_ERROR).

    If ``client`` is set, the setting originated from a peer with that role.
    """
    if setting == SettingCodes.ENABLE_PUSH:
        # RFC 9113 section 6.5.2: "A client MUST treat receipt of a
        # SETTINGS frame with SETTINGS_ENABLE_PUSH set to 1 as a connection
        # error (Section 5.4.1) of type PROTOCOL_ERROR."
        if value not in (0, 1) or (client is False and value != 0):
            return ErrorCodes.PROTOCOL_ERROR
    elif setting == SettingCodes.INITIAL_WINDOW_SIZE:
        if not 0 <= value <= 2147483647:  # 2^31 - 1
            return ErrorCodes.FLOW_CONTROL_ERROR
    elif setting == SettingCodes.MAX_FRAME_SIZE:
        if not 16384 <= value <= 16777215:  # 2^14 and 2^24 - 1
            return ErrorCodes.PROTOCOL_ERROR
    elif setting == SettingCodes.MAX_HEADER_LIST_SIZE:
        if value < 0:
            return ErrorCodes.PROTOCOL_ERROR
    elif setting == SettingCodes.ENABLE_CONNECT_PROTOCOL and value not in (0, 1):
        return ErrorCodes.PROTOCOL_ERROR

    return ErrorCodes.NO_ERROR
