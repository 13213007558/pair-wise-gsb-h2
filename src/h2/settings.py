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
    Additionally, it keeps track of the stack of proposed values: each time an
    acknowledgement is sent/received, it updates the current values with the
    stack of proposed values. On top of all that, it validates the values to
    make sure they're allowed, and raises :class:`InvalidSettingsValueError
    <h2.exceptions.InvalidSettingsValueError>` if they are not.

    Finally, this object understands what the default values of the HTTP/2
    settings are, and sets those defaults appropriately.

    .. versionchanged:: 2.2.0
       Added the ``initial_values`` parameter.

    .. versionchanged:: 2.5.0
       Added the ``max_header_list_size`` property.

    .. versionchanged:: 4.4.2
       Each acknowledgement now applies the changes from exactly one
       outstanding SETTINGS frame, instead of applying all outstanding
       changes at once.

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
        # (setting: [list of values]), where the first value in the list is the
        # current value of the setting. Strictly this doesn't use lists but
        # instead uses collections.deque to avoid repeated memory allocations.
        #
        # This contains the default values for HTTP/2.
        self._settings: dict[SettingCodes | int, collections.deque[int]] = {
            SettingCodes.HEADER_TABLE_SIZE: collections.deque([4096]),
            SettingCodes.ENABLE_PUSH: collections.deque([int(client)]),
            SettingCodes.INITIAL_WINDOW_SIZE: collections.deque([65535]),
            SettingCodes.MAX_FRAME_SIZE: collections.deque([16384]),
            SettingCodes.ENABLE_CONNECT_PROTOCOL: collections.deque([0]),
        }

        # Queue of unacknowledged SETTINGS frames. Each entry is a dictionary
        # of {setting: value} carried by a single sent (or received) SETTINGS
        # frame, in the order those frames were sent (or received). Each
        # acknowledgement consumes exactly one entry: this ensures that a
        # single ACK only ever applies the changes from a single SETTINGS
        # frame, even when multiple frames are in flight. Empty SETTINGS
        # frames occupy their own slot in this queue.
        self._pending_frames: collections.deque[dict[SettingCodes | int, int]] = collections.deque()

        if initial_values is not None:
            for key, value in initial_values.items():
                invalid = _validate_setting(key, value)
                if invalid:
                    msg = f"Setting {key} has invalid value {value}"
                    raise InvalidSettingsValueError(
                        msg,
                        error_code=invalid,
                    )
                self._settings[key] = collections.deque([value])

    def acknowledge(self) -> dict[SettingCodes | int, ChangedSetting]:
        """
        The settings have been acknowledged, either by the user (remote
        settings) or by the remote peer (local settings).

        A single acknowledgement applies the changes from exactly one
        outstanding SETTINGS frame: the oldest one. Settings that were not
        changed by that frame keep their current values, and changes carried
        by later frames remain pending until their own acknowledgement
        arrives.

        :returns: A dict of {setting: ChangedSetting} that were applied.
        """
        changed_settings: dict[SettingCodes | int, ChangedSetting] = {}

        if not self._pending_frames:
            return changed_settings

        frame = self._pending_frames.popleft()
        for setting in frame:
            code = _setting_code_from_int(setting)
            values = self._settings.get(setting)
            if values is None or len(values) < 2:
                # The pending value was deleted before it could be
                # acknowledged: there is nothing to apply.
                continue
            old_setting = values.popleft()
            new_setting = values[0]
            changed_settings[code] = ChangedSetting(
                code, old_setting, new_setting,
            )

        return changed_settings

    def _register_empty_frame(self) -> None:
        """
        Record that a SETTINGS frame carrying no pending changes was sent.

        This is used for frames whose values are already in effect (such as
        the initial SETTINGS frame sent at connection startup): the frame
        still occupies a slot in the acknowledgement queue so that its ACK
        does not consume changes from later frames.
        """
        self._pending_frames.append({})

    def _set_pending_value(self, key: SettingCodes | int, value: int) -> None:
        """
        Validate and queue a new pending value for a setting, without
        associating it with a SETTINGS frame.
        """
        invalid = _validate_setting(key, value)
        if invalid:
            msg = f"Setting {key} has invalid value {value}"
            raise InvalidSettingsValueError(
                msg,
                error_code=invalid,
            )

        try:
            items = self._settings[key]
        except KeyError:
            items = collections.deque([None])  # type: ignore
            self._settings[key] = items

        items.append(value)

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
        val = self._settings[key][0]

        # Things that were created when a setting was received should stay
        # KeyError'd.
        if val is None:
            raise KeyError

        return val

    def __setitem__(self, key: SettingCodes | int, value: int) -> None:
        self._set_pending_value(key, value)

        # Associate the change with the most recent unacknowledged frame,
        # so that it is applied when that frame is acknowledged. If no frame
        # is outstanding, begin a new one.
        if not self._pending_frames:
            self._pending_frames.append({})
        self._pending_frames[-1][key] = value

    def update(self, other=(), **kwargs: int) -> None:  # type: ignore[override]
        """
        Apply a collection of new settings values as a single SETTINGS
        frame.

        All values given in one call to this method are treated as belonging
        to the same SETTINGS frame: a single acknowledgement will apply all
        of them together, and no acknowledgement will apply any of them
        before the changes from earlier frames.
        """
        frame_settings: dict[SettingCodes | int, int] = dict(other, **kwargs)
        for key, value in frame_settings.items():
            self._set_pending_value(key, value)
        self._pending_frames.append(frame_settings)

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

    def __iter__(self) -> Iterator[SettingCodes | int]:
        return self._settings.__iter__()

    def __len__(self) -> int:
        return len(self._settings)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Settings):
            return self._settings == other._settings
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
