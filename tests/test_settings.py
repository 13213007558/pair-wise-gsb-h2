"""
Test the Settings object.
"""
from __future__ import annotations

import pytest
from hypothesis import assume, given
from hypothesis.strategies import booleans, builds, fixed_dictionaries, integers

import h2.errors
import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.settings


class TestSettings:
    """
    Test the Settings object behaves as expected.
    """

    def test_settings_defaults_client(self) -> None:
        """
        The Settings object begins with the appropriate defaults for clients.
        """
        s = h2.settings.Settings(client=True)

        assert s[h2.settings.SettingCodes.HEADER_TABLE_SIZE] == 4096
        assert s[h2.settings.SettingCodes.ENABLE_PUSH] == 1
        assert s[h2.settings.SettingCodes.INITIAL_WINDOW_SIZE] == 65535
        assert s[h2.settings.SettingCodes.MAX_FRAME_SIZE] == 16384
        assert s[h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL] == 0

    def test_settings_defaults_server(self) -> None:
        """
        The Settings object begins with the appropriate defaults for servers.
        """
        s = h2.settings.Settings(client=False)

        assert s[h2.settings.SettingCodes.HEADER_TABLE_SIZE] == 4096
        assert s[h2.settings.SettingCodes.ENABLE_PUSH] == 0
        assert s[h2.settings.SettingCodes.INITIAL_WINDOW_SIZE] == 65535
        assert s[h2.settings.SettingCodes.MAX_FRAME_SIZE] == 16384
        assert s[h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL] == 0

    @pytest.mark.parametrize("client", [True, False])
    def test_can_set_initial_values(self, client) -> None:
        """
        The Settings object can be provided initial values that override the
        defaults.
        """
        overrides = {
            h2.settings.SettingCodes.HEADER_TABLE_SIZE: 8080,
            h2.settings.SettingCodes.MAX_FRAME_SIZE: 16388,
            h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 100,
            h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE: 2**16,
            h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL: 1,
        }
        s = h2.settings.Settings(client=client, initial_values=overrides)

        assert s[h2.settings.SettingCodes.HEADER_TABLE_SIZE] == 8080
        assert s[h2.settings.SettingCodes.ENABLE_PUSH] == bool(client)
        assert s[h2.settings.SettingCodes.INITIAL_WINDOW_SIZE] == 65535
        assert s[h2.settings.SettingCodes.MAX_FRAME_SIZE] == 16388
        assert s[h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS] == 100
        assert s[h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE] == 2**16
        assert s[h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL] == 1

    @pytest.mark.parametrize(
        ("setting", "value"),
        [
            (h2.settings.SettingCodes.ENABLE_PUSH, 2),
            (h2.settings.SettingCodes.ENABLE_PUSH, -1),
            (h2.settings.SettingCodes.INITIAL_WINDOW_SIZE, -1),
            (h2.settings.SettingCodes.INITIAL_WINDOW_SIZE, 2**34),
            (h2.settings.SettingCodes.MAX_FRAME_SIZE, 1),
            (h2.settings.SettingCodes.MAX_FRAME_SIZE, 2**30),
            (h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE, -1),
            (h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL, -1),
        ],
    )
    def test_cannot_set_invalid_initial_values(self, setting, value) -> None:
        """
        The Settings object can be provided initial values that override the
        defaults.
        """
        overrides = {setting: value}

        with pytest.raises(h2.exceptions.InvalidSettingsValueError):
            h2.settings.Settings(initial_values=overrides)

    def test_applying_value_doesnt_take_effect_immediately(self) -> None:
        """
        When a value is applied to the settings object, it doesn't immediately
        take effect.
        """
        s = h2.settings.Settings(client=True)
        s[h2.settings.SettingCodes.HEADER_TABLE_SIZE] == 8000

        assert s[h2.settings.SettingCodes.HEADER_TABLE_SIZE] == 4096

    def test_acknowledging_values(self) -> None:
        """
        When we acknowledge settings, the values change.
        """
        s = h2.settings.Settings(client=True)
        old_settings = dict(s)

        new_settings = {
            h2.settings.SettingCodes.HEADER_TABLE_SIZE: 4000,
            h2.settings.SettingCodes.ENABLE_PUSH: 0,
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 60,
            h2.settings.SettingCodes.MAX_FRAME_SIZE: 16385,
            h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL: 1,
        }
        s.update(new_settings)

        assert dict(s) == old_settings
        s.acknowledge()
        assert dict(s) == new_settings

    def test_acknowledging_returns_the_changed_settings(self) -> None:
        """
        Acknowledging settings returns the changes.
        """
        s = h2.settings.Settings(client=True)
        s[h2.settings.SettingCodes.HEADER_TABLE_SIZE] = 8000
        s[h2.settings.SettingCodes.ENABLE_PUSH] = 0

        changes = s.acknowledge()
        assert len(changes) == 2

        table_size_change = (
            changes[h2.settings.SettingCodes.HEADER_TABLE_SIZE]
        )
        push_change = changes[h2.settings.SettingCodes.ENABLE_PUSH]

        assert table_size_change.setting == (
            h2.settings.SettingCodes.HEADER_TABLE_SIZE
        )
        assert table_size_change.original_value == 4096
        assert table_size_change.new_value == 8000

        assert push_change.setting == h2.settings.SettingCodes.ENABLE_PUSH
        assert push_change.original_value == 1
        assert push_change.new_value == 0

    def test_acknowledging_only_returns_changed_settings(self) -> None:
        """
        Acknowledging settings does not return unchanged settings.
        """
        s = h2.settings.Settings(client=True)
        s[h2.settings.SettingCodes.INITIAL_WINDOW_SIZE] = 70

        changes = s.acknowledge()
        assert len(changes) == 1
        assert list(changes.keys()) == [
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE,
        ]

    def test_deleting_values_deletes_all_of_them(self) -> None:
        """
        When we delete a key we lose all state about it.
        """
        s = h2.settings.Settings(client=True)
        s[h2.settings.SettingCodes.HEADER_TABLE_SIZE] == 8000

        del s[h2.settings.SettingCodes.HEADER_TABLE_SIZE]

        with pytest.raises(KeyError):
            s[h2.settings.SettingCodes.HEADER_TABLE_SIZE]

    def test_length_correctly_reported(self) -> None:
        """
        Length is related only to the number of keys.
        """
        s = h2.settings.Settings(client=True)
        assert len(s) == 5

        s[h2.settings.SettingCodes.HEADER_TABLE_SIZE] == 8000
        assert len(s) == 5

        s.acknowledge()
        assert len(s) == 5

        del s[h2.settings.SettingCodes.HEADER_TABLE_SIZE]
        assert len(s) == 4

    def test_new_values_work(self) -> None:
        """
        New values initially don't appear
        """
        s = h2.settings.Settings(client=True)
        s[80] = 81

        with pytest.raises(KeyError):
            s[80]

    def test_new_values_follow_basic_acknowledgement_rules(self) -> None:
        """
        A new value properly appears when acknowledged.
        """
        s = h2.settings.Settings(client=True)
        s[80] = 81
        changed_settings = s.acknowledge()

        assert s[80] == 81
        assert len(changed_settings) == 1

        changed = changed_settings[80]
        assert changed.setting == 80
        assert changed.original_value is None
        assert changed.new_value == 81

    def test_single_values_arent_affected_by_acknowledgement(self) -> None:
        """
        When acknowledged, unchanged settings remain unchanged.
        """
        s = h2.settings.Settings(client=True)
        assert s[h2.settings.SettingCodes.HEADER_TABLE_SIZE] == 4096

        s.acknowledge()
        assert s[h2.settings.SettingCodes.HEADER_TABLE_SIZE] == 4096

    def test_acknowledgement_applies_one_frame_at_a_time(self) -> None:
        """
        Each acknowledgement applies the changes from exactly one
        outstanding SETTINGS frame: the oldest one.
        """
        s = h2.settings.Settings(client=True)
        s.update({h2.settings.SettingCodes.HEADER_TABLE_SIZE: 100})
        s.update({h2.settings.SettingCodes.MAX_FRAME_SIZE: 32768})

        changes = s.acknowledge()
        assert list(changes) == [h2.settings.SettingCodes.HEADER_TABLE_SIZE]
        change = changes[h2.settings.SettingCodes.HEADER_TABLE_SIZE]
        assert change.original_value == 4096
        assert change.new_value == 100
        assert s.header_table_size == 100
        assert s.max_frame_size == 16384

        changes = s.acknowledge()
        assert list(changes) == [h2.settings.SettingCodes.MAX_FRAME_SIZE]
        change = changes[h2.settings.SettingCodes.MAX_FRAME_SIZE]
        assert change.original_value == 16384
        assert change.new_value == 32768
        assert s.max_frame_size == 32768

    def test_acknowledgement_same_setting_consecutive_frames(self) -> None:
        """
        A setting changed in consecutive frames takes effect one frame at a
        time.
        """
        s = h2.settings.Settings(client=True)
        s.update({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 100})
        s.update({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 200})

        changes = s.acknowledge()
        assert list(changes) == [h2.settings.SettingCodes.INITIAL_WINDOW_SIZE]
        change = changes[h2.settings.SettingCodes.INITIAL_WINDOW_SIZE]
        assert change.original_value == 65535
        assert change.new_value == 100
        assert s.initial_window_size == 100

        changes = s.acknowledge()
        assert list(changes) == [h2.settings.SettingCodes.INITIAL_WINDOW_SIZE]
        change = changes[h2.settings.SettingCodes.INITIAL_WINDOW_SIZE]
        assert change.original_value == 100
        assert change.new_value == 200
        assert s.initial_window_size == 200

    def test_empty_frame_occupies_acknowledgement_slot(self) -> None:
        """
        An empty SETTINGS frame consumes one acknowledgement without
        applying any changes.
        """
        s = h2.settings.Settings(client=True)
        s.update({})
        s.update({h2.settings.SettingCodes.HEADER_TABLE_SIZE: 100})

        assert s.acknowledge() == {}
        assert s.header_table_size == 4096

        changes = s.acknowledge()
        assert list(changes) == [h2.settings.SettingCodes.HEADER_TABLE_SIZE]
        assert s.header_table_size == 100

    def test_acknowledgement_with_nothing_outstanding(self) -> None:
        """
        An acknowledgement with no outstanding SETTINGS frames changes
        nothing.
        """
        s = h2.settings.Settings(client=True)

        assert s.acknowledge() == {}
        assert s.header_table_size == 4096

    def test_settings_getters(self) -> None:
        """
        Getters exist for well-known settings.
        """
        s = h2.settings.Settings(client=True)

        assert s.header_table_size == (
            s[h2.settings.SettingCodes.HEADER_TABLE_SIZE]
        )
        assert s.enable_push == s[h2.settings.SettingCodes.ENABLE_PUSH]
        assert s.initial_window_size == (
            s[h2.settings.SettingCodes.INITIAL_WINDOW_SIZE]
        )
        assert s.max_frame_size == s[h2.settings.SettingCodes.MAX_FRAME_SIZE]
        assert s.max_concurrent_streams == 2**32 + 1  # A sensible default.
        assert s.max_header_list_size is None
        assert s.enable_connect_protocol == s[
            h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL
        ]

    def test_settings_setters(self) -> None:
        """
        Setters exist for well-known settings.
        """
        s = h2.settings.Settings(client=True)

        s.header_table_size = 0
        s.enable_push = 1
        s.initial_window_size = 2
        s.max_frame_size = 16385
        s.max_concurrent_streams = 4
        s.max_header_list_size = 2**16
        s.enable_connect_protocol = 1

        s.acknowledge()
        assert s[h2.settings.SettingCodes.HEADER_TABLE_SIZE] == 0
        assert s[h2.settings.SettingCodes.ENABLE_PUSH] == 1
        assert s[h2.settings.SettingCodes.INITIAL_WINDOW_SIZE] == 2
        assert s[h2.settings.SettingCodes.MAX_FRAME_SIZE] == 16385
        assert s[h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS] == 4
        assert s[h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE] == 2**16
        assert s[h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL] == 1

    @given(integers())
    def test_cannot_set_invalid_values_for_enable_push(self, val) -> None:
        """
        SETTINGS_ENABLE_PUSH only allows two values: 0, 1.
        """
        assume(val not in (0, 1))
        s = h2.settings.Settings()

        with pytest.raises(h2.exceptions.InvalidSettingsValueError) as e:
            s.enable_push = val

        s.acknowledge()
        assert e.value.error_code == h2.errors.ErrorCodes.PROTOCOL_ERROR
        assert s.enable_push == 1

        with pytest.raises(h2.exceptions.InvalidSettingsValueError) as e:
            s[h2.settings.SettingCodes.ENABLE_PUSH] = val

        s.acknowledge()
        assert e.value.error_code == h2.errors.ErrorCodes.PROTOCOL_ERROR
        assert s[h2.settings.SettingCodes.ENABLE_PUSH] == 1

    @given(integers())
    def test_cannot_set_invalid_vals_for_initial_window_size(self, val) -> None:
        """
        SETTINGS_INITIAL_WINDOW_SIZE only allows values between 0 and 2**32 - 1
        inclusive.
        """
        s = h2.settings.Settings()

        if 0 <= val <= 2**31 - 1:
            s.initial_window_size = val
            s.acknowledge()
            assert s.initial_window_size == val
        else:
            with pytest.raises(h2.exceptions.InvalidSettingsValueError) as e:
                s.initial_window_size = val

            s.acknowledge()
            assert (
                e.value.error_code == h2.errors.ErrorCodes.FLOW_CONTROL_ERROR
            )
            assert s.initial_window_size == 65535

            with pytest.raises(h2.exceptions.InvalidSettingsValueError) as e:
                s[h2.settings.SettingCodes.INITIAL_WINDOW_SIZE] = val

            s.acknowledge()
            assert (
                e.value.error_code == h2.errors.ErrorCodes.FLOW_CONTROL_ERROR
            )
            assert s[h2.settings.SettingCodes.INITIAL_WINDOW_SIZE] == 65535

    @given(integers())
    def test_cannot_set_invalid_values_for_max_frame_size(self, val) -> None:
        """
        SETTINGS_MAX_FRAME_SIZE only allows values between 2**14 and 2**24 - 1.
        """
        s = h2.settings.Settings()

        if 2**14 <= val <= 2**24 - 1:
            s.max_frame_size = val
            s.acknowledge()
            assert s.max_frame_size == val
        else:
            with pytest.raises(h2.exceptions.InvalidSettingsValueError) as e:
                s.max_frame_size = val

            s.acknowledge()
            assert e.value.error_code == h2.errors.ErrorCodes.PROTOCOL_ERROR
            assert s.max_frame_size == 16384

            with pytest.raises(h2.exceptions.InvalidSettingsValueError) as e:
                s[h2.settings.SettingCodes.MAX_FRAME_SIZE] = val

            s.acknowledge()
            assert e.value.error_code == h2.errors.ErrorCodes.PROTOCOL_ERROR
            assert s[h2.settings.SettingCodes.MAX_FRAME_SIZE] == 16384

    @given(integers())
    def test_cannot_set_invalid_values_for_max_header_list_size(self, val) -> None:
        """
        SETTINGS_MAX_HEADER_LIST_SIZE only allows non-negative values.
        """
        s = h2.settings.Settings()

        if val >= 0:
            s.max_header_list_size = val
            s.acknowledge()
            assert s.max_header_list_size == val
        else:
            with pytest.raises(h2.exceptions.InvalidSettingsValueError) as e:
                s.max_header_list_size = val

            s.acknowledge()
            assert e.value.error_code == h2.errors.ErrorCodes.PROTOCOL_ERROR
            assert s.max_header_list_size is None

            with pytest.raises(h2.exceptions.InvalidSettingsValueError) as e:
                s[h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE] = val

            s.acknowledge()
            assert e.value.error_code == h2.errors.ErrorCodes.PROTOCOL_ERROR

            with pytest.raises(KeyError):
                s[h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE]

    @given(integers())
    def test_cannot_set_invalid_values_for_enable_connect_protocol(self, val) -> None:
        """
        SETTINGS_ENABLE_CONNECT_PROTOCOL only allows two values: 0, 1.
        """
        assume(val not in (0, 1))
        s = h2.settings.Settings()

        with pytest.raises(h2.exceptions.InvalidSettingsValueError) as e:
            s.enable_connect_protocol = val

        s.acknowledge()
        assert e.value.error_code == h2.errors.ErrorCodes.PROTOCOL_ERROR
        assert s.enable_connect_protocol == 0

        with pytest.raises(h2.exceptions.InvalidSettingsValueError) as e:
            s[h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL] = val

        s.acknowledge()
        assert e.value.error_code == h2.errors.ErrorCodes.PROTOCOL_ERROR
        assert s[h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL] == 0


class TestSettingsEquality:
    """
    A class defining tests for the standard implementation of == and != .
    """

    SettingsStrategy = builds(
        h2.settings.Settings,
        client=booleans(),
        initial_values=fixed_dictionaries({
            h2.settings.SettingCodes.HEADER_TABLE_SIZE:
                integers(0, 2**32 - 1),
            h2.settings.SettingCodes.ENABLE_PUSH: integers(0, 1),
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE:
                integers(0, 2**31 - 1),
            h2.settings.SettingCodes.MAX_FRAME_SIZE:
                integers(2**14, 2**24 - 1),
            h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS:
                integers(0, 2**32 - 1),
            h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE:
                integers(0, 2**32 - 1),
        }),
    )

    @given(settings=SettingsStrategy)
    def test_equality_reflexive(self, settings) -> None:
        """
        An object compares equal to itself using the == operator and the !=
        operator.
        """
        assert (settings == settings)
        assert settings == settings

    @given(settings=SettingsStrategy, o_settings=SettingsStrategy)
    def test_equality_multiple(self, settings, o_settings) -> None:
        """
        Two objects compare themselves using the == operator and the !=
        operator.
        """
        if settings == o_settings:
            assert settings == o_settings
            assert settings == o_settings
        else:
            assert settings != o_settings
            assert settings != o_settings

    @given(settings=SettingsStrategy)
    def test_another_type_equality(self, settings) -> None:
        """
        The object does not compare equal to an object of an unrelated type
        (which does not implement the comparison) using the == operator.
        """
        obj = object()
        assert (settings != obj)
        assert settings != obj

    @given(settings=SettingsStrategy)
    def test_delegated_eq(self, settings) -> None:
        """
        The result of comparison is delegated to the right-hand operand if
        it is of an unrelated type.
        """
        class Delegate:
            def __eq__(self, other):
                return [self]

            def __ne__(self, other):
                return [self]

        delg = Delegate()
        assert (settings == delg) == [delg]
        assert (settings != delg) == [delg]


class TestConnectionSettingsAcknowledgement:
    """
    Test that a connection applies acknowledged settings one SETTINGS frame
    at a time, in the order the frames were sent.
    """

    example_request_headers = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]

    def _initiate_connection(self, frame_factory, client):
        """
        Return a connection, either client- or server-side, that has sent
        its initial SETTINGS frame.
        """
        if client:
            c = h2.connection.H2Connection()
        else:
            config = h2.config.H2Configuration(client_side=False)
            c = h2.connection.H2Connection(config=config)
        c.initiate_connection()
        if not client:
            c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()
        return c

    def _open_stream(self, frame_factory, c, client):
        """
        Open stream 1 so that its flow control window can be observed.
        """
        if client:
            c.send_headers(1, self.example_request_headers, end_stream=True)
        else:
            f = frame_factory.build_headers_frame(
                self.example_request_headers,
            )
            c.receive_data(f.serialize())
        c.clear_outbound_data_buffer()

    @pytest.mark.parametrize("client", [True, False])
    def test_two_frames_different_settings(self, frame_factory, client) -> None:
        """
        Two SETTINGS frames changing different settings are applied by two
        separate ACKs, one frame at a time.
        """
        c = self._initiate_connection(frame_factory, client)

        c.update_settings({h2.settings.SettingCodes.HEADER_TABLE_SIZE: 100})
        c.update_settings({h2.settings.SettingCodes.MAX_FRAME_SIZE: 32768})
        c.clear_outbound_data_buffer()

        ack = frame_factory.build_settings_frame({}, ack=True).serialize()

        # The first ACK acknowledges the initial SETTINGS frame: nothing
        # changes.
        events = c.receive_data(ack)
        assert len(events) == 1
        assert isinstance(events[0], h2.events.SettingsAcknowledged)
        assert events[0].changed_settings == {}
        assert c.local_settings.header_table_size == 4096
        assert c.local_settings.max_frame_size == 16384
        assert c.max_inbound_frame_size == 16384

        # The second ACK applies only the HEADER_TABLE_SIZE change.
        events = c.receive_data(ack)
        assert len(events) == 1
        changes = events[0].changed_settings
        assert list(changes) == [h2.settings.SettingCodes.HEADER_TABLE_SIZE]
        change = changes[h2.settings.SettingCodes.HEADER_TABLE_SIZE]
        assert change.original_value == 4096
        assert change.new_value == 100
        assert c.local_settings.header_table_size == 100
        assert c.local_settings.max_frame_size == 16384
        assert c.max_inbound_frame_size == 16384

        # The third ACK applies only the MAX_FRAME_SIZE change.
        events = c.receive_data(ack)
        assert len(events) == 1
        changes = events[0].changed_settings
        assert list(changes) == [h2.settings.SettingCodes.MAX_FRAME_SIZE]
        change = changes[h2.settings.SettingCodes.MAX_FRAME_SIZE]
        assert change.original_value == 16384
        assert change.new_value == 32768
        assert c.local_settings.max_frame_size == 32768
        assert c.max_inbound_frame_size == 32768

    @pytest.mark.parametrize("client", [True, False])
    def test_same_setting_changed_in_consecutive_frames(self, frame_factory, client) -> None:
        """
        A setting changed in consecutive SETTINGS frames takes effect one
        frame at a time, adjusting existing streams' windows each time.
        """
        c = self._initiate_connection(frame_factory, client)
        self._open_stream(frame_factory, c, client)
        assert c.remote_flow_control_window(1) == 65535

        c.update_settings(
            {h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 1000},
        )
        c.update_settings(
            {h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 2000},
        )
        c.clear_outbound_data_buffer()

        ack = frame_factory.build_settings_frame({}, ack=True).serialize()

        # The first ACK acknowledges the initial SETTINGS frame: nothing
        # changes.
        events = c.receive_data(ack)
        assert events[0].changed_settings == {}
        assert c.local_settings.initial_window_size == 65535
        assert c.remote_flow_control_window(1) == 65535

        # The second ACK applies the first INITIAL_WINDOW_SIZE change.
        events = c.receive_data(ack)
        changes = events[0].changed_settings
        assert list(changes) == [h2.settings.SettingCodes.INITIAL_WINDOW_SIZE]
        change = changes[h2.settings.SettingCodes.INITIAL_WINDOW_SIZE]
        assert change.original_value == 65535
        assert change.new_value == 1000
        assert c.local_settings.initial_window_size == 1000
        assert c.remote_flow_control_window(1) == 1000

        # The third ACK applies the second INITIAL_WINDOW_SIZE change.
        events = c.receive_data(ack)
        changes = events[0].changed_settings
        assert list(changes) == [h2.settings.SettingCodes.INITIAL_WINDOW_SIZE]
        change = changes[h2.settings.SettingCodes.INITIAL_WINDOW_SIZE]
        assert change.original_value == 1000
        assert change.new_value == 2000
        assert c.local_settings.initial_window_size == 2000
        assert c.remote_flow_control_window(1) == 2000

    @pytest.mark.parametrize("client", [True, False])
    def test_empty_settings_frame_has_own_acknowledgement(self, frame_factory, client) -> None:
        """
        An empty SETTINGS frame occupies its own acknowledgement slot: its
        ACK does not apply changes from later frames.
        """
        c = self._initiate_connection(frame_factory, client)

        c.update_settings({})
        c.update_settings({h2.settings.SettingCodes.HEADER_TABLE_SIZE: 100})
        c.clear_outbound_data_buffer()

        ack = frame_factory.build_settings_frame({}, ack=True).serialize()

        # The first ACK acknowledges the initial SETTINGS frame.
        events = c.receive_data(ack)
        assert events[0].changed_settings == {}

        # The second ACK acknowledges the empty SETTINGS frame: nothing
        # changes.
        events = c.receive_data(ack)
        assert events[0].changed_settings == {}
        assert c.local_settings.header_table_size == 4096

        # The third ACK applies the HEADER_TABLE_SIZE change.
        events = c.receive_data(ack)
        changes = events[0].changed_settings
        assert list(changes) == [h2.settings.SettingCodes.HEADER_TABLE_SIZE]
        assert c.local_settings.header_table_size == 100

    @pytest.mark.parametrize("client", [True, False])
    def test_ack_with_nothing_outstanding(self, frame_factory, client) -> None:
        """
        An ACK received when no SETTINGS frame is awaiting acknowledgement
        changes nothing and does not error.
        """
        c = self._initiate_connection(frame_factory, client)

        ack = frame_factory.build_settings_frame({}, ack=True).serialize()

        # Acknowledge the initial SETTINGS frame.
        events = c.receive_data(ack)
        assert events[0].changed_settings == {}

        # A further ACK has nothing to acknowledge.
        events = c.receive_data(ack)
        assert len(events) == 1
        assert isinstance(events[0], h2.events.SettingsAcknowledged)
        assert events[0].changed_settings == {}
        assert c.local_settings.header_table_size == 4096

    @pytest.mark.parametrize("client", [True, False])
    def test_received_frames_apply_in_order(self, frame_factory, client) -> None:
        """
        Received SETTINGS frames take effect one frame at a time, emitting
        one event per frame and adjusting existing streams' windows by each
        frame's delta.
        """
        c = self._initiate_connection(frame_factory, client)
        self._open_stream(frame_factory, c, client)
        assert c.local_flow_control_window(1) == 65535

        # The first frame changes HEADER_TABLE_SIZE only.
        f = frame_factory.build_settings_frame(
            {h2.settings.SettingCodes.HEADER_TABLE_SIZE: 100},
        )
        events = c.receive_data(f.serialize())
        assert len(events) == 1
        assert isinstance(events[0], h2.events.RemoteSettingsChanged)
        changes = events[0].changed_settings
        assert list(changes) == [h2.settings.SettingCodes.HEADER_TABLE_SIZE]
        change = changes[h2.settings.SettingCodes.HEADER_TABLE_SIZE]
        assert change.original_value == 4096
        assert change.new_value == 100
        assert c.remote_settings.header_table_size == 100
        assert c.remote_settings.max_frame_size == 16384
        assert c.max_outbound_frame_size == 16384

        # The second frame changes MAX_FRAME_SIZE only.
        f = frame_factory.build_settings_frame(
            {h2.settings.SettingCodes.MAX_FRAME_SIZE: 32768},
        )
        events = c.receive_data(f.serialize())
        assert len(events) == 1
        changes = events[0].changed_settings
        assert list(changes) == [h2.settings.SettingCodes.MAX_FRAME_SIZE]
        change = changes[h2.settings.SettingCodes.MAX_FRAME_SIZE]
        assert change.original_value == 16384
        assert change.new_value == 32768
        assert c.remote_settings.max_frame_size == 32768
        assert c.max_outbound_frame_size == 32768

        # Two consecutive frames change INITIAL_WINDOW_SIZE: the stream
        # window follows each frame's delta.
        f = frame_factory.build_settings_frame(
            {h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 1000},
        )
        events = c.receive_data(f.serialize())
        assert len(events) == 1
        changes = events[0].changed_settings
        assert list(changes) == [h2.settings.SettingCodes.INITIAL_WINDOW_SIZE]
        change = changes[h2.settings.SettingCodes.INITIAL_WINDOW_SIZE]
        assert change.original_value == 65535
        assert change.new_value == 1000
        assert c.remote_settings.initial_window_size == 1000
        assert c.local_flow_control_window(1) == 1000

        f = frame_factory.build_settings_frame(
            {h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 2000},
        )
        events = c.receive_data(f.serialize())
        assert len(events) == 1
        changes = events[0].changed_settings
        assert list(changes) == [h2.settings.SettingCodes.INITIAL_WINDOW_SIZE]
        change = changes[h2.settings.SettingCodes.INITIAL_WINDOW_SIZE]
        assert change.original_value == 1000
        assert change.new_value == 2000
        assert c.remote_settings.initial_window_size == 2000
        assert c.local_flow_control_window(1) == 2000
