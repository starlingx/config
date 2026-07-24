# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Unit tests for synce4l parameter handling in networking puppet module.
# Validates: CGTS-100128 (monitoring params), CGTS-100134 (no sysfs),
#            CGTS-100129 (external source)

import mock
import uuid as uuidutils

from sysinv.common import constants
from sysinv.puppet import networking as networking_puppet
from sysinv.tests import base as test_base


class TestSynce4lParameters(test_base.TestCase):
    """Test synce4l parameter routing in NetworkingPuppet.

    These tests call _set_ptp_instance_global_parameters() directly
    with mock instance data to validate parameter routing without
    requiring a full DB-backed host setup.
    """

    def setUp(self):
        super(TestSynce4lParameters, self).setUp()
        self.mock_operator = mock.MagicMock()
        self.mock_operator.dbapi = mock.MagicMock()
        self.operator = networking_puppet.NetworkingPuppet(self.mock_operator)

    def _make_instance(self, name='synce_test', service='synce4l',
                       uuid_val=None):
        """Create a minimal PTP instance dict matching DB as_dict() output."""
        return {
            'id': 1,
            'uuid': uuid_val or str(uuidutils.uuid4()),
            'name': name,
            'service': service,
            'interfaces': [],
            'global_parameters': {},
            'device_parameters': {},
            'monitoring_parameters': {},
            'section_parameters': {},
            'cmdline_opts': '',
            'pmc_gm_settings': {},
            'gnss_uart_disable': True,
            'external_source': {},
        }

    def _make_ptp4l_instance(self, name='test_ptp4l'):
        return self._make_instance(name=name, service='ptp4l')

    # ===================================================================
    # CGTS-100128: Monitoring parameters
    # ===================================================================

    def test_synce4l_monitoring_params_have_defaults(self):
        """synce4l instance gets default monitoring_parameters."""
        instances = [self._make_instance()]
        self.operator._set_ptp_instance_global_parameters(
            instances, [])
        inst = instances[0]
        ptp_config = {inst['name']: inst}
        self.operator._set_ptp_instance_monitoring_parameters(
            ptp_config, [])
        self.assertIn('holdover_ql', inst['monitoring_parameters'])
        self.assertIn('freerun_ql', inst['monitoring_parameters'])
        self.assertIn('holdover_timer', inst['monitoring_parameters'])
        self.assertIn('source', inst['monitoring_parameters'])
        self.assertEqual(inst['monitoring_parameters']['holdover_ql'],
                         constants.PTP_SYNCE_HOLDOVER_QL)
        self.assertEqual(inst['monitoring_parameters']['freerun_ql'],
                         constants.PTP_SYNCE_FREERUN_QL)
        self.assertEqual(inst['monitoring_parameters']['holdover_timer'],
                         constants.PTP_SYNCE_HOLDOVER_TIMER)
        self.assertEqual(inst['monitoring_parameters']['source'],
                         constants.PTP_SYNCE_SOURCE_PRIORITY)

    def test_synce4l_smc_socket_path_in_global_and_monitoring(self):
        """smc_socket_path set in both global_parameters and monitoring_parameters."""
        instances = [self._make_instance()]
        self.operator._set_ptp_instance_global_parameters(
            instances, [])
        inst = instances[0]
        ptp_config = {inst['name']: inst}
        self.operator._set_ptp_instance_monitoring_parameters(
            ptp_config, [])
        expected_socket = '/tmp/synce4l_socket_synce_test'
        self.assertEqual(inst['global_parameters']['smc_socket_path'],
                         expected_socket)
        self.assertEqual(inst['monitoring_parameters']['smc_socket_path'],
                         expected_socket)

    def test_synce4l_user_override_routes_to_monitoring(self):
        """User-supplied holdover_ql via monitoring section overrides default."""
        uuid_val = str(uuidutils.uuid4())
        instances = [self._make_instance(uuid_val=uuid_val)]
        self.operator._set_ptp_instance_global_parameters(
            instances, [])
        inst = instances[0]
        inst['interfaces'] = [
            {'ifname': 'enp81s0f1', 'port_names': ['enp81s0f1'],
             'parameters': {}, 'uuid': str(uuidutils.uuid4())}
        ]
        # User sets holdover_ql via --section monitoring
        monitoring_param = {
            'name': 'holdover_ql',
            'value': '0x02',
            'section': 'monitoring',
            'owners': [uuid_val],
        }
        ptp_config = {inst['name']: inst}
        self.operator._set_ptp_instance_monitoring_parameters(
            ptp_config, [monitoring_param])
        self.assertEqual(inst['monitoring_parameters']['holdover_ql'],
                         '0x02')

    def test_synce4l_monitoring_params_in_global_go_to_device(self):
        """Monitoring params in global section fall through to device_parameters."""
        uuid_val = str(uuidutils.uuid4())
        instances = [self._make_instance(uuid_val=uuid_val)]
        user_param = {
            'name': 'holdover_ql',
            'value': '0x02',
            'section': 'global',
            'owners': [uuid_val],
        }
        self.operator._set_ptp_instance_global_parameters(
            instances, [user_param])
        inst = instances[0]
        ptp_config = {inst['name']: inst}
        self.operator._set_ptp_instance_monitoring_parameters(
            ptp_config, [])
        # Goes to device_parameters (synce4l ignores unknown params)
        self.assertEqual(inst['device_parameters']['holdover_ql'], '0x02')
        # Default monitoring value remains unchanged
        self.assertEqual(inst['monitoring_parameters']['holdover_ql'],
                         constants.PTP_SYNCE_HOLDOVER_QL)

    @mock.patch('sysinv.common.utils.is_centos', return_value=False)
    def test_ptp4l_instance_no_monitoring_params(self, mock_centos):
        """ptp4l instances do not get synce monitoring_parameters."""
        instances = [self._make_ptp4l_instance()]
        self.operator._set_ptp_instance_global_parameters(
            instances, [])
        inst = instances[0]
        self.assertEqual(inst['monitoring_parameters'], {})

    # ===================================================================
    # CGTS-102081: Interface auto-populated in monitoring_parameters
    # ===================================================================

    def test_synce4l_interface_auto_populated_in_monitoring(self):
        """interface auto-populated from assigned ptp-interface port."""
        instances = [self._make_instance()]
        self.operator._set_ptp_instance_global_parameters(
            instances, [])
        inst = instances[0]
        # Simulate interfaces already resolved by _set_ptp_instance_interfaces
        inst['interfaces'] = [
            {'ifname': 'enp81s0f1', 'port_names': ['enp81s0f1'],
             'parameters': {}, 'uuid': str(uuidutils.uuid4())}
        ]
        ptp_config = {inst['name']: inst}
        self.operator._set_ptp_instance_monitoring_parameters(
            ptp_config, [])
        self.assertIn('interface', inst['monitoring_parameters'])
        self.assertEqual(inst['monitoring_parameters']['interface'],
                         'enp81s0f1')

    def test_synce4l_interface_not_overridden_when_explicit(self):
        """User-supplied interface in monitoring section is not overridden."""
        uuid_val = str(uuidutils.uuid4())
        instances = [self._make_instance(uuid_val=uuid_val)]
        self.operator._set_ptp_instance_global_parameters(
            instances, [])
        inst = instances[0]
        inst['interfaces'] = [
            {'ifname': 'enp81s0f1', 'port_names': ['enp81s0f1'],
             'parameters': {}, 'uuid': str(uuidutils.uuid4())}
        ]
        # User explicitly set interface in monitoring section
        monitoring_param = {
            'name': 'interface',
            'value': 'enp81s0f0',
            'section': 'monitoring',
            'owners': [uuid_val],
        }
        ptp_config = {inst['name']: inst}
        self.operator._set_ptp_instance_monitoring_parameters(
            ptp_config, [monitoring_param])
        # Should keep the user-supplied value, not override with port_names
        self.assertEqual(inst['monitoring_parameters']['interface'],
                         'enp81s0f0')

    def test_synce4l_no_interface_when_no_ports_assigned(self):
        """No interface set when instance has no assigned interfaces."""
        instances = [self._make_instance()]
        self.operator._set_ptp_instance_global_parameters(
            instances, [])
        inst = instances[0]
        inst['interfaces'] = []
        ptp_config = {inst['name']: inst}
        self.operator._set_ptp_instance_monitoring_parameters(
            ptp_config, [])
        self.assertNotIn('interface', inst['monitoring_parameters'])

    # ===================================================================
    # CGTS-100134: No sysfs eec_get_state_cmd
    # ===================================================================

    def test_synce4l_no_eec_get_state_cmd_in_device_params(self):
        """synce4l device_parameters does not contain eec_get_state_cmd."""
        instances = [self._make_instance()]
        self.operator._set_ptp_instance_global_parameters(
            instances, [])
        inst = instances[0]
        self.assertNotIn('eec_get_state_cmd', inst['device_parameters'])

    def test_synce4l_no_eec_values_in_device_params(self):
        """eec_*_value sysfs mapping defaults are not in device_parameters."""
        instances = [self._make_instance()]
        self.operator._set_ptp_instance_global_parameters(
            instances, [])
        inst = instances[0]
        eec_keys = ['eec_holdover_value', 'eec_locked_ho_value',
                    'eec_locked_value', 'eec_freerun_value',
                    'eec_invalid_value']
        for key in eec_keys:
            self.assertNotIn(key, inst['device_parameters'])

    def test_synce4l_valid_device_params_present(self):
        """Valid synce4l device_parameters still populated after sysfs removal."""
        instances = [self._make_instance()]
        self.operator._set_ptp_instance_global_parameters(
            instances, [])
        inst = instances[0]
        expected_keys = ['input_mode', 'input_QL', 'input_ext_QL',
                         'extended_tlv', 'network_option', 'recover_time']
        for key in expected_keys:
            self.assertIn(key, inst['device_parameters'],
                          '%s missing from device_parameters' % key)

    def test_synce4l_user_supplied_eec_get_state_cmd_allowed(self):
        """User can still explicitly supply eec_get_state_cmd."""
        uuid_val = str(uuidutils.uuid4())
        instances = [self._make_instance(uuid_val=uuid_val)]
        user_param = {
            'name': 'eec_get_state_cmd',
            'value': 'cat /custom/path',
            'section': 'global',
            'owners': [uuid_val],
        }
        self.operator._set_ptp_instance_global_parameters(
            instances, [user_param])
        inst = instances[0]
        self.assertEqual(inst['device_parameters']['eec_get_state_cmd'],
                         'cat /custom/path')

    # ===================================================================
    # CGTS-100129: External clock source section
    # ===================================================================

    @mock.patch('glob.glob')
    @mock.patch('builtins.open', mock.mock_open(read_data='pin_func 1 pin_channel 0'))
    def test_external_source_populated_when_param_set(self, mock_glob):
        """external_source populated when interface has external_source param."""
        mock_glob.return_value = [
            '/sys/class/net/enp81s0f0/device/ptp/ptp0/pins/SMA1'
        ]
        iface_uuid = str(uuidutils.uuid4())
        iface_params = [
            {'name': 'external_source', 'value': 'SMA1',
             'owners': [iface_uuid]},
        ]
        result = self.operator._set_external_source_parameters(
            iface_uuid, iface_params, 'enp81s0f0')
        self.assertIn('name', result)
        self.assertEqual(result['name'], 'SMA1')
        self.assertIn('params', result)
        self.assertIn('external_enable_cmd', result['params'])
        self.assertIn('external_disable_cmd', result['params'])

    def test_external_source_empty_when_no_param(self):
        """external_source empty when no external_source param on interface."""
        iface_uuid = str(uuidutils.uuid4())
        iface_params = [
            {'name': 'recover_time', 'value': '20',
             'owners': [iface_uuid]},
        ]
        result = self.operator._set_external_source_parameters(
            iface_uuid, iface_params, 'enp81s0f0')
        self.assertEqual(result, {})

    @mock.patch('glob.glob')
    def test_external_source_empty_when_pin_not_found(self, mock_glob):
        """external_source gracefully empty when NIC pin sysfs not found."""
        mock_glob.return_value = []
        iface_uuid = str(uuidutils.uuid4())
        iface_params = [
            {'name': 'external_source', 'value': 'SMA1',
             'owners': [iface_uuid]},
        ]
        result = self.operator._set_external_source_parameters(
            iface_uuid, iface_params, 'enp81s0f0')
        self.assertEqual(result, {})
