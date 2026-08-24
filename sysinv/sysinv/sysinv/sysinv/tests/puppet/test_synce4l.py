# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Unit tests for synce4l parameter handling in networking puppet module.
# Validates: monitoring params, no sysfs eec_get_state_cmd,
#            external source section rendering

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
            'external_sources': [],
        }

    def _make_ptp4l_instance(self, name='test_ptp4l'):
        return self._make_instance(name=name, service='ptp4l')

    # ===================================================================
    # Monitoring parameters
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
    # Interface auto-populated in monitoring_parameters
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
    # No sysfs eec_get_state_cmd default
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
        expected_keys = ['extended_tlv', 'network_option', 'recover_time']
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
    # External clock source section
    # ===================================================================

    def test_external_source_populated_when_param_set(self):
        """external_source populated when interface has external_source param (E810)."""
        iface_params = [
            {'name': 'external_source', 'value': 'SMA1',
             'owners': ['iface-uuid-1']},
        ]
        result = self.operator._set_external_source_parameters(
            'iface-uuid-1', iface_params, 'enp81s0f0')
        self.assertIn('name', result)
        self.assertEqual(result['name'], 'SMA1')
        self.assertIn('params', result)
        # All ice NICs use board_label via DPLL netlink
        self.assertEqual(result['params']['board_label'], 'SMA1')
        # Must NOT have sysfs commands
        self.assertNotIn('external_enable_cmd', result['params'])
        self.assertNotIn('external_disable_cmd', result['params'])

    def test_external_source_empty_when_no_param(self):
        """external_source empty when no external_source param on interface."""
        iface_params = [
            {'name': 'recover_time', 'value': '20',
             'owners': ['iface-uuid-1']},
        ]
        result = self.operator._set_external_source_parameters(
            'iface-uuid-1', iface_params, 'enp81s0f0')
        self.assertEqual(result, {})

    def test_external_source_unknown_pin_gets_board_label(self):
        """Unknown pin name is passed through as board_label (user-specified)."""
        iface_params = [
            {'name': 'external_source', 'value': 'CUSTOM_PIN_LABEL',
             'owners': ['iface-uuid-1']},
        ]
        result = self.operator._set_external_source_parameters(
            'iface-uuid-1', iface_params, 'enp81s0f0')
        self.assertIn('name', result)
        self.assertEqual(result['name'], 'CUSTOM_PIN_LABEL')
        self.assertEqual(result['params']['board_label'], 'CUSTOM_PIN_LABEL')

    # ===================================================================
    # GNR-D (E825/zl3073x) external source — DPLL mode
    # ===================================================================

    def test_external_source_gnrd_generates_board_label(self):
        """GNR-D external source produces board_label, no sysfs commands."""
        iface_params = [
            {'name': 'external_source', 'value': 'GNSS_1PPS_IN',
             'owners': ['iface-uuid-1']},
        ]
        result = self.operator._set_external_source_parameters(
            'iface-uuid-1', iface_params, 'enp81s0f0')
        self.assertIn('name', result)
        self.assertEqual(result['name'], 'GNSS_1PPS_IN')
        self.assertIn('params', result)
        # Must have board_label matching the kernel DPLL pin
        self.assertEqual(result['params']['board_label'], 'GNSS_1PPS_IN')
        # Must NOT have sysfs commands (DPLL netlink handles pin control)
        self.assertNotIn('external_enable_cmd', result['params'])
        self.assertNotIn('external_disable_cmd', result['params'])
        # Must have default QL values
        self.assertEqual(result['params']['input_QL'],
                         constants.PTP_SYNCE_EXTERNAL_INPUT_QL)
        self.assertEqual(result['params']['input_ext_QL'],
                         constants.PTP_SYNCE_EXTERNAL_INPUT_EXT_QL)

    def test_external_source_gnrd_gnss_10m(self):
        """GNR-D GNSS_10M_IN pin produces correct section."""
        iface_params = [
            {'name': 'external_source', 'value': 'GNSS_10M_IN',
             'owners': ['iface-uuid-1']},
        ]
        result = self.operator._set_external_source_parameters(
            'iface-uuid-1', iface_params, 'enp81s0f0')
        self.assertEqual(result['name'], 'GNSS_10M_IN')
        self.assertEqual(result['params']['board_label'], 'GNSS_10M_IN')
        self.assertNotIn('external_enable_cmd', result['params'])

    def test_external_source_gnrd_1epps_in(self):
        """GNR-D 1EPPS_IN pin produces correct section."""
        iface_params = [
            {'name': 'external_source', 'value': '1EPPS_IN',
             'owners': ['iface-uuid-1']},
        ]
        result = self.operator._set_external_source_parameters(
            'iface-uuid-1', iface_params, 'enp81s0f0')
        self.assertEqual(result['name'], '1EPPS_IN')
        self.assertEqual(result['params']['board_label'], '1EPPS_IN')

    def test_external_source_gnrd_user_ql_override(self):
        """GNR-D user-supplied input_QL overrides default."""
        iface_params = [
            {'name': 'external_source', 'value': 'GNSS_1PPS_IN',
             'owners': ['iface-uuid-1']},
            {'name': 'input_QL', 'value': '0x01',
             'owners': ['iface-uuid-1']},
            {'name': 'input_ext_QL', 'value': '0x21',
             'owners': ['iface-uuid-1']},
        ]
        result = self.operator._set_external_source_parameters(
            'iface-uuid-1', iface_params, 'enp81s0f0')
        self.assertEqual(result['params']['input_QL'], '0x01')
        self.assertEqual(result['params']['input_ext_QL'], '0x21')
        self.assertEqual(result['params']['board_label'], 'GNSS_1PPS_IN')

    def test_external_source_gnrd_user_board_label_override(self):
        """User can override board_label if kernel pin label differs."""
        iface_params = [
            {'name': 'external_source', 'value': 'GNSS_1PPS_IN',
             'owners': ['iface-uuid-1']},
            {'name': 'board_label', 'value': 'CUSTOM_LABEL',
             'owners': ['iface-uuid-1']},
        ]
        result = self.operator._set_external_source_parameters(
            'iface-uuid-1', iface_params, 'enp81s0f0')
        self.assertEqual(result['params']['board_label'], 'CUSTOM_LABEL')

    def test_external_source_gnrd_unknown_pin_still_generates(self):
        """GNR-D with unknown pin generates section (synce4l validates at runtime)."""
        iface_params = [
            {'name': 'external_source', 'value': 'FUTURE_PIN',
             'owners': ['iface-uuid-1']},
        ]
        result = self.operator._set_external_source_parameters(
            'iface-uuid-1', iface_params, 'enp81s0f0')
        self.assertIn('name', result)
        self.assertEqual(result['params']['board_label'], 'FUTURE_PIN')

    # ===================================================================
    # E810 must NOT get clock_id/module_name auto-detection
    #              E825/GNR-D MUST get module_name=zl3073x + clock_id
    # ===================================================================

    def _make_host(self, hostname='controller-0'):
        host = mock.MagicMock()
        host.id = 1
        host.hostname = hostname
        return host

    def _make_port(self, name, pdevice, mac='aa:bb:cc:dd:ee:ff',
                   driver='ice', pciaddr='0000:13:00.0'):
        port = mock.MagicMock()
        port.name = name
        port.pdevice = pdevice
        port.mac = mac
        port_data = {
            'name': name, 'driver': driver, 'pciaddr': pciaddr,
            'pdevice': pdevice, 'mac': mac,
        }
        port.get = mock.MagicMock(
            side_effect=lambda k, d='': port_data.get(k, d))
        port.__getitem__ = mock.MagicMock(
            side_effect=lambda k: port_data[k])
        return port

    def _make_synce4l_for_interface_params(self, name='synce_t1'):
        """Create instance ready for _set_ptp_instance_interface_parameters."""
        inst = self._make_instance(name=name)
        inst['device_parameters'] = {
            'extended_tlv': constants.PTP_SYNCE_EXTERNAL_TLV,
            'network_option': constants.PTP_SYNCE_NETWORK_OPTION,
            'recover_time': constants.PTP_SYNCE_RECOVER_TIME,
        }
        inst['interfaces'] = [{
            'ifname': 'enp81s0f0',
            'port_names': ['enp81s0f0'],
            'parameters': {},
            'uuid': str(uuidutils.uuid4()),
        }]
        return inst

    def test_e810_auto_generates_module_name_ice_and_clock_id(self):
        """E810 port gets module_name=ice and clock_id from MAC (EUI-64).

        All ice-driver NICs use DPLL netlink mode. E810 gets module_name=ice
        and clock_id derived from the base port MAC as EUI-64.
        """
        host = self._make_host()
        e810_port = self._make_port(
            'enp81s0f0', 'Ethernet Controller E810-XXV for backplane',
            mac='a0:b0:c0:d0:e0:f0')
        self.operator.dbapi.ethernet_port_get_by_host.return_value = \
            [e810_port]

        inst = self._make_synce4l_for_interface_params()
        instances = {inst['name']: inst}

        self.operator._set_synce4l_dpll_parameters(
            host, instances)

        self.assertEqual(
            inst['device_parameters']['module_name'], 'ice')
        # EUI-64: a0b0c0 + ffff + d0e0f0 = a0b0c0ffffd0e0f0
        expected_clock_id = str(int('a0b0c0ffffd0e0f0', 16))
        self.assertEqual(
            inst['device_parameters']['clock_id'], expected_clock_id)

    def test_e825_auto_generates_module_name_and_clock_id(self):
        """E825 (GNR-D) gets module_name=zl3073x and clock_id from port capabilities.

        E825 uses DPLL netlink mode. synce4l needs clock_id and module_name
        to find the correct DPLL device via netlink. The clock_id is
        read from the port capabilities (reported by sysinv-agent).
        """
        host = self._make_host()
        e825_port = self._make_port(
            'enp81s0f0', 'Ethernet Controller E825-C for backplane')
        e825_port.capabilities = {'dpll_clock_id': '12345678'}
        self.operator.dbapi.ethernet_port_get_by_host.return_value = \
            [e825_port]

        inst = self._make_synce4l_for_interface_params()
        instances = {inst['name']: inst}

        self.operator._set_synce4l_dpll_parameters(
            host, instances)

        self.assertEqual(
            inst['device_parameters']['module_name'], 'zl3073x')
        self.assertEqual(
            inst['device_parameters']['clock_id'], '12345678')

    def test_e825_user_clock_id_not_overridden(self):
        """User-supplied clock_id is preserved (not overridden by auto-detect)."""
        host = self._make_host()
        e825_port = self._make_port(
            'enp81s0f0', 'Ethernet Controller E825-C for backplane')
        self.operator.dbapi.ethernet_port_get_by_host.return_value = \
            [e825_port]

        inst = self._make_synce4l_for_interface_params()
        inst['device_parameters']['clock_id'] = '99999'
        inst['device_parameters']['module_name'] = 'zl3073x'
        instances = {inst['name']: inst}

        self.operator._set_synce4l_dpll_parameters(
            host, instances)

        # User values preserved — auto-detect skipped
        self.assertEqual(inst['device_parameters']['clock_id'], '99999')
        self.assertEqual(
            inst['device_parameters']['module_name'], 'zl3073x')

    # ===================================================================
    # E810/E830 external source — DPLL netlink mode (board_label)
    # ===================================================================

    def test_external_source_e830_gnss_1pps(self):
        """E830 GNSS-1PPS pin produces board_label section."""
        iface_params = [
            {'name': 'external_source', 'value': 'GNSS-1PPS',
             'owners': ['iface-uuid-1']},
        ]
        result = self.operator._set_external_source_parameters(
            'iface-uuid-1', iface_params, 'enp108s0f0')
        self.assertIn('name', result)
        self.assertEqual(result['name'], 'GNSS-1PPS')
        self.assertEqual(result['params']['board_label'], 'GNSS-1PPS')
        self.assertNotIn('external_enable_cmd', result['params'])
        self.assertNotIn('external_disable_cmd', result['params'])

    def test_external_source_e810_sma1(self):
        """E810 SMA1 pin produces board_label section (not sysfs commands)."""
        iface_params = [
            {'name': 'external_source', 'value': 'SMA1',
             'owners': ['iface-uuid-1']},
        ]
        result = self.operator._set_external_source_parameters(
            'iface-uuid-1', iface_params, 'enp81s0f0')
        self.assertEqual(result['name'], 'SMA1')
        self.assertEqual(result['params']['board_label'], 'SMA1')
        self.assertNotIn('external_enable_cmd', result['params'])
        self.assertNotIn('external_disable_cmd', result['params'])

    # ===================================================================
    # Multiple external sources per instance
    # ===================================================================

    def test_multiple_external_sources_appended(self):
        """Two interfaces with external_source produce two entries in list."""
        inst = self._make_instance(name='synce_dual')
        iface1_uuid = str(uuidutils.uuid4())
        iface2_uuid = str(uuidutils.uuid4())
        inst['interfaces'] = [
            {
                'ifname': 'eno8303',
                'port_names': ['eno8303'],
                'parameters': {},
                'uuid': iface1_uuid,
            },
            {
                'ifname': 'eno8403',
                'port_names': ['eno8403'],
                'parameters': {},
                'uuid': iface2_uuid,
            },
        ]
        ptp_parameters_interface = [
            {'name': 'external_source', 'value': 'GNSS_1PPS_IN',
             'owners': [iface1_uuid]},
            {'name': 'internal_prio', 'value': '128',
             'owners': [iface1_uuid]},
            {'name': 'external_source', 'value': 'CLK_78M125_NAC0_SYNCE0',
             'owners': [iface2_uuid]},
            {'name': 'internal_prio', 'value': '0',
             'owners': [iface2_uuid]},
            {'name': 'source_ports', 'value': 'eno8303',
             'owners': [iface2_uuid]},
        ]
        host = self._make_host()
        port1 = self._make_port('eno8303',
                                'Ethernet Controller E825-C for backplane')
        port2 = self._make_port('eno8403',
                                'Ethernet Controller E825-C for backplane',
                                pciaddr='0000:13:00.1')
        self.operator.dbapi.ethernet_port_get_by_host.return_value = \
            [port1, port2]

        ptp_instances = {'synce_dual': inst}
        self.operator._set_ptp_instance_interface_parameters(
            host, ptp_instances, ptp_parameters_interface)

        ext_sources = ptp_instances['synce_dual']['external_sources']
        self.assertEqual(len(ext_sources), 2)
        # First ext_src: GNSS
        self.assertEqual(ext_sources[0]['name'], 'GNSS_1PPS_IN')
        self.assertEqual(ext_sources[0]['params']['internal_prio'], '128')
        self.assertEqual(ext_sources[0]['params']['board_label'],
                         'GNSS_1PPS_IN')
        # Second ext_src: SyncE rclk
        self.assertEqual(ext_sources[1]['name'], 'CLK_78M125_NAC0_SYNCE0')
        self.assertEqual(ext_sources[1]['params']['internal_prio'], '0')
        self.assertEqual(ext_sources[1]['params']['source_ports'], 'eno8303')
        self.assertEqual(ext_sources[1]['params']['board_label'],
                         'CLK_78M125_NAC0_SYNCE0')

    def test_single_external_source_still_works(self):
        """Single interface with external_source produces list of one."""
        inst = self._make_instance(name='synce_single')
        iface_uuid = str(uuidutils.uuid4())
        inst['interfaces'] = [
            {
                'ifname': 'eno8303',
                'port_names': ['eno8303'],
                'parameters': {},
                'uuid': iface_uuid,
            },
        ]
        ptp_parameters_interface = [
            {'name': 'external_source', 'value': 'GNSS_1PPS_IN',
             'owners': [iface_uuid]},
        ]
        host = self._make_host()
        port = self._make_port('eno8303',
                               'Ethernet Controller E825-C for backplane')
        self.operator.dbapi.ethernet_port_get_by_host.return_value = [port]

        ptp_instances = {'synce_single': inst}
        self.operator._set_ptp_instance_interface_parameters(
            host, ptp_instances, ptp_parameters_interface)

        ext_sources = ptp_instances['synce_single']['external_sources']
        self.assertEqual(len(ext_sources), 1)
        self.assertEqual(ext_sources[0]['name'], 'GNSS_1PPS_IN')

    def test_no_external_source_produces_empty_list(self):
        """Interface without external_source leaves external_sources empty."""
        inst = self._make_instance(name='synce_plain')
        iface_uuid = str(uuidutils.uuid4())
        inst['interfaces'] = [
            {
                'ifname': 'eno8303',
                'port_names': ['eno8303'],
                'parameters': {},
                'uuid': iface_uuid,
            },
        ]
        ptp_parameters_interface = [
            {'name': 'rx_heartbeat_msec', 'value': '500',
             'owners': [iface_uuid]},
        ]
        host = self._make_host()
        port = self._make_port('eno8303',
                               'Ethernet Controller E825-C for backplane')
        self.operator.dbapi.ethernet_port_get_by_host.return_value = [port]

        ptp_instances = {'synce_plain': inst}
        self.operator._set_ptp_instance_interface_parameters(
            host, ptp_instances, ptp_parameters_interface)

        ext_sources = ptp_instances['synce_plain']['external_sources']
        self.assertEqual(ext_sources, [])

    def test_multiple_ext_sources_same_port_deduplicates(self):
        """Two ptp-interfaces on same port produce one port section."""
        inst = self._make_instance(name='synce_dedup')
        iface1_uuid = str(uuidutils.uuid4())
        iface2_uuid = str(uuidutils.uuid4())
        inst['interfaces'] = [
            {
                'ifname': 'data0',
                'port_names': ['eno8303'],
                'parameters': {},
                'uuid': iface1_uuid,
            },
            {
                'ifname': 'data0',
                'port_names': ['eno8303'],
                'parameters': {},
                'uuid': iface2_uuid,
            },
        ]
        ptp_parameters_interface = [
            {'name': 'external_source', 'value': 'GNSS_1PPS_IN',
             'owners': [iface1_uuid]},
            {'name': 'internal_prio', 'value': '128',
             'owners': [iface1_uuid]},
            {'name': 'external_source', 'value': 'CLK_78M125_NAC0_SYNCE0',
             'owners': [iface2_uuid]},
            {'name': 'internal_prio', 'value': '0',
             'owners': [iface2_uuid]},
            {'name': 'source_ports', 'value': 'eno8303',
             'owners': [iface2_uuid]},
        ]
        host = self._make_host()
        port = self._make_port('eno8303',
                               'Ethernet Controller E825-C for backplane')
        self.operator.dbapi.ethernet_port_get_by_host.return_value = [port]

        ptp_instances = {'synce_dedup': inst}
        self.operator._set_ptp_instance_interface_parameters(
            host, ptp_instances, ptp_parameters_interface)

        # Only one port section after deduplication
        interfaces = ptp_instances['synce_dedup']['interfaces']
        self.assertEqual(len(interfaces), 1)
        self.assertEqual(interfaces[0]['port_names'], ['eno8303'])
        # But both ext_src sections are present
        ext_sources = ptp_instances['synce_dedup']['external_sources']
        self.assertEqual(len(ext_sources), 2)
        self.assertEqual(ext_sources[0]['name'], 'GNSS_1PPS_IN')
        self.assertEqual(ext_sources[1]['name'], 'CLK_78M125_NAC0_SYNCE0')
