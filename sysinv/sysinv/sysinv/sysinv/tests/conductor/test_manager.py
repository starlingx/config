# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8

# Copyright 2013 Hewlett-Packard Development Company, L.P.
# Copyright 2013 International Business Machines Corporation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2019 Wind River Systems, Inc.
#

"""Test class for Sysinv ManagerService."""

import mock
import os.path
import tsconfig.tsconfig as tsc
import uuid

from sysinv.agent import rpcapi as agent_rpcapi
from sysinv.common import constants
from sysinv.common import device as dconstants
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import utils as cutils
from sysinv.conductor import manager
from sysinv.db import api as dbapi
from sysinv.openstack.common import context

from sysinv.tests.db import base
from sysinv.tests.db import utils


class FakeCephOperator(object):

    def __init__(self, db_api):
        self.dbapi = dbapi


class FakePuppetOperator(object):

    def __init__(self, db_api):
        self.dbapi = dbapi
        self.update_host_config = mock.MagicMock()
        self.update_system_config = mock.MagicMock()
        self.update_secure_system_config = mock.MagicMock()


class FakePopen(object):

    def __init__(self, **kwargs):
        # Pretend all is OK
        self.returncode = 0

    def communicate(self):
        return "Fake stdout", "Fake stderr"


class ManagerTestCase(base.DbTestCase):

    def setUp(self):
        super(ManagerTestCase, self).setUp()

        # Set up objects for testing
        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()
        self.context = context.get_admin_context()
        self.dbapi = dbapi.get_instance()
        self.system = utils.create_test_isystem()
        self.load = utils.create_test_load()
        self.dnsmasq_hosts_file = '/tmp/dnsmasq.hosts'

        # Mock the ceph operator
        self.fake_ceph_operator = FakeCephOperator(self.dbapi)
        p = mock.patch('sysinv.conductor.ceph.CephOperator')
        self.mock_ceph_operator = p.start()
        self.mock_ceph_operator.return_value = self.fake_ceph_operator
        self.addCleanup(p.stop)

        # Mock the puppet operator
        self.fakepuppet_operator = FakePuppetOperator(self.dbapi)
        p = mock.patch('sysinv.puppet.puppet.PuppetOperator')
        self.mockpuppet_operator = p.start()
        self.mockpuppet_operator.return_value = self.fakepuppet_operator
        self.addCleanup(p.stop)
        self.service._puppet = self.fakepuppet_operator

        # Mock manager methods
        self.upgrade_downgrade_kube_components_patcher = mock.patch.object(
            manager.ConductorManager, '_upgrade_downgrade_kube_components')
        self.mock_upgrade_downgrade_kube_components = \
            self.upgrade_downgrade_kube_components_patcher.start()
        self.addCleanup(self.mock_upgrade_downgrade_kube_components.stop)

        self.service.fm_api = mock.Mock()
        self.service.fm_api.set_fault.side_effect = self._raise_alarm
        self.service.fm_api.clear_fault.side_effect = self._clear_alarm

        # Mock sw_version check since tox tsc.SW_VERSION is "TEST.SW_VERSION"
        self.host_load_matches_sw_version_patcher = mock.patch.object(
            manager.ConductorManager, 'host_load_matches_sw_version')
        self.mock_host_load_matches_sw_version = \
            self.host_load_matches_sw_version_patcher.start()
        self.mock_host_load_matches_sw_version.return_value = True
        self.addCleanup(self.host_load_matches_sw_version_patcher.stop)

        self.fail_config_apply_runtime_manifest = False

        # Mock ready to apply runtime config
        self._ready_to_apply_runtime_config = True
        self.ready_to_apply_runtime_config_patcher = mock.patch.object(
            manager.ConductorManager, '_ready_to_apply_runtime_config')
        self.mock_ready_to_apply_runtime_config = \
            self.ready_to_apply_runtime_config_patcher.start()
        self.mock_ready_to_apply_runtime_config.return_value = \
            self._ready_to_apply_runtime_config
        self.addCleanup(self.ready_to_apply_runtime_config_patcher.stop)

        # Mock agent config_apply_runtime_manifest
        def mock_agent_config_apply_runtime_manifest(obj, context, config_uuid,
                                                      config_dict):
            if not self.fail_config_apply_runtime_manifest:
                # Pretend the config was applied
                if 'host_uuids' in config_dict:
                    for host_uuid in config_dict['host_uuids']:
                        self.dbapi.ihost_update(host_uuid,
                                                {'config_applied': config_uuid})
                else:
                    for personality in config_dict['personalities']:
                        hosts = self.dbapi.ihost_get_by_personality(personality)
                        for host in hosts:
                            self.dbapi.ihost_update(
                                host.uuid, {'config_applied': config_uuid})

        self.mocked_rpcapi_config_apply_runtime_manifest = mock.patch.object(
            agent_rpcapi.AgentAPI, 'config_apply_runtime_manifest',
            mock_agent_config_apply_runtime_manifest)
        self.mocked_rpcapi_config_apply_runtime_manifest.start()
        self.addCleanup(self.mocked_rpcapi_config_apply_runtime_manifest.stop)

        self.fail_config_apply_runtime_manifest = False

        # Mock agent iconfig_update_file
        def mock_agent_iconfig_update_file(obj, context, iconfig_uuid, iconfig_dict):
            if not self.fail_config_apply_runtime_manifest:
                # Simulate the config was applied
                if 'host_uuids' in iconfig_dict:
                    for host_uuid in iconfig_dict['host_uuids']:
                        self.dbapi.ihost_update(host_uuid,
                                                {'config_applied': iconfig_uuid})
                else:
                    for personality in iconfig_dict['personalities']:
                        hosts = self.dbapi.ihost_get_by_personality(personality)
                        for host in hosts:
                            self.dbapi.ihost_update(
                                host.uuid, {'config_applied': iconfig_uuid})

        self.mocked_rpcapi_iconfig_update_file = mock.patch.object(
            agent_rpcapi.AgentAPI, 'iconfig_update_file',
            mock_agent_iconfig_update_file)
        self.mocked_rpcapi_iconfig_update_file.start()
        self.addCleanup(self.mocked_rpcapi_iconfig_update_file.stop)

        self.mocked_is_initial_config_complete = mock.patch.object(
            cutils, 'is_initial_config_complete')
        self.mocked_is_initial_config_complete.start()
        self.mocked_is_initial_config_complete.return_value = True
        self.addCleanup(self.mocked_is_initial_config_complete.stop)

        # Mock subprocess popen
        self.fake_subprocess_popen = FakePopen()
        p = mock.patch('eventlet.green.subprocess.Popen')
        self.mock_subprocess_popen = p.start()
        self.mock_subprocess_popen.return_value = self.fake_subprocess_popen
        self.addCleanup(p.stop)

        # Mock the KubeOperator
        self.kube_get_control_plane_versions_result = {
            'controller-0': 'v1.42.1',
            'controller-1': 'v1.42.1',
            'worker-0': 'v1.42.1'}

        def mock_kube_get_control_plane_versions(obj):
            return self.kube_get_control_plane_versions_result
        self.mocked_kube_get_control_plane_versions = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
            mock_kube_get_control_plane_versions)
        self.mocked_kube_get_control_plane_versions.start()
        self.addCleanup(self.mocked_kube_get_control_plane_versions.stop)

        self.kube_get_kubelet_versions_result = {
            'controller-0': 'v1.42.1',
            'controller-1': 'v1.42.1',
            'worker-0': 'v1.42.1'}

        def mock_kube_get_kubelet_versions(obj):
            return self.kube_get_kubelet_versions_result
        self.mocked_kube_get_kubelet_versions = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
            mock_kube_get_kubelet_versions)
        self.mocked_kube_get_kubelet_versions.start()
        self.addCleanup(self.mocked_kube_get_kubelet_versions.stop)

        # Mock the KubeVersion
        self.get_kube_versions_result = [
            {'version': 'v1.42.1',
             'upgrade_from': [],
             'downgrade_to': [],
             'applied_patches': [],
             'available_patches': [],
             },
            {'version': 'v1.42.2',
             'upgrade_from': ['v1.42.1'],
             'downgrade_to': [],
             'applied_patches': [],
             'available_patches': [],
             },
        ]

        def mock_get_kube_versions():
            return self.get_kube_versions_result
        self.mocked_get_kube_versions = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        self.mocked_get_kube_versions.start()
        self.addCleanup(self.mocked_get_kube_versions.stop)

        self.service._puppet = mock.Mock()
        self.service._allocate_addresses_for_host = mock.Mock()
        self.service._update_pxe_config = mock.Mock()
        self.service._ceph_mon_create = mock.Mock()
        self.service._sx_to_dx_post_migration_actions = mock.Mock()
        self.alarm_raised = False

    def tearDown(self):
        super(ManagerTestCase, self).tearDown()
        self.upgrade_downgrade_kube_components_patcher.stop()

    def _create_test_ihost(self, **kwargs):
        # ensure the system ID for proper association
        kwargs['forisystemid'] = self.system['id']
        ihost_dict = utils.get_test_ihost(**kwargs)
        # Let DB generate ID if it isn't specified explicitly
        if 'id' not in kwargs:
            del ihost_dict['id']
        ihost = self.dbapi.ihost_create(ihost_dict)
        return ihost

    def test_create_ihost(self):
        ihost_dict = {'mgmt_mac': '00:11:22:33:44:55',
                      'mgmt_ip': '1.2.3.4'}

        self.service.start()
        res = self.service.create_ihost(self.context, ihost_dict)
        self.assertEqual(res['mgmt_mac'], '00:11:22:33:44:55')
        self.assertEqual(res['mgmt_ip'], '1.2.3.4')

    def test_create_duplicate_ihost(self):
        ihost_dict = {'mgmt_mac': '00:11:22:33:44:55',
                      'mgmt_ip': '1.2.3.4'}

        self.service.start()
        # Create first ihost
        res1 = self.service.create_ihost(self.context, ihost_dict)
        # Update the serialid
        res1['serialid'] = '1234567890abc'
        res1 = self.service.update_ihost(self.context, res1)

        # Attempt to create duplicate ihost
        res2 = self.service.create_ihost(self.context, ihost_dict)

        # Verify that original ihost was returned
        self.assertEqual(res1['serialid'], res2['serialid'])

    def test_create_ihost_without_mac(self):
        ihost_dict = {'mgmt_ip': '1.2.3.4'}

        self.assertRaises(exception.SysinvException,
                          self.service.create_ihost,
                          self.context,
                          ihost_dict)

        # verify create did not happen
        res = self.dbapi.ihost_get_list()
        self.assertEqual(len(res), 0)

    def test_create_ihost_with_invalid_mac(self):
        ihost_dict = {'mgmt_mac': '52:54:00:59:02:9'}

        self.assertRaises(exception.SysinvException,
                          self.service.create_ihost,
                          self.context,
                          ihost_dict)

        # verify create did not happen
        res = self.dbapi.ihost_get_list()
        self.assertEqual(len(res), 0)

    def test_create_ihost_without_ip(self):
        ihost_dict = {'mgmt_mac': '00:11:22:33:44:55'}

        self.service.start()
        self.service.create_ihost(self.context, ihost_dict)

        # verify create happened
        res = self.dbapi.ihost_get_list()
        self.assertEqual(len(res), 1)

    def test_create_ihost_with_values(self):
        ihost_dict = {'mgmt_mac': '00:11:22:33:44:55',
                      'mgmt_ip': '1.2.3.4',
                      'hostname': 'newhost',
                      'invprovision': 'unprovisioned',
                      'personality': 'worker',
                      'administrative': 'locked',
                      'operational': 'disabled',
                      'availability': 'not-installed',
                      'serialid': '1234567890abc',
                      'boot_device': 'sda',
                      'rootfs_device': 'sda',
                      'install_output': 'text',
                      'console': 'ttyS0,115200',
                      'tboot': ''
                      }

        self.service.start()
        res = self.service.create_ihost(self.context, ihost_dict)

        for k, v in ihost_dict.items():
            self.assertEqual(res[k], v)

    def test_update_ihost(self):
        ihost = self._create_test_ihost()

        ihost['mgmt_mac'] = '00:11:22:33:44:55'
        ihost['mgmt_ip'] = '1.2.3.4'
        ihost['hostname'] = 'newhost'
        ihost['invprovision'] = 'unprovisioned'
        ihost['personality'] = 'worker'
        ihost['administrative'] = 'locked'
        ihost['operational'] = 'disabled'
        ihost['availability'] = 'not-installed'
        ihost['serialid'] = '1234567890abc'
        ihost['boot_device'] = 'sda'
        ihost['rootfs_device'] = 'sda'
        ihost['install_output'] = 'text'
        ihost['console'] = 'ttyS0,115200'

        res = self.service.update_ihost(self.context, ihost)

        self.assertEqual(res['mgmt_mac'], '00:11:22:33:44:55')
        self.assertEqual(res['mgmt_ip'], '1.2.3.4')
        self.assertEqual(res['hostname'], 'newhost')
        self.assertEqual(res['invprovision'], 'unprovisioned')
        self.assertEqual(res['personality'], 'worker')
        self.assertEqual(res['administrative'], 'locked')
        self.assertEqual(res['operational'], 'disabled')
        self.assertEqual(res['availability'], 'not-installed')
        self.assertEqual(res['serialid'], '1234567890abc')
        self.assertEqual(res['boot_device'], 'sda')
        self.assertEqual(res['rootfs_device'], 'sda')
        self.assertEqual(res['install_output'], 'text')
        self.assertEqual(res['console'], 'ttyS0,115200')

    def test_update_ihost_id(self):
        ihost = self._create_test_ihost()

        ihost['id'] = '12345'
        self.assertRaises(exception.SysinvException,
                          self.service.update_ihost,
                          self.context,
                          ihost)

    def test_update_ihost_uuid(self):
        ihost = self._create_test_ihost()

        ihost['uuid'] = 'asdf12345'
        self.assertRaises(exception.SysinvException,
                          self.service.update_ihost,
                          self.context,
                          ihost)

    def test_configure_ihost_new(self):
        # Test skipped to prevent error message in Jenkins. Error thrown is:
        # in test_configure_ihost_new
        # with open(self.dnsmasq_hosts_file, 'w') as f:
        # IOError: [Errno 13] Permission denied: '/tmp/dnsmasq.hosts'
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        with open(self.dnsmasq_hosts_file, 'w') as f:
            f.write("dhcp-host=08:00:27:0a:fa:fa,worker-1,192.168.204.25,2h\n")

        ihost = self._create_test_ihost()

        ihost['mgmt_mac'] = '00:11:22:33:44:55'
        ihost['mgmt_ip'] = '1.2.3.4'
        ihost['hostname'] = 'newhost'
        ihost['invprovision'] = 'unprovisioned'
        ihost['personality'] = 'worker'
        ihost['administrative'] = 'locked'
        ihost['operational'] = 'disabled'
        ihost['availability'] = 'not-installed'
        ihost['serialid'] = '1234567890abc'
        ihost['boot_device'] = 'sda'
        ihost['rootfs_device'] = 'sda'
        ihost['install_output'] = 'text'
        ihost['console'] = 'ttyS0,115200'

        self.service.configure_ihost(self.context, ihost)

        with open(self.dnsmasq_hosts_file, 'r') as f:
            self.assertEqual(
                f.readline(),
                "dhcp-host=08:00:27:0a:fa:fa,worker-1,192.168.204.25,2h\n")
            self.assertEqual(
                f.readline(),
                "dhcp-host=00:11:22:33:44:55,newhost,1.2.3.4,2h\n")

    def test_configure_ihost_replace(self):
        # Test skipped to prevent error message in Jenkins. Error thrown is:
        # in test_configure_ihost_replace
        # with open(self.dnsmasq_hosts_file, 'w') as f:
        # IOError: [Errno 13] Permission denied: '/tmp/dnsmasq.hosts'
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        with open(self.dnsmasq_hosts_file, 'w') as f:
            f.write("dhcp-host=00:11:22:33:44:55,oldhost,1.2.3.4,2h\n")
            f.write("dhcp-host=08:00:27:0a:fa:fa,worker-1,192.168.204.25,2h\n")

        ihost = self._create_test_ihost()

        ihost['mgmt_mac'] = '00:11:22:33:44:55'
        ihost['mgmt_ip'] = '1.2.3.42'
        ihost['hostname'] = 'newhost'
        ihost['invprovision'] = 'unprovisioned'
        ihost['personality'] = 'worker'
        ihost['administrative'] = 'locked'
        ihost['operational'] = 'disabled'
        ihost['availability'] = 'not-installed'
        ihost['serialid'] = '1234567890abc'
        ihost['boot_device'] = 'sda'
        ihost['rootfs_device'] = 'sda'
        ihost['install_output'] = 'text'
        ihost['console'] = 'ttyS0,115200'

        self.service.configure_ihost(self.context, ihost)

        with open(self.dnsmasq_hosts_file, 'r') as f:
            self.assertEqual(
                f.readline(),
                "dhcp-host=00:11:22:33:44:55,newhost,1.2.3.42,2h\n")
            self.assertEqual(
                f.readline(),
                "dhcp-host=08:00:27:0a:fa:fa,worker-1,192.168.204.25,2h\n")

    def test_configure_ihost_no_hostname(self):
        # Test skipped to prevent error message in Jenkins. Error thrown is:
        # in update_dnsmasq_config
        # os.rename(temp_dnsmasq_hosts_file, dnsmasq_hosts_file)
        # OSError: [Errno 1] Operation not permitted
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        ihost = self._create_test_ihost()

        ihost['hostname'] = ''
        self.assertRaises(exception.SysinvException,
                          self.service.configure_ihost,
                          self.context,
                          ihost)

    def test_vim_host_add(self):
        mock_vim_host_add = mock.MagicMock()
        p = mock.patch('sysinv.api.controllers.v1.vim_api.vim_host_add',
                mock_vim_host_add)
        p.start().return_value = {}
        self.addCleanup(p.stop)

        ret = self.service.vim_host_add(self.context, None, str(uuid.uuid4()),
                    "newhostname", "worker", "locked", "disabled", "offline",
                    "disabled", "not-installed", 10)

        mock_vim_host_add.assert_called_with(mock.ANY, mock.ANY,
                "newhostname", "worker", "locked", "disabled", "offline",
                "disabled", "not-installed", 10)

        self.assertEqual(ret, {})

    def test_mtc_host_add(self):
        mock_notify_mtc_and_recv = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.notify_mtc_and_recv',
                    mock_notify_mtc_and_recv)
        p.start().return_value = {'status': 'pass'}
        self.addCleanup(p.stop)

        ihost = {}
        ihost['hostname'] = 'newhost'
        ihost['personality'] = 'worker'

        self.service.mtc_host_add(self.context, "localhost", 2112, ihost)
        mock_notify_mtc_and_recv.assert_called_with("localhost", 2112, ihost)

    def test_ilvg_get_nova_ilvg_by_ihost(self):
        ihost = self._create_test_ihost()
        lvg_dict = {
            'lvm_vg_name': constants.LVG_NOVA_LOCAL,
        }
        ilvg = self.dbapi.ilvg_create(ihost['id'], lvg_dict)
        ret = self.service.ilvg_get_nova_ilvg_by_ihost(self.context, ihost['uuid'])
        self.assertEqual(ret[0]['uuid'], ilvg['uuid'])

    def test_ilvg_get_nova_ilvg_by_ihost_no_nova_ilvg(self):
        ihost = self._create_test_ihost()
        ret = self.service.ilvg_get_nova_ilvg_by_ihost(self.context, ihost['uuid'])
        self.assertEqual(ret, [])

    def test_lldp_neighbour_tlv_update_exceed_length(self):
        # Set up
        ihost = self._create_test_ihost()
        interface = utils.create_test_interface(
            ifname='mgmt',
            forihostid=ihost['id'],
            ihost_uuid=ihost['uuid'],
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_ETHERNET)
        port = utils.create_test_ethernet_port(
            name='eth0',
            host_id=ihost['id'],
            interface_id=interface['id'],
            pciaddr='0000:00:00.01',
            dev_id=0)

        # create fake neighbour
        neighbour = self.dbapi.lldp_neighbour_create(
            port.id, ihost.id, {
                "msap": "08:00:27:82:35:fb,08:00:27:0d:ac:03"
            })

        # create tlv with excessive size
        tlv_list = self.dbapi.lldp_tlv_get_list()
        bad_size = (
            'enp0s8.100, enp0s8.101, enp0s8.102, enp0s8.103,'
            ' enp0s8.104, enp0s8.105, enp0s8.106, enp0s8.107,'
            ' enp0s8.108, enp0s8.109, enp0s8.110, enp0s8.111,'
            ' enp0s8.112, enp0s8.113, enp0s8.114, enp0s8.115,'
            ' enp0s8.116, enp0s8.117, enp0s8.118, enp0s8.119,'
            ' enp0s8.120, enp0s8.121, enp0s8.122, enp0s8.12,'
            ' enp0s8.123'
        )
        vlan_list = bad_size
        self.service.lldp_neighbour_tlv_update({
            constants.LLDP_TLV_TYPE_DOT1_VLAN_NAMES: vlan_list
        }, neighbour)
        tlv_list = self.dbapi.lldp_tlv_get_list()
        self.assertEqual(tlv_list[0]['value'][-3:], "...")
        self.assertTrue(len(tlv_list[0]['value']) <= 255)

        # update tlv to acceptable size
        vlan_list = 'enp0s8.100'
        self.service.lldp_neighbour_tlv_update({
            constants.LLDP_TLV_TYPE_DOT1_VLAN_NAMES: vlan_list
        }, neighbour)
        tlv_list = self.dbapi.lldp_tlv_get_list()
        self.assertEqual(tlv_list[0]['value'], vlan_list)

        # update tlv to excessive size
        vlan_list = bad_size
        self.service.lldp_neighbour_tlv_update({
            constants.LLDP_TLV_TYPE_DOT1_VLAN_NAMES: vlan_list
        }, neighbour)
        tlv_list = self.dbapi.lldp_tlv_get_list()
        self.assertEqual(tlv_list[0]['value'][-3:], "...")
        self.assertTrue(len(tlv_list[0]['value']) <= 255)

    def test_platform_interfaces(self):
        ihost = self._create_test_ihost()
        interface = utils.create_test_interface(
                ifname='mgmt',
                forihostid=ihost['id'],
                ihost_uuid=ihost['uuid'],
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                iftype=constants.INTERFACE_TYPE_ETHERNET)
        port = utils.create_test_ethernet_port(
            name='eth0',
            host_id=ihost['id'],
            interface_id=interface['id'],
            pciaddr='0000:00:00.01',
            dev_id=0)

        ret = self.service.platform_interfaces(self.context, ihost['id'])
        self.assertEqual(ret[0]['name'], port['name'])

    def test_platform_interfaces_multi(self):
        ihost = self._create_test_ihost()
        interface_mgmt = utils.create_test_interface(
                ifname='mgmt',
                forihostid=ihost['id'],
                ihost_uuid=ihost['uuid'],
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                iftype=constants.INTERFACE_TYPE_ETHERNET)
        port_mgmt = utils.create_test_ethernet_port(
            name='eth0',
            host_id=ihost['id'],
            interface_id=interface_mgmt['id'],
            pciaddr='0000:00:00.01',
            dev_id=0)

        interface_oam = utils.create_test_interface(
                ifname='oam',
                forihostid=ihost['id'],
                ihost_uuid=ihost['uuid'],
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                iftype=constants.INTERFACE_TYPE_ETHERNET)
        port_oam = utils.create_test_ethernet_port(
            name='eth1',
            host_id=ihost['id'],
            interface_id=interface_oam['id'],
            pciaddr='0000:00:00.02',
            dev_id=1)

        interface_data = utils.create_test_interface(
                ifname='data',
                forihostid=ihost['id'],
                ihost_uuid=ihost['uuid'],
                ifclass=constants.INTERFACE_CLASS_DATA,
                iftype=constants.INTERFACE_TYPE_VLAN)
        utils.create_test_ethernet_port(
            name='eth2',
            host_id=ihost['id'],
            interface_id=interface_data['id'],
            pciaddr='0000:00:00.03',
            dev_id=2)

        ret = self.service.platform_interfaces(self.context, ihost['id'])
        self.assertEqual(len(ret), 2)
        self.assertEqual(ret[0]['name'], port_mgmt['name'])
        self.assertEqual(ret[1]['name'], port_oam['name'])

    def test_platform_interfaces_no_port(self):
        ihost = self._create_test_ihost()
        utils.create_test_interface(
                ifname='mgmt',
                forihostid=ihost['id'],
                ihost_uuid=ihost['uuid'],
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                iftype=constants.INTERFACE_TYPE_ETHERNET)

        ret = self.service.platform_interfaces(self.context, ihost['id'])
        self.assertEqual(ret, [])

    def test_platform_interfaces_invalid_ihost(self):
        ihost = self._create_test_ihost()
        interface = utils.create_test_interface(
                ifname='mgmt',
                forihostid=ihost['id'],
                ihost_uuid=ihost['uuid'],
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                iftype=constants.INTERFACE_TYPE_ETHERNET)
        utils.create_test_ethernet_port(
            name='eth0',
            host_id=ihost['id'],
            interface_id=interface['id'],
            pciaddr='0000:00:00.01',
            dev_id=0)

        ret = self.service.platform_interfaces(self.context, ihost['id'] + 1)
        self.assertEqual(ret, [])

    def test_kube_download_images(self):
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES,
        )

        # Download images
        self.service.kube_download_images(self.context, 'v1.42.2')

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADE_DOWNLOADED_IMAGES)

    def test_kube_download_images_ansible_fail(self):
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )
        # Fake an ansible failure
        self.fake_subprocess_popen.returncode = 1

        # Download images
        self.service.kube_download_images(self.context, 'v1.42.2')

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED)

    def test_kube_upgrade_init_actions(self):
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # Test the handling of transitory upgrade states
        expected_fail_results = [
            (kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES,
             kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED),
            (kubernetes.KUBE_UPGRADING_FIRST_MASTER,
             kubernetes.KUBE_UPGRADING_FIRST_MASTER_FAILED),
            (kubernetes.KUBE_UPGRADING_NETWORKING,
             kubernetes.KUBE_UPGRADING_NETWORKING_FAILED),
            (kubernetes.KUBE_UPGRADING_SECOND_MASTER,
             kubernetes.KUBE_UPGRADING_SECOND_MASTER_FAILED),
        ]

        for current_state, fail_state in expected_fail_results:
            utils.create_test_kube_upgrade(
                from_version='v1.42.1',
                to_version='v1.42.2',
                state=current_state,
            )
            self.service._kube_upgrade_init_actions()
            updated_upgrade = self.dbapi.kube_upgrade_get_one()
            self.assertEqual(updated_upgrade.state, fail_state)
            self.dbapi.kube_upgrade_destroy(updated_upgrade.id)

        # Test the handling of transitory host upgrade states
        expected_fail_results = [
            (kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE,
             kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE_FAILED),
            (kubernetes.KUBE_HOST_UPGRADING_KUBELET,
             kubernetes.KUBE_HOST_UPGRADING_KUBELET_FAILED),
        ]

        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )

        for current_status, fail_status in expected_fail_results:
            self.dbapi.kube_host_upgrade_update(1, {'status': current_status})
            self.service._kube_upgrade_init_actions()
            updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
            self.assertEqual(updated_host_upgrade.status, fail_status)

    def test_kube_download_images_one_controller(self):
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES,
        )
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # Speed up the test
        kubernetes.MANIFEST_APPLY_INTERVAL = 1
        kubernetes.MANIFEST_APPLY_TIMEOUT = 1

        # Download images
        self.service.kube_download_images(self.context, 'v1.42.2')

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADE_DOWNLOADED_IMAGES)

    def test_kube_download_images_one_controller_manifest_timeout(self):
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES,
        )
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # Speed up the test
        kubernetes.MANIFEST_APPLY_INTERVAL = 1
        kubernetes.MANIFEST_APPLY_TIMEOUT = 1

        # Make the manifest apply fail
        self.fail_config_apply_runtime_manifest = True

        # Download images
        self.service.kube_download_images(self.context, 'v1.42.2')

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED)

    def test_kube_download_images_two_controllers(self):
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES,
        )
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        # Create controller-1
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-1',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:56',
            mgmt_ip='1.2.3.5',
        )

        # Speed up the test
        kubernetes.MANIFEST_APPLY_INTERVAL = 1
        kubernetes.MANIFEST_APPLY_TIMEOUT = 1

        # Download images
        self.service.kube_download_images(self.context, 'v1.42.2')

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADE_DOWNLOADED_IMAGES)

    def test_kube_upgrade_control_plane_first_master(self):
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        c0 = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        # Set the target version for controller-0
        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})
        # Make the control plane upgrade pass
        self.kube_get_control_plane_versions_result = {
            'controller-0': 'v1.42.2',
            'controller-1': 'v1.42.1',
            'worker-0': 'v1.42.1'}

        # Speed up the test
        kubernetes.MANIFEST_APPLY_INTERVAL = 1
        kubernetes.POD_START_INTERVAL = 1

        # Upgrade the control plane
        self.service.kube_upgrade_control_plane(self.context, c0.uuid)

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADED_FIRST_MASTER)

        # Verify that the host upgrade status was cleared
        updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
        self.assertEqual(updated_host_upgrade.status, None)

    def test_kube_upgrade_control_plane_first_master_manifest_timeout(self):
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        c0 = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        # Set the target version for controller-0
        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})
        # Make the manifest apply fail
        self.fail_config_apply_runtime_manifest = True

        # Speed up the test
        kubernetes.MANIFEST_APPLY_INTERVAL = 1
        kubernetes.MANIFEST_APPLY_TIMEOUT = 1

        # Upgrade the control plane
        self.service.kube_upgrade_control_plane(self.context, c0.uuid)

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADING_FIRST_MASTER_FAILED)

        # Verify that the host upgrade status was set
        updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
        self.assertEqual(updated_host_upgrade.status,
                         kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE_FAILED)

    def test_kube_upgrade_control_plane_first_master_upgrade_fail(self):
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        c0 = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        # Set the target version for controller-0
        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})

        # Speed up the test
        kubernetes.MANIFEST_APPLY_INTERVAL = 1
        kubernetes.POD_START_INTERVAL = 1
        kubernetes.POD_START_TIMEOUT = 1

        # Upgrade the control plane
        self.service.kube_upgrade_control_plane(self.context, c0.uuid)

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADING_FIRST_MASTER_FAILED)

        # Verify that the host upgrade status was cleared
        updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
        self.assertIsNotNone(updated_host_upgrade.status)

    def test_kube_upgrade_control_plane_second_master(self):
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_SECOND_MASTER,
        )
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:55',
            mgmt_ip='1.2.3.4',
        )
        # Set the target version for controller-0
        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})
        # Create controller-1
        config_uuid = str(uuid.uuid4())
        c1 = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-1',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:56',
            mgmt_ip='1.2.3.5',
        )
        # Set the target version for controller-1
        self.dbapi.kube_host_upgrade_update(2, {'target_version': 'v1.42.2'})
        # Make the control plane upgrade pass
        self.kube_get_control_plane_versions_result = {
            'controller-0': 'v1.42.2',
            'controller-1': 'v1.42.2',
            'worker-0': 'v1.42.1'}

        # Speed up the test
        kubernetes.MANIFEST_APPLY_INTERVAL = 1
        kubernetes.POD_START_INTERVAL = 1

        # Upgrade the control plane
        self.service.kube_upgrade_control_plane(self.context, c1.uuid)

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADED_SECOND_MASTER)

        # Verify that the host upgrade status was cleared
        updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
        self.assertEqual(updated_host_upgrade.status, None)

    def test_kube_upgrade_kubelet_controller(self):
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_SECOND_MASTER,
        )
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        c0 = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        # Set the target version for controller-0
        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})
        # Make the kubelet upgrade pass
        self.kube_get_kubelet_versions_result = {
            'controller-0': 'v1.42.2',
            'controller-1': 'v1.42.1',
            'worker-0': 'v1.42.1'}

        # Speed up the test
        kubernetes.MANIFEST_APPLY_INTERVAL = 1
        kubernetes.POD_START_INTERVAL = 1

        # Upgrade the kubelet
        self.service.kube_upgrade_kubelet(self.context, c0.uuid)

        # Verify that the upgrade state was not updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADED_SECOND_MASTER)

        # Verify that the host upgrade status was cleared
        updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
        self.assertEqual(updated_host_upgrade.status, None)

    def test_kube_upgrade_kubelet_second_master(self):
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_SECOND_MASTER,
        )
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:55',
            mgmt_ip='1.2.3.4',
        )
        # Set the target version for controller-0
        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})
        # Create controller-1
        config_uuid = str(uuid.uuid4())
        c1 = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-1',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:56',
            mgmt_ip='1.2.3.5',
        )
        # Set the target version for controller-1
        self.dbapi.kube_host_upgrade_update(2, {'target_version': 'v1.42.2'})
        # Make the kubelet upgrade pass
        self.kube_get_kubelet_versions_result = {
            'controller-0': 'v1.42.2',
            'controller-1': 'v1.42.2'}
        # Make the upgrade pass
        self.kube_get_control_plane_versions_result = {
            'controller-0': 'v1.42.2',
            'controller-1': 'v1.42.2'}

        # Speed up the test
        kubernetes.MANIFEST_APPLY_INTERVAL = 1
        kubernetes.POD_START_INTERVAL = 1

        # Upgrade the kubelet
        self.service.kube_upgrade_kubelet(self.context, c1.uuid)

        # Verify that the host upgrade status was cleared
        updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
        self.assertEqual(updated_host_upgrade.status, None)

    def test_kube_upgrade_kubelet_controller_manifest_timeout(self):
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        c0 = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        # Set the target version for controller-0
        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})
        # Make the manifest apply fail
        self.fail_config_apply_runtime_manifest = True

        # Speed up the test
        kubernetes.MANIFEST_APPLY_INTERVAL = 1
        kubernetes.MANIFEST_APPLY_TIMEOUT = 1

        # Upgrade the kubelet
        self.service.kube_upgrade_kubelet(self.context, c0.uuid)

        # Verify that the upgrade state was not updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADING_KUBELETS)

        # Verify that the host upgrade status was set
        updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
        self.assertEqual(updated_host_upgrade.status,
                         kubernetes.KUBE_HOST_UPGRADING_KUBELET_FAILED)

    def test_kube_upgrade_kubelet_controller_upgrade_fail(self):
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        c0 = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        # Set the target version for controller-0
        self.dbapi.kube_host_upgrade_update(1, {'target_version': 'v1.42.2'})

        # Speed up the test
        kubernetes.MANIFEST_APPLY_INTERVAL = 1
        kubernetes.POD_START_INTERVAL = 1
        kubernetes.POD_START_TIMEOUT = 1

        # Upgrade the kubelet
        self.service.kube_upgrade_kubelet(self.context, c0.uuid)

        # Verify that the upgrade state was not updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADING_KUBELETS)

        # Verify that the host upgrade status was cleared
        updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
        self.assertIsNotNone(updated_host_upgrade.status)

    def test_kube_upgrade_networking(self):
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_NETWORKING,
        )

        # Upgrade kubernetes networking
        self.service.kube_upgrade_networking(self.context, 'v1.42.2')

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADED_NETWORKING)

    def test_kube_upgrade_networking_ansible_fail(self):
        # Create an upgrade
        utils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_NETWORKING,
        )
        # Fake an ansible failure
        self.fake_subprocess_popen.returncode = 1

        # Upgrade kubernetes networking
        self.service.kube_upgrade_networking(self.context, 'v1.42.2')

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADING_NETWORKING_FAILED)

    def _create_test_controller_config_out_of_date(self, hostname):
        config_applied = self.service._config_set_reboot_required(uuid.uuid4())
        config_target = self.service._config_set_reboot_required(uuid.uuid4())
        ihost = self._create_test_ihost(
            uuid=str(uuid.uuid4()),
            config_applied=config_applied,
            config_target=config_target)
        ihost['mgmt_mac'] = '00:11:22:33:44:55'
        ihost['mgmt_ip'] = '1.2.3.42'
        ihost['hostname'] = hostname
        ihost['invprovision'] = 'provisioned'
        ihost['personality'] = 'controller'
        ihost['administrative'] = 'unlocked'
        ihost['operational'] = 'disabled'
        ihost['availability'] = 'online'
        ihost['serialid'] = '1234567890abc'
        ihost['boot_device'] = 'sda'
        ihost['rootfs_device'] = 'sda'
        ihost['install_output'] = 'text'
        ihost['console'] = 'ttyS0,115200'

        return ihost

    def test_configure_out_of_date(self):
        os.path.isfile = mock.Mock(return_value=True)
        cutils.is_aio_system = mock.Mock(return_value=True)
        ihost = self._create_test_controller_config_out_of_date('controller-0')
        self.service.configure_ihost(self.context, ihost)
        res = self.dbapi.ihost_get(ihost['uuid'])
        imsg_dict = {'config_applied': res['config_target']}
        self.service.iconfig_update_by_ihost(self.context, ihost['uuid'], imsg_dict)
        self.assertEqual(self.alarm_raised, False)

        personalities = [constants.CONTROLLER]
        self.service._config_update_hosts(self.context, personalities, reboot=True)
        res = self.dbapi.ihost_get(ihost['uuid'])

        personalities = [constants.CONTROLLER]
        self.service._config_update_hosts(self.context, personalities, reboot=False)
        res = self.dbapi.ihost_get(ihost['uuid'])
        config_uuid = self.service._config_clear_reboot_required(res['config_target'])
        imsg_dict = {'config_applied': config_uuid}
        self.service.iconfig_update_by_ihost(self.context, ihost['uuid'], imsg_dict)
        self.assertEqual(self.alarm_raised, True)

    def test_configure_out_of_date_upgrade(self):
        os.path.isfile = mock.Mock(return_value=True)
        cutils.is_aio_system = mock.Mock(return_value=True)

        # Check upgrade where the target sw_version does not match
        self.mock_host_load_matches_sw_version.return_value = False
        ihost = self._create_test_controller_config_out_of_date('controller-1')
        self.service.configure_ihost(self.context, ihost)
        res = self.dbapi.ihost_get(ihost['uuid'])
        imsg_dict = {'config_applied': res['config_target']}
        self.service.iconfig_update_by_ihost(self.context, ihost['uuid'], imsg_dict)
        self.assertEqual(self.alarm_raised, False)

        personalities = [constants.CONTROLLER]
        self.service._config_update_hosts(self.context, personalities, reboot=True)
        res = self.dbapi.ihost_get(ihost['uuid'])

        personalities = [constants.CONTROLLER]
        self.service._config_update_hosts(self.context, personalities, reboot=False)
        res = self.dbapi.ihost_get(ihost['uuid'])
        config_uuid = self.service._config_clear_reboot_required(res['config_target'])
        imsg_dict = {'config_applied': config_uuid}
        self.service.iconfig_update_by_ihost(self.context, ihost['uuid'], imsg_dict)
        self.assertEqual(self.alarm_raised, True)

    def fake_rename(self, old, new):
        self.executes.append(('mv', old, new))

    @staticmethod
    def scope_open(*args, **kwargs):
        fake_contents = "lorem ipsum"
        fake_file = mock.Mock()
        fake_file.read.return_value = fake_contents
        fake_context_manager = mock.MagicMock()
        fake_context_manager.__enter__.return_value = fake_file
        fake_context_manager.__exit__.return_value = None

        if not args[0].startswith(  # filename
                os.path.join(tsc.CONFIG_PATH, 'resolv.conf')):
            return open(*args, **kwargs)
        else:
            return fake_context_manager

    def test_deferred_runtime_config_file(self):

        # Create controller-0
        config_uuid = str(uuid.uuid4())
        chost = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # create test dns nameservers config
        utils.create_test_dns(forisystemid=self.system.id,
                              nameservers='8.8.8.8,8.8.4.4')
        cutils.gethostbyname = mock.Mock(return_value='192.168.204.2')

        self.executes = []
        self.stub_out('os.rename', self.fake_rename)

        # These mock for builtin open are needed for py27 and py3 compatibility
        mock_trace_caller = mock.MagicMock()
        p = mock.patch(
            'traceback.format_stack',
            mock_trace_caller)
        p.start()
        p.return_value = ['one', 'two', 'three']
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open):
            mock_open.side_effect = self.scope_open
            self.mock_ready_to_apply_runtime_config.return_value = False
            self.service.update_dns_config(self.context)
            chost_updated = self.dbapi.ihost_get(chost.uuid)

            # Verify that the config is updated and alarm is raised
            self.assertNotEqual(chost_updated.config_applied,
                                chost_updated.config_target)
            self.assertEqual(self.alarm_raised, True)

            self.mock_ready_to_apply_runtime_config.return_value = True
            self.service._audit_deferred_runtime_config(self.context)

            # Simulate agent update
            chost_updated = self.dbapi.ihost_get(chost.uuid)
            self.service._update_host_config_applied(
                self.context, chost_updated, chost_updated.config_applied)

            # Verify the config is up to date.
            self.assertEqual(chost_updated.config_target,
                             chost_updated.config_applied)
            self.assertEqual(self.alarm_raised, False)

    def test_deferred_runtime_config_manifest(self):
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        chost = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        self.mock_ready_to_apply_runtime_config.return_value = False
        self.service.update_user_config(self.context)
        chost_updated = self.dbapi.ihost_get(chost.uuid)

        # Verify that the config is updated and alarm is raised
        self.assertNotEqual(chost_updated.config_applied,
                            chost_updated.config_target)
        self.assertEqual(self.alarm_raised, True)

        self.mock_ready_to_apply_runtime_config.return_value = True
        self.service._audit_deferred_runtime_config(self.context)

        # Simulate agent update
        chost_updated = self.dbapi.ihost_get(chost.uuid)
        self.service._update_host_config_applied(
            self.context, chost_updated, chost_updated.config_applied)

        # Verify the config is up to date.
        self.assertEqual(chost_updated.config_target,
                         chost_updated.config_applied)
        self.assertEqual(self.alarm_raised, False)

    def test_deferred_multiple_runtime_config(self):
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        chost = self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # create test dns nameservers config
        utils.create_test_dns(forisystemid=self.system.id,
                              nameservers='8.8.8.8,8.8.4.4')
        cutils.gethostbyname = mock.Mock(return_value='192.168.204.2')

        self.executes = []
        self.stub_out('os.rename', self.fake_rename)

        # These mock for builtin open are needed for py27 and py3 compatibility
        mock_trace_caller = mock.MagicMock()
        p = mock.patch(
            'traceback.format_stack',
            mock_trace_caller)
        p.start()
        p.return_value = ['one', 'two', 'three']
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open):
            mock_open.side_effect = self.scope_open
            # Attempt to apply a runtime config, which is deferred
            self.mock_ready_to_apply_runtime_config.return_value = False
            self.service.update_dns_config(self.context)
            c1host_updated = self.dbapi.ihost_get(chost.uuid)

            # Verify that the config is updated and alarm is raised
            self.assertNotEqual(c1host_updated.config_applied,
                                c1host_updated.config_target)
            self.assertEqual(self.alarm_raised, True)

            # Attempt another runtime config, which is also deferred
            self.service.update_user_config(self.context)
            c2host_updated = self.dbapi.ihost_get(chost.uuid)

            # Verify that the target is updated and alarm is still raised
            self.assertNotEqual(c1host_updated.config_target,
                                c2host_updated.config_target)
            self.assertEqual(c1host_updated.config_applied,
                             c1host_updated.config_applied)
            self.assertNotEqual(c2host_updated.config_applied,
                                c2host_updated.config_target)
            self.assertEqual(self.alarm_raised, True)

            # Run the audit for deferred runtime config
            self.mock_ready_to_apply_runtime_config.return_value = True
            self.service._audit_deferred_runtime_config(self.context)

            # Simulate agent update
            chost_updated = self.dbapi.ihost_get(chost.uuid)
            self.service._update_host_config_applied(
                self.context, chost_updated, chost_updated.config_applied)

            # Verify the config is up to date.
            self.assertEqual(chost_updated.config_target,
                             chost_updated.config_applied)
            self.assertEqual(self.alarm_raised, False)

    def _raise_alarm(self, fault):
        self.alarm_raised = True

    def _clear_alarm(self, fm_id, fm_instance):
        self.alarm_raised = False

    def _create_test_ihosts(self):
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='00:11:22:33:44:55',
            mgmt_ip='1.2.3.4')
        # Create controller-1
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.CONTROLLER,
            hostname='controller-1',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='22:44:33:55:11:66',
            mgmt_ip='1.2.3.5')
        # Create compute-0
        config_uuid = str(uuid.uuid4())
        self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            mgmt_mac='22:44:33:55:11:77',
            mgmt_ip='1.2.3.6')

    def test_get_ihost_by_macs(self):
        self._create_test_ihosts()
        ihost_macs = ['22:44:33:55:11:66', '22:44:33:88:11:66']
        ihost = self.service.get_ihost_by_macs(self.context, ihost_macs)
        self.assertEqual(ihost.mgmt_mac, '22:44:33:55:11:66')

    def test_get_ihost_by_macs_no_match(self):
        self._create_test_ihosts()
        ihost = None
        ihost_macs = ['22:44:33:99:11:66', '22:44:33:88:11:66']
        ihost = self.service.get_ihost_by_macs(self.context, ihost_macs)
        self.assertEqual(ihost, None)

    def test_get_ihost_by_hostname(self):
        self._create_test_ihosts()
        ihost_hostname = 'controller-1'
        ihost = self.service.get_ihost_by_hostname(self.context, ihost_hostname)
        self.assertEqual(ihost.mgmt_mac, '22:44:33:55:11:66')
        self.assertEqual(ihost.mgmt_ip, '1.2.3.5')
        self.assertEqual(ihost.hostname, 'controller-1')

    def test_get_ihost_by_hostname_invalid_name(self):
        self._create_test_ihosts()
        ihost_hostname = 'compute'
        ihost = None
        ihost = self.service.get_ihost_by_hostname(self.context, ihost_hostname)
        self.assertEqual(ihost, None)

    def test_pci_device_update_by_host(self):
        # Create compute-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        host_uuid = ihost['uuid']
        host_id = ihost['id']
        PCI_DEV_1 = {'uuid': str(uuid.uuid4()),
                     'name': 'pci_dev_1',
                     'pciaddr': '0000:0b:01.0',
                     'pclass_id': '060100',
                     'pvendor_id': '8086',
                     'pdevice_id': '0443',
                     'enabled': True}
        PCI_DEV_2 = {'uuid': str(uuid.uuid4()),
                     'name': 'pci_dev_2',
                     'pciaddr': '0000:0c:01.0',
                     'pclass_id': '060200',
                     'pvendor_id': '8088',
                     'pdevice_id': '0444',
                     'enabled': True}
        pci_device_dict_array = [PCI_DEV_1, PCI_DEV_2]

        # create new dev
        self.service.pci_device_update_by_host(self.context, host_uuid, pci_device_dict_array)

        dev = self.dbapi.pci_device_get(PCI_DEV_1['pciaddr'], host_id)
        for key in PCI_DEV_1:
            self.assertEqual(dev[key], PCI_DEV_1[key])

        dev = self.dbapi.pci_device_get(PCI_DEV_2['pciaddr'], host_id)
        for key in PCI_DEV_2:
            self.assertEqual(dev[key], PCI_DEV_2[key])

        # update existed dev
        pci_dev_dict_update1 = [{'pciaddr': PCI_DEV_2['pciaddr'],
                                'pclass_id': '060500',
                                'pvendor_id': '8086',
                                'pdevice_id': '0449',
                                'pclass': '0600',
                                'pvendor': '',
                                'psvendor': '',
                                'psdevice': 'qat',
                                'sriov_totalvfs': 32,
                                'sriov_numvfs': 4,
                                'sriov_vf_driver': None,
                                'sriov_vf_pdevice_id': '0450',
                                'sriov_vfs_pci_address': '',
                                'driver': ''}]
        self.service.pci_device_update_by_host(self.context, host_uuid, pci_dev_dict_update1)

        dev = self.dbapi.pci_device_get(PCI_DEV_2['pciaddr'], host_id)

        for key in pci_dev_dict_update1[0]:
            self.assertEqual(dev[key], pci_dev_dict_update1[0][key])

        # update existed dev failure case, failed to change uuid.
        pci_dev_dict_update2 = [{'pciaddr': PCI_DEV_2['pciaddr'],
                                'pclass_id': '060500',
                                'pvendor_id': '8086',
                                'pdevice_id': '0449',
                                'pclass': '0600',
                                'pvendor': '',
                                'psvendor': '',
                                'psdevice': 'qat',
                                'sriov_totalvfs': 32,
                                'sriov_numvfs': 4,
                                'sriov_vf_driver': None,
                                'sriov_vf_pdevice_id': '0450',
                                'sriov_vfs_pci_address': '',
                                'driver': '',
                                'uuid': 1122}]

        self.service.pci_device_update_by_host(self.context, host_uuid, pci_dev_dict_update2)
        dev = self.dbapi.pci_device_get(PCI_DEV_2['pciaddr'], host_id)
        self.assertEqual(dev['uuid'], PCI_DEV_2['uuid'])

    def test_inumas_update_by_ihost(self):
        # Create compute-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        host_uuid = ihost['uuid']
        host_id = ihost['id']
        utils.create_test_node(id=1, numa_node=0, forihostid=host_id)
        utils.create_test_node(id=2, numa_node=1, forihostid=host_id)
        port1 = utils.create_test_ethernet_port(
            id=1, name="port1", host_id=host_id,
            interface_id="1122", mac='08:00:27:43:60:11', numa_node=3)
        self.assertEqual(port1['node_id'], None)
        inuma_dict_array = [{'numa_node': 1}, {'numa_node': 3}]
        self.service.inumas_update_by_ihost(self.context, host_uuid, inuma_dict_array)
        updated_port = self.dbapi.ethernet_port_get(port1['uuid'], host_id)

        self.assertEqual(updated_port['node_id'], 3)

    def test_fpga_device_update_by_host(self):
        # Create compute-0 node
        config_uuid = str(uuid.uuid4())
        ihost = self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=str(uuid.uuid4()),
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )
        host_uuid = ihost['uuid']
        host_id = ihost['id']
        PCI_DEV_1 = {'uuid': str(uuid.uuid4()),
                     'name': 'pci_dev_1',
                     'pciaddr': '0000:0b:01.0',
                     'pclass_id': '060100',
                     'pvendor_id': '8086',
                     'pdevice_id': '0443',
                     'enabled': True}
        PCI_DEV_2 = {'uuid': str(uuid.uuid4()),
                     'name': 'pci_dev_2',
                     'pciaddr': '0000:0c:01.0',
                     'pclass_id': '012000',
                     'pvendor_id': '8086',
                     'pdevice_id': '0b30',
                     'enabled': True}
        pci_device_dict_array = [PCI_DEV_1, PCI_DEV_2]

        # create new PCI dev
        self.service.pci_device_update_by_host(self.context, host_uuid, pci_device_dict_array)

        dev = self.dbapi.pci_device_get(PCI_DEV_1['pciaddr'], host_id)
        for key in PCI_DEV_1:
            self.assertEqual(dev[key], PCI_DEV_1[key])

        dev = self.dbapi.pci_device_get(PCI_DEV_2['pciaddr'], host_id)
        for key in PCI_DEV_2:
            self.assertEqual(dev[key], PCI_DEV_2[key])

        FPGA_DEV_1 = {
            'pciaddr': PCI_DEV_1['pciaddr'],
            'bmc_build_version': 'D.2.0.6',
            'bmc_fw_version': 'D.2.0.21',
            'boot_page': 'user',
            'bitstream_id': '0x2383A62A010504',
            'root_key': '0x2973c55fc739e8181b16b9b51b786a39c0860159df8fb94652b0fbca87223bc7',
            'revoked_key_ids': '2,10,50-51',
        }
        fpga_device_dict_array = [FPGA_DEV_1]

        # Create new FPGA device.
        self.service.fpga_device_update_by_host(self.context, host_uuid,
                                                fpga_device_dict_array)
        dev = self.dbapi.fpga_device_get(FPGA_DEV_1['pciaddr'], host_id)
        for key in FPGA_DEV_1:
            self.assertEqual(dev[key], FPGA_DEV_1[key])

        # Update existing FPGA device.
        fpga_dev_dict_update = {
            'pciaddr': FPGA_DEV_1['pciaddr'],
            'bmc_build_version': 'D.2.0.7',
            'bmc_fw_version': 'D.2.0.22',
            'boot_page': 'factory',
            'bitstream_id': '0x2383A62A010504',
            'root_key': '',
            'revoked_key_ids': '',
        }
        fpga_dev_dict_update_array = [fpga_dev_dict_update]
        self.service.fpga_device_update_by_host(self.context, host_uuid,
                                                fpga_dev_dict_update_array)
        dev = self.dbapi.fpga_device_get(FPGA_DEV_1['pciaddr'], host_id)
        for key in fpga_dev_dict_update:
            self.assertEqual(dev[key], fpga_dev_dict_update[key])

    def test_device_update_image_status(self):

        mock_host_device_image_update_next = mock.MagicMock()
        p = mock.patch(
            'sysinv.conductor.manager.ConductorManager.host_device_image_update_next',
            mock_host_device_image_update_next)
        p.start()
        self.addCleanup(p.stop)

        # Create compute-0 node
        ihost = self._create_test_ihost(
            personality=constants.WORKER,
            hostname='compute-0',
            uuid=str(uuid.uuid4()),
        )

        host_uuid = ihost.uuid
        host_id = ihost.id

        # Make sure we start with this set to false.
        self.dbapi.ihost_update(host_uuid, {'reboot_needed': False})

        DEV_IMG_STATE = {
            'host_id': host_id,
            'pcidevice_id': 5,
            'image_id': 11,
            'status': '',
        }
        device_image_state = self.dbapi.device_image_state_create(
            DEV_IMG_STATE)
        for key in DEV_IMG_STATE:
            self.assertEqual(device_image_state[key], DEV_IMG_STATE[key])

        # set status to "in-progress"
        self.service.device_update_image_status(self.context,
            host_uuid, device_image_state.uuid,
            dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS)

        mock_host_device_image_update_next.assert_not_called()

        device_image_state = self.dbapi.device_image_state_get(
            device_image_state.id)
        self.assertEqual(device_image_state.status,
                         dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS)
        ihost = self.dbapi.ihost_get(host_id)
        self.assertEqual(ihost.reboot_needed, False)

        # set status to "completed"
        self.service.device_update_image_status(self.context,
            host_uuid, device_image_state.uuid,
            dconstants.DEVICE_IMAGE_UPDATE_COMPLETED)

        mock_host_device_image_update_next.assert_called_with(
            self.context, host_uuid)

        device_image_state = self.dbapi.device_image_state_get(
            device_image_state.id)
        self.assertEqual(device_image_state.status,
                         dconstants.DEVICE_IMAGE_UPDATE_COMPLETED)
        ihost = self.dbapi.ihost_get(host_id)
        self.assertEqual(ihost.reboot_needed, True)

    def test_update_dnsmasq_config(self):
        mock_config_update_hosts = mock.MagicMock()
        mock_config_apply_runtime_manifest = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._config_update_hosts',
                       mock_config_update_hosts)
        p.start().return_value = '1234'
        self.addCleanup(p.stop)
        p2 = mock.patch('sysinv.conductor.manager.ConductorManager._config_apply_runtime_manifest',
                        mock_config_apply_runtime_manifest)
        p2.start()
        self.addCleanup(p2.stop)
        self.service.update_dnsmasq_config(self.context)
        personalities = [constants.CONTROLLER]
        config_dict = {
            "personalities": personalities,
            "classes": ['platform::dns::dnsmasq::runtime'],
        }
        mock_config_apply_runtime_manifest.assert_called_with(mock.ANY, '1234', config_dict)

    def test_update_ldap_client_config(self):
        mock_config_update_hosts = mock.MagicMock()
        mock_config_apply_runtime_manifest = mock.MagicMock()
        p = mock.patch('sysinv.conductor.manager.ConductorManager._config_update_hosts',
                       mock_config_update_hosts)
        p.start().return_value = '1234'
        self.addCleanup(p.stop)
        p2 = mock.patch('sysinv.conductor.manager.ConductorManager._config_apply_runtime_manifest',
                        mock_config_apply_runtime_manifest)
        p2.start()
        self.addCleanup(p2.stop)
        self.service.update_ldap_client_config(self.context)
        personalities = [constants.CONTROLLER]
        config_dict = {
            "personalities": personalities,
            "classes": ['platform::ldap::client::runtime'],
        }
        mock_config_apply_runtime_manifest.assert_called_with(mock.ANY, '1234', config_dict)


class ManagerTestCaseInternal(base.BaseHostTestCase):

    def setUp(self):
        super(ManagerTestCaseInternal, self).setUp()

        # Set up objects for testing
        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()

    def test_remove_lease_for_address(self):
        # create test interface
        ihost = self._create_test_host(
            personality=constants.WORKER,
            administrative=constants.ADMIN_UNLOCKED)
        iface = utils.create_test_interface(
                ifname="test0",
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                forihostid=ihost.id,
                ihost_uuid=ihost.uuid)
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        utils.create_test_interface_network(
            interface_id=iface.id,
            network_id=network.id)

        # create test address associated with interface
        address_name = cutils.format_address_name(ihost.hostname,
            network.type)
        self.dbapi.address_create({
            'name': address_name,
            'family': self.oam_subnet.version,
            'prefix': self.oam_subnet.prefixlen,
            'address': str(self.oam_subnet[24]),
            'interface_id': iface.id,
            'enable_dad': self.oam_subnet.version == 6
        })

        # stub the system i/o calls
        self.mock_objs = [
            mock.patch.object(
                manager.ConductorManager, '_find_local_interface_name',
                lambda x, y: iface.ifname),
            mock.patch('sysinv.common.utils.get_dhcp_cid',
                lambda x, y, z: None),
            mock.patch.object(
                manager.ConductorManager, '_dhcp_release',
                lambda a, b, c, d, e: None)
        ]

        for mock_obj in self.mock_objs:
            mock_obj.start()
            self.addCleanup(mock_obj.stop)

        self.service._remove_lease_for_address(ihost.hostname,
            constants.NETWORK_TYPE_MGMT)
