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
import uuid

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import kubernetes
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

        self.do_update_alarm_status_patcher = mock.patch.object(
            manager.ConductorManager, '_do_update_alarm_status')
        self.mock_do_update_alarm_status = \
            self.do_update_alarm_status_patcher.start()
        self.addCleanup(self.mock_do_update_alarm_status.stop)

        self.fail_config_apply_runtime_manifest = False

        def mock_config_apply_runtime_manifest(obj, context, config_uuid,
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

        self.mocked_config_apply_runtime_manifest = mock.patch.object(
            manager.ConductorManager, '_config_apply_runtime_manifest',
            mock_config_apply_runtime_manifest)
        self.mocked_config_apply_runtime_manifest.start()
        self.addCleanup(self.mocked_config_apply_runtime_manifest.stop)

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
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADE_STARTED)

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
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADE_FAILED)

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
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADE_STARTED)

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
                         kubernetes.KUBE_UPGRADE_FAILED)

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
        self.assertEqual(updated_upgrade.state, kubernetes.KUBE_UPGRADE_STARTED)

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
                         kubernetes.KUBE_UPGRADE_FAILED)

        # Verify that the host upgrade status was set
        updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
        self.assertIsNotNone(updated_host_upgrade.status)

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
                         kubernetes.KUBE_UPGRADE_FAILED)

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

        # Upgrade the kubelet
        self.service.kube_upgrade_kubelet(self.context, c0.uuid)

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADE_FAILED)

        # Verify that the host upgrade status was set
        updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
        self.assertIsNotNone(updated_host_upgrade.status)

    def test_kube_upgrade_kubelet_controller_upgrade_fail(self):
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

        # Upgrade the kubelet
        self.service.kube_upgrade_kubelet(self.context, c0.uuid)

        # Verify that the upgrade state was updated
        updated_upgrade = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(updated_upgrade.state,
                         kubernetes.KUBE_UPGRADE_FAILED)

        # Verify that the host upgrade status was cleared
        updated_host_upgrade = self.dbapi.kube_host_upgrade_get(1)
        self.assertIsNotNone(updated_host_upgrade.status)
