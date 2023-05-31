#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the sysinv agent manager.
"""

import mock

from tsconfig import tsconfig
from oslo_context import context

from sysinv.agent.manager import AgentManager
from sysinv.common import constants
from sysinv.tests import base


class FakeConductorAPI(object):

    def __init__(self, isystem=None):
        self.create_host_filesystems = mock.MagicMock()
        self.update_host_max_cpu_mhz_configured = mock.MagicMock()
        self.device_plugin_labels_update_by_ihost = mock.MagicMock()
        self.is_virtual_system_config_result = False
        self.isystem = isystem

    def is_virtual_system_config(self, ctxt):
        return self.is_virtual_system_config_result

    def get_isystem(self, ctxt):
        if not self.isystem:
            return {}
        return self.isystem


class TestAgentManager(base.TestCase):

    def setUp(self):
        super(TestAgentManager, self).setUp()

        # Set up objects for testing
        self.agent_manager = AgentManager('test-host', 'test-topic')
        self.agent_manager._ihost_uuid = "FAKEUUID"
        self.agent_manager._ihost_rootfs_device = "fake_rootfs_dev"
        self.context = context.get_admin_context()
        self.fake_conductor_api = FakeConductorAPI()
        self.fake_conductor_api_dc_std = FakeConductorAPI(isystem={
            "distributed_cloud_role": constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER,
            "system_type": constants.TIS_STD_BUILD,
        })
        self.fake_conductor_api_dc_aio = FakeConductorAPI(isystem={
            "distributed_cloud_role": constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER,
            "system_type": constants.TIS_AIO_BUILD,
        })

        # Mock get_disk_capacity utility
        self.mock_get_disk_capacity = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.get_disk_capacity_mib',
                       self.mock_get_disk_capacity)
        p.start().return_value = 512000
        self.addCleanup(p.stop)

        # Mock get_current_fs_size utility
        self.scratch_fs_size = 16
        self.backup_fs_size = 20
        self.docker_fs_size = 30
        self.kubelet_fs_size = 10
        self.log_fs_size = 8
        self.var_fs_size = 20
        self.root_fs_size = 20

        def mock_get_current_fs_size(fs_name):
            if fs_name == constants.FILESYSTEM_NAME_SCRATCH:
                return self.scratch_fs_size
            elif fs_name == constants.FILESYSTEM_NAME_BACKUP:
                return self.backup_fs_size
            elif fs_name == constants.FILESYSTEM_NAME_DOCKER:
                return self.docker_fs_size
            elif fs_name == constants.FILESYSTEM_NAME_KUBELET:
                return self.kubelet_fs_size
            elif fs_name == constants.FILESYSTEM_NAME_LOG:
                return self.log_fs_size
            elif fs_name == constants.FILESYSTEM_NAME_VAR:
                return self.var_fs_size
            elif fs_name == constants.FILESYSTEM_NAME_ROOT:
                return self.root_fs_size
        self.mocked_get_current_fs_size = mock.patch(
            'sysinv.common.utils.get_current_fs_size',
            mock_get_current_fs_size)
        self.mocked_get_current_fs_size.start()
        self.addCleanup(self.mocked_get_current_fs_size.stop)

    def tearDown(self):
        super(TestAgentManager, self).tearDown()

    def test_create_host_filesystems_controller_large(self):

        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.mock_get_disk_capacity.return_value = \
            (constants.DEFAULT_SMALL_DISK_SIZE + 1) * 1024

        self.agent_manager._create_host_filesystems(self.fake_conductor_api,
                                                    self.context)

        # Verify expected filesystems and sizes
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'backup-lv', 'name': 'backup', 'size': 25},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 30},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)

    def test_create_host_filesystems_controller_small(self):

        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.mock_get_disk_capacity.return_value = \
            constants.MINIMUM_SMALL_DISK_SIZE * 1024

        self.agent_manager._create_host_filesystems(self.fake_conductor_api,
                                                    self.context)

        # Verify expected filesystems and sizes
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'backup-lv', 'name': 'backup', 'size': 20},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 30},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)

    def test_create_host_filesystems_controller_tiny_virtual_fail(self):

        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.mock_get_disk_capacity.return_value = \
            constants.MINIMUM_TINY_DISK_SIZE * 1024
        self.fake_conductor_api.is_virtual_system_config_result = True

        # Verify filesystems were not created
        self.fake_conductor_api.create_host_filesystems.assert_not_called()
        self.assertEqual(self.agent_manager._prev_fs, None)

    def test_create_host_filesystems_controller_too_small_fail(self):

        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.mock_get_disk_capacity.return_value = \
            (constants.MINIMUM_TINY_DISK_SIZE - 1) * 1024

        # Verify filesystems were not created
        self.fake_conductor_api.create_host_filesystems.assert_not_called()
        self.assertEqual(self.agent_manager._prev_fs, None)

    def test_create_host_filesystems_aio_tiny_virtual(self):

        tsconfig.system_type = constants.TIS_AIO_BUILD
        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.mock_get_disk_capacity.return_value = \
            constants.MINIMUM_TINY_DISK_SIZE * 1024
        self.fake_conductor_api.is_virtual_system_config_result = True

        self.agent_manager._create_host_filesystems(self.fake_conductor_api,
                                                    self.context)

        # Verify expected filesystems and sizes
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'backup-lv', 'name': 'backup', 'size': 1},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 20},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 2},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)

    def test_create_host_filesystems_worker_large(self):

        self.agent_manager._ihost_personality = constants.WORKER
        self.mock_get_disk_capacity.return_value = \
            (constants.DEFAULT_SMALL_DISK_SIZE + 1) * 1024

        self.agent_manager._create_host_filesystems(self.fake_conductor_api,
                                                    self.context)

        # Verify expected filesystems and sizes
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 30},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)

    def test_create_host_filesystems_worker_small(self):

        self.agent_manager._ihost_personality = constants.WORKER
        self.mock_get_disk_capacity.return_value = \
            constants.MINIMUM_SMALL_DISK_SIZE * 1024

        self.agent_manager._create_host_filesystems(self.fake_conductor_api,
                                                    self.context)

        # Verify expected filesystems and sizes
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 30},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)

    def test_create_host_filesystems_worker_tiny(self):

        self.agent_manager._ihost_personality = constants.WORKER
        self.mock_get_disk_capacity.return_value = 80 * 1024
        self.fake_conductor_api.is_virtual_system_config_result = True

        self.agent_manager._create_host_filesystems(self.fake_conductor_api,
                                                    self.context)

        # Verify expected filesystems and sizes
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 30},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)

    def test_create_host_filesystems_storage_large(self):

        self.agent_manager._ihost_personality = constants.STORAGE
        self.mock_get_disk_capacity.return_value = \
            (constants.DEFAULT_SMALL_DISK_SIZE + 1) * 1024

        self.agent_manager._create_host_filesystems(self.fake_conductor_api,
                                                    self.context)

        # Verify expected filesystems and sizes
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 30},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)

    def test_create_host_filesystems_storage_small(self):

        self.agent_manager._ihost_personality = constants.STORAGE
        self.mock_get_disk_capacity.return_value = \
            constants.MINIMUM_SMALL_DISK_SIZE * 1024

        self.agent_manager._create_host_filesystems(self.fake_conductor_api,
                                                    self.context)

        # Verify expected filesystems and sizes
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 30},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)

    def test_create_host_filesystems_storage_tiny(self):

        self.agent_manager._ihost_personality = constants.STORAGE
        self.mock_get_disk_capacity.return_value = 80 * 1024
        self.fake_conductor_api.is_virtual_system_config_result = True

        self.agent_manager._create_host_filesystems(self.fake_conductor_api,
                                                    self.context)

        # Verify expected filesystems and sizes
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 30},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)

    def test_create_host_filesystem_systemcontroller_aio_controller_large(self):
        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.mock_get_disk_capacity.return_value = \
            (constants.DEFAULT_SMALL_DISK_SIZE + 1) * 1024

        self.agent_manager._create_host_filesystems(self.fake_conductor_api_dc_aio,
                                                    self.context)
        # Verify expected filesystems and sizes
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'backup-lv', 'name': 'backup', 'size': 25},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 30},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api_dc_aio.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)

    def test_create_host_filesystem_systemcontroller_aio_controller_small(self):
        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.mock_get_disk_capacity.return_value = \
            constants.MINIMUM_SMALL_DISK_SIZE * 1024

        self.agent_manager._create_host_filesystems(self.fake_conductor_api_dc_aio,
                                                    self.context)
        # Verify expected filesystems and sizes
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'backup-lv', 'name': 'backup', 'size': 20},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 30},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api_dc_aio.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)

    def test_create_host_filesystem_systemcontroller_standard_controller_large(self):
        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.mock_get_disk_capacity.return_value = \
            (constants.DEFAULT_SMALL_DISK_SIZE + 1) * 1024

        self.agent_manager._create_host_filesystems(self.fake_conductor_api_dc_std,
                                                    self.context)
        # Verify expected filesystems and sizes
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'backup-lv', 'name': 'backup', 'size': 35},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 30},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api_dc_std.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)

    def test_create_host_filesystem_systemcontroller_standard_controller_small(self):
        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.mock_get_disk_capacity.return_value = \
            constants.MINIMUM_SMALL_DISK_SIZE * 1024

        self.agent_manager._create_host_filesystems(self.fake_conductor_api_dc_std,
                                                    self.context)
        # Verify expected filesystems and sizes
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'backup-lv', 'name': 'backup', 'size': 20},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 30},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api_dc_std.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)

    def test_create_host_filesystem_systemcontroller_standard_worker_large(self):
        self.agent_manager._ihost_personality = constants.WORKER
        self.mock_get_disk_capacity.return_value = \
            (constants.DEFAULT_SMALL_DISK_SIZE + 1) * 1024

        self.agent_manager._create_host_filesystems(self.fake_conductor_api_dc_std,
                                                    self.context)
        # Verify expected filesystems and sizes
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 30},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api_dc_std.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)

    def test_create_host_filesystem_systemcontroller_standard_worker_small(self):
        self.agent_manager._ihost_personality = constants.WORKER
        self.mock_get_disk_capacity.return_value = \
            constants.MINIMUM_SMALL_DISK_SIZE * 1024

        self.agent_manager._create_host_filesystems(self.fake_conductor_api_dc_std,
                                                    self.context)
        # Verify expected filesystems and sizes
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 30},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api_dc_std.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)

    def test_report_supported_device_plugin(self):

        # Mock _get_ports_inventory
        self.mock_get_ports_inventory = mock.MagicMock()
        p = mock.patch('sysinv.agent.manager.AgentManager._get_ports_inventory',
                       self.mock_get_ports_inventory)
        p.start().return_value = ["", ['k8s_device_plugin', 'port', 'pci_device'], ""]
        self.addCleanup(p.stop)

        # Mock get_supported_device_plugins
        self.mock_get_supported_device_plugins = mock.MagicMock()
        p = mock.patch('sysinv.agent.pci.PCIOperator.get_supported_device_plugins',
                       self.mock_get_supported_device_plugins)
        p.start().return_value = ['intelgpu']
        self.addCleanup(p.stop)

        self.agent_manager._ihost_uuid = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
        # Verify the expected label_key and label_value to be called
        expected_label = ['intelgpu']
        self.agent_manager._report_supported_device_plugin(self.context, self.fake_conductor_api)
        self.fake_conductor_api.device_plugin_labels_update_by_ihost.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_label)
        self.assertIn('k8s_device_plugin', self.agent_manager._inventory_reported)
