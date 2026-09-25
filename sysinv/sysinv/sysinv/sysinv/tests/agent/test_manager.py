#
# Copyright (c) 2023, 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the sysinv agent manager.
"""

import inspect
import mock

from oslo_context import context

from sysinv.agent.manager import AgentManager
from sysinv.common import constants
from sysinv.common import exception
from sysinv.tests import base
from tsconfig import tsconfig


class FakeConductorAPI(object):

    def __init__(self, isystem=None):
        self.create_host_filesystems = mock.MagicMock()
        self.update_host_max_cpu_mhz_configured = mock.MagicMock()
        self.is_virtual_system_config_result = False
        self.isystem = isystem

    def is_virtual_system_config(self, ctxt):
        return self.is_virtual_system_config_result

    def get_isystem(self, ctxt):
        if not self.isystem:
            return {}
        return self.isystem


class TestHostFileSystems(base.TestCase):
    def setUp(self):
        super(TestHostFileSystems, self).setUp()

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
        self.docker_fs_size = 40
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
        super(TestHostFileSystems, self).tearDown()

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
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 40},
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
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 40},
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
        # Simulate tiny virtual LV size as puppet would have configured
        self.docker_fs_size = constants.TINY_KUBERNETES_DOCKER_STOR_SIZE

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

    def test_create_host_filesystems_controller_custom_docker_size(self):

        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.mock_get_disk_capacity.return_value = \
            (constants.DEFAULT_SMALL_DISK_SIZE + 1) * 1024
        # Simulate a custom docker LV size configured via bootstrap overrides
        self.docker_fs_size = 60

        self.agent_manager._create_host_filesystems(self.fake_conductor_api,
                                                    self.context)

        # Verify expected filesystems and sizes - docker should use
        # the custom size (60) rather than default (30 or 40)
        expected_filesystems = [
            {'logical_volume': 'scratch-lv', 'name': 'scratch', 'size': 16},
            {'logical_volume': 'backup-lv', 'name': 'backup', 'size': 25},
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 60},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
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
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 40},
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
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 40},
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
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 40},
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
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 40},
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
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 40},
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
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 40},
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
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 40},
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
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 40},
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
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 40},
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
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 40},
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
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 40},
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
            {'logical_volume': 'docker-lv', 'name': 'docker', 'size': 40},
            {'logical_volume': 'kubelet-lv', 'name': 'kubelet', 'size': 10},
            {'logical_volume': 'log-lv', 'name': 'log', 'size': 8},
            {'logical_volume': 'var-lv', 'name': 'var', 'size': 20},
            {'logical_volume': 'root-lv', 'name': 'root', 'size': 20}]

        self.fake_conductor_api_dc_std.create_host_filesystems.assert_called_with(
            self.context,
            self.agent_manager._ihost_uuid,
            expected_filesystems)
        self.assertEqual(self.agent_manager._prev_fs, expected_filesystems)


class TestHostKubernetesOperations(base.TestCase):

    def setUp(self):
        super(TestHostKubernetesOperations, self).setUp()

        # Set up objects for testing
        self.agent_manager = AgentManager('test-host', 'test-topic')
        self.agent_manager._ihost_uuid = "FAKEUUID"
        self.context = context.get_admin_context()
        self.fake_conductor_api = FakeConductorAPI()

    def tearDown(self):
        super(TestHostKubernetesOperations, self).tearDown()

    def test_pull_kubernetes_images_success(self):
        """Test pull kubernetes images: Successful execution
        """
        images_to_be_pulled = ['fake_image1', 'fake_image2', 'fake_image3', 'fake_image4']
        fake_crictl_auth = "fake_username:fake_password"
        result = True

        mock_save_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_save_kube_upgrade_method_details',
            mock_save_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        mock_disable_kubelet_garbage_collection = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.disable_kubelet_garbage_collection',
                       mock_disable_kubelet_garbage_collection)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        mock_pull_images = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.ContainerdOperator.pull_images', mock_pull_images)
        p.start().return_value = result
        self.addCleanup(p.stop)

        mock_report_download_images_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.report_download_images_result',
                       mock_report_download_images_result)
        p.start()
        self.addCleanup(p.stop)

        mock_cleanup_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_cleanup_kube_upgrade_method_details',
            mock_cleanup_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager.pull_kubernetes_images(
            self.context, self.agent_manager._ihost_uuid, images_to_be_pulled, fake_crictl_auth)

        mock_save_kube_upgrade_method_details.assert_called_once()
        mock_cleanup_kube_upgrade_method_details.assert_called_once()
        mock_disable_kubelet_garbage_collection.assert_called_once()
        mock_pmon_restart_service.assert_called_once()
        mock_pull_images.assert_called_once_with(images_to_be_pulled, fake_crictl_auth)
        mock_report_download_images_result.assert_called_once_with(self.context, result)

    def test_pull_kubernetes_images_success_disable_gc_failed(self):
        """Test pull kubernetes images: Successful execution even though disable GC failed
        """
        images_to_be_pulled = ['fake_image1', 'fake_image2', 'fake_image3', 'fake_image4']
        fake_crictl_auth = "fake_username:fake_password"
        result = True

        mock_save_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_save_kube_upgrade_method_details',
            mock_save_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        mock_disable_kubelet_garbage_collection = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.disable_kubelet_garbage_collection',
                       mock_disable_kubelet_garbage_collection)
        p.start().side_effect = exception.SysinvException("Fake error")
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        mock_pull_images = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.ContainerdOperator.pull_images', mock_pull_images)
        p.start().return_value = result
        self.addCleanup(p.stop)

        mock_report_download_images_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.report_download_images_result',
                       mock_report_download_images_result)
        p.start()
        self.addCleanup(p.stop)

        mock_cleanup_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_cleanup_kube_upgrade_method_details',
            mock_cleanup_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager.pull_kubernetes_images(
            self.context, self.agent_manager._ihost_uuid, images_to_be_pulled, fake_crictl_auth)

        mock_save_kube_upgrade_method_details.assert_called_once()
        mock_cleanup_kube_upgrade_method_details.assert_called_once()
        mock_disable_kubelet_garbage_collection.assert_called_once()
        mock_pmon_restart_service.assert_not_called()
        mock_pull_images.assert_called_once_with(images_to_be_pulled, fake_crictl_auth)
        mock_report_download_images_result.assert_called_once_with(self.context, result)

    def test_pull_kubernetes_images_failure(self):
        """Test pull kubernetes images failure: crictl image pull failed
        """
        images_to_be_pulled = ['fake_image1', 'fake_image2', 'fake_image3', 'fake_image4']
        fake_crictl_auth = "fake_username:fake_password"
        result = False

        mock_save_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_save_kube_upgrade_method_details',
            mock_save_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        mock_disable_kubelet_garbage_collection = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.disable_kubelet_garbage_collection',
                       mock_disable_kubelet_garbage_collection)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        mock_pull_images = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.ContainerdOperator.pull_images', mock_pull_images)
        p.start().return_value = result
        self.addCleanup(p.stop)

        mock_report_download_images_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.report_download_images_result',
                       mock_report_download_images_result)
        p.start()
        self.addCleanup(p.stop)

        mock_cleanup_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_cleanup_kube_upgrade_method_details',
            mock_cleanup_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager.pull_kubernetes_images(
            self.context, self.agent_manager._ihost_uuid, images_to_be_pulled, fake_crictl_auth)

        mock_save_kube_upgrade_method_details.assert_called_once()
        mock_cleanup_kube_upgrade_method_details.assert_called_once()
        mock_disable_kubelet_garbage_collection.assert_called_once()
        mock_pmon_restart_service.assert_called_once()
        mock_pull_images.assert_called_once_with(images_to_be_pulled, fake_crictl_auth)
        mock_report_download_images_result.assert_called_once_with(self.context, result)

    def test_kube_upgrade_kubelet_success_controller_node(self):
        """Test successful execution of kubelet upgrade on a controller node
        """
        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.agent_manager._ihostname = 'fake_host_name'
        fake_link = '/fake/path/to/fake_from_kube_version'
        to_kube_version = 'vfake_to_kube_version'
        upgrade_result = True
        is_final_version = True

        mock_save_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_save_kube_upgrade_method_details',
            mock_save_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        mock_os_readlink = mock.MagicMock()
        p = mock.patch('os.readlink', mock_os_readlink)
        p.start().return_value = fake_link
        self.addCleanup(p.stop)

        mock_upgrade_controller_kubelet = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.upgrade_kubelet',
                       mock_upgrade_controller_kubelet)
        p.start()
        self.addCleanup(p.stop)

        mock_upgrade_worker_kubelet = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeWorkerOperator.upgrade_kubelet',
                       mock_upgrade_worker_kubelet)
        p.start()
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_kubelet_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.report_kube_upgrade_kubelet_result',
                       mock_report_kube_upgrade_kubelet_result)
        p.start()
        self.addCleanup(p.stop)

        mock_cleanup_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_cleanup_kube_upgrade_method_details',
            mock_cleanup_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager.kube_upgrade_kubelet(
            self.context, self.agent_manager._ihost_uuid, to_kube_version, is_final_version)

        mock_save_kube_upgrade_method_details.assert_called_once()
        mock_cleanup_kube_upgrade_method_details.assert_called_once()
        mock_os_readlink.assert_called_once()
        mock_upgrade_controller_kubelet.assert_called_once_with(
            'vfake_from_kube_version', to_kube_version, is_final_version)
        mock_upgrade_worker_kubelet.assert_not_called()
        mock_report_kube_upgrade_kubelet_result.assert_called_once_with(
            self.context, self.agent_manager._ihost_uuid, to_kube_version, upgrade_result)

    def test_kube_upgrade_kubelet_success_worker_node(self):
        """Test successful execution of kubelet upgrade on a worker node
        """
        self.agent_manager._ihost_personality = constants.WORKER
        self.agent_manager._ihostname = 'fake_host_name'
        fake_link = '/fake/path/to/fake_from_kube_version'
        to_kube_version = 'vfake_to_kube_version'
        upgrade_result = True
        is_final_version = True

        mock_save_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_save_kube_upgrade_method_details',
            mock_save_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        mock_os_readlink = mock.MagicMock()
        p = mock.patch('os.readlink', mock_os_readlink)
        p.start().return_value = fake_link
        self.addCleanup(p.stop)

        mock_upgrade_controller_kubelet = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.upgrade_kubelet',
                       mock_upgrade_controller_kubelet)
        p.start()
        self.addCleanup(p.stop)

        mock_upgrade_worker_kubelet = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeWorkerOperator.upgrade_kubelet',
                       mock_upgrade_worker_kubelet)
        p.start()
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_kubelet_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.report_kube_upgrade_kubelet_result',
                       mock_report_kube_upgrade_kubelet_result)
        p.start()
        self.addCleanup(p.stop)

        mock_cleanup_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_cleanup_kube_upgrade_method_details',
            mock_cleanup_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager.kube_upgrade_kubelet(
            self.context, self.agent_manager._ihost_uuid, to_kube_version, is_final_version)

        mock_save_kube_upgrade_method_details.assert_called_once()
        mock_cleanup_kube_upgrade_method_details.assert_called_once()
        mock_os_readlink.assert_called_once()
        mock_upgrade_controller_kubelet.assert_not_called()
        mock_upgrade_worker_kubelet.assert_called_once_with(
            'vfake_from_kube_version', to_kube_version, is_final_version)
        mock_report_kube_upgrade_kubelet_result.assert_called_once_with(
            self.context, self.agent_manager._ihost_uuid, to_kube_version, upgrade_result)

    def test_kube_upgrade_kubelet_failure(self):
        """Test failed execution of kubelet upgrade on a worker node
        """
        self.agent_manager._ihost_personality = constants.WORKER
        self.agent_manager._ihostname = 'fake_host_name'
        fake_link = '/fake/path/to/fake_from_kube_version'
        to_kube_version = 'vfake_to_kube_version'
        upgrade_result = False
        is_final_version = True

        mock_save_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_save_kube_upgrade_method_details',
            mock_save_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        mock_os_readlink = mock.MagicMock()
        p = mock.patch('os.readlink', mock_os_readlink)
        p.start().return_value = fake_link
        self.addCleanup(p.stop)

        mock_upgrade_controller_kubelet = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.upgrade_kubelet',
                       mock_upgrade_controller_kubelet)
        p.start()
        self.addCleanup(p.stop)

        mock_upgrade_worker_kubelet = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeWorkerOperator.upgrade_kubelet',
                       mock_upgrade_worker_kubelet)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_kubelet_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.report_kube_upgrade_kubelet_result',
                       mock_report_kube_upgrade_kubelet_result)
        p.start()
        self.addCleanup(p.stop)

        mock_cleanup_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_cleanup_kube_upgrade_method_details',
            mock_cleanup_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager.kube_upgrade_kubelet(
            self.context, self.agent_manager._ihost_uuid, to_kube_version, is_final_version)

        mock_save_kube_upgrade_method_details.assert_called_once()
        mock_cleanup_kube_upgrade_method_details.assert_called_once()
        mock_os_readlink.assert_called_once()
        mock_upgrade_controller_kubelet.assert_not_called()
        mock_upgrade_worker_kubelet.assert_called_once_with(
            'vfake_from_kube_version', to_kube_version, is_final_version)
        mock_report_kube_upgrade_kubelet_result.assert_called_once_with(
            self.context, self.agent_manager._ihost_uuid, to_kube_version, upgrade_result)

    def test_unfinished_kube_upgrade_check_success_k8s_upgrade_found_and_rerun(self):
        """Test successful execution of _unfinished_kube_upgrade_check for pull_kubernetes_images

        It should be enough to have a success path test for just one method (pull_kubernetes_images)
        although it is used in three more kubernetes upgrade related methods.
        """
        ctx = context.get_admin_context()
        fake_host_uuid = 'fake_uuid'
        fake_images = ['fake_image1', 'fake_image2']

        pickled_data = {
            'method_name': 'pull_kubernetes_images',
            'context': ctx,
            'host_uuid': fake_host_uuid,
            'images': fake_images
        }

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        mock_time_sleep = mock.MagicMock()
        p = mock.patch('time.sleep', mock_time_sleep)
        p.start()
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_pickle_load = mock.MagicMock()
        p = mock.patch('pickle.load', mock_pickle_load)
        p.start().return_value = pickled_data
        self.addCleanup(p.stop)

        mock_pull_kubernetes_images = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, 'pull_kubernetes_images', mock_pull_kubernetes_images)
        p.start()
        self.addCleanup(p.stop)

        mock_report_unfinished_kube_upgrade_from_agent = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                       'report_unfinished_kube_upgrade_from_agent',
                       mock_report_unfinished_kube_upgrade_from_agent)
        p.start()
        self.addCleanup(p.stop)

        mock_cleanup_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_cleanup_kube_upgrade_method_details',
            mock_cleanup_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager._unfinished_kube_upgrade_check()

        mock_os_path_exists.assert_called_once()
        mock_time_sleep.assert_not_called()
        mock_open.assert_called_once()
        mock_pickle_load.assert_called_once()
        mock_pull_kubernetes_images.assert_called_with(
            context=ctx, host_uuid=fake_host_uuid, images=fake_images)
        mock_report_unfinished_kube_upgrade_from_agent.assert_not_called()
        mock_cleanup_kube_upgrade_method_details.assert_called_once()

    def test_unfinished_kube_upgrade_check_success_no_unfinished_k8s_upgrade_found(self):
        """Test successful execution of _unfinished_kube_upgrade_check: No unfinished upgrade found
        """
        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = False
        self.addCleanup(p.stop)

        mock_time_sleep = mock.MagicMock()
        p = mock.patch('time.sleep', mock_time_sleep)
        p.start()
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_pickle_load = mock.MagicMock()
        p = mock.patch('pickle.load', mock_pickle_load)
        p.start()
        self.addCleanup(p.stop)

        mock_pull_kubernetes_images = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, 'pull_kubernetes_images', mock_pull_kubernetes_images)
        p.start()
        self.addCleanup(p.stop)

        mock_report_unfinished_kube_upgrade_from_agent = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                       'report_unfinished_kube_upgrade_from_agent',
                       mock_report_unfinished_kube_upgrade_from_agent)
        p.start()
        self.addCleanup(p.stop)

        mock_cleanup_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_cleanup_kube_upgrade_method_details',
            mock_cleanup_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager._unfinished_kube_upgrade_check()

        mock_os_path_exists.assert_called_once()
        mock_time_sleep.assert_not_called()
        mock_open.assert_not_called()
        mock_pickle_load.assert_not_called()
        mock_pull_kubernetes_images.assert_not_called()
        mock_report_unfinished_kube_upgrade_from_agent.assert_not_called()
        mock_cleanup_kube_upgrade_method_details.assert_not_called()

    def test_unfinished_kube_upgrade_check_failure_corrupted_saved_data(self):
        """Test failed execution of _unfinished_kube_upgrade_check: corrupted saved data
        """
        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        mock_time_sleep = mock.MagicMock()
        p = mock.patch('time.sleep', mock_time_sleep)
        p.start()
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_pickle_load = mock.MagicMock()
        p = mock.patch('pickle.load', mock_pickle_load)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        mock_pull_kubernetes_images = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, 'pull_kubernetes_images', mock_pull_kubernetes_images)
        p.start()
        self.addCleanup(p.stop)

        mock_report_unfinished_kube_upgrade_from_agent = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                       'report_unfinished_kube_upgrade_from_agent',
                       mock_report_unfinished_kube_upgrade_from_agent)
        p.start()
        self.addCleanup(p.stop)

        mock_cleanup_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_cleanup_kube_upgrade_method_details',
            mock_cleanup_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager._unfinished_kube_upgrade_check()

        mock_os_path_exists.assert_called()
        mock_time_sleep.assert_not_called()
        mock_open.assert_called_once()
        mock_pickle_load.assert_called_once()
        mock_pull_kubernetes_images.assert_not_called()
        mock_report_unfinished_kube_upgrade_from_agent.assert_called_once()
        mock_cleanup_kube_upgrade_method_details.assert_called_once()

    def test_unfinished_kube_upgrade_check_failure_k8s_upgrade_details_unavailable(self):
        """Test failed execution of _unfinished_kube_upgrade_check: k8s upgrade details unavailable

        pickle.load successful but without expected details
        """
        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        mock_time_sleep = mock.MagicMock()
        p = mock.patch('time.sleep', mock_time_sleep)
        p.start()
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_pickle_load = mock.MagicMock()
        p = mock.patch('pickle.load', mock_pickle_load)
        p.start().return_value = None
        self.addCleanup(p.stop)

        mock_pull_kubernetes_images = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, 'pull_kubernetes_images', mock_pull_kubernetes_images)
        p.start()
        self.addCleanup(p.stop)

        mock_report_unfinished_kube_upgrade_from_agent = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                       'report_unfinished_kube_upgrade_from_agent',
                       mock_report_unfinished_kube_upgrade_from_agent)
        p.start()
        self.addCleanup(p.stop)

        mock_cleanup_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_cleanup_kube_upgrade_method_details',
            mock_cleanup_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager._unfinished_kube_upgrade_check()

        mock_os_path_exists.assert_called_once()
        mock_time_sleep.assert_not_called()
        mock_open.assert_called_once()
        mock_pickle_load.assert_called_once()
        mock_pull_kubernetes_images.assert_not_called()
        mock_report_unfinished_kube_upgrade_from_agent.assert_called_once()
        mock_cleanup_kube_upgrade_method_details.assert_called_once()

    def test_unfinished_kube_upgrade_check_failure_method_name_unavailable(self):
        """Test failed execution of _unfinished_kube_upgrade_check: method name unavailable
        """
        pickled_data = {
            'irrelevant': 'data'
        }

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        mock_time_sleep = mock.MagicMock()
        p = mock.patch('time.sleep', mock_time_sleep)
        p.start()
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_pickle_load = mock.MagicMock()
        p = mock.patch('pickle.load', mock_pickle_load)
        p.start().return_value = pickled_data
        self.addCleanup(p.stop)

        mock_pull_kubernetes_images = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, 'pull_kubernetes_images', mock_pull_kubernetes_images)
        p.start()
        self.addCleanup(p.stop)

        mock_report_unfinished_kube_upgrade_from_agent = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                       'report_unfinished_kube_upgrade_from_agent',
                       mock_report_unfinished_kube_upgrade_from_agent)
        p.start()
        self.addCleanup(p.stop)

        mock_cleanup_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_cleanup_kube_upgrade_method_details',
            mock_cleanup_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager._unfinished_kube_upgrade_check()

        mock_os_path_exists.assert_called_once()
        mock_time_sleep.assert_not_called()
        mock_open.assert_called_once()
        mock_pickle_load.assert_called_once()
        mock_pull_kubernetes_images.assert_not_called()
        mock_report_unfinished_kube_upgrade_from_agent.assert_called_once()
        mock_cleanup_kube_upgrade_method_details.assert_called_once()

    def test_unfinished_kube_upgrade_check_failure_invalid_method_name(self):
        """Test failed execution of _unfinished_kube_upgrade_check: invalid method name
        """
        pickled_data = {
            'method_name': 'some_non_existing_method'
        }

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        mock_time_sleep = mock.MagicMock()
        p = mock.patch('time.sleep', mock_time_sleep)
        p.start()
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_pickle_load = mock.MagicMock()
        p = mock.patch('pickle.load', mock_pickle_load)
        p.start().return_value = pickled_data
        self.addCleanup(p.stop)

        mock_pull_kubernetes_images = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, 'pull_kubernetes_images', mock_pull_kubernetes_images)
        p.start()
        self.addCleanup(p.stop)

        mock_report_unfinished_kube_upgrade_from_agent = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                       'report_unfinished_kube_upgrade_from_agent',
                       mock_report_unfinished_kube_upgrade_from_agent)
        p.start()
        self.addCleanup(p.stop)

        mock_cleanup_kube_upgrade_method_details = mock.MagicMock()
        p = mock.patch.object(
            self.agent_manager, '_cleanup_kube_upgrade_method_details',
            mock_cleanup_kube_upgrade_method_details)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager._unfinished_kube_upgrade_check()

        mock_os_path_exists.assert_called_once()
        mock_time_sleep.assert_not_called()
        mock_open.assert_called_once()
        mock_pickle_load.assert_called_once()
        mock_pull_kubernetes_images.assert_not_called()
        mock_report_unfinished_kube_upgrade_from_agent.assert_called_once()
        mock_cleanup_kube_upgrade_method_details.assert_called_once()

    def test_save_kube_upgrade_method_details_success(self):
        """Test successful execution of method _save_kube_upgrade_method_details
        """
        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_pickle_dump = mock.MagicMock()
        p = mock.patch('pickle.dump', mock_pickle_dump)
        p.start()
        self.addCleanup(p.stop)

        frame = inspect.currentframe()
        self.agent_manager._save_kube_upgrade_method_details(frame)

        mock_open.assert_called_once()
        mock_pickle_dump.assert_called_once()

    def test_save_kube_upgrade_method_details_failure_none_frame(self):
        """Test failed execution of method _save_kube_upgrade_method_details: frame=None
        """
        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_pickle_dump = mock.MagicMock()
        p = mock.patch('pickle.dump', mock_pickle_dump)
        p.start()
        self.addCleanup(p.stop)

        frame = None
        self.assertRaises(exception.SysinvException,
                          self.agent_manager._save_kube_upgrade_method_details,
                          frame)

        mock_open.assert_not_called()
        mock_pickle_dump.assert_not_called()

    def test_save_kube_upgrade_method_details_failure_frame_not_a_frame(self):
        """Test failed execution of method _save_kube_upgrade_method_details: invalid frame value
        """
        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_pickle_dump = mock.MagicMock()
        p = mock.patch('pickle.dump', mock_pickle_dump)
        p.start()
        self.addCleanup(p.stop)

        # Different datatypes other than 'frame' object
        frame_values = [1, True, 32.43, 'invalid_string']

        for frame in frame_values:
            self.assertRaises(exception.SysinvException,
                            self.agent_manager._save_kube_upgrade_method_details,
                            frame)

            mock_open.assert_not_called()
            mock_pickle_dump.assert_not_called()

    def test_save_kube_upgrade_method_details_failure_arg_info_none(self):
        """Test failed execution of method _save_kube_upgrade_method_details: arg_info = None
        """
        mock_inspect_getargvalues = mock.mock_open()
        p = mock.patch('inspect.getargvalues', mock_inspect_getargvalues)
        p.start().return_value = None
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_pickle_dump = mock.MagicMock()
        p = mock.patch('pickle.dump', mock_pickle_dump)
        p.start()
        self.addCleanup(p.stop)

        frame = inspect.currentframe()
        self.assertRaises(exception.SysinvException,
                          self.agent_manager._save_kube_upgrade_method_details,
                          frame)

        mock_open.assert_not_called()
        mock_pickle_dump.assert_not_called()

    def test_save_kube_upgrade_method_details_failure_data_to_save_is_none(self):
        """Test failed execution of method _save_kube_upgrade_method_details: arg_info.locals=None
        """
        arg_info_object = inspect.ArgInfo(args=[], locals=None, varargs=None, keywords=None)

        mock_inspect_getargvalues = mock.mock_open()
        p = mock.patch('inspect.getargvalues', mock_inspect_getargvalues)
        p.start().return_value = arg_info_object
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_pickle_dump = mock.MagicMock()
        p = mock.patch('pickle.dump', mock_pickle_dump)
        p.start()
        self.addCleanup(p.stop)

        frame = inspect.currentframe()
        self.assertRaises(exception.SysinvException,
                          self.agent_manager._save_kube_upgrade_method_details,
                          frame)

        mock_open.assert_not_called()
        mock_pickle_dump.assert_not_called()

    def test_save_kube_upgrade_method_details_failure_frame_is_absent_in_the_data_to_save(self):
        """Test failed execution of method _save_kube_upgrade_method_details: 'frame' absent
        """
        # No 'frame' in frame object
        arg_info_object = inspect.ArgInfo(
            args=[], locals={'self': self}, varargs=None, keywords=None)

        mock_inspect_getargvalues = mock.mock_open()
        p = mock.patch('inspect.getargvalues', mock_inspect_getargvalues)
        p.start().return_value = arg_info_object
        self.addCleanup(p.stop)

        mock_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_open)
        p.start()
        self.addCleanup(p.stop)

        mock_pickle_dump = mock.MagicMock()
        p = mock.patch('pickle.dump', mock_pickle_dump)
        p.start()
        self.addCleanup(p.stop)

        frame = inspect.currentframe()
        self.assertRaises(exception.SysinvException,
                          self.agent_manager._save_kube_upgrade_method_details,
                          frame)

        mock_open.assert_not_called()
        mock_pickle_dump.assert_not_called()

    def test_cleanup_kube_upgrade_method_details_success(self):
        """Test successful execution of method _cleanup_kube_upgrade_method_details
        """
        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager._cleanup_kube_upgrade_method_details()

        mock_os_path_exists.assert_called_once()
        mock_os_remove.assert_called_once()

    def test_cleanup_kube_upgrade_method_details_success_file_unexisting(self):
        """Test successful execution of method _cleanup_kube_upgrade_method_details: File not exist.
        """
        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = False
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager._cleanup_kube_upgrade_method_details()

        mock_os_path_exists.assert_called_once()
        mock_os_remove.assert_not_called()

    def test_cleanup_kube_upgrade_method_details_exception(self):
        """Test successful execution of method _cleanup_kube_upgrade_method_details: Exception
        """
        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.agent_manager._cleanup_kube_upgrade_method_details()

        mock_os_path_exists.assert_called_once()
        mock_os_remove.assert_called_once()

    def test_kube_upgrade_control_plane_success_first_attempt(self):
        """Test successful execution of control plane upgrade
        """
        self.skipTest("WIP:jgauld etcd-versions")

        # WIP: fix the following
        # Failed to save kube control plane upgrade method details with error:
        #  [Failed to save kubernetes upgrade method name and arguments.
        #  Error: [[Errno 2] No such file or directory:
        #  '/etc/platform/.sysinv_agent_k8s_upgrade_in_progress.pkl']]. Continuing...
        # Unable to find etcd version in symlink target /usr/local/kubernetes/1.32.2/stage1
        # etcd binary upgrade not required from: None
        # Kubernetes control-plane upgrade to version vfake_to_kube_version started on this host. Attempt: 1
        # Kubernetes control-plane upgrade to version vfake_to_kube_version successful on this host.

        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.agent_manager._ihostname = 'fake_host_name'
        target_etcd_version = '3.5.26'
        to_kube_version = 'vfake_to_kube_version'
        current_link_etcd = '/usr/local/etcd/3.4.37/stage0'
        current_link_kube = '/usr/local/kubernetes/1.32.2/stage1'
        upgrade_result = True
        is_first_master = True

        mock_os_readlink_etcd = mock.MagicMock()
        p = mock.patch('os.readlink', mock_os_readlink_etcd)
        p.start().return_value = current_link_etcd
        self.addCleanup(p.stop)

        mock_upgrade_etcd_binary = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.upgrade_etcd_binary',
                       mock_upgrade_etcd_binary)
        p.start()
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_etcd_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                       'report_kube_upgrade_etcd_result',
                       mock_report_kube_upgrade_etcd_result)
        p.start()
        self.addCleanup(p.stop)

        mock_os_readlink_kube = mock.MagicMock()
        p = mock.patch('os.readlink', mock_os_readlink_kube)
        p.start().return_value = current_link_kube
        self.addCleanup(p.stop)

        mock_preflight = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.'
                       'wait_for_kube_upgrade_preflight_readiness',
                       mock_preflight)
        p.start()
        self.addCleanup(p.stop)

        mock_upgrade_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.upgrade_control_plane',
                       mock_upgrade_control_plane)
        p.start()
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_control_plane_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                       'report_kube_upgrade_control_plane_result',
                       mock_report_kube_upgrade_control_plane_result)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager.kube_upgrade_control_plane(
            self.context, self.agent_manager._ihost_uuid, target_etcd_version,
            to_kube_version, is_first_master)

        mock_upgrade_etcd_binary.assert_called_once_with(
            target_etcd_version, is_first_master)

        mock_upgrade_control_plane.assert_called_once_with(
            'v1.32.2', to_kube_version, is_first_master)

        mock_os_readlink_etcd.assert_called_once()

        mock_report_kube_upgrade_etcd_result.assert_called_once_with(
            self.context, self.agent_manager._ihost_uuid, target_etcd_version,
            is_first_master, upgrade_result)

        mock_os_readlink_kube.assert_called_once()

        mock_report_kube_upgrade_control_plane_result.assert_called_once_with(
            self.context, self.agent_manager._ihost_uuid, to_kube_version,
            is_first_master, upgrade_result)

    def test_kube_upgrade_control_plane_success_retry(self):
        """Test successful execution of control plane upgrade in retry attempt
        """
        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.agent_manager._ihostname = 'fake_host_name'
        target_etcd_version = 'vfake_target_etcd_version'
        to_kube_version = 'vfake_to_kube_version'
        current_link_etcd = '/usr/local/etcd/3.4.37/stage0'
        current_link_kube = '/usr/local/kubernetes/1.32.2/stage1'
        upgrade_result = True
        is_first_master = True

        mock_preflight = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.'
                       'wait_for_kube_upgrade_preflight_readiness',
                       mock_preflight)
        p.start()
        self.addCleanup(p.stop)

        mock_upgrade_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.upgrade_control_plane',
                       mock_upgrade_control_plane)
        p.start().side_effect = [Exception("Fake error"), True]
        self.addCleanup(p.stop)

        mock_os_readlink_etcd = mock.MagicMock()
        p = mock.patch('os.readlink', mock_os_readlink_etcd)
        p.start().return_value = current_link_etcd
        self.addCleanup(p.stop)

        mock_os_readlink_kube = mock.MagicMock()
        p = mock.patch('os.readlink', mock_os_readlink_kube)
        p.start().return_value = current_link_kube
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_control_plane_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                       'report_kube_upgrade_control_plane_result',
                       mock_report_kube_upgrade_control_plane_result)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager.kube_upgrade_control_plane(
            self.context, self.agent_manager._ihost_uuid, target_etcd_version,
            to_kube_version, is_first_master)

        mock_upgrade_control_plane.assert_called()
        self.assertEqual(mock_upgrade_control_plane.call_count, 2)

        # Proactive preflight readiness wait runs once before the retry loop.
        mock_preflight.assert_called_once_with()

        # TODO(jgauld) - WIP
        # mock_report_kube_upgrade_etcd_result.assert_called_once_with(
        #     self.context, self.agent_manager._ihost_uuid, target_etcd_version,
        #     is_first_master, upgrade_result)

        mock_report_kube_upgrade_control_plane_result.assert_called_once_with(
            self.context, self.agent_manager._ihost_uuid, to_kube_version,
            is_first_master, upgrade_result)

    def test_kube_upgrade_control_plane_preflight_exception_proceeds(self):
        """Test control plane upgrade proceeds when preflight readiness fails.

        The proactive preflight readiness wait is best effort: if it raises
        (e.g. it times out waiting for the node to become Ready), the upgrade
        must still proceed and let the retry loop handle it. This verifies the
        exception is caught and the control-plane upgrade is still attempted
        and succeeds.
        """
        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.agent_manager._ihostname = 'fake_host_name'
        target_etcd_version = 'vfake_target_etcd_version'
        to_kube_version = 'vfake_to_kube_version'
        current_link_etcd = '/usr/local/etcd/3.4.37/stage0'
        current_link_kube = '/usr/local/kubernetes/1.32.2/stage1'
        upgrade_result = True
        is_first_master = True

        # Preflight readiness raises - upgrade must proceed anyway.
        mock_preflight = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.'
                       'wait_for_kube_upgrade_preflight_readiness',
                       mock_preflight)
        p.start().side_effect = exception.SysinvException(
            "Preflight readiness failed")
        self.addCleanup(p.stop)

        mock_upgrade_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.upgrade_control_plane',
                       mock_upgrade_control_plane)
        p.start().return_value = True
        self.addCleanup(p.stop)

        mock_os_readlink_etcd = mock.MagicMock()
        p = mock.patch('os.readlink', mock_os_readlink_etcd)
        p.start().return_value = current_link_etcd
        self.addCleanup(p.stop)

        mock_os_readlink_kube = mock.MagicMock()
        p = mock.patch('os.readlink', mock_os_readlink_kube)
        p.start().return_value = current_link_kube
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_control_plane_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                       'report_kube_upgrade_control_plane_result',
                       mock_report_kube_upgrade_control_plane_result)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager.kube_upgrade_control_plane(
            self.context, self.agent_manager._ihost_uuid, target_etcd_version,
            to_kube_version, is_first_master)

        # Preflight was attempted once and raised.
        mock_preflight.assert_called_once_with()

        # The upgrade proceeded despite the preflight exception and succeeded
        # on the first attempt.
        mock_upgrade_control_plane.assert_called_once()

        mock_report_kube_upgrade_control_plane_result.assert_called_once_with(
            self.context, self.agent_manager._ihost_uuid, to_kube_version,
            is_first_master, upgrade_result)

    def test_kube_upgrade_control_plane_non_controller(self):
        """Test successful execution of control plane upgrade on a non-controller host
        """
        personalities = [constants.WORKER, constants.STORAGE]
        self.agent_manager._ihostname = 'fake_host_name'
        target_etcd_version = 'vfake_target_etcd_version'
        to_kube_version = 'vfake_to_kube_version'
        current_link_etcd = '/usr/local/etcd/3.4.37/stage0'
        current_link_kube = '/usr/local/kubernetes/1.32.2/stage1'
        is_first_master = True

        for personality in personalities:
            self.agent_manager._ihost_personality = personality
            mock_upgrade_control_plane = mock.MagicMock()
            p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.upgrade_control_plane',
                           mock_upgrade_control_plane)
            p.start()
            self.addCleanup(p.stop)

            mock_os_readlink_etcd = mock.MagicMock()
            p = mock.patch('os.readlink', mock_os_readlink_etcd)
            p.start().return_value = current_link_etcd
            self.addCleanup(p.stop)

            mock_os_readlink_kube = mock.MagicMock()
            p = mock.patch('os.readlink', mock_os_readlink_kube)
            p.start().return_value = current_link_kube
            self.addCleanup(p.stop)

            # TODO(jgauld) - WIP

            mock_report_kube_upgrade_control_plane_result = mock.MagicMock()
            p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                           'report_kube_upgrade_control_plane_result',
                           mock_report_kube_upgrade_control_plane_result)
            p.start()
            self.addCleanup(p.stop)

            self.agent_manager.kube_upgrade_control_plane(
                self.context, self.agent_manager._ihost_uuid, target_etcd_version,
                to_kube_version, is_first_master)

            mock_upgrade_control_plane.assert_not_called()
            # TODO(jgauld) - WIP
            mock_report_kube_upgrade_control_plane_result.assert_not_called()

    def test_kube_upgrade_control_plane_failure(self):
        """Test failed execution of control plane upgrade
        """
        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.agent_manager._ihostname = 'fake_host_name'
        target_etcd_version = 'vfake_target_etcd_version'
        to_kube_version = 'vfake_to_kube_version'
        current_link_etcd = '/usr/local/etcd/3.4.37/stage0'
        current_link_kube = '/usr/local/kubernetes/1.32.2/stage1'
        upgrade_result = False
        is_first_master = True

        mock_preflight = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.'
                       'wait_for_kube_upgrade_preflight_readiness',
                       mock_preflight)
        p.start()
        self.addCleanup(p.stop)

        mock_upgrade_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.upgrade_control_plane',
                       mock_upgrade_control_plane)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        mock_os_readlink_etcd = mock.MagicMock()
        p = mock.patch('os.readlink', mock_os_readlink_etcd)
        p.start().return_value = current_link_etcd
        self.addCleanup(p.stop)

        mock_os_readlink_kube = mock.MagicMock()
        p = mock.patch('os.readlink', mock_os_readlink_kube)
        p.start().return_value = current_link_kube
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_control_plane_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                       'report_kube_upgrade_control_plane_result',
                       mock_report_kube_upgrade_control_plane_result)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager.kube_upgrade_control_plane(
            self.context, self.agent_manager._ihost_uuid, target_etcd_version,
            to_kube_version, is_first_master)

        mock_upgrade_control_plane.assert_called()
        self.assertEqual(mock_upgrade_control_plane.call_count, 2)

        # Proactive preflight readiness wait runs once before the retry loop,
        # not once per failed attempt.
        mock_preflight.assert_called_once_with()

        # TODO(jgauld) - WIP

        mock_report_kube_upgrade_control_plane_result.assert_called_once_with(
            self.context, self.agent_manager._ihost_uuid, to_kube_version,
            is_first_master, upgrade_result)

    def test_pin_kubernetes_control_plane_images_success(self):
        """ Test successful execution of pin kubernetes control plane images
        """
        FAKE_KUBE_VERSION = 'v1.32.2'

        mock_pin_unpin_control_plane_images = mock.MagicMock()
        p = mock.patch(
            'sysinv.agent.kube_host.KubeControllerOperator._pin_unpin_control_plane_images',
            mock_pin_unpin_control_plane_images)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager.pin_kubernetes_control_plane_images(
            self.context, self.agent_manager._ihost_uuid, FAKE_KUBE_VERSION)

        mock_pin_unpin_control_plane_images.assert_called_once_with(
            pin_images_version=FAKE_KUBE_VERSION)

    def test_pin_kubernetes_control_plane_images_failed(self):
        """ Test failed execution of pin kubernetes control plane images
        """
        FAKE_KUBE_VERSION = 'v1.32.2'

        mock_pin_unpin_control_plane_images = mock.MagicMock()
        p = mock.patch(
            'sysinv.agent.kube_host.KubeControllerOperator._pin_unpin_control_plane_images',
            mock_pin_unpin_control_plane_images)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager.pin_kubernetes_control_plane_images(
            self.context, self.agent_manager._ihost_uuid, FAKE_KUBE_VERSION)

        mock_pin_unpin_control_plane_images.assert_called_once_with(
            pin_images_version=FAKE_KUBE_VERSION)

    def test_report_kubelet_version_update_status_success(self):
        """Test report kubelet version update status successful execution

        """
        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        version = '1.32.2'
        to_kubelet_version = 'v' + version
        link2_kube_version = version
        expected_success = True
        to_release = "TEST.SW.VERSION"
        version_details = '{"from_release": "FROM_TEST.SW.VERSION", ' \
                          '"to_release": "%s", ' \
                          '"to_kubelet_version": "%s"}' \
                          % (to_release, to_kubelet_version)
        mock_file_open = mock.mock_open(read_data=version_details)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_systemctl_is_active_service_status = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.systemctl_is_active_service_status',
                       mock_systemctl_is_active_service_status)
        p.start().return_value = constants.SYSTEMD_SERVICE_ACTIVE
        self.addCleanup(p.stop)

        mock_get_kube_version_from_symlink = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_kube_version_from_symlink',
                       mock_get_kube_version_from_symlink)
        p.start().return_value = link2_kube_version
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_kubelet_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.report_kube_upgrade_kubelet_result',
                       mock_report_kube_upgrade_kubelet_result)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        tsconfig.system_mode = constants.SYSTEM_MODE_SIMPLEX

        self.agent_manager._report_kubelet_version_update_status()

        mock_os_path_exists.assert_called()
        mock_file_open.assert_called()
        mock_get_kube_version_from_symlink.assert_called()
        mock_report_kube_upgrade_kubelet_result.assert_called_with(
            mock.ANY, self.agent_manager._ihost_uuid, to_kubelet_version, expected_success)
        mock_os_remove.assert_called()

    def test_report_kubelet_version_update_status_success_non_aio_sx(self):
        """Test _report_kubelet_version_update_status in case of non AIO-SX

        """
        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        to_kubelet_version = "v1.32.2"
        to_release = "TEST.SW.VERSION"
        version_details = '{"from_release": "FROM_TEST.SW.VERSION", ' \
                          '"to_release": "%s", ' \
                          '"to_kubelet_version": "%s"}' \
                          % (to_release, to_kubelet_version)
        mock_file_open = mock.mock_open(read_data=version_details)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_systemctl_is_active_service_status = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.systemctl_is_active_service_status',
                       mock_systemctl_is_active_service_status)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kube_version_from_symlink = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_kube_version_from_symlink',
                       mock_get_kube_version_from_symlink)
        p.start()
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_kubelet_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.report_kube_upgrade_kubelet_result',
                       mock_report_kube_upgrade_kubelet_result)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        tsconfig.system_mode = constants.SYSTEM_MODE_DUPLEX

        self.agent_manager._report_kubelet_version_update_status()

        mock_os_path_exists.assert_not_called()
        mock_file_open.assert_not_called()
        mock_get_kube_version_from_symlink.assert_not_called()
        mock_report_kube_upgrade_kubelet_result.assert_not_called()
        mock_os_remove.assert_not_called()

    def test_report_kubelet_version_update_status_version_details_unavailable(self):
        """Test _report_kubelet_version_update_status when version details file does not exist

        """
        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = False  # version file doesn't exist
        self.addCleanup(p.stop)

        to_kubelet_version = "v1.32.2"
        to_release = "TEST.SW.VERSION"
        version_details = '{"from_release": "FROM_TEST.SW.VERSION", ' \
                          '"to_release": "%s", ' \
                          '"to_kubelet_version": "%s"}' \
                          % (to_release, to_kubelet_version)
        mock_file_open = mock.mock_open(read_data=version_details)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_systemctl_is_active_service_status = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.systemctl_is_active_service_status',
                       mock_systemctl_is_active_service_status)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kube_version_from_symlink = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_kube_version_from_symlink',
                       mock_get_kube_version_from_symlink)
        p.start()
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_kubelet_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.report_kube_upgrade_kubelet_result',
                       mock_report_kube_upgrade_kubelet_result)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        tsconfig.system_mode = constants.SYSTEM_MODE_SIMPLEX

        self.agent_manager._report_kubelet_version_update_status()

        mock_os_path_exists.assert_called()
        mock_file_open.assert_not_called()
        mock_get_kube_version_from_symlink.assert_not_called()
        mock_report_kube_upgrade_kubelet_result.assert_not_called()
        mock_os_remove.assert_not_called()

    def test_report_kubelet_version_update_status_version_read_details_error(self):
        """Test _report_kubelet_version_update_status: error getting version details

        """
        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        to_kubelet_version = "v1.32.2"
        to_release = "TEST.SW.VERSION"
        version_details = '{"from_release": "FROM_TEST.SW.VERSION", ' \
                          '"to_release": "%s", ' \
                          '"to_kubelet_version": "%s"}' \
                          % (to_release, to_kubelet_version)
        mock_file_open = mock.mock_open(read_data=version_details)
        p = mock.patch('builtins.open', mock_file_open)
        p.start().side_effect = Exception("Some Error!")
        self.addCleanup(p.stop)

        mock_systemctl_is_active_service_status = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.systemctl_is_active_service_status',
                       mock_systemctl_is_active_service_status)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kube_version_from_symlink = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_kube_version_from_symlink',
                       mock_get_kube_version_from_symlink)
        p.start()
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_kubelet_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.report_kube_upgrade_kubelet_result',
                       mock_report_kube_upgrade_kubelet_result)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        tsconfig.system_mode = constants.SYSTEM_MODE_SIMPLEX

        self.agent_manager._report_kubelet_version_update_status()

        mock_os_path_exists.assert_called()
        mock_file_open.assert_called()
        mock_get_kube_version_from_symlink.assert_not_called()
        mock_report_kube_upgrade_kubelet_result.assert_not_called()
        mock_os_remove.assert_not_called()

    def test_report_kubelet_version_update_status_version_to_release_mismatch(self):
        """Test _report_kubelet_version_update_status: "to_release" mismatch

        """
        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        to_kubelet_version = "v1.32.2"
        from_release = "FROM_TEST.SW.VERSION"
        to_release = "TEST.SW.VERSION"
        version_details = '{"from_release": "%s", ' \
                          '"to_release": "%s", ' \
                          '"to_kubelet_version": "%s"}' \
                          % (from_release, to_release, to_kubelet_version)
        mock_file_open = mock.mock_open(read_data=version_details)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_systemctl_is_active_service_status = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.systemctl_is_active_service_status',
                       mock_systemctl_is_active_service_status)
        p.start()
        self.addCleanup(p.stop)

        mock_get_kube_version_from_symlink = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_kube_version_from_symlink',
                       mock_get_kube_version_from_symlink)
        p.start()
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_kubelet_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.report_kube_upgrade_kubelet_result',
                       mock_report_kube_upgrade_kubelet_result)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        tsconfig.SW_VERSION = from_release  # release mismatch
        tsconfig.system_mode = constants.SYSTEM_MODE_SIMPLEX

        self.agent_manager._report_kubelet_version_update_status()

        mock_os_path_exists.assert_called()
        mock_file_open.assert_called()
        mock_get_kube_version_from_symlink.assert_not_called()
        mock_report_kube_upgrade_kubelet_result.assert_not_called()
        mock_os_remove.assert_not_called()

    def test_report_kubelet_version_update_status_version_missing_to_kubelet_version(self):
        """Test _report_kubelet_version_update_status: missing to_kubelet_version

        """
        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        to_release = "TEST.SW.VERSION"
        version_details = '{"from_release": "FROM_TEST.SW.VERSION", ' \
                          '"to_release": "%s", ' \
                          '"to_kubelet_version": ""}' \
                          % (to_release)
        mock_file_open = mock.mock_open(read_data=version_details)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_systemctl_is_active_service_status = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.systemctl_is_active_service_status',
                       mock_systemctl_is_active_service_status)
        p.start().return_value = constants.SYSTEMD_SERVICE_ACTIVE
        self.addCleanup(p.stop)

        mock_get_kube_version_from_symlink = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_kube_version_from_symlink',
                       mock_get_kube_version_from_symlink)
        p.start()
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_kubelet_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.report_kube_upgrade_kubelet_result',
                       mock_report_kube_upgrade_kubelet_result)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        tsconfig.system_mode = constants.SYSTEM_MODE_SIMPLEX

        self.agent_manager._report_kubelet_version_update_status()

        mock_os_path_exists.assert_called()
        mock_file_open.assert_called()
        mock_get_kube_version_from_symlink.assert_not_called()
        mock_report_kube_upgrade_kubelet_result.assert_not_called()
        mock_os_remove.assert_not_called()

    def test_report_kubelet_version_update_status_failure(self):
        """Test report kubelet version update status failed execution

        """
        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        version = '1.32.2'
        to_kubelet_version = 'v' + version
        link2_kube_version = '1.31.5'  # mismatched version, kubelet didn't update
        expected_success = False
        to_release = "TEST.SW.VERSION"
        version_details = '{"from_release": "FROM_TEST.SW.VERSION", ' \
                          '"to_release": "%s", ' \
                          '"to_kubelet_version": "%s"}' \
                          % (to_release, to_kubelet_version)
        mock_file_open = mock.mock_open(read_data=version_details)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_systemctl_is_active_service_status = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.systemctl_is_active_service_status',
                       mock_systemctl_is_active_service_status)
        p.start().return_value = constants.SYSTEMD_SERVICE_ACTIVE
        self.addCleanup(p.stop)

        mock_get_kube_version_from_symlink = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_kube_version_from_symlink',
                       mock_get_kube_version_from_symlink)
        p.start().return_value = link2_kube_version
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_kubelet_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.report_kube_upgrade_kubelet_result',
                       mock_report_kube_upgrade_kubelet_result)
        p.start()
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        tsconfig.system_mode = constants.SYSTEM_MODE_SIMPLEX

        self.agent_manager._report_kubelet_version_update_status()

        mock_os_path_exists.assert_called()
        mock_file_open.assert_called()
        mock_get_kube_version_from_symlink.assert_called()
        mock_report_kube_upgrade_kubelet_result.assert_called_with(
            mock.ANY, self.agent_manager._ihost_uuid, to_kubelet_version, expected_success)
        mock_os_remove.assert_not_called()


class TestCpuFrequencyConfigurable(base.TestCase):
    """Tests for CPU frequency configuration detection."""

    def setUp(self):
        super(TestCpuFrequencyConfigurable, self).setUp()
        self.agent_manager = AgentManager('test-host', 'test-topic')

    def tearDown(self):
        super(TestCpuFrequencyConfigurable, self).tearDown()

    @mock.patch('os.path.exists')
    def test_is_max_cpu_mhz_configurable_supported(self, mock_exists):
        """Test CPU frequency scaling is detected as configurable when sysfs path exists."""
        mock_exists.return_value = True

        result = self.agent_manager._is_max_cpu_mhz_configurable()

        self.assertEqual(result, constants.CONFIGURABLE)
        mock_exists.assert_called_once_with(
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq")

    @mock.patch('os.path.exists')
    def test_is_max_cpu_mhz_configurable_not_supported(self, mock_exists):
        """Test CPU frequency scaling is detected as not configurable when sysfs path missing."""
        mock_exists.return_value = False

        result = self.agent_manager._is_max_cpu_mhz_configurable()

        self.assertEqual(result, constants.NOT_CONFIGURABLE)
        mock_exists.assert_called_once_with(
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq")

    @mock.patch('os.path.exists')
    def test_is_max_cpu_mhz_configurable_exception(self, mock_exists):
        """Test CPU frequency scaling returns not configurable on exception."""
        mock_exists.side_effect = Exception("Test exception")

        result = self.agent_manager._is_max_cpu_mhz_configurable()

        self.assertEqual(result, constants.NOT_CONFIGURABLE)


class TestHostPortChannelUpdate(base.TestCase):
    """Tests for change-detected periodic port re-report (CGTS-105820)."""

    def setUp(self):
        super(TestHostPortChannelUpdate, self).setUp()
        self.agent_manager = AgentManager('test-host', 'test-topic')
        self.agent_manager._ihost_uuid = "FAKEUUID"
        self.context = context.get_admin_context()
        self.rpcapi = mock.MagicMock()
        # host_port_channel_update() gates the expensive _get_ports_inventory() behind
        # a cheap channel-signature pre-check. For the behavioral tests below
        # we stub the signature so it always looks "changed", exercising the
        # full report path deterministically without touching real NIC
        # hardware. Pre-check skip behavior is covered by dedicated tests.
        sig = mock.patch.object(
            self.agent_manager, '_get_channel_signature',
            side_effect=self._changing_signature)
        sig.start()
        self.addCleanup(sig.stop)

    def _changing_signature(self):
        """Return a distinct signature object each call so the cheap
        pre-check never short-circuits (used by the behavioral tests).
        """
        return {'sig': object()}

    def tearDown(self):
        super(TestHostPortChannelUpdate, self).tearDown()

    def _mock_ports_inventory(self, port_list):
        mock_get = mock.MagicMock(return_value=(port_list, [], []))
        p = mock.patch.object(
            self.agent_manager, '_get_ports_inventory', mock_get)
        p.start()
        self.addCleanup(p.stop)
        return mock_get

    def test_host_port_channel_update_first_report(self):
        """First audit reports ports and records prev state."""
        port_list = [{'name': 'ens1f1', 'numchannels': 8}]
        self._mock_ports_inventory(port_list)

        self.agent_manager.host_port_channel_update(self.context, self.rpcapi)

        self.rpcapi.iport_update_by_ihost.assert_called_once_with(
            self.context, self.agent_manager._ihost_uuid, port_list)
        self.assertEqual(self.agent_manager._prev_port, port_list)
        self.assertIn(self.agent_manager.PORT,
                      self.agent_manager._inventory_reported)

    def test_host_port_channel_update_reports_on_change(self):
        """A numchannels change triggers a re-report."""
        # Pretend a previous report already happened at numchannels=64.
        self.agent_manager._prev_port = [{'name': 'ens1f1', 'numchannels': 64}]
        self.agent_manager._inventory_reported.add(self.agent_manager.PORT)

        changed = [{'name': 'ens1f1', 'numchannels': 8}]
        self._mock_ports_inventory(changed)

        self.agent_manager.host_port_channel_update(self.context, self.rpcapi)

        self.rpcapi.iport_update_by_ihost.assert_called_once_with(
            self.context, self.agent_manager._ihost_uuid, changed)
        self.assertEqual(self.agent_manager._prev_port, changed)

    def test_host_port_channel_update_no_report_when_unchanged(self):
        """No re-report when the port inventory is unchanged."""
        port_list = [{'name': 'ens1f1', 'numchannels': 8}]
        self.agent_manager._prev_port = port_list
        self.agent_manager._inventory_reported.add(self.agent_manager.PORT)
        self._mock_ports_inventory(list(port_list))

        self.agent_manager.host_port_channel_update(self.context, self.rpcapi)

        self.rpcapi.iport_update_by_ihost.assert_not_called()

    def test_host_port_channel_update_empty_inventory_noop(self):
        """Empty port inventory results in no report."""
        self._mock_ports_inventory([])

        self.agent_manager.host_port_channel_update(self.context, self.rpcapi)

        self.rpcapi.iport_update_by_ihost.assert_not_called()
        self.assertIsNone(self.agent_manager._prev_port)

    def test_host_port_channel_update_sysinv_exception_resets_prev(self):
        """A SysinvException clears prev_port so the next audit retries."""
        port_list = [{'name': 'ens1f1', 'numchannels': 8}]
        self._mock_ports_inventory(port_list)
        self.rpcapi.iport_update_by_ihost.side_effect = \
            exception.SysinvException("boom")

        self.agent_manager.host_port_channel_update(self.context, self.rpcapi)

        self.rpcapi.iport_update_by_ihost.assert_called_once()
        self.assertIsNone(self.agent_manager._prev_port)

    def test_host_port_channel_update_skips_full_inventory_when_channels_unchanged(self):
        """An unchanged channel signature short-circuits before the expensive
        _get_ports_inventory().
        """
        self.agent_manager._inventory_reported.add(self.agent_manager.PORT)
        self.agent_manager._prev_channel_sig = {'ens1f1': (64, 8)}
        get_ports = self._mock_ports_inventory(
            [{'name': 'ens1f1', 'numchannels': 8}])
        # Stub replaces the setUp "always changing" stub with a matching one.
        self.agent_manager._get_channel_signature = mock.MagicMock(
            return_value={'ens1f1': (64, 8)})

        self.agent_manager.host_port_channel_update(self.context, self.rpcapi)

        # Signature matched prev -> expensive path and report both skipped.
        get_ports.assert_not_called()
        self.rpcapi.iport_update_by_ihost.assert_not_called()

    def test_host_port_channel_update_runs_full_inventory_when_channels_changed(self):
        """A changed channel signature falls through to the full inventory and
        re-reports, caching the new signature.
        """
        self.agent_manager._inventory_reported.add(self.agent_manager.PORT)
        self.agent_manager._prev_port = [{'name': 'ens1f1', 'numchannels': 64}]
        self.agent_manager._prev_channel_sig = {'ens1f1': (128, 64)}
        changed_ports = [{'name': 'ens1f1', 'numchannels': 8}]
        self._mock_ports_inventory(changed_ports)
        new_sig = {'ens1f1': (128, 8)}
        self.agent_manager._get_channel_signature = mock.MagicMock(
            return_value=new_sig)

        self.agent_manager.host_port_channel_update(self.context, self.rpcapi)

        self.rpcapi.iport_update_by_ihost.assert_called_once_with(
            self.context, self.agent_manager._ihost_uuid, changed_ports)
        self.assertEqual(self.agent_manager._prev_port, changed_ports)
        self.assertEqual(self.agent_manager._prev_channel_sig, new_sig)

    def test_host_port_channel_update_signature_none_falls_back_to_full(self):
        """If the cheap signature cannot be built (None), fall back to the
        full inventory to stay safe.
        """
        self.agent_manager._inventory_reported.add(self.agent_manager.PORT)
        self.agent_manager._prev_channel_sig = {'ens1f1': (64, 8)}
        port_list = [{'name': 'ens1f1', 'numchannels': 8}]
        self._mock_ports_inventory(port_list)
        self.agent_manager._get_channel_signature = mock.MagicMock(
            return_value=None)

        self.agent_manager.host_port_channel_update(self.context, self.rpcapi)

        self.rpcapi.iport_update_by_ihost.assert_called_once_with(
            self.context, self.agent_manager._ihost_uuid, port_list)


class TestPortChannelAudit(base.TestCase):
    """Tests for the dedicated _port_channel_audit periodic task."""

    def setUp(self):
        super(TestPortChannelAudit, self).setUp()
        self.agent_manager = AgentManager('test-host', 'test-topic')
        self.context = context.get_admin_context()

    def test_port_channel_audit_noop_without_host_uuid(self):
        """No host uuid -> no port update."""
        self.agent_manager._ihost_uuid = ""
        self.agent_manager._inventoried_initial = True
        self.agent_manager.host_port_channel_update = mock.MagicMock()

        self.agent_manager._port_channel_audit(self.context)

        self.agent_manager.host_port_channel_update.assert_not_called()

    def test_port_channel_audit_noop_before_initial_inventory(self):
        """Before initial inventory -> no port update (avoid racing first
        port report).
        """
        self.agent_manager._ihost_uuid = "FAKEUUID"
        self.agent_manager._inventoried_initial = False
        self.agent_manager.host_port_channel_update = mock.MagicMock()

        self.agent_manager._port_channel_audit(self.context)

        self.agent_manager.host_port_channel_update.assert_not_called()

    def test_port_channel_audit_runs_update_when_ready(self):
        """Once inventoried, the audit drives host_port_channel_update."""
        self.agent_manager._ihost_uuid = "FAKEUUID"
        self.agent_manager._inventoried_initial = True
        self.agent_manager.host_port_channel_update = mock.MagicMock()

        self.agent_manager._port_channel_audit(self.context)

        self.agent_manager.host_port_channel_update.assert_called_once()


class TestGetChannelSignature(base.TestCase):
    """Tests for AgentManager._get_channel_signature cheap pre-check."""

    def setUp(self):
        super(TestGetChannelSignature, self).setUp()
        self.agent_manager = AgentManager('test-host', 'test-topic')

    @mock.patch('os.path.exists')
    def test_signature_filters_virtual_and_collects_channels(self, mock_exists):
        """Virtual/loopback ifaces are skipped; physical ports' channels are
        collected via ethtool -l.
        """
        mock_exists.return_value = True
        op = self.agent_manager._ipci_operator
        op.pci_get_net_names = mock.MagicMock(return_value=[
            'lo', 'cali1234', 'docker0', 'vlan41', 'ovs-br0',
            'ens1f0', 'ens1f1'])

        def fake_channels(name):
            return {'ens1f0': (128, 64), 'ens1f1': (128, 8)}.get(name,
                                                                  (None, None))
        op._get_interface_channels = mock.MagicMock(side_effect=fake_channels)

        sig = self.agent_manager._get_channel_signature()

        self.assertEqual(sig, {'ens1f0': (128, 64), 'ens1f1': (128, 8)})

    @mock.patch('os.path.exists')
    def test_signature_returns_none_on_exception(self, mock_exists):
        """Any failure yields None so the caller falls back to full inventory."""
        mock_exists.return_value = True
        op = self.agent_manager._ipci_operator
        op.pci_get_net_names = mock.MagicMock(side_effect=Exception("boom"))

        self.assertIsNone(self.agent_manager._get_channel_signature())


class TestChangedChannelPorts(base.TestCase):
    """Tests for AgentManager._changed_channel_ports channel-count diff."""

    def setUp(self):
        super(TestChangedChannelPorts, self).setUp()
        self.agent_manager = AgentManager('test-host', 'test-topic')

    def test_no_change_returns_empty_set(self):
        """Identical PF channel counts yield no changed ports."""
        prev = [{'pname': 'ens1f0', 'numchannels': 8},
                {'pname': 'ens1f1', 'numchannels': 8}]
        curr = [{'pname': 'ens1f0', 'numchannels': 8},
                {'pname': 'ens1f1', 'numchannels': 8}]
        self.assertEqual(
            self.agent_manager._changed_channel_ports(prev, curr), set())

    def test_pf_channel_bump_reports_that_port(self):
        """A numchannels change reports only the changed port."""
        prev = [{'pname': 'ens1f0', 'numchannels': 4},
                {'pname': 'ens1f1', 'numchannels': 8}]
        curr = [{'pname': 'ens1f0', 'numchannels': 8},
                {'pname': 'ens1f1', 'numchannels': 8}]
        self.assertEqual(
            self.agent_manager._changed_channel_ports(prev, curr),
            {'ens1f0'})

    def test_vf_channel_change_ignored(self):
        """A VF channel change alone does not flag the port (PF unchanged)."""
        prev = [{'pname': 'ens1f0', 'numchannels': 8,
                 'sriov_vf_numchannels': 4}]
        curr = [{'pname': 'ens1f0', 'numchannels': 8,
                 'sriov_vf_numchannels': 8}]
        self.assertEqual(
            self.agent_manager._changed_channel_ports(prev, curr), set())

    def test_new_port_is_reported(self):
        """A port present only in the current inventory is reported."""
        prev = [{'pname': 'ens1f0', 'numchannels': 8}]
        curr = [{'pname': 'ens1f0', 'numchannels': 8},
                {'pname': 'ens1f1', 'numchannels': 8}]
        self.assertEqual(
            self.agent_manager._changed_channel_ports(prev, curr),
            {'ens1f1'})

    def test_empty_prev_reports_all_current(self):
        """With no previous entries, all current ports are 'changed'."""
        curr = [{'pname': 'ens1f0', 'numchannels': 8},
                {'pname': 'ens1f1', 'numchannels': 8}]
        self.assertEqual(
            self.agent_manager._changed_channel_ports([], curr),
            {'ens1f0', 'ens1f1'})

    def test_none_prev_treated_as_empty(self):
        """prev_port=None behaves like an empty previous inventory."""
        curr = [{'pname': 'ens1f0', 'numchannels': 8}]
        self.assertEqual(
            self.agent_manager._changed_channel_ports(None, curr),
            {'ens1f0'})

    def test_port_missing_pname_is_ignored(self):
        """Entries without a pname are not considered."""
        prev = [{'pname': 'ens1f0', 'numchannels': 8}]
        curr = [{'pname': 'ens1f0', 'numchannels': 8},
                {'numchannels': 8}]
        self.assertEqual(
            self.agent_manager._changed_channel_ports(prev, curr), set())
