#
# Copyright (c) 2023 Wind River Systems, Inc.
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
        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.agent_manager._ihostname = 'fake_host_name'
        to_kube_version = 'vfake_to_kube_version'
        current_link = '/usr/local/kubernetes/1.29.2/stage1'
        upgrade_result = True
        is_first_master = True

        mock_os_readlink = mock.MagicMock()
        p = mock.patch('os.readlink', mock_os_readlink)
        p.start().return_value = current_link
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
            self.context, self.agent_manager._ihost_uuid, to_kube_version, is_first_master)

        mock_upgrade_control_plane.assert_called_once_with(
            'v1.29.2', to_kube_version, is_first_master)

        mock_os_readlink.assert_called_once()
        mock_report_kube_upgrade_control_plane_result.assert_called_once_with(
            self.context, self.agent_manager._ihost_uuid, to_kube_version,
            is_first_master, upgrade_result)

    def test_kube_upgrade_control_plane_success_retry(self):
        """Test successful execution of control plane upgrade in retry attempt
        """
        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.agent_manager._ihostname = 'fake_host_name'
        to_kube_version = 'vfake_to_kube_version'
        current_link = '/usr/local/kubernetes/1.29.2/stage1'
        upgrade_result = True
        is_first_master = True

        mock_upgrade_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.upgrade_control_plane',
                       mock_upgrade_control_plane)
        p.start().side_effect = [Exception("Fake error"), True]
        self.addCleanup(p.stop)

        mock_os_readlink = mock.MagicMock()
        p = mock.patch('os.readlink', mock_os_readlink)
        p.start().return_value = current_link
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_control_plane_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                       'report_kube_upgrade_control_plane_result',
                       mock_report_kube_upgrade_control_plane_result)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager.kube_upgrade_control_plane(
            self.context, self.agent_manager._ihost_uuid, to_kube_version, is_first_master)

        mock_upgrade_control_plane.assert_called()
        self.assertEqual(mock_upgrade_control_plane.call_count, 2)

        mock_report_kube_upgrade_control_plane_result.assert_called_once_with(
            self.context, self.agent_manager._ihost_uuid, to_kube_version,
            is_first_master, upgrade_result)

    def test_kube_upgrade_control_plane_non_controller(self):
        """Test successful execution of control plane upgrade on a non-controller host
        """
        personalities = [constants.WORKER, constants.STORAGE]
        self.agent_manager._ihostname = 'fake_host_name'
        current_link = '/usr/local/kubernetes/1.29.2/stage1'
        to_kube_version = 'vfake_to_kube_version'
        is_first_master = True

        for personality in personalities:
            self.agent_manager._ihost_personality = personality
            mock_upgrade_control_plane = mock.MagicMock()
            p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.upgrade_control_plane',
                           mock_upgrade_control_plane)
            p.start()
            self.addCleanup(p.stop)

            mock_os_readlink = mock.MagicMock()
            p = mock.patch('os.readlink', mock_os_readlink)
            p.start().return_value = current_link
            self.addCleanup(p.stop)

            mock_report_kube_upgrade_control_plane_result = mock.MagicMock()
            p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                           'report_kube_upgrade_control_plane_result',
                           mock_report_kube_upgrade_control_plane_result)
            p.start()
            self.addCleanup(p.stop)

            self.agent_manager.kube_upgrade_control_plane(
                self.context, self.agent_manager._ihost_uuid, to_kube_version, is_first_master)

            mock_upgrade_control_plane.assert_not_called()
            mock_report_kube_upgrade_control_plane_result.assert_not_called()

    def test_kube_upgrade_control_plane_failure(self):
        """Test failed execution of control plane upgrade
        """
        self.agent_manager._ihost_personality = constants.CONTROLLER
        self.agent_manager._ihostname = 'fake_host_name'
        current_link = '/usr/local/kubernetes/1.29.2/stage1'
        to_kube_version = 'vfake_to_kube_version'
        upgrade_result = False
        is_first_master = True

        mock_upgrade_control_plane = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.upgrade_control_plane',
                       mock_upgrade_control_plane)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        mock_os_readlink = mock.MagicMock()
        p = mock.patch('os.readlink', mock_os_readlink)
        p.start().return_value = current_link
        self.addCleanup(p.stop)

        mock_report_kube_upgrade_control_plane_result = mock.MagicMock()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                       'report_kube_upgrade_control_plane_result',
                       mock_report_kube_upgrade_control_plane_result)
        p.start()
        self.addCleanup(p.stop)

        self.agent_manager.kube_upgrade_control_plane(
            self.context, self.agent_manager._ihost_uuid, to_kube_version, is_first_master)

        mock_upgrade_control_plane.assert_called()
        self.assertEqual(mock_upgrade_control_plane.call_count, 2)

        mock_report_kube_upgrade_control_plane_result.assert_called_once_with(
            self.context, self.agent_manager._ihost_uuid, to_kube_version,
            is_first_master, upgrade_result)

    def test_pin_kubernetes_control_plane_images_success(self):
        """ Test successful execution of pin kubernetes control plane images
        """
        FAKE_KUBE_VERSION = 'v1.29.2'

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
        FAKE_KUBE_VERSION = 'v1.29.2'

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
