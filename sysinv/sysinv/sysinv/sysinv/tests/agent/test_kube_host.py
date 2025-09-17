#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the kubernetes host functions.
"""

import datetime
import io
import mock

from oslo_context import context
from sysinv.tests import base
from sysinv.agent import kube_host
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import kubernetes


class TestContainerdOperator(base.TestCase):

    def setUp(self):
        self.containerd_operator = kube_host.ContainerdOperator()
        super(TestContainerdOperator, self).setUp()

    def tearDown(self):
        super(TestContainerdOperator, self).tearDown()

    def test_get_auth(self):
        """Test get auth information
        """
        fake_file_object = io.TextIOWrapper(io.BytesIO())
        hieradata = {'platform::dockerdistribution::params::registry_username': 'fake_username',
                     'platform::dockerdistribution::params::registry_password': 'fake_password'}

        mock_open = mock.MagicMock()
        p = mock.patch('builtins.open', mock_open)
        p.start().return_value = fake_file_object
        self.addCleanup(p.stop)

        mock_ruamel_yaml = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml)
        p.start().return_value = hieradata
        self.addCleanup(p.stop)

        auth = self.containerd_operator._get_auth()

        self.assertEqual(auth, "fake_username:fake_password")
        mock_open.assert_called_once()
        mock_ruamel_yaml.assert_called_once_with(fake_file_object)

    def test_get_auth_file_read_error(self):
        """Test get auth information: Fail to read hieradata file for some reason
        """
        mock_open = mock.MagicMock()
        p = mock.patch('builtins.open', mock_open)
        p.start().side_effect = Exception("Fake exception")
        self.addCleanup(p.stop)

        mock_ruamel_yaml = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml)
        p.start()
        self.addCleanup(p.stop)

        auth = self.containerd_operator._get_auth()

        # Actually asserts auth == None
        self.assertFalse(auth)
        mock_open.assert_called_once()
        mock_ruamel_yaml.assert_not_called()

    def test_get_auth_yaml_load_error(self):
        """Test get auth information: Failed to safe_load hieradata yaml
        """
        fake_file_object = io.TextIOWrapper(io.BytesIO())

        mock_open = mock.MagicMock()
        p = mock.patch('builtins.open', mock_open)
        p.start().return_value = fake_file_object
        self.addCleanup(p.stop)

        mock_ruamel_yaml = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        auth = self.containerd_operator._get_auth()

        # Actually asserts auth == None
        self.assertFalse(auth)
        mock_open.assert_called_once()
        mock_ruamel_yaml.assert_called_once_with(fake_file_object)

    def test_get_auth_missing_credentials(self):
        """Test get auth information: Missing auth credentials
        """
        fake_file_object = io.TextIOWrapper(io.BytesIO())
        hieradata = {'other': 'fields',
                     'other': 'fields'}

        mock_open = mock.MagicMock()
        p = mock.patch('builtins.open', mock_open)
        p.start().return_value = fake_file_object
        self.addCleanup(p.stop)

        mock_ruamel_yaml = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml)
        p.start().return_value = hieradata
        self.addCleanup(p.stop)

        auth = self.containerd_operator._get_auth()

        # Actually asserts auth == None
        self.assertFalse(auth)
        mock_open.assert_called_once()
        mock_ruamel_yaml.assert_called_once_with(fake_file_object)

    def test_get_auth_corrupted_hieradata_file_content(self):
        """Test get auth information: hieradata file contents corrupted
        """
        fake_file_object = io.TextIOWrapper(io.BytesIO())
        hieradata = {}

        mock_open = mock.MagicMock()
        p = mock.patch('builtins.open', mock_open)
        p.start().return_value = fake_file_object
        self.addCleanup(p.stop)

        mock_ruamel_yaml = mock.MagicMock()
        p = mock.patch('ruamel.yaml.safe_load', mock_ruamel_yaml)
        p.start().return_value = hieradata
        self.addCleanup(p.stop)

        auth = self.containerd_operator._get_auth()

        # Actually asserts auth == None
        self.assertFalse(auth)
        mock_open.assert_called_once()
        mock_ruamel_yaml.assert_called_once_with(fake_file_object)

    def test_pull_images_suceess(self):
        """Test successful image pull
        """
        fake_auth = "fake_username:fake_password"
        fake_exisitng_image_list = [f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1",
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2"]
        images_to_be_pulled = ['fake_image1', 'fake_image2', 'fake_image3', 'fake_image4']

        mock_get_crictl_image_list = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.get_crictl_image_list', mock_get_crictl_image_list)
        p.start().return_value = fake_exisitng_image_list
        self.addCleanup(p.stop)

        mock_pull_image_to_crictl = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.pull_image_to_crictl', mock_pull_image_to_crictl)
        p.start()
        self.addCleanup(p.stop)

        result = self.containerd_operator.pull_images(images_to_be_pulled, fake_auth)

        self.assertTrue(result)
        mock_get_crictl_image_list.assert_called_once()
        expected_calls = [mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3", fake_auth),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image4", fake_auth)]
        mock_pull_image_to_crictl.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_pull_image_to_crictl.call_count, 2)

    def test_pull_images_suceess_all_images_exist_already(self):
        """Test successful image pull. All images to be pulled existed alaready in crictl
        """
        fake_auth = "fake_username:fake_password"
        fake_exisitng_image_list = [f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1",
                                    f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2"]
        images_to_be_pulled = ['fake_image1', 'fake_image2']

        mock_get_crictl_image_list = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.get_crictl_image_list', mock_get_crictl_image_list)
        p.start().return_value = fake_exisitng_image_list
        self.addCleanup(p.stop)

        mock_pull_image_to_crictl = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.pull_image_to_crictl', mock_pull_image_to_crictl)
        p.start()
        self.addCleanup(p.stop)

        result = self.containerd_operator.pull_images(images_to_be_pulled, fake_auth)

        self.assertTrue(result)
        mock_get_crictl_image_list.assert_called_once()
        mock_pull_image_to_crictl.assert_not_called()

    def test_pull_images_suceess_failed_to_get_existing_image_list(self):
        """Test successful image pull: Failed to get existing crictl image list
        """
        fake_auth = "fake_username:fake_password"
        images_to_be_pulled = ['fake_image1', 'fake_image2', 'fake_image3', 'fake_image4']

        mock_get_crictl_image_list = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.get_crictl_image_list', mock_get_crictl_image_list)
        p.start().side_effect = exception.SysinvException("Fake Error")
        self.addCleanup(p.stop)

        mock_pull_image_to_crictl = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.pull_image_to_crictl', mock_pull_image_to_crictl)
        p.start()
        self.addCleanup(p.stop)

        result = self.containerd_operator.pull_images(images_to_be_pulled, fake_auth)

        self.assertTrue(result)
        mock_get_crictl_image_list.assert_called_once()
        expected_calls = [mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1", fake_auth),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2", fake_auth),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3", fake_auth),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image4", fake_auth)]
        mock_pull_image_to_crictl.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_pull_image_to_crictl.call_count, 4)

    def test_pull_images_failure_image_pull_exception(self):
        """Test image pull failure: Image pull exception
        """
        fake_auth = "fake_username:fake_password"
        images_to_be_pulled = ['fake_image1', 'fake_image2', 'fake_image3', 'fake_image4']

        mock_get_crictl_image_list = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.get_crictl_image_list', mock_get_crictl_image_list)
        p.start().return_value = []
        self.addCleanup(p.stop)

        mock_pull_image_to_crictl = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.pull_image_to_crictl', mock_pull_image_to_crictl)
        p.start().side_effect = exception.SysinvException("Fake error")
        self.addCleanup(p.stop)

        result = self.containerd_operator.pull_images(images_to_be_pulled, fake_auth)

        self.assertFalse(result)
        mock_get_crictl_image_list.assert_called_once()
        mock_pull_image_to_crictl.assert_called()


class TestKubernetesOperator(base.TestCase):

    def setUp(self):
        super(TestKubernetesOperator, self).setUp()
        self.context = context.get_admin_context()
        self.kube_controller_operator = kube_host.KubeControllerOperator(
            self.context, "FAKE_UUID", "FAKE_HOSTNAME")
        self.kube_worker_operator = kube_host.KubeWorkerOperator(
            self.context, "FAKE_UUID", "FAKE_HOSTNAME")

    def tearDown(self):
        super(TestKubernetesOperator, self).tearDown()

    def test_kube_upgrade_kubelet_controller_host_success_same_pause_image_version(self):
        """Test successful kubelet upgrade on controller hosts (same pause image versions)
        """
        from_kube_version = 'vfake_from_kube_version'
        to_kube_version = 'vfake_to_kube_version'
        is_final_version = False
        same_fake_pause_image = 'same_fake_pause_image'
        containerd_read_data = 'sandbox_image = "%s/%s"' % (constants.DOCKER_REGISTRY_SERVER,
                                                            same_fake_pause_image)

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().side_effect = [{'pause': same_fake_pause_image},
                                 {'pause': same_fake_pause_image}]
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start()
        self.addCleanup(p.stop)

        # Mock open inside method _update_pause_image_in_containerd
        mock_file_open = mock.mock_open(read_data=containerd_read_data)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start()
        self.addCleanup(p.stop)

        mock_enable_kubelet_garbage_collection = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.enable_kubelet_garbage_collection',
                       mock_enable_kubelet_garbage_collection)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        self.kube_controller_operator.upgrade_kubelet(
            from_kube_version, to_kube_version, is_final_version)

        self.assertEqual(mock_get_k8s_images.call_count, 2)
        mock_get_k8s_images.assert_has_calls([mock.call('fake_from_kube_version'),
                                              mock.call('fake_to_kube_version')], any_order=True)
        mock_file_open.assert_not_called()
        mock_kubeadm_upgrade_node.assert_not_called()
        mock_update_symlink.assert_called_once_with(kubernetes.KUBERNETES_SYMLINKS_STAGE_2,
                                                    'fake_to_kube_version')
        mock_enable_kubelet_garbage_collection.assert_not_called()
        mock_pmon_restart_service.assert_called_once()

    def test_kube_upgrade_kubelet_controller_host_success_different_pause_image_version(self):
        """Test successful kubelet upgrade on controller hosts (different pause image versions)
        """
        from_kube_version = 'vfake_from_kube_version'
        to_kube_version = 'vfake_to_kube_version'
        is_final_version = False
        fake_pause_image = 'fake_pause_image'
        different_fake_pause_image = 'different_fake_pause_image'
        containerd_read_data = 'sandbox_image = "%s/%s"' % (constants.DOCKER_REGISTRY_SERVER,
                                                            fake_pause_image)
        containerd_write_data = 'sandbox_image = "%s/%s"' % (constants.DOCKER_REGISTRY_SERVER,
                                                            different_fake_pause_image)

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().side_effect = [{'pause': fake_pause_image},
                                 {'pause': different_fake_pause_image}]
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start()
        self.addCleanup(p.stop)

        # Mock open inside method _update_pause_image_in_containerd
        mock_file_open = mock.mock_open(read_data=containerd_read_data)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start()
        self.addCleanup(p.stop)

        mock_enable_kubelet_garbage_collection = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.enable_kubelet_garbage_collection',
                       mock_enable_kubelet_garbage_collection)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        self.kube_controller_operator.upgrade_kubelet(
            from_kube_version, to_kube_version, is_final_version)

        self.assertEqual(mock_get_k8s_images.call_count, 2)
        mock_get_k8s_images.assert_has_calls([mock.call('fake_from_kube_version'),
                                              mock.call('fake_to_kube_version')], any_order=True)
        mock_file_open.return_value.write.assert_called_with(containerd_write_data + '\n')
        mock_kubeadm_upgrade_node.assert_not_called()
        mock_update_symlink.assert_called_once_with(kubernetes.KUBERNETES_SYMLINKS_STAGE_2,
                                                    'fake_to_kube_version')
        mock_enable_kubelet_garbage_collection.assert_not_called()
        mock_pmon_restart_service.assert_called_once()

    def test_kube_upgrade_kubelet_controller_host_success_final_kube_version(self):
        """Test successful kubelet upgrade on controller hosts (is_final_version is True)

        to_kube_version is final version in the current multi-version kubernetes upgrade attempt
        """
        from_kube_version = 'vfake_from_kube_version'
        to_kube_version = 'vfake_to_kube_version'
        is_final_version = True
        same_fake_pause_image = 'same_fake_pause_image'
        containerd_read_data = 'sandbox_image = "%s/%s"' % (constants.DOCKER_REGISTRY_SERVER,
                                                            same_fake_pause_image)

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().side_effect = [{'pause': same_fake_pause_image},
                                 {'pause': same_fake_pause_image}]
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start()
        self.addCleanup(p.stop)

        # Mock open inside method _update_pause_image_in_containerd
        mock_file_open = mock.mock_open(read_data=containerd_read_data)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start()
        self.addCleanup(p.stop)

        mock_enable_kubelet_garbage_collection = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.enable_kubelet_garbage_collection',
                       mock_enable_kubelet_garbage_collection)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        self.kube_controller_operator.upgrade_kubelet(
            from_kube_version, to_kube_version, is_final_version)

        self.assertEqual(mock_get_k8s_images.call_count, 2)
        mock_get_k8s_images.assert_has_calls([mock.call('fake_from_kube_version'),
                                              mock.call('fake_to_kube_version')], any_order=True)
        mock_file_open.assert_not_called()
        mock_kubeadm_upgrade_node.assert_not_called()
        mock_update_symlink.assert_called_once_with(kubernetes.KUBERNETES_SYMLINKS_STAGE_2,
                                                    'fake_to_kube_version')
        mock_enable_kubelet_garbage_collection.assert_called_once()
        mock_pmon_restart_service.assert_called_once()

    def test_kube_upgrade_kubelet_controller_host_failure_pause_image_version_update_failure(self):
        """Test failure of kubelet upgrade on controller hosts (pause image update failure)
        """
        from_kube_version = 'vfake_from_kube_version'
        to_kube_version = 'vfake_to_kube_version'
        is_final_version = True
        fake_pause_image = 'fake_pause_image'
        different_fake_pause_image = 'different_fake_pause_image'
        containerd_read_data = 'sandbox_image = "%s/%s"' % (constants.DOCKER_REGISTRY_SERVER,
                                                            fake_pause_image)

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().side_effect = [{'pause': fake_pause_image},
                                 {'pause': different_fake_pause_image}]
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start()
        self.addCleanup(p.stop)

        # Mock open inside method _update_pause_image_in_containerd
        mock_file_open = mock.mock_open(read_data=containerd_read_data)
        p = mock.patch('builtins.open', mock_file_open)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start()
        self.addCleanup(p.stop)

        mock_enable_kubelet_garbage_collection = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.enable_kubelet_garbage_collection',
                       mock_enable_kubelet_garbage_collection)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.kube_controller_operator.upgrade_kubelet,
                          from_kube_version,
                          to_kube_version,
                          is_final_version)

        self.assertEqual(mock_get_k8s_images.call_count, 2)
        mock_get_k8s_images.assert_has_calls([mock.call('fake_from_kube_version'),
                                              mock.call('fake_to_kube_version')], any_order=True)
        mock_kubeadm_upgrade_node.assert_not_called()
        mock_update_symlink.assert_not_called()
        mock_enable_kubelet_garbage_collection.assert_not_called()
        mock_pmon_restart_service.assert_not_called()

    def test_kube_upgrade_kubelet_controller_host_failure_symlink_update_failure(self):
        """Test failure of kubelet upgrade on controller hosts (symlink update failure)
        """
        from_kube_version = 'vfake_from_kube_version'
        to_kube_version = 'vfake_to_kube_version'
        is_final_version = True
        fake_pause_image = 'fake_pause_image'
        different_fake_pause_image = 'different_fake_pause_image'
        containerd_read_data = 'sandbox_image = "%s/%s"' % (constants.DOCKER_REGISTRY_SERVER,
                                                            fake_pause_image)
        containerd_write_data = 'sandbox_image = "%s/%s"' % (constants.DOCKER_REGISTRY_SERVER,
                                                            different_fake_pause_image)

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().side_effect = [{'pause': fake_pause_image},
                                 {'pause': different_fake_pause_image}]
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start()
        self.addCleanup(p.stop)

        # Mock open inside method _update_pause_image_in_containerd
        mock_file_open = mock.mock_open(read_data=containerd_read_data)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        mock_enable_kubelet_garbage_collection = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.enable_kubelet_garbage_collection',
                       mock_enable_kubelet_garbage_collection)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.kube_controller_operator.upgrade_kubelet,
                          from_kube_version,
                          to_kube_version,
                          is_final_version)

        self.assertEqual(mock_get_k8s_images.call_count, 2)
        mock_get_k8s_images.assert_has_calls([mock.call('fake_from_kube_version'),
                                              mock.call('fake_to_kube_version')], any_order=True)
        mock_file_open.return_value.write.assert_called_with(containerd_write_data + '\n')
        mock_kubeadm_upgrade_node.assert_not_called()
        mock_update_symlink.assert_called_once()
        mock_enable_kubelet_garbage_collection.assert_not_called()
        mock_pmon_restart_service.assert_not_called()

    def test_kube_upgrade_kubelet_controller_host_failure_service_restart_failure(self):
        """Test failure of kubelet upgrade on controller hosts (kubelet service restart failure)
        """
        from_kube_version = 'vfake_from_kube_version'
        to_kube_version = 'vfake_to_kube_version'
        is_final_version = True
        fake_pause_image = 'fake_pause_image'
        different_fake_pause_image = 'different_fake_pause_image'
        containerd_read_data = 'sandbox_image = "%s/%s"' % (constants.DOCKER_REGISTRY_SERVER,
                                                            fake_pause_image)
        containerd_write_data = 'sandbox_image = "%s/%s"' % (constants.DOCKER_REGISTRY_SERVER,
                                                            different_fake_pause_image)

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().side_effect = [{'pause': fake_pause_image},
                                 {'pause': different_fake_pause_image}]
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start()
        self.addCleanup(p.stop)

        # Mock open inside method _update_pause_image_in_containerd
        mock_file_open = mock.mock_open(read_data=containerd_read_data)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start()
        self.addCleanup(p.stop)

        mock_enable_kubelet_garbage_collection = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.enable_kubelet_garbage_collection',
                       mock_enable_kubelet_garbage_collection)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.kube_controller_operator.upgrade_kubelet,
                          from_kube_version,
                          to_kube_version,
                          is_final_version)

        self.assertEqual(mock_get_k8s_images.call_count, 2)
        mock_get_k8s_images.assert_has_calls([mock.call('fake_from_kube_version'),
                                              mock.call('fake_to_kube_version')], any_order=True)
        mock_file_open.return_value.write.assert_called_with(containerd_write_data + '\n')
        mock_kubeadm_upgrade_node.assert_not_called()
        mock_update_symlink.assert_called_once()
        mock_enable_kubelet_garbage_collection.assert_called_once()
        mock_pmon_restart_service.assert_called_once()

    def test_kube_upgrade_kubelet_worker_host_success_same_pause_image_version(self):
        """Test successful kubelet upgrade on worker hosts (same pause image versions)
        """
        from_kube_version = 'vfake_from_kube_version'
        to_kube_version = 'vfake_to_kube_version'
        is_final_version = False
        same_fake_pause_image = 'same_fake_pause_image'
        containerd_read_data = 'sandbox_image = "%s/%s"' % (constants.DOCKER_REGISTRY_SERVER,
                                                            same_fake_pause_image)

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().side_effect = [{'pause': same_fake_pause_image},
                                 {'pause': same_fake_pause_image}]
        self.addCleanup(p.stop)

        mock_crictl_pull_images = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.ContainerdOperator.pull_images',
                       mock_crictl_pull_images)
        p.start()
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start()
        self.addCleanup(p.stop)

        # Mock open inside method _update_pause_image_in_containerd
        mock_file_open = mock.mock_open(read_data=containerd_read_data)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        self.kube_worker_operator.upgrade_kubelet(
            from_kube_version, to_kube_version, is_final_version)

        self.assertEqual(mock_get_k8s_images.call_count, 2)
        mock_get_k8s_images.assert_has_calls([mock.call('fake_from_kube_version'),
                                              mock.call('fake_to_kube_version')], any_order=True)
        mock_file_open.assert_not_called()
        mock_crictl_pull_images.assert_not_called()
        mock_kubeadm_upgrade_node.assert_called_once_with('fake_to_kube_version')
        mock_update_symlink.assert_has_calls([mock.call(kubernetes.KUBERNETES_SYMLINKS_STAGE_1,
                                                        'fake_to_kube_version'),
                                              mock.call(kubernetes.KUBERNETES_SYMLINKS_STAGE_2,
                                                        'fake_to_kube_version')],
                                              any_order=True)
        self.assertEqual(mock_update_symlink.call_count, 2)
        mock_pmon_restart_service.assert_called_once()

    def test_kube_upgrade_kubelet_worker_host_success_different_pause_image_versions(self):
        """Test successful kubelet upgrade on worker hosts (different pause image versions)
        """
        from_kube_version = 'vfake_from_kube_version'
        to_kube_version = 'vfake_to_kube_version'
        is_final_version = False
        fake_creds = {'username': 'fake_username', 'password': 'fake_password'}
        fake_pause_image = 'fake_pause_image'
        different_fake_pause_image = 'different_fake_pause_image'
        containerd_read_data = 'sandbox_image = "%s/%s"' % (constants.DOCKER_REGISTRY_SERVER,
                                                            fake_pause_image)
        containerd_write_data = 'sandbox_image = "%s/%s"' % (constants.DOCKER_REGISTRY_SERVER,
                                                            different_fake_pause_image)
        image_pull_result = True

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().side_effect = [{'pause': fake_pause_image},
                                 {'pause': different_fake_pause_image}]
        self.addCleanup(p.stop)

        mock_get_local_docker_registry_auth = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.get_local_docker_registry_auth',
                       mock_get_local_docker_registry_auth)
        p.start().return_value = fake_creds
        self.addCleanup(p.stop)

        mock_crictl_pull_images = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.ContainerdOperator.pull_images',
                       mock_crictl_pull_images)
        p.start().return_value = image_pull_result
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start()
        self.addCleanup(p.stop)

        # Mock open inside method _update_pause_image_in_containerd
        mock_file_open = mock.mock_open(read_data=containerd_read_data)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        self.kube_worker_operator.upgrade_kubelet(
            from_kube_version, to_kube_version, is_final_version)

        self.assertEqual(mock_get_k8s_images.call_count, 2)
        mock_get_k8s_images.assert_has_calls([mock.call('fake_from_kube_version'),
                                              mock.call('fake_to_kube_version')], any_order=True)
        mock_file_open.assert_called()
        mock_file_open.return_value.write.assert_called_with(containerd_write_data + '\n')
        mock_crictl_pull_images.assert_called_once()
        mock_get_local_docker_registry_auth.assert_called_once()
        mock_kubeadm_upgrade_node.assert_called_once_with('fake_to_kube_version')
        mock_update_symlink.assert_has_calls([mock.call(kubernetes.KUBERNETES_SYMLINKS_STAGE_1,
                                                        'fake_to_kube_version'),
                                              mock.call(kubernetes.KUBERNETES_SYMLINKS_STAGE_2,
                                                        'fake_to_kube_version')],
                                              any_order=True)
        self.assertEqual(mock_update_symlink.call_count, 2)
        mock_pmon_restart_service.assert_called_once()

    def test_kube_upgrade_kubelet_worker_host_failure_image_pull_failure(self):
        """Test failed kubelet upgrade on worker hosts (Image pull failure)
        """
        from_kube_version = 'vfake_from_kube_version'
        to_kube_version = 'vfake_to_kube_version'
        is_final_version = False
        fake_creds = {'username': 'fake_username', 'password': 'fake_password'}
        fake_pause_image = 'fake_pause_image'
        different_fake_pause_image = 'different_fake_pause_image'
        containerd_read_data = 'sandbox_image = "%s/%s"' % (constants.DOCKER_REGISTRY_SERVER,
                                                            fake_pause_image)
        image_pull_result = False

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().side_effect = [{'pause': fake_pause_image},
                                 {'pause': different_fake_pause_image}]
        self.addCleanup(p.stop)

        mock_get_local_docker_registry_auth = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.get_local_docker_registry_auth',
                       mock_get_local_docker_registry_auth)
        p.start().return_value = fake_creds
        self.addCleanup(p.stop)

        mock_crictl_pull_images = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.ContainerdOperator.pull_images',
                       mock_crictl_pull_images)
        p.start().return_value = image_pull_result
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start()
        self.addCleanup(p.stop)

        # Mock open inside method _update_pause_image_in_containerd
        mock_file_open = mock.mock_open(read_data=containerd_read_data)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.kube_worker_operator.upgrade_kubelet,
                          from_kube_version,
                          to_kube_version,
                          is_final_version)

        self.assertEqual(mock_get_k8s_images.call_count, 2)
        mock_get_k8s_images.assert_has_calls([mock.call('fake_from_kube_version'),
                                              mock.call('fake_to_kube_version')], any_order=True)
        mock_file_open.assert_not_called()
        mock_get_local_docker_registry_auth.assert_called_once()
        mock_crictl_pull_images.assert_called_once()
        mock_kubeadm_upgrade_node.assert_not_called()
        mock_update_symlink.assert_not_called()
        mock_pmon_restart_service.assert_not_called()

    def test_kube_upgrade_kubelet_worker_host_failure_kubeadm_upgrade_node_failed(self):
        """Test failed kubelet upgrade on worker hosts (kubeadm upgrade node)
        """
        from_kube_version = 'vfake_from_kube_version'
        to_kube_version = 'vfake_to_kube_version'
        is_final_version = False
        fake_creds = {'username': 'fake_username', 'password': 'fake_password'}
        fake_pause_image = 'fake_pause_image'
        different_fake_pause_image = 'different_fake_pause_image'
        containerd_read_data = 'sandbox_image = "%s/%s"' % (constants.DOCKER_REGISTRY_SERVER,
                                                            fake_pause_image)
        image_pull_result = True

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().side_effect = [{'pause': fake_pause_image},
                                 {'pause': different_fake_pause_image}]
        self.addCleanup(p.stop)

        mock_get_local_docker_registry_auth = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.get_local_docker_registry_auth',
                       mock_get_local_docker_registry_auth)
        p.start().return_value = fake_creds
        self.addCleanup(p.stop)

        mock_crictl_pull_images = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.ContainerdOperator.pull_images',
                       mock_crictl_pull_images)
        p.start().return_value = image_pull_result
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        # Mock open inside method _update_pause_image_in_containerd
        mock_file_open = mock.mock_open(read_data=containerd_read_data)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.kube_worker_operator.upgrade_kubelet,
                          from_kube_version,
                          to_kube_version,
                          is_final_version)

        self.assertEqual(mock_get_k8s_images.call_count, 2)
        mock_get_k8s_images.assert_has_calls([mock.call('fake_from_kube_version'),
                                              mock.call('fake_to_kube_version')], any_order=True)
        mock_file_open.assert_not_called()
        mock_get_local_docker_registry_auth.assert_called_once()
        mock_crictl_pull_images.assert_called_once()
        mock_kubeadm_upgrade_node.assert_called_once()
        mock_update_symlink.assert_not_called()
        mock_pmon_restart_service.assert_not_called()

    def test_kube_upgrade_kubelet_worker_host_failure_containerd_config_invalid_content(self):
        """Test failure of kubelet upgrade on worker hosts (pause image update failure)

        Containerd config.toml invalid content
        """
        from_kube_version = 'vfake_from_kube_version'
        to_kube_version = 'vfake_to_kube_version'
        is_final_version = True
        fake_pause_image = 'fake_pause_image'
        different_fake_pause_image = 'different_fake_pause_image'
        containerd_read_data = ""

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().side_effect = [{'pause': fake_pause_image},
                                 {'pause': different_fake_pause_image}]
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start()
        self.addCleanup(p.stop)

        # Mock open inside method _update_pause_image_in_containerd
        mock_file_open = mock.mock_open(read_data=containerd_read_data)
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start()
        self.addCleanup(p.stop)

        mock_enable_kubelet_garbage_collection = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.enable_kubelet_garbage_collection',
                       mock_enable_kubelet_garbage_collection)
        p.start()
        self.addCleanup(p.stop)

        mock_pmon_restart_service = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.pmon_restart_service', mock_pmon_restart_service)
        p.start()
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.kube_worker_operator.upgrade_kubelet,
                          from_kube_version,
                          to_kube_version,
                          is_final_version)

        self.assertEqual(mock_get_k8s_images.call_count, 2)
        mock_get_k8s_images.assert_has_calls([mock.call('fake_from_kube_version'),
                                              mock.call('fake_to_kube_version')], any_order=True)
        mock_kubeadm_upgrade_node.assert_not_called()
        mock_update_symlink.assert_not_called()
        mock_enable_kubelet_garbage_collection.assert_not_called()
        mock_pmon_restart_service.assert_not_called()

    def test_kubeadm_upgrade_node_success(self):
        """Test successful execution of kubeadm upgrade node on worker host
        """
        to_kube_version = 'vfake_to_kube_version'

        mock_execute_and_watch = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute_and_watch', mock_execute_and_watch)
        p.start()
        self.addCleanup(p.stop)

        self.kube_worker_operator.kubeadm_upgrade_node(to_kube_version)

        mock_execute_and_watch.assert_called()

    def test_kubeadm_upgrade_node_command_failure(self):
        """Test failed execution of kubeadm upgrade node on a controller host
        """
        to_kube_version = 'vfake_to_kube_version'

        mock_execute_and_watch = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute_and_watch', mock_execute_and_watch)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.kube_controller_operator.kubeadm_upgrade_node,
                          to_kube_version)

        mock_execute_and_watch.assert_called_once()

    def test_kubeadm_upgrade_apply_success(self):
        """Test successful execution of kubeadm upgrade apply
        """
        to_kube_version = 'vfake_to_kube_version'

        mock_execute_and_watch = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute_and_watch', mock_execute_and_watch)
        p.start()
        self.addCleanup(p.stop)

        self.kube_controller_operator.kubeadm_upgrade_apply(to_kube_version)

        mock_execute_and_watch.assert_called()

    def test_kubeadm_upgrade_apply_command_failure(self):
        """Test failed execution of kubeadm upgrade apply on a controller host
        """
        to_kube_version = 'vfake_to_kube_version'

        mock_execute_and_watch = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute_and_watch', mock_execute_and_watch)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.kube_controller_operator.kubeadm_upgrade_apply,
                          to_kube_version)

        mock_execute_and_watch.assert_called_once()

    def test_kube_upgrade_control_plane_success_simplex(self):
        """Test successful execution of kubernetes control plane upgrade on simplex
        """
        to_kube_version = 'vfake_to_kube_version'
        is_first_master = True

        mock_kubeadm_upgrade_apply = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.kubeadm_upgrade_apply',
                       mock_kubeadm_upgrade_apply)
        p.start()
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start()
        self.addCleanup(p.stop)

        cm_newest = kubernetes.client.V1ConfigMap(
                        kind="ConfigMap",
                        metadata=kubernetes.client.V1ObjectMeta(
                            name='kubelet-config-xyz',
                            namespace=kubernetes.NAMESPACE_KUBE_SYSTEM,
                            creation_timestamp=datetime.datetime(
                                2025, 8, 5, 20, 40, 41),
                            resource_version='1614'
                        ),
                    )

        configmaps = [cm_newest]

        mock_kube_get_all_configmaps = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_all_configmaps',
            mock_kube_get_all_configmaps)
        p.start().return_value = configmaps
        self.addCleanup(p.stop)

        mock_kube_delete_config_map = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_delete_config_map',
            mock_kube_delete_config_map)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_patch_service_account = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_patch_service_account',
            mock_kube_patch_service_account)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_patch_deployment = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_patch_deployment',
            mock_kube_patch_deployment)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_patch_daemonset = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_patch_daemonset',
            mock_kube_patch_daemonset)
        p.start()
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start()
        self.addCleanup(p.stop)

        self.kube_controller_operator._system_mode = \
            constants.SYSTEM_MODE_SIMPLEX
        self.kube_controller_operator.upgrade_control_plane(to_kube_version, is_first_master)

        mock_kubeadm_upgrade_apply.assert_called_once_with(to_kube_version)
        mock_kubeadm_upgrade_node.assert_not_called()
        mock_kube_get_all_configmaps.assert_called_once()
        mock_kube_delete_config_map.assert_not_called()

        self.assertEqual(mock_kube_patch_service_account.call_count, 2)
        mock_kube_patch_service_account.assert_has_calls(
            [mock.call('coredns', kubernetes.NAMESPACE_KUBE_SYSTEM, body=mock.ANY),
            mock.call('kube-proxy', kubernetes.NAMESPACE_KUBE_SYSTEM, body=mock.ANY)],
            any_order=True)

        mock_kube_patch_deployment.assert_called_once_with(
            'coredns', kubernetes.NAMESPACE_KUBE_SYSTEM, body=mock.ANY)
        mock_kube_patch_daemonset.assert_called_once_with(
            'kube-proxy', kubernetes.NAMESPACE_KUBE_SYSTEM, body=mock.ANY)
        mock_update_symlink.assert_called()

    def test_kube_upgrade_control_plane_success_duplex_first_master(self):
        """Test successful execution of kubernetes control plane upgrade on duplex: first master
        """
        to_kube_version = 'vfake_to_kube_version'
        is_first_master = True

        mock_kubeadm_upgrade_apply = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.kubeadm_upgrade_apply',
                       mock_kubeadm_upgrade_apply)
        p.start()
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_get_all_configmaps = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_all_configmaps',
            mock_kube_get_all_configmaps)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_delete_config_map = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_delete_config_map',
            mock_kube_delete_config_map)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_patch_service_account = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_patch_service_account',
            mock_kube_patch_service_account)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_patch_deployment = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_patch_deployment',
            mock_kube_patch_deployment)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_patch_daemonset = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_patch_daemonset',
            mock_kube_patch_daemonset)
        p.start()
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start()
        self.addCleanup(p.stop)

        self.kube_controller_operator._system_mode = \
            constants.SYSTEM_MODE_DUPLEX
        self.kube_controller_operator.upgrade_control_plane(to_kube_version, is_first_master)

        mock_kubeadm_upgrade_apply.assert_called()
        mock_kubeadm_upgrade_node.assert_not_called()
        mock_kube_get_all_configmaps.assert_not_called()
        mock_kube_delete_config_map.assert_not_called()
        mock_kube_patch_deployment.assert_not_called()
        mock_kube_patch_daemonset.assert_not_called()
        mock_update_symlink.assert_called_once()

    def test_kube_upgrade_control_plane_success_duplex_second_master(self):
        """Test successful execution of kubernetes control plane upgrade on duplex: Second master
        """
        to_kube_version = 'vfake_to_kube_version'
        is_first_master = False

        mock_kubeadm_upgrade_apply = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.kubeadm_upgrade_apply',
                       mock_kubeadm_upgrade_apply)
        p.start()
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start()
        self.addCleanup(p.stop)

        cm_oldest = kubernetes.client.V1ConfigMap(
                        kind="ConfigMap",
                        metadata=kubernetes.client.V1ObjectMeta(
                            name='kubelet-config-abc',
                            namespace=kubernetes.NAMESPACE_KUBE_SYSTEM,
                            creation_timestamp=datetime.datetime(
                                2025, 8, 5, 20, 40, 40),
                            resource_version='1612'
                        ),
                    )

        cm_old = kubernetes.client.V1ConfigMap(
                    kind="ConfigMap",
                    metadata=kubernetes.client.V1ObjectMeta(
                        name='kubelet-config-pqr',
                        namespace=kubernetes.NAMESPACE_KUBE_SYSTEM,
                        creation_timestamp=datetime.datetime(
                            2025, 8, 5, 20, 40, 41),
                        resource_version='1613'
                    ),
                )

        cm_newest = kubernetes.client.V1ConfigMap(
                        kind="ConfigMap",
                        metadata=kubernetes.client.V1ObjectMeta(
                            name='kubelet-config-xyz',
                            namespace=kubernetes.NAMESPACE_KUBE_SYSTEM,
                            creation_timestamp=datetime.datetime(
                                2025, 8, 5, 20, 40, 41),
                            resource_version='1614'
                        ),
                    )

        configmaps = [cm_oldest, cm_old, cm_newest]

        mock_kube_get_all_configmaps = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_all_configmaps',
            mock_kube_get_all_configmaps)
        p.start().return_value = configmaps
        self.addCleanup(p.stop)

        mock_kube_delete_config_map = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_delete_config_map',
            mock_kube_delete_config_map)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_patch_service_account = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_patch_service_account',
            mock_kube_patch_service_account)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_patch_deployment = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_patch_deployment',
            mock_kube_patch_deployment)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_patch_daemonset = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_patch_daemonset',
            mock_kube_patch_daemonset)
        p.start()
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start()
        self.addCleanup(p.stop)

        self.kube_controller_operator._system_mode = \
            constants.SYSTEM_MODE_DUPLEX
        self.kube_controller_operator.upgrade_control_plane(to_kube_version, is_first_master)

        mock_kubeadm_upgrade_apply.assert_not_called()
        mock_kubeadm_upgrade_node.assert_called_once_with(to_kube_version)
        mock_kube_get_all_configmaps.assert_called_once()

        self.assertEqual(mock_kube_delete_config_map.call_count, 2)
        mock_kube_delete_config_map.assert_has_calls(
            [mock.call('kubelet-config-abc', kubernetes.NAMESPACE_KUBE_SYSTEM),
            mock.call('kubelet-config-pqr', kubernetes.NAMESPACE_KUBE_SYSTEM)],
            any_order=True)

        self.assertEqual(mock_kube_patch_service_account.call_count, 2)
        mock_kube_patch_service_account.assert_has_calls(
            [mock.call('coredns', kubernetes.NAMESPACE_KUBE_SYSTEM, body=mock.ANY),
            mock.call('kube-proxy', kubernetes.NAMESPACE_KUBE_SYSTEM, body=mock.ANY)],
            any_order=True)

        mock_kube_patch_deployment.assert_called_once_with(
            'coredns', kubernetes.NAMESPACE_KUBE_SYSTEM, body=mock.ANY)
        mock_kube_patch_daemonset.assert_called_once_with(
            'kube-proxy', kubernetes.NAMESPACE_KUBE_SYSTEM, body=mock.ANY)
        mock_update_symlink.assert_called()

    def test_kube_upgrade_control_plane_failure_simplex(self):
        """Test failed execution of kubernetes control plane upgrade on simplex
        """
        to_kube_version = 'vfake_to_kube_version'
        is_first_master = True

        mock_kubeadm_upgrade_apply = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.kubeadm_upgrade_apply',
                       mock_kubeadm_upgrade_apply)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_get_all_configmaps = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_all_configmaps',
                       mock_kube_get_all_configmaps)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_delete_config_map = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_delete_config_map',
                       mock_kube_delete_config_map)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_patch_service_account = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_patch_service_account',
                       mock_kube_patch_service_account)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_patch_deployment = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_patch_deployment',
                       mock_kube_patch_deployment)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_patch_daemonset = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_patch_daemonset',
                       mock_kube_patch_daemonset)
        p.start()
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start()
        self.addCleanup(p.stop)

        self.kube_controller_operator._system_mode = \
            constants.SYSTEM_MODE_SIMPLEX
        self.assertRaises(exception.SysinvException,
                          self.kube_controller_operator.upgrade_control_plane,
                          to_kube_version,
                          is_first_master)

        mock_kubeadm_upgrade_apply.assert_called_once_with(to_kube_version)
        mock_kubeadm_upgrade_node.assert_not_called()
        mock_kube_get_all_configmaps.assert_not_called()
        mock_kube_delete_config_map.assert_not_called()
        mock_kube_patch_service_account.assert_not_called()
        mock_kube_patch_deployment.assert_not_called()
        mock_kube_patch_daemonset.assert_not_called()
        mock_update_symlink.assert_not_called()

    def test_kube_upgrade_control_plane_failure_duplex(self):
        """Test failed execution of kubernetes control plane upgrade on duplex
        """
        to_kube_version = 'vfake_to_kube_version'
        is_first_master = False

        mock_kubeadm_upgrade_apply = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeControllerOperator.kubeadm_upgrade_apply',
                       mock_kubeadm_upgrade_apply)
        p.start()
        self.addCleanup(p.stop)

        mock_kubeadm_upgrade_node = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator.kubeadm_upgrade_node',
                       mock_kubeadm_upgrade_node)
        p.start()
        self.addCleanup(p.stop)

        cm_newest = kubernetes.client.V1ConfigMap(
                        kind="ConfigMap",
                        metadata=kubernetes.client.V1ObjectMeta(
                            name='kubelet-config-xyz',
                            namespace=kubernetes.NAMESPACE_KUBE_SYSTEM,
                            creation_timestamp=datetime.datetime(
                                2025, 8, 5, 20, 40, 41),
                            resource_version='1614'
                        ),
                    )

        configmaps = [cm_newest]

        mock_kube_get_all_configmaps = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_get_all_configmaps',
                       mock_kube_get_all_configmaps)
        p.start().return_value = configmaps
        self.addCleanup(p.stop)

        mock_kube_delete_config_map = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_delete_config_map',
                       mock_kube_delete_config_map)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_patch_service_account = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_patch_service_account',
                       mock_kube_patch_service_account)
        p.start()
        self.addCleanup(p.stop)

        mock_kube_patch_deployment = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_patch_deployment',
                       mock_kube_patch_deployment)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        mock_kube_patch_daemonset = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_patch_daemonset',
                       mock_kube_patch_daemonset)
        p.start()
        self.addCleanup(p.stop)

        mock_update_symlink = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.KubeHostOperator._update_symlink',
                       mock_update_symlink)
        p.start()
        self.addCleanup(p.stop)

        self.kube_controller_operator._system_mode = \
            constants.SYSTEM_MODE_DUPLEX
        self.assertRaises(exception.SysinvException,
                          self.kube_controller_operator.upgrade_control_plane,
                          to_kube_version,
                          is_first_master)

        mock_kubeadm_upgrade_apply.assert_not_called()
        mock_kubeadm_upgrade_node.assert_called_once_with(to_kube_version)
        mock_kube_get_all_configmaps.assert_called_once()
        mock_kube_delete_config_map.assert_not_called()
        mock_kube_patch_service_account.assert_called()
        mock_kube_patch_deployment.assert_called()
        mock_kube_patch_daemonset.assert_not_called()
        mock_update_symlink.assert_not_called()

    def test_update_symlink_success_stage1(self):
        """Test successful execution of symlink update: stage1
        """
        link = kubernetes.KUBERNETES_SYMLINKS_STAGE_1
        to_kube_version = "vfake_to_kube_version"
        versioned_stage = "fake_versioned_stage"

        mock_os_path_join = mock.MagicMock()
        p = mock.patch('os.path.join', mock_os_path_join)
        p.start().return_value = versioned_stage
        self.addCleanup(p.stop)

        mock_os_path_islink = mock.MagicMock()
        p = mock.patch('os.path.islink', mock_os_path_islink)
        p.start().return_value = True
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        mock_os_symlink = mock.MagicMock()
        p = mock.patch('os.symlink', mock_os_symlink)
        p.start()
        self.addCleanup(p.stop)

        self.kube_controller_operator._update_symlink(link, to_kube_version)

        mock_os_path_join.assert_called()
        mock_os_path_islink.assert_called_once_with(link)
        mock_os_remove.assert_called_once_with(link)
        mock_os_symlink.assert_called_once_with(versioned_stage, link)

    def test_update_symlink_success_stage2(self):
        """Test successful execution of symlink update: stage2
        """
        link = kubernetes.KUBERNETES_SYMLINKS_STAGE_2
        to_kube_version = "vfake_to_kube_version"
        versioned_stage = "fake_versioned_stage"

        mock_os_path_join = mock.MagicMock()
        p = mock.patch('os.path.join', mock_os_path_join)
        p.start().return_value = versioned_stage
        self.addCleanup(p.stop)

        mock_os_path_islink = mock.MagicMock()
        p = mock.patch('os.path.islink', mock_os_path_islink)
        p.start().return_value = False
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        mock_os_symlink = mock.MagicMock()
        p = mock.patch('os.symlink', mock_os_symlink)
        p.start()
        self.addCleanup(p.stop)

        self.kube_controller_operator._update_symlink(link, to_kube_version)

        mock_os_path_join.assert_called()
        mock_os_path_islink.assert_called_once_with(link)
        mock_os_remove.assert_not_called()
        mock_os_symlink.assert_called_once_with(versioned_stage, link)

    def test_update_symlink_failure_invalid_link(self):
        """Test failed execution of symlink update: invalid link
        """
        link = 'crap_link_path'
        to_kube_version = "vfake_to_kube_version"

        mock_os_path_join = mock.MagicMock()
        p = mock.patch('os.path.join', mock_os_path_join)
        p.start()
        self.addCleanup(p.stop)

        mock_os_path_islink = mock.MagicMock()
        p = mock.patch('os.path.islink', mock_os_path_islink)
        p.start().return_value = False
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        mock_os_symlink = mock.MagicMock()
        p = mock.patch('os.symlink', mock_os_symlink)
        p.start()
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.kube_controller_operator._update_symlink,
                          link,
                          to_kube_version)

        mock_os_path_join.assert_not_called()
        mock_os_path_islink.assert_not_called()
        mock_os_remove.assert_not_called()
        mock_os_symlink.assert_not_called()

    def test_update_symlink_failure_invalid_kube_version(self):
        """Test failed execution of symlink update: invalid kube version
        """
        link = kubernetes.KUBERNETES_SYMLINKS_STAGE_1
        to_kube_version = "vfake_invalid_to_kube_version"
        versioned_stage = "fake_versioned_stage"

        mock_os_path_join = mock.MagicMock()
        p = mock.patch('os.path.join', mock_os_path_join)
        p.start().return_value = versioned_stage
        self.addCleanup(p.stop)

        mock_os_path_islink = mock.MagicMock()
        p = mock.patch('os.path.islink', mock_os_path_islink)
        p.start().return_value = True
        self.addCleanup(p.stop)

        mock_os_remove = mock.MagicMock()
        p = mock.patch('os.remove', mock_os_remove)
        p.start()
        self.addCleanup(p.stop)

        mock_os_symlink = mock.MagicMock()
        p = mock.patch('os.symlink', mock_os_symlink)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          self.kube_controller_operator._update_symlink,
                          link,
                          to_kube_version)

        mock_os_path_join.assert_called_once()
        mock_os_path_islink.assert_called_once_with(link)
        mock_os_remove.assert_called_once_with(link)
        mock_os_symlink.assert_called_once_with(versioned_stage, link)
