#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the kubernetes host functions.
"""

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

        mock_get_auth = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.ContainerdOperator._get_auth', mock_get_auth)
        p.start().return_value = fake_auth
        self.addCleanup(p.stop)

        mock_get_crictl_image_list = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.get_crictl_image_list', mock_get_crictl_image_list)
        p.start().return_value = fake_exisitng_image_list
        self.addCleanup(p.stop)

        mock_pull_image_to_crictl = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.pull_image_to_crictl', mock_pull_image_to_crictl)
        p.start()
        self.addCleanup(p.stop)

        result = self.containerd_operator.pull_images(images_to_be_pulled)

        self.assertTrue(result)
        mock_get_auth.assert_called_once()
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

        mock_get_auth = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.ContainerdOperator._get_auth', mock_get_auth)
        p.start().return_value = fake_auth
        self.addCleanup(p.stop)

        mock_get_crictl_image_list = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.get_crictl_image_list', mock_get_crictl_image_list)
        p.start().return_value = fake_exisitng_image_list
        self.addCleanup(p.stop)

        mock_pull_image_to_crictl = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.pull_image_to_crictl', mock_pull_image_to_crictl)
        p.start()
        self.addCleanup(p.stop)

        result = self.containerd_operator.pull_images(images_to_be_pulled)

        self.assertTrue(result)
        mock_get_auth.assert_called_once()
        mock_get_crictl_image_list.assert_called_once()
        mock_pull_image_to_crictl.assert_not_called()

    def test_pull_images_suceess_failed_to_get_existing_image_list(self):
        """Test successful image pull: Failed to get existing crictl image list
        """
        fake_auth = "fake_username:fake_password"
        images_to_be_pulled = ['fake_image1', 'fake_image2', 'fake_image3', 'fake_image4']

        mock_get_auth = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.ContainerdOperator._get_auth', mock_get_auth)
        p.start().return_value = fake_auth
        self.addCleanup(p.stop)

        mock_get_crictl_image_list = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.get_crictl_image_list', mock_get_crictl_image_list)
        p.start().side_effect = exception.SysinvException("Fake Error")
        self.addCleanup(p.stop)

        mock_pull_image_to_crictl = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.pull_image_to_crictl', mock_pull_image_to_crictl)
        p.start()
        self.addCleanup(p.stop)

        result = self.containerd_operator.pull_images(images_to_be_pulled)

        self.assertTrue(result)
        mock_get_auth.assert_called_once()
        mock_get_crictl_image_list.assert_called_once()
        expected_calls = [mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image1", fake_auth),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image2", fake_auth),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image3", fake_auth),
                          mock.call(f"{constants.DOCKER_REGISTRY_SERVER}/fake_image4", fake_auth)]
        mock_pull_image_to_crictl.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_pull_image_to_crictl.call_count, 4)

    def test_pull_images_failure_failed_to_get_auth(self):
        """Test successful image pull: Failed to get auth credentials
        """
        images_to_be_pulled = ['fake_image1', 'fake_image2', 'fake_image3', 'fake_image4']

        mock_get_auth = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.ContainerdOperator._get_auth', mock_get_auth)
        p.start().return_value = None
        self.addCleanup(p.stop)

        mock_get_crictl_image_list = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.get_crictl_image_list', mock_get_crictl_image_list)
        p.start()
        self.addCleanup(p.stop)

        mock_pull_image_to_crictl = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.pull_image_to_crictl', mock_pull_image_to_crictl)
        p.start()
        self.addCleanup(p.stop)

        result = self.containerd_operator.pull_images(images_to_be_pulled)

        self.assertFalse(result)
        mock_get_auth.assert_called_once()
        mock_get_crictl_image_list.assert_not_called()
        mock_pull_image_to_crictl.assert_not_called()

    def test_pull_images_failure_image_pull_exception(self):
        """Test image pull failure: Image pull exception
        """
        fake_auth = "fake_username:fake_password"
        images_to_be_pulled = ['fake_image1', 'fake_image2', 'fake_image3', 'fake_image4']

        mock_get_auth = mock.MagicMock()
        p = mock.patch('sysinv.agent.kube_host.ContainerdOperator._get_auth', mock_get_auth)
        p.start().return_value = fake_auth
        self.addCleanup(p.stop)

        mock_get_crictl_image_list = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.get_crictl_image_list', mock_get_crictl_image_list)
        p.start().return_value = []
        self.addCleanup(p.stop)

        mock_pull_image_to_crictl = mock.MagicMock()
        p = mock.patch('sysinv.common.containers.pull_image_to_crictl', mock_pull_image_to_crictl)
        p.start().side_effect = exception.SysinvException("Fake error")
        self.addCleanup(p.stop)

        result = self.containerd_operator.pull_images(images_to_be_pulled)

        self.assertFalse(result)
        mock_get_auth.assert_called_once()
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
