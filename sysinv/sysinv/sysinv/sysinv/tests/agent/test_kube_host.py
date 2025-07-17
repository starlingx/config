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

from sysinv.tests import base
from sysinv.agent import kube_host
from sysinv.common import constants
from sysinv.common import exception


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
