#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for common containerd operations.
"""

import io
import json
import mock

from sysinv.tests import base
from sysinv.common import containers
from sysinv.common import exception


class FakePopen(object):

    def __init__(self, return_code):
        self.returncode = return_code
        self.stdin = io.TextIOWrapper(io.BytesIO())
        self.communicate_attempts = 0

    def communicate(self, process_input=None, timeout=60):
        self.communicate_attempts += 1
        return "Fake stdout", "Fake stderr"


class TestContainers(base.TestCase):

    def setUp(self):
        super(TestContainers, self).setUp()

    def tearDown(self):
        super(TestContainers, self).tearDown()

    def test_pull_image_to_crictl_success(self):
        """Test successful execution of crictl pull
        """
        image_to_be_pulled = 'fake_image1'
        fake_auth = "fake_username:fake_password"
        cmd = ["crictl", "pull", "--creds", fake_auth, image_to_be_pulled]

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        containers.pull_image_to_crictl(image_to_be_pulled, fake_auth)

        mock_utils_execute.assert_called_once_with(
            *cmd, attempts=5, delay_on_retry=True, check_exit_code=0)

    def test_pull_image_to_crictl_failure(self):
        """Test crictl pull failure
        """
        image_to_be_pulled = 'fake_image1'
        fake_auth = "fake_username:fake_password"
        attempts = 4

        fake_popen = FakePopen(return_code=1)
        mock_subprocess = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.subprocess.Popen', mock_subprocess)
        p.start().return_value = fake_popen
        self.addCleanup(p.stop)

        mock_fsdecode = mock.MagicMock()
        p = mock.patch('os.fsdecode', mock_fsdecode)
        p.start().return_value = "fake output"
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          containers.pull_image_to_crictl,
                          image_to_be_pulled,
                          fake_auth,
                          attempts=attempts)

        mock_subprocess.assert_called()
        self.assertEqual(fake_popen.communicate_attempts, attempts)

        mock_fsdecode.assert_called()
        self.assertEqual(mock_fsdecode.call_count, 2 * attempts)

    def test_get_crictl_image_list_success(self):
        """Test successful execution of crictl get all images
        """
        mock_execute_output = {'images': [{'id': 'sha256:fakeID1', 'repoTags': ['fake_image1']},
                                          {'id': 'sha256:fakeID2', 'repoTags': ['fake_image2']}]}
        expected_list_of_images = ['fake_image1', 'fake_image2']

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start().return_value = (json.dumps(mock_execute_output), None)
        self.addCleanup(p.stop)

        image_list = containers.get_crictl_image_list()

        self.assertEqual(image_list, expected_list_of_images)
        mock_utils_execute.assert_called_once()

    def test_get_crictl_image_list_failure(self):
        """Test execution failure of crictl get all images
        """
        fake_popen = FakePopen(return_code=1)
        mock_subprocess = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.subprocess.Popen', mock_subprocess)
        p.start().return_value = fake_popen
        self.addCleanup(p.stop)

        mock_fsdecode = mock.MagicMock()
        p = mock.patch('os.fsdecode', mock_fsdecode)
        p.start().return_value = "fake output"
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          containers.get_crictl_image_list)

        mock_subprocess.assert_called()
        self.assertEqual(fake_popen.communicate_attempts, 1)

        mock_fsdecode.assert_called()
        self.assertEqual(mock_fsdecode.call_count, 2)

    def test_get_crictl_image_list_failure_json_loads_failure(self):
        """Test execution failure of crictl get all images: Failed to parse json output
        """
        invalid_json_output = 'invalid json output'

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start().return_value = (invalid_json_output, None)
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          containers.get_crictl_image_list)
        mock_utils_execute.assert_called_once()

    def test_label_ctr_images_success(self):
        """Test successful execution of label containerd images.
        """
        fake_image = "fake_image"
        fake_label_key = "fake_label_key"
        fake_label_value = "fake_label_value"
        expected_cmd = ['ctr', '-n', 'k8s.io', 'images', 'label',
                        'fake_image', 'fake_label_key=fake_label_value']

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        containers.label_ctr_image(fake_image, fake_label_key, fake_label_value)

        mock_utils_execute.assert_called_once_with(*expected_cmd, check_exit_code=0)

    def test_label_ctr_images_failure(self):
        """Test failed execution of label containerd images.
        """
        fake_image = "fake_image"
        fake_label_key = "fake_label_key"
        fake_label_value = "fake_label_value"
        expected_cmd = ['ctr', '-n', 'k8s.io', 'images', 'label',
                        'fake_image', 'fake_label_key=fake_label_value']

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          containers.label_ctr_image,
                          fake_image,
                          fake_label_key,
                          fake_label_value)

        mock_utils_execute.assert_called_once_with(*expected_cmd, check_exit_code=0)

    def test_label_ctr_images_failure_invalid_image_name(self):
        """Test failed execution of label containerd images: invalid image name
        """
        fake_image = 3
        fake_label_key = "fake_label_key"
        fake_label_value = "fake_label_value"

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          containers.label_ctr_image,
                          fake_image,
                          fake_label_key,
                          fake_label_value)

        mock_utils_execute.assert_not_called()

    def test_label_ctr_images_success_label_key_and_value_none(self):
        """Test failed execution of label containerd images: label key and value None
        """
        fake_image = "fake_image"
        fake_label_key = None
        fake_label_value = None
        expected_cmd = ['ctr', '-n', 'k8s.io', 'images', 'label',
                        'fake_image', 'None=None']

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          containers.label_ctr_image,
                          fake_image,
                          fake_label_key,
                          fake_label_value)

        mock_utils_execute.assert_called_once_with(*expected_cmd, check_exit_code=0)

    def test_pin_ctr_images_success(self):
        """Test successful execution of pin_ctr_image.
        """
        fake_image = "fake_image"

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        containers.pin_ctr_image(fake_image)

        mock_utils_execute.assert_called_once()

    def test_pin_ctr_images_failure(self):
        """Test failed execution of pin_ctr_image.
        """
        fake_image = "fake_image"

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          containers.pin_ctr_image,
                          fake_image)

        mock_utils_execute.assert_called_once()

    def test_pin_ctr_images_failure_invalid_image_names(self):
        """Test failed execution of pin_ctr_image: invalid image names
        """
        fake_invalid_image_names = [3, 2.4, False]

        for fake_image in fake_invalid_image_names:
            mock_utils_execute = mock.MagicMock()
            p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
            p.start().side_effect = Exception("Fake error")
            self.addCleanup(p.stop)

            self.assertRaises(exception.SysinvException,
                              containers.pin_ctr_image,
                              fake_image)

            mock_utils_execute.assert_not_called()

    def test_unpin_ctr_images_success(self):
        """Test successful execution of unpin_ctr_image.
        """
        fake_image = "fake_image"

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        containers.unpin_ctr_image(fake_image)

        mock_utils_execute.assert_called_once()

    def test_unpin_ctr_images_failure(self):
        """Test failed execution of unpin_ctr_image.
        """
        fake_image = "fake_image"

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          containers.unpin_ctr_image,
                          fake_image)

        mock_utils_execute.assert_called_once()

    def test_unpin_ctr_images_failure_invalid_image_names(self):
        """Test failed execution of unpin_ctr_image: invalid image names
        """
        fake_invalid_image_names = [3, 2.4, False]

        for fake_image in fake_invalid_image_names:
            mock_utils_execute = mock.MagicMock()
            p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
            p.start().side_effect = Exception("Fake error")
            self.addCleanup(p.stop)

            self.assertRaises(exception.SysinvException,
                              containers.unpin_ctr_image,
                              fake_image)

            mock_utils_execute.assert_not_called()
