#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
import uuid
import yaml

from cgtsclient import exc
from cgtsclient.tests import test_shell
from cgtsclient.v1.ihost import ihost
from cgtsclient.v1.label import KubernetesLabel

from testtools import ExpectedException


FAKE_HOST_CONTROLLER_0 = {
    'uuid': str(uuid.uuid4()),
    'hostname': 'controller-0',
    'id': '0',
}

FAKE_HOST_LABEL_1 = {
    'uuid': str(uuid.uuid4()),
    'host_uuid': FAKE_HOST_CONTROLLER_0['uuid'],
    'hostname': FAKE_HOST_CONTROLLER_0['hostname'],
    'label_key': 'testkey1',
    'label_value': 'testvalue1',
}

FAKE_HOST_LABEL_2 = {
    'uuid': str(uuid.uuid4()),
    'host_uuid': FAKE_HOST_CONTROLLER_0['uuid'],
    'hostname': FAKE_HOST_CONTROLLER_0['hostname'],
    'label_key': 'testkey2',
    'label_value': 'testvalue2',
}


class KubernetesLabelTest(test_shell.ShellTest):

    def setUp(self):
        super(KubernetesLabelTest, self).setUp()
        self.make_env()

    def tearDown(self):
        super(KubernetesLabelTest, self).tearDown()

    @mock.patch('cgtsclient.v1.label.KubernetesLabelManager.list')
    @mock.patch('cgtsclient.v1.ihost._find_ihost')
    def test_host_label_list(self, mock_find_ihost, mock_label_list):
        mock_find_ihost.return_value = ihost(None, FAKE_HOST_CONTROLLER_0, True)
        mock_label_list.return_value = [
            KubernetesLabel(None, FAKE_HOST_LABEL_1, True),
            KubernetesLabel(None, FAKE_HOST_LABEL_2, True),
        ]
        results_str = self.shell("host-label-list --format yaml controller-0")
        results_list = yaml.safe_load(results_str)
        self.assertTrue(isinstance(results_list, list),
                        "host-label-list should return a list")

        returned_keys = [
            'hostname',
            'label_key',
            'label_value',
        ]
        lbl_1 = {
            k: v for k, v in FAKE_HOST_LABEL_1.items() if k in returned_keys
        }
        lbl_2 = {
            k: v for k, v in FAKE_HOST_LABEL_2.items() if k in returned_keys
        }
        expected_labels = [lbl_1, lbl_2]
        self.assertListEqual(expected_labels, results_list)

    @mock.patch('cgtsclient.v1.ihost.ihostManager.list')
    def test_host_label_list_host_not_found(self, mock_ihost_list,):
        mock_ihost_list.return_value = [
            ihost(None, FAKE_HOST_CONTROLLER_0, True)
        ]
        hostname = "controller-1"
        exception_str = f"host not found: {hostname}"
        with ExpectedException(exc.CommandError, exception_str):
            self.shell(f"host-label-list {hostname}")

    @mock.patch('cgtsclient.v1.label.KubernetesLabelManager.get')
    @mock.patch('cgtsclient.v1.label.KubernetesLabelManager.assign')
    @mock.patch('cgtsclient.v1.ihost._find_ihost')
    def test_host_label_assign(self, mock_find_ihost, mock_label_assign, mock_label_get):
        mock_find_ihost.return_value = ihost(None, FAKE_HOST_CONTROLLER_0, True)
        mock_label_assign.return_value = [
            KubernetesLabel(None, FAKE_HOST_LABEL_1, True),
            KubernetesLabel(None, FAKE_HOST_LABEL_2, True),
        ]
        mock_label_get.side_effect = [
            KubernetesLabel(None, FAKE_HOST_LABEL_1, True),
            KubernetesLabel(None, FAKE_HOST_LABEL_2, True),
        ]
        hostname = "controller-0"
        parameters = \
            f" {FAKE_HOST_LABEL_1['label_key']}"\
            f"={FAKE_HOST_LABEL_1['label_value']}"\
            f" {FAKE_HOST_LABEL_2['label_key']}"\
            f"={FAKE_HOST_LABEL_2['label_value']}"

        self.shell(f"host-label-assign {hostname} {parameters}")

    @mock.patch('cgtsclient.v1.ihost.ihostManager.list')
    def test_host_label_assign_host_not_found(self, mock_ihost_list):
        mock_ihost_list.return_value = [
            ihost(None, FAKE_HOST_CONTROLLER_0, True)
        ]
        hostname = "controller-1"
        exception_str = f'host not found: {hostname}'
        with ExpectedException(exc.CommandError, exception_str):
            self.shell(f"host-label-assign {hostname} newkey=newvalue")

    @mock.patch('cgtsclient.v1.label.KubernetesLabelManager.remove')
    @mock.patch('cgtsclient.v1.label.KubernetesLabelManager.list')
    @mock.patch('cgtsclient.v1.ihost._find_ihost')
    def test_host_label_remove(self,
                               mock_find_ihost,
                               mock_label_list,
                               mock_label_remove):
        mock_find_ihost.return_value = ihost(None, FAKE_HOST_CONTROLLER_0, True)
        mock_label_list.return_value = [
            KubernetesLabel(None, FAKE_HOST_LABEL_1, True),
            KubernetesLabel(None, FAKE_HOST_LABEL_2, True),
        ]
        hostname = 'controller-0'
        key1 = FAKE_HOST_LABEL_1['label_key']
        key2 = FAKE_HOST_LABEL_2['label_key']
        self.shell(f"host-label-remove {hostname} {key1} {key2}")

        label1_uuid = FAKE_HOST_LABEL_1['uuid']
        label2_uuid = FAKE_HOST_LABEL_2['uuid']
        mock_label_remove.assert_has_calls(
            [
                mock.call(label1_uuid),
                mock.call(label2_uuid),
            ]
        )

    @mock.patch('cgtsclient.v1.ihost.ihostManager.list')
    def test_host_label_remove_host_not_found(self, mock_ihost_list):
        mock_ihost_list.return_value = [
            ihost(None, FAKE_HOST_CONTROLLER_0, True)
        ]
        hostname = "controller-1"
        exception_str = f'host not found: {hostname}'
        with ExpectedException(exc.CommandError, exception_str):
            self.shell(f"host-label-remove {hostname} key1")

    @mock.patch('cgtsclient.v1.label.KubernetesLabelManager.remove')
    @mock.patch('cgtsclient.v1.label.KubernetesLabelManager.list')
    @mock.patch('cgtsclient.v1.ihost._find_ihost')
    def test_host_label_remove_label_not_found(self,
                                               mock_find_ihost,
                                               mock_label_list,
                                               mock_label_remove):
        mock_find_ihost.return_value = ihost(None, FAKE_HOST_CONTROLLER_0, True)
        mock_label_list.return_value = [
            KubernetesLabel(None, FAKE_HOST_LABEL_1, True),
            KubernetesLabel(None, FAKE_HOST_LABEL_2, True),
        ]
        hostname = "controller-0"
        self.shell(f"host-label-remove {hostname} unknownkey")

        mock_label_remove.assert_not_called()
