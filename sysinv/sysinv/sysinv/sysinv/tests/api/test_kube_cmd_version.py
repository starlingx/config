#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from six.moves import http_client
from sysinv.tests.api import base
from sysinv.common import kubernetes


class TestKubeCmdVersion(base.FunctionalTest):
    API_HEADERS = {'User-Agent': 'sysinv-test'}
    API_PREFIX = '/kube_cmd_versions'
    expected_api_fields = ['kubeadm_version',
                           'kubelet_version']

    def setUp(self):
        super(TestKubeCmdVersion, self).setUp()

    def assert_fields(self, api_object):
        # Verify that expected attributes are returned
        for field in self.expected_api_fields:
            self.assertIn(field, api_object)

    def test_show_kube_cmd_version_success(self):
        response = self.get_json(self.API_PREFIX,
                                 headers=self.API_HEADERS)
        self.assert_fields(response)
        self.assertEqual(response['kubeadm_version'],
                         kubernetes.K8S_INITIAL_CMD_VERSION)
        self.assertEqual(response['kubelet_version'],
                         kubernetes.K8S_INITIAL_CMD_VERSION)

    def test_patch_kube_cmd_version_success(self):
        values = {
            'kubeadm_version': '1.5.1',
            'kubelet_version': '1.5.2'
        }
        response = self.patch_dict_json(self.API_PREFIX,
                                        headers=self.API_HEADERS,
                                        **values)
        self.assertEqual(http_client.OK, response.status_int)
        self.assert_fields(response.json)
        for k in values:
            self.assertEqual(values[k], response.json[k])
        get_response = self.get_json(self.API_PREFIX,
                                     headers=self.API_HEADERS)
        for k in values:
            self.assertEqual(values[k], get_response[k])

    def test_patch_kube_cmd_version_failure(self):
        wrong_value = {
            'kube_version': '1.5.1'
        }
        response = self.patch_dict_json(self.API_PREFIX,
                                        headers=self.API_HEADERS,
                                        expect_errors=True,
                                        **wrong_value)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json.get('error_message'))
