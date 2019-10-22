# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from six.moves import http_client

from sysinv.common import constants
from sysinv.db import api as dbapi
from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils

HEADER = {'User-Agent': 'sysinv'}


class LabelTestCase(base.FunctionalTest):

    def setUp(self):
        super(LabelTestCase, self).setUp()
        self.dbapi = dbapi.get_instance()
        self.system = dbutils.create_test_isystem()
        self.load = dbutils.create_test_load()
        self.controller = dbutils.create_test_ihost(
            id='1',
            uuid=None,
            forisystemid=self.system.id,
            hostname='controller-0',
            personality=constants.CONTROLLER,
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
        )
        self.worker = dbutils.create_test_ihost(
            id='2',
            uuid=None,
            forisystemid=self.system.id,
            hostname='worker-0',
            personality=constants.WORKER,
            subfunctions=constants.WORKER,
            mgmt_mac='01:02.03.04.05.C0',
            mgmt_ip='192.168.24.12',
            invprovision=constants.PROVISIONED,
        )

    def _get_path(self, path=None):
        if path:
            return '/labels/' + path
        else:
            return '/labels'


class LabelAssignTestCase(LabelTestCase):
    def setUp(self):
        super(LabelAssignTestCase, self).setUp()

    def test_create_validated_labels_success(self):
        host_uuid = self.worker.uuid
        cpu_mgr_label = {
            'kube-cpu-mgr-policy': 'static',
        }
        response = self.post_json('%s' % self._get_path(host_uuid), cpu_mgr_label)
        self.assertEqual(http_client.OK, response.status_int)
        topology_mgr_label = {
            'kube-topology-mgr-policy': 'restricted',
        }
        response = self.post_json('%s' % self._get_path(host_uuid), topology_mgr_label)
        self.assertEqual(http_client.OK, response.status_int)

        response = self.get_json("/ihosts/%s/labels" % host_uuid)
        labels = response['labels']
        self.assertEqual(2, len(labels))
        input_data = {}
        for input_label in [cpu_mgr_label, topology_mgr_label]:
            input_data.update(input_label)
        for label in labels:
            label_key = label["label_key"]
            label_value = label["label_value"]
            self.assertIn(label_key, input_data.keys())
            self.assertEqual(label_value, input_data[label_key])

    def test_create_validated_labels_failure(self):
        host_uuid = self.worker.uuid
        cpu_mgr_label = {
            'kube-cpu-mgr-policy': 'invalid',
        }
        response = self.post_json('%s' % self._get_path(host_uuid), cpu_mgr_label, expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json['error_message'])
        topology_mgr_label = {
            'kube-topology-mgr-policy': 'invalid',
        }
        response = self.post_json('%s' % self._get_path(host_uuid), topology_mgr_label, expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json['error_message'])
