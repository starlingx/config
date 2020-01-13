# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
import platform
from six.moves import http_client
from sysinv.common import constants
from sysinv.db import api as dbapi
from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils

if platform.python_version().startswith('2.7'):
    from urllib import urlencode
else:
    from urllib.parse import urlencode

HEADER = {'User-Agent': 'sysinv'}
es_labels = {'elastic-data': 'enabled',
                'elastic-controller': 'enabled',
                'elastic-client': 'enabled',
                'elastic-master': 'enabled', }

es_worker_labels = {'elastic-master': 'enabled'}
es_invalid_worker_labels = {'elastic-master': 'mandalorian'}


def mock_helm_override_get(dbapi, app_name, chart_name, namespace):
    return True


class LabelTestCase(base.FunctionalTest):
    def setUp(self):
        super(LabelTestCase, self).setUp()
        self.dbapi = dbapi.get_instance()
        self.system = dbutils.create_test_isystem()
        self.load = dbutils.create_test_load()

    def _get_path(self, host=None, params=None):
        if host:
            path = '/labels/' + host
        else:
            path = '/labels'

        if params:
            path += '?' + urlencode(params)
        return path

    def validate_labels(self, input_data, response_data):
        self.assertEqual(len(input_data), len(response_data))
        for label in response_data:
            label_key = label["label_key"]
            label_value = label["label_value"]
            self.assertIn(label_key, input_data.keys())
            self.assertEqual(label_value, input_data[label_key])

    def assign_labels(self, host_uuid, input_data, parameters=None):
        response = self.post_json('%s' % self._get_path(host_uuid, parameters), input_data)
        self.assertEqual(http_client.OK, response.status_int)
        return response

    def assign_labels_failure(self, host_uuid, input_data, parameters=None):
        response = self.post_json('%s' % self._get_path(host_uuid, parameters), input_data, expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json['error_message'])

    def get_host_labels(self, host_uuid):
        response = self.get_json("/ihosts/%s/labels" % host_uuid)
        return response['labels']


class LabelAssignTestCase(LabelTestCase):
    def setUp(self):
        super(LabelAssignTestCase, self).setUp()
        self.controller = dbutils.create_test_ihost(
            id='1',
            uuid=None,
            forisystemid=self.system.id,
            hostname='controller-0',
            personality=constants.CONTROLLER,
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED
        )
        self.worker = dbutils.create_test_ihost(
            id='2',
            uuid=None,
            forisystemid=self.system.id,
            hostname='worker-1',
            personality=constants.WORKER,
            subfunctions=constants.WORKER,
            mgmt_mac='01:02:03:04:05:C5',
            mgmt_ip='192.168.24.14',
            invprovision=constants.PROVISIONED,
        )

    generic_labels = {
        'apps': 'enabled',
        'foo': 'bar'
    }

    def test_create_labels(self):
        host_uuid = self.worker.uuid
        input_data = self.generic_labels
        self.assign_labels(host_uuid, input_data)
        response_data = self.get_host_labels(host_uuid)
        self.validate_labels(input_data, response_data)

    def test_overwrite_labels_success(self):
        host_uuid = self.worker.uuid
        input_data = self.generic_labels
        self.assign_labels(host_uuid, input_data)

        new_input_values = {
            'apps': 'disabled',
            'foo': 'free'
        }
        self.assign_labels(host_uuid, new_input_values, parameters={'overwrite': True})
        response_data = self.get_host_labels(host_uuid)
        self.validate_labels(new_input_values, response_data)

    def test_overwrite_labels_failure(self):
        host_uuid = self.worker.uuid
        input_data = self.generic_labels
        self.assign_labels(host_uuid, input_data)

        new_input_values = {
            'apps': 'disabled',
            'foo': 'free'
        }
        # Default value should be overwrite=False
        self.assign_labels_failure(host_uuid, new_input_values)
        # Test explicit overwrite=False
        self.assign_labels_failure(host_uuid, new_input_values, parameters={'overwrite': False})

        # Labels should be unchanged from initial values
        response_data = self.get_host_labels(host_uuid)
        self.validate_labels(input_data, response_data)

    def test_create_validated_labels_success(self):
        host_uuid = self.worker.uuid
        cpu_mgr_label = {
            'kube-cpu-mgr-policy': 'static',
        }
        self.assign_labels(host_uuid, cpu_mgr_label)
        topology_mgr_label = {
            'kube-topology-mgr-policy': 'restricted',
        }
        self.assign_labels(host_uuid, topology_mgr_label)

        input_data = {}
        for input_label in [cpu_mgr_label, topology_mgr_label]:
            input_data.update(input_label)

        response_data = self.get_host_labels(host_uuid)
        self.validate_labels(input_data, response_data)

    def test_create_validated_labels_failure(self):
        host_uuid = self.worker.uuid
        cpu_mgr_label = {
            'kube-cpu-mgr-policy': 'invalid',
        }
        self.assign_labels_failure(host_uuid, cpu_mgr_label)
        topology_mgr_label = {
            'kube-topology-mgr-policy': 'invalid',
        }
        self.assign_labels_failure(host_uuid, topology_mgr_label)

    def mock_get_system_enabled_k8s_plugins_return_plugins():
        return {"intel-gpu-plugin": "intelgpu=enabled",
                "intel-qat-plugin": "intelqat=enabled"}

    def mock_get_system_enabled_k8s_plugins_return_none():
        return None

    @mock.patch('sysinv.api.controllers.v1.label._get_system_enabled_k8s_plugins',
                mock_get_system_enabled_k8s_plugins_return_plugins)
    def test_create_plugin_labels_on_supported_node(self):
        dbutils.create_test_pci_devices(
            host_id=self.worker.id,
            pclass='VGA compatible controller',
            driver='i915',)

        test_plugin_label = {'intelgpu': 'enabled', }
        self.assign_labels(self.worker.uuid, test_plugin_label)

        response_data = self.get_host_labels(self.worker.uuid)
        self.validate_labels(test_plugin_label, response_data)

    @mock.patch('sysinv.api.controllers.v1.label._get_system_enabled_k8s_plugins',
                mock_get_system_enabled_k8s_plugins_return_plugins)
    def test_create_plugin_labels_on_unsupported_node(self):
        dbutils.create_test_pci_devices(
            host_id=self.worker.id,
            pclass='VGA compatible controller',
            driver='',)
        test_plugin_label = {'intelgpu': 'enabled', }
        self.assign_labels_failure(self.worker.uuid, test_plugin_label)

    @mock.patch('sysinv.api.controllers.v1.label._get_system_enabled_k8s_plugins',
                mock_get_system_enabled_k8s_plugins_return_none)
    def test_create_plugin_labels_on_non_plugin_system(self):
        test_plugin_label = {'intelgpu': 'enabled', }

        self.assign_labels(self.worker.uuid, test_plugin_label)

        response_data = self.get_host_labels(self.worker.uuid)
        self.validate_labels(test_plugin_label, response_data)


@mock.patch('sysinv.common.utils.is_chart_enabled', mock_helm_override_get)
class StxAppLabelsTest(LabelTestCase):
    def setUp(self):
        super(StxAppLabelsTest, self).setUp()
        dbutils.create_test_app(name="stx-monitor", status="uploaded", progress="completed")
        self.controller = dbutils.create_test_ihost(
            id='1',
            uuid=None,
            forisystemid=self.system.id,
            hostname='controller-0',
            personality=constants.CONTROLLER,
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED
        )
        self.controller1 = dbutils.create_test_ihost(
            id='2',
            uuid=None,
            forisystemid=self.system.id,
            hostname='controller-1',
            personality=constants.CONTROLLER,
            subfunctions=constants.CONTROLLER,
            mgmt_mac='01:02:03:04:05:C1',
            mgmt_ip='192.168.24.13',
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED
        )
        self.worker = dbutils.create_test_ihost(
            id='3',
            uuid=None,
            forisystemid=self.system.id,
            hostname='worker-0',
            personality=constants.WORKER,
            subfunctions=constants.WORKER,
            mgmt_mac='01:02:03:04:05:C5',
            mgmt_ip='192.168.24.14',
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED
        )

    def test_apply_stx_app_with_missing_labels(self):
        response = self.patch_json('/apps/stx-monitor?directive=apply',
                        {'values': {}},
                        headers={'User-Agent': 'sysinv-test'}, expect_errors=True)
        self.assertIn("system host-label-assign controller-0 elastic-data=enabled",
                response.json['error_message'])
        self.assertIn("system host-label-assign controller-1 elastic-data=enabled",
                response.json['error_message'])
        self.assertIn("Please use [system host-label-assign <worker hostname> elastic-master=enabled]",
                response.json['error_message'])

    def test_apply_stx_app_with_missing_worker_labels(self):
        self.assign_labels(self.controller.uuid, es_labels)
        response_data_controller0 = self.get_host_labels(self.controller.uuid)
        self.validate_labels(es_labels, response_data_controller0)

        self.assign_labels(self.controller1.uuid, es_labels)
        response_data_controller1 = self.get_host_labels(self.controller1.uuid)
        self.validate_labels(es_labels, response_data_controller1)

        response = self.patch_json('/apps/stx-monitor?directive=apply',
                        {'values': {}},
                        headers={'User-Agent': 'sysinv-test'}, expect_errors=True)

        self.assertIn("Please use [system host-label-assign <worker hostname> elastic-master=enabled]",
                response.json['error_message'])
        self.assertNotIn("system host-label-assign controller-0 elastic-data=enabled", response.json['error_message'])
        self.assertNotIn("system host-label-assign controller-1 elastic-data=enabled", response.json['error_message'])

    def test_apply_stx_app_with_missing_controller0_labels(self):
        self.assign_labels(self.worker.uuid, es_worker_labels)
        response_data_worker = self.get_host_labels(self.worker.uuid)
        self.validate_labels(es_worker_labels, response_data_worker)

        self.assign_labels(self.controller1.uuid, es_labels)
        response_data_controller1 = self.get_host_labels(self.controller1.uuid)
        self.validate_labels(es_labels, response_data_controller1)

        response = self.patch_json('/apps/stx-monitor?directive=apply',
                        {'values': {}},
                        headers={'User-Agent': 'sysinv-test'}, expect_errors=True)

        self.assertIn("system host-label-assign controller-0 elastic-data=enabled", response.json['error_message'])
        self.assertNotIn("Please use [system host-label-assign <worker hostname> elastic-master=enabled]",
                response.json['error_message'])
        self.assertNotIn("system host-label-assign controller-1 elastic-data=enabled", response.json['error_message'])

    def test_apply_stx_app_with_invalid_worker_labels(self):
        self.assign_labels(self.controller.uuid, es_labels)
        response_data_controller0 = self.get_host_labels(self.controller.uuid)
        self.validate_labels(es_labels, response_data_controller0)

        self.assign_labels(self.controller1.uuid, es_labels)
        response_data_controller1 = self.get_host_labels(self.controller1.uuid)
        self.validate_labels(es_labels, response_data_controller1)

        self.assign_labels(self.worker.uuid, es_invalid_worker_labels)
        response_data_worker = self.get_host_labels(self.worker.uuid)
        self.validate_labels(es_invalid_worker_labels, response_data_worker)

        response = self.patch_json('/apps/stx-monitor?directive=apply',
                        {'values': {}},
                        headers={'User-Agent': 'sysinv-test'}, expect_errors=True)
        self.assertIn("Please use [system host-label-assign <worker hostname> elastic-master=enabled]",
                response.json['error_message'])
        self.assertIn("Please correct host labels values to be enabled [worker-0 elastic-master=",
                response.json['error_message'])
        self.assertNotIn("system host-label-assign controller-0 elastic-data=enabled", response.json['error_message'])
        self.assertNotIn("system host-label-assign controller-1 elastic-data=enabled", response.json['error_message'])

    def test_apply_stx_app_with_required_labels(self):
        self.assign_labels(self.worker.uuid, es_labels)
        response_data_worker = self.get_host_labels(self.worker.uuid)
        self.validate_labels(es_labels, response_data_worker)

        self.assign_labels(self.controller.uuid, es_labels)
        response_data_controller0 = self.get_host_labels(self.controller.uuid)
        self.validate_labels(es_labels, response_data_controller0)

        self.assign_labels(self.controller1.uuid, es_labels)
        response_data_controller1 = self.get_host_labels(self.controller1.uuid)
        self.validate_labels(es_labels, response_data_controller1)

        response = self.patch_json('/apps/stx-monitor?directive=apply',
                        {'values': {}},
                        headers={'User-Agent': 'sysinv-test'}, expect_errors=True)
        self.assertIn("applying", response.json['status'])
