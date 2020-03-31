# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
from six.moves import http_client
from six.moves.urllib.parse import urlencode

from sysinv.db import api as dbapi
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class DeviceLabelTestCase(base.FunctionalTest, dbbase.ControllerHostTestCase):
    def setUp(self):
        super(DeviceLabelTestCase, self).setUp()
        self.dbapi = dbapi.get_instance()
        # Create a pci_device and fpga_device object
        self.pci_device = dbutils.create_test_pci_devices(
            host_id=self.host.id,
            pclass='Processing accelerators',
            pclass_id='120000',)
        self.fpga_device = dbutils.create_test_fpga_device(
            host_id=self.host.id,
            pci_id=self.pci_device.id)
        self.generic_labels = {
            'pcidevice_uuid': self.pci_device.uuid,
            'key1': 'value1',
            'key2': 'value2'
        }

    def _get_path(self, params=None):
        path = '/device_labels'

        if params:
            path += '?' + urlencode(params)
        return path

    def validate_labels(self, input_data, response_data):
        for t in response_data:
            for k, v in t.items():
                if k in input_data.keys():
                    self.assertEqual(v, input_data[k])

    def assign_labels(self, input_data, parameters=None):
        response = self.post_json('%s' % self._get_path(parameters), input_data)
        self.assertEqual(http_client.OK, response.status_int)
        return response

    def assign_labels_failure(self, input_data, parameters=None):
        response = self.post_json('%s' % self._get_path(parameters), input_data,
                                  expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json['error_message'])

    def get_device_labels(self):
        response = self.get_json("/device_labels")
        return response['device_labels']


class DeviceLabelAssignTestCase(DeviceLabelTestCase):
    def setUp(self):
        super(DeviceLabelAssignTestCase, self).setUp()

    def test_create_device_labels(self):
        self.assign_labels(self.generic_labels)
        response_data = self.get_device_labels()
        self.validate_labels(self.generic_labels, response_data)

    def test_overwrite_device_labels_success(self):
        self.assign_labels(self.generic_labels)

        new_input_values = {
            'pcidevice_uuid': self.pci_device.uuid,
            'key1': 'string1',
            'key2': 'string2'
        }
        self.assign_labels(new_input_values, parameters={'overwrite': True})
        response_data = self.get_device_labels()
        self.validate_labels(new_input_values, response_data)

    def test_overwrite_device_labels_failure(self):
        self.assign_labels(self.generic_labels)

        new_input_values = {
            'pcidevice_uuid': self.pci_device.uuid,
            'key1': 'string1',
            'key2': 'string2'
        }
        # Default value should be overwrite=False
        self.assign_labels_failure(new_input_values)
        # Test explicit overwrite=False
        self.assign_labels_failure(new_input_values, parameters={'overwrite': False})

        # Labels should be unchanged from initial values
        response_data = self.get_device_labels()
        self.validate_labels(self.generic_labels, response_data)

    def test_create_validated_device_labels_success(self):
        label1 = {
            'pcidevice_uuid': self.pci_device.uuid,
            'key1': 'value1',
        }
        self.assign_labels(label1)
        label2 = {
            'pcidevice_uuid': self.pci_device.uuid,
            'key2': 'value2',
        }
        self.assign_labels(label2)

        input_data = {}
        for input_label in [label1, label2]:
            input_data.update(input_label)

        response_data = self.get_device_labels()
        self.validate_labels(input_data, response_data)


class DeviceLabelRemoveTestCase(DeviceLabelTestCase):
    def setUp(self):
        super(DeviceLabelRemoveTestCase, self).setUp()

    def test_remove_device_labels(self):
        # Assign labels to a device
        response = self.assign_labels(self.generic_labels)
        resp = json.loads(response.body)
        self.assertIn('device_labels', resp)
        resp_dict = resp.get('device_labels')
        uuid = resp_dict[0]['uuid']

        # Remove a label from the device
        self.delete('/device_labels/%s' % uuid,
                    headers={'User-Agent': 'sysinv-test'})

        # Verify the device label no longer exists
        response = self.get_json('/device_labels/%s' % uuid,
                                 expect_errors=True)
        self.assertEqual(response.status_int, http_client.BAD_REQUEST)
        self.assertEqual(response.content_type, 'application/json')
        self.assertTrue(response.json['error_message'])
