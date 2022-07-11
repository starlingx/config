#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /device_images/ methods.
"""

import json
import mock
import os
from oslo_utils import uuidutils
from six.moves import http_client

from sysinv.common import constants
from sysinv.common import device as dconstants
from sysinv.fpga_agent import constants as fpga_constants
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class FakeConductorAPI(object):

    def __init__(self):
        self.store_bitstream_file = mock.MagicMock()
        self.delete_bitstream_file = mock.MagicMock()
        self.apply_device_image = mock.MagicMock()
        self.clear_device_image_alarm = mock.MagicMock()


class TestDeviceImage(base.FunctionalTest, dbbase.BaseHostTestCase):
    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/device_images'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'device_images'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['id',
                           'uuid',
                           'bitstream_type',
                           'pci_vendor',
                           'pci_device',
                           'bitstream_id',
                           'key_signature',
                           'revoke_key_id',
                           ]

    # hidden_api_fields are attributes that should not be populated by
    # an API query
    hidden_api_fields = ['']

    def setUp(self):
        super(TestDeviceImage, self).setUp()

        # Mock the Conductor API
        self.fake_conductor_api = FakeConductorAPI()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

    def get_single_url(self, uuid):
        return '%s/%s' % (self.API_PREFIX, uuid)


class TestListDeviceImage(TestDeviceImage):
    def setUp(self):
        super(TestListDeviceImage, self).setUp()

    def test_one(self):
        device_image = dbutils.create_test_device_image(
            bitstream_type=dconstants.BITSTREAM_TYPE_FUNCTIONAL,
            pci_vendor='80ee',
            pci_device='beef',
            bitstream_id='12345',
        )
        result = self.get_json('/device_images/%s' % device_image['uuid'])

        # Verify that the upgrade has the expected attributes
        self.assertEqual(result['bitstream_type'],
                         dconstants.BITSTREAM_TYPE_FUNCTIONAL)
        self.assertEqual(result['pci_vendor'], '80ee')
        self.assertEqual(result['pci_device'], 'beef')
        self.assertEqual(result['bitstream_id'], '12345')

    def test_list_all(self):
        dbutils.create_test_device_image(
            bitstream_type=dconstants.BITSTREAM_TYPE_FUNCTIONAL,
            pci_vendor='80ee',
            pci_device='beef',
            bitstream_id='12345',
        )
        data = self.get_json('/device_images')
        self.assertEqual(1, len(data['device_images']))
        self.assertEqual(data['device_images'][0]['bitstream_type'],
                         dconstants.BITSTREAM_TYPE_FUNCTIONAL)
        self.assertEqual(data['device_images'][0]['pci_vendor'], '80ee')
        self.assertEqual(data['device_images'][0]['pci_device'], 'beef')
        self.assertEqual(data['device_images'][0]['bitstream_id'], '12345')


class TestPostDeviceImage(TestDeviceImage, dbbase.ControllerHostTestCase):

    def test_create_functional_image(self):
        # Test creation of device image
        bitstream_file = os.path.join(os.path.dirname(__file__), "data",
                                'bitstream.bit')
        data = {
            'bitstream_type': dconstants.BITSTREAM_TYPE_FUNCTIONAL,
            'pci_vendor': fpga_constants.N3000_VENDOR,
            'pci_device': fpga_constants.N3000_DEVICE,
            'bitstream_id': '12345',
        }
        upload_file = [('file', bitstream_file)]
        result = None
        open_mock = mock.Mock()
        fd_mock = mock.mock_open()
        with mock.patch('os.open', open_mock), mock.patch.object(
                os, 'fdopen', fd_mock):
            result = self.post_with_files('/device_images',
                                          data,
                                          upload_files=upload_file,
                                          headers=self.API_HEADERS,
                                          expect_errors=False)
        self.assertEqual(result.status_code, http_client.OK)

        # Verify that the images were downloaded
        self.fake_conductor_api.store_bitstream_file.\
            assert_called_with(mock.ANY, mock.ANY)

        resp = json.loads(result.body)
        self.assertIn('device_image', resp)
        resp_dict = resp.get('device_image')
        # Verify that the device image has the expected attributes
        self.assertEqual(resp_dict['bitstream_type'],
                         dconstants.BITSTREAM_TYPE_FUNCTIONAL)
        self.assertEqual(resp_dict['pci_vendor'], fpga_constants.N3000_VENDOR)
        self.assertEqual(resp_dict['pci_device'], fpga_constants.N3000_DEVICE)
        self.assertEqual(resp_dict['bitstream_id'], '12345')

    def test_create_root_key_image(self):
        # Test creation of device image
        bitstream_file = os.path.join(os.path.dirname(__file__), "data",
                                'bitstream.bit')
        data = {
            'bitstream_type': dconstants.BITSTREAM_TYPE_ROOT_KEY,
            'pci_vendor': fpga_constants.N3000_VENDOR,
            'pci_device': fpga_constants.N3000_DEVICE,
            'key_signature': '12345',
        }
        upload_file = [('file', bitstream_file)]
        result = None
        open_mock = mock.Mock()
        fd_mock = mock.mock_open()
        with mock.patch('os.open', open_mock), mock.patch.object(
                os, 'fdopen', fd_mock):
            result = self.post_with_files('/device_images',
                                          data,
                                          upload_files=upload_file,
                                          headers=self.API_HEADERS,
                                          expect_errors=False)
        self.assertEqual(result.status_code, http_client.OK)

        # Verify that the images were downloaded
        self.fake_conductor_api.store_bitstream_file.\
            assert_called_with(mock.ANY, mock.ANY)

        resp = json.loads(result.body)
        self.assertIn('device_image', resp)
        resp_dict = resp.get('device_image')
        # Verify that the device image has the expected attributes
        self.assertEqual(resp_dict['bitstream_type'],
                         dconstants.BITSTREAM_TYPE_ROOT_KEY)
        self.assertEqual(resp_dict['pci_vendor'], fpga_constants.N3000_VENDOR)
        self.assertEqual(resp_dict['pci_device'], fpga_constants.N3000_DEVICE)
        self.assertEqual(resp_dict['key_signature'], '12345')

    def test_create_revoke_key_image(self):
        # Test creation of device image
        bitstream_file = os.path.join(os.path.dirname(__file__), "data",
                                'bitstream.bit')
        data = {
            'bitstream_type': dconstants.BITSTREAM_TYPE_KEY_REVOCATION,
            'pci_vendor': fpga_constants.N3000_VENDOR,
            'pci_device': fpga_constants.N3000_DEVICE,
            'revoke_key_id': 12345,
        }
        upload_file = [('file', bitstream_file)]
        # mocking the os.open and os.fdopen calls
        # these mock entries must be scoped to the POST operaion
        result = None
        open_mock = mock.Mock()
        fd_mock = mock.mock_open()
        with mock.patch('os.open', open_mock), mock.patch.object(
                os, 'fdopen', fd_mock):
            result = self.post_with_files('/device_images',
                                          data,
                                          upload_files=upload_file,
                                          headers=self.API_HEADERS,
                                          expect_errors=False)
        self.assertEqual(result.status_code, http_client.OK)

        # Verify that the images were downloaded
        self.fake_conductor_api.store_bitstream_file.\
            assert_called_with(mock.ANY, mock.ANY)

        resp = json.loads(result.body)
        self.assertIn('device_image', resp)
        resp_dict = resp.get('device_image')
        # Verify that the device image has the expected attributes
        self.assertEqual(resp_dict['bitstream_type'],
                         dconstants.BITSTREAM_TYPE_KEY_REVOCATION)
        self.assertEqual(resp_dict['pci_vendor'], fpga_constants.N3000_VENDOR)
        self.assertEqual(resp_dict['pci_device'], fpga_constants.N3000_DEVICE)
        self.assertEqual(resp_dict['revoke_key_id'], 12345)

    def test_create_functional_image_failure(self):
        # Test creation of device image
        bitstream_file = os.path.join(os.path.dirname(__file__), "data",
                                'bitstream.bit')
        data = {
            'bitstream_type': dconstants.BITSTREAM_TYPE_FUNCTIONAL,
            'pci_vendor': fpga_constants.N3000_VENDOR,
            'pci_device': fpga_constants.N3000_DEVICE,
            'revoke_key_id': '12345',
        }
        upload_file = [('file', bitstream_file)]
        result = self.post_with_files('/device_images', data,
                                      upload_files=upload_file,
                                      headers=self.API_HEADERS,
                                      expect_errors=True)
        self.assertIn("bitstream_id is required for functional bitstream type",
                      str(result))

    def test_create_root_key_image_failure(self):
        # Test creation of device image
        bitstream_file = os.path.join(os.path.dirname(__file__), "data",
                                'bitstream.bit')
        data = {
            'bitstream_type': dconstants.BITSTREAM_TYPE_ROOT_KEY,
            'pci_vendor': fpga_constants.N3000_VENDOR,
            'pci_device': fpga_constants.N3000_DEVICE,
            'revoke_key_id': '12345',
        }
        upload_file = [('file', bitstream_file)]
        result = self.post_with_files('/device_images', data,
                                      upload_files=upload_file,
                                      headers=self.API_HEADERS,
                                      expect_errors=True)
        self.assertIn("key_signature is required for root key bitstream type",
                      str(result))

    def test_create_revoke_key_image_failure(self):
        # Test creation of device image
        bitstream_file = os.path.join(os.path.dirname(__file__), "data",
                                'bitstream.bit')
        data = {
            'bitstream_type': dconstants.BITSTREAM_TYPE_KEY_REVOCATION,
            'pci_vendor': fpga_constants.N3000_VENDOR,
            'pci_device': fpga_constants.N3000_DEVICE,
            'bitstream_id': '12345',
        }
        upload_file = [('file', bitstream_file)]
        result = self.post_with_files('/device_images', data,
                                      upload_files=upload_file,
                                      headers=self.API_HEADERS,
                                      expect_errors=True)
        self.assertIn("revoke_key_id is required for key revocation bitstream"
                      " type", str(result))

    def test_create_non_functional_image_with_retimer(self):
        # Test creation of device image
        bitstream_file = os.path.join(os.path.dirname(__file__), "data",
                                'bitstream.bit')
        data = {
            'bitstream_type': dconstants.BITSTREAM_TYPE_KEY_REVOCATION,
            'pci_vendor': fpga_constants.N3000_VENDOR,
            'pci_device': fpga_constants.N3000_DEVICE,
            'revoke_key_id': '12345',
            'retimer_included': True,
        }
        upload_file = [('file', bitstream_file)]
        result = self.post_with_files('/device_images', data,
                                      upload_files=upload_file,
                                      headers=self.API_HEADERS,
                                      expect_errors=True)
        self.assertIn("retimer_included option is only applicable to"
                      " functional BMC image", str(result))

    def test_create_functional_image_non_bmc_with_retimer(self):
        # Test creation of device image
        bitstream_file = os.path.join(os.path.dirname(__file__), "data",
                                'bitstream.bit')
        data = {
            'bitstream_type': dconstants.BITSTREAM_TYPE_ROOT_KEY,
            'pci_vendor': fpga_constants.N3000_VENDOR,
            'pci_device': fpga_constants.N3000_DEVICE,
            'key_signature': '12345',
            'bmc': True,
        }
        upload_file = [('file', bitstream_file)]
        result = self.post_with_files('/device_images', data,
                                      upload_files=upload_file,
                                      headers=self.API_HEADERS,
                                      expect_errors=True)
        self.assertIn("bmc option is only applicable to"
                      " functional image", str(result))

    def test_create_bmc_and_retimer_strtobool_conversion(self):
        # Test creation of device image
        bitstream_file = os.path.join(os.path.dirname(__file__), "data",
                                'bitstream.bit')
        data = {
            'bitstream_type': dconstants.BITSTREAM_TYPE_FUNCTIONAL,
            'pci_vendor': fpga_constants.N3000_VENDOR,
            'pci_device': fpga_constants.N3000_DEVICE,
            'bitstream_id': '12345',
            'bmc': 'True',
            'retimer_included': 'True',
        }
        upload_file = [('file', bitstream_file)]
        result = None
        open_mock = mock.Mock()
        fd_mock = mock.mock_open()
        with mock.patch('os.open', open_mock), mock.patch.object(
                os, 'fdopen', fd_mock):
            result = self.post_with_files('/device_images',
                                          data,
                                          upload_files=upload_file,
                                          headers=self.API_HEADERS,
                                          expect_errors=False)
        self.assertEqual(result.status_code, http_client.OK)

        # Verify that the images were downloaded
        self.fake_conductor_api.store_bitstream_file.\
            assert_called_with(mock.ANY, mock.ANY)

        resp = json.loads(result.body)
        self.assertIn('device_image', resp)
        resp_dict = resp.get('device_image')
        # Verify that the device image has the expected attributes
        self.assertEqual(resp_dict['bitstream_type'],
                         dconstants.BITSTREAM_TYPE_FUNCTIONAL)
        self.assertEqual(resp_dict['pci_vendor'], fpga_constants.N3000_VENDOR)
        self.assertEqual(resp_dict['pci_device'], fpga_constants.N3000_DEVICE)
        self.assertEqual(resp_dict['bitstream_id'], '12345')
        self.assertEqual(resp_dict['bmc'], True)
        self.assertEqual(resp_dict['retimer_included'], True)

    def test_create_bitstream_type_invalid(self):
        # Test creation of device image
        bitstream_file = os.path.join(os.path.dirname(__file__), "data",
                                'bitstream.bit')
        data = {
            'bitstream_type': 'wrong_type',
            'pci_vendor': fpga_constants.N3000_VENDOR,
            'pci_device': fpga_constants.N3000_DEVICE,
            'bitstream_id': '12345',
        }
        upload_file = [('file', bitstream_file)]
        result = self.post_with_files('/device_images', data,
                                      upload_files=upload_file,
                                      headers=self.API_HEADERS,
                                      expect_errors=True)
        self.assertIn("Bitstream type wrong_type not supported", str(result))

    def test_create_pci_vendor_device_invalid(self):
        # Test creation of device image
        bitstream_file = os.path.join(os.path.dirname(__file__), "data",
                                'bitstream.bit')
        data = {
            'bitstream_type': dconstants.BITSTREAM_TYPE_FUNCTIONAL,
            'pci_vendor': '80ee',
            'pci_device': 'beef',
            'bitstream_id': '12345',
        }
        upload_file = [('file', bitstream_file)]
        result = self.post_with_files('/device_images', data,
                                      upload_files=upload_file,
                                      headers=self.API_HEADERS,
                                      expect_errors=True)
        self.assertIn("Supported vendor ID", str(result))


class TestPatch(TestDeviceImage):
    def setUp(self):
        super(TestPatch, self).setUp()
        self.controller = dbutils.create_test_ihost(
            id='1',
            uuid=None,
            forisystemid=self.system.id,
            hostname='controller-0',
            personality=constants.CONTROLLER,
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED
        )
        # Create a pci_device and fpga_device object
        self.pci_device = dbutils.create_test_pci_device(
            host_id=self.controller.id,
            pclass='Processing accelerators',
            pclass_id='120000',)
        self.fpga_device = dbutils.create_test_fpga_device(
            host_id=self.controller.id,
            pci_id=self.pci_device.id)

        # Create a device image
        self.device_image = dbutils.create_test_device_image(
            bitstream_type=dconstants.BITSTREAM_TYPE_FUNCTIONAL,
            pci_vendor='80ee',
            pci_device='beef',
            bitstream_id='12345')
        self.device_image2 = dbutils.create_test_device_image(
            bitstream_type=dconstants.BITSTREAM_TYPE_FUNCTIONAL,
            pci_vendor='80ee',
            pci_device='beef',
            bitstream_id='6789')
        self.device_image_bmc = dbutils.create_test_device_image(
            bitstream_type=dconstants.BITSTREAM_TYPE_FUNCTIONAL,
            pci_vendor='80ee',
            pci_device='beef',
            bitstream_id='0x2300011001030F',
            bmc=True,
            retimer_included=False)
        self.device_image_bmc_retimer = dbutils.create_test_device_image(
            bitstream_type=dconstants.BITSTREAM_TYPE_FUNCTIONAL,
            pci_vendor='80ee',
            pci_device='beef',
            bitstream_id='0x2300011001030F',
            bmc=True,
            retimer_included=True)

    def test_device_image_apply_all_hosts(self):
        # Test applying device image to all hosts with fpga devices

        # Apply the device image
        path = '/device_images/%s?action=apply' % self.device_image.uuid
        response = self.patch_json(path, {},
                                   headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json['bitstream_type'],
                         dconstants.BITSTREAM_TYPE_FUNCTIONAL)
        self.assertEqual(response.json['pci_vendor'], '80ee')
        self.assertEqual(response.json['pci_device'], 'beef')
        self.assertEqual(response.json['bitstream_id'], '12345')

        # Verify that an entry of image to device mapping is updated
        dev_img_state = self.dbapi.device_image_state_get_by_image_device(
            self.device_image.id, self.pci_device.id)
        self.assertEqual(dconstants.DEVICE_IMAGE_UPDATE_PENDING,
                         dev_img_state.status)

    def test_device_image_apply_invalid_image(self):
        # Test applying device image with non-existing image

        # Apply the device image
        path = '/device_images/%s?action=apply' % uuidutils.generate_uuid()
        response = self.patch_json(path, {},
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertIn("image does not exist",
                      response.json['error_message'])

    def test_device_image_apply_with_label(self):
        # Test applying device image to pci devices with specified label

        # Assign label to a device
        self.post_json('/device_labels',
                       [{'pcidevice_uuid': self.pci_device.uuid},
                        {'key1': 'value1'}],
                       headers=self.API_HEADERS)

        # Apply the device image with label
        path = '/device_images/%s?action=apply' % self.device_image.uuid
        response = self.patch_json(path, [{'key1': 'value1'}],
                                   headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json['bitstream_type'],
                         dconstants.BITSTREAM_TYPE_FUNCTIONAL)
        self.assertEqual(response.json['pci_vendor'], '80ee')
        self.assertEqual(response.json['pci_device'], 'beef')
        self.assertEqual(response.json['bitstream_id'], '12345')
        self.assertEqual(response.json['applied_labels'], [{'key1': 'value1'}])

        # Verify that the image to device mapping is updated
        dev_img_state = self.dbapi.device_image_state_get_by_image_device(
            self.device_image.id, self.pci_device.id)
        self.assertEqual(dconstants.DEVICE_IMAGE_UPDATE_PENDING,
                         dev_img_state.status)

    def test_device_image_apply_with_label_without_device(self):
        # Test applying device image with label with non-existing device

        # Apply the device image
        path = '/device_images/%s?action=apply' % self.device_image.uuid
        response = self.patch_json(path, [{'key1': 'value1'}],
                                   headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

    def test_device_image_apply_overwrite_functional(self):
        # Test applying second device image with label

        # Assign label to a device
        self.post_json('/device_labels',
                       [{'pcidevice_uuid': self.pci_device.uuid},
                        {'key1': 'value1'}],
                       headers=self.API_HEADERS)

        # Apply the device image with label
        path = '/device_images/%s?action=apply' % self.device_image.uuid
        response = self.patch_json(path, [{'key1': 'value1'}],
                                   headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Apply a second functional device image with label
        path = '/device_images/%s?action=apply' % self.device_image2.uuid
        response = self.patch_json(path, [{'key1': 'value1'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that an entry of image to device mapping is updated
        dev_img_state = self.dbapi.device_image_state_get_by_image_device(
            self.device_image2.id, self.pci_device.id)
        self.assertEqual(self.device_image2.id, dev_img_state.image_id)

    def test_device_image_apply_functional_user_bmc(self):
        # Test applying second device image with label

        # Assign label to a device
        self.post_json('/device_labels',
                       [{'pcidevice_uuid': self.pci_device.uuid},
                        {'key1': 'value1'}],
                       headers=self.API_HEADERS)

        # Apply the device user image
        path = '/device_images/%s?action=apply' % self.device_image.uuid
        response = self.patch_json(path, [{'key1': 'value1'}],
                                   headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        # Verify that an entry of image to device mapping is updated
        dev_img_state = self.dbapi.device_image_state_get_by_image_device(
            self.device_image.id, self.pci_device.id)
        self.assertEqual(dconstants.DEVICE_IMAGE_UPDATE_PENDING,
                         dev_img_state.status)

        # Test 1: Apply a functional BMC device image
        path = '/device_images/%s?action=apply' % self.device_image_bmc.uuid
        response = self.patch_json(path, [{'key1': 'value1'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        # Verify that the entries for both images exist
        dev_img_state = self.dbapi.device_image_state_get_by_image_device(
            self.device_image.id, self.pci_device.id)
        self.assertEqual(self.device_image.id, dev_img_state.image_id)
        dev_img_state = self.dbapi.device_image_state_get_by_image_device(
            self.device_image_bmc.id, self.pci_device.id)
        self.assertEqual(self.device_image_bmc.id, dev_img_state.image_id)

        # Test 2: Apply a functional BMC retimer device image
        path = '/device_images/%s?action=apply' % self.device_image_bmc_retimer.uuid
        response = self.patch_json(path, [{'key1': 'value1'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        # Verify that the old bmc image is replaced with new bmc image with retimer
        state_list = self.dbapi.device_image_state_get_list()
        self.assertEqual(len(state_list), 2)
        dev_img_state = self.dbapi.device_image_state_get_by_image_device(
            self.device_image.id, self.pci_device.id)
        self.assertEqual(self.device_image.id, dev_img_state.image_id)
        dev_img_state = self.dbapi.device_image_state_get_by_image_device(
            self.device_image_bmc_retimer.id, self.pci_device.id)
        self.assertEqual(self.device_image_bmc_retimer.id, dev_img_state.image_id)

        # Test 3: Apply a BMC image w/o retimer
        path = '/device_images/%s?action=apply' % self.device_image_bmc.uuid
        response = self.patch_json(path, [{'key1': 'value1'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        # Verify that all three states exist, the old BMC retimer image state exists
        state_list = self.dbapi.device_image_state_get_list()
        self.assertEqual(len(state_list), 3)
        dev_img_state = self.dbapi.device_image_state_get_by_image_device(
            self.device_image.id, self.pci_device.id)
        self.assertEqual(self.device_image.id, dev_img_state.image_id)
        dev_img_state = self.dbapi.device_image_state_get_by_image_device(
            self.device_image_bmc_retimer.id, self.pci_device.id)
        self.assertEqual(self.device_image_bmc_retimer.id, dev_img_state.image_id)
        dev_img_state = self.dbapi.device_image_state_get_by_image_device(
            self.device_image_bmc.id, self.pci_device.id)
        self.assertEqual(self.device_image_bmc.id, dev_img_state.image_id)

        # Test 4: Apply a BMC image with retimer
        path = '/device_images/%s?action=apply' % self.device_image_bmc_retimer.uuid
        response = self.patch_json(path, [{'key1': 'value1'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        # Verify that state for BMC image without retimer is deleted
        state_list = self.dbapi.device_image_state_get_list()
        self.assertEqual(len(state_list), 2)
        dev_img_state = self.dbapi.device_image_state_get_by_image_device(
            self.device_image.id, self.pci_device.id)
        self.assertEqual(self.device_image.id, dev_img_state.image_id)
        dev_img_state = self.dbapi.device_image_state_get_by_image_device(
            self.device_image_bmc_retimer.id, self.pci_device.id)
        self.assertEqual(self.device_image_bmc_retimer.id, dev_img_state.image_id)

    def test_device_image_remove_all_hosts(self):
        # Test removing device image for all hosts with fpga devices
        # Remove the device image
        path = '/device_images/%s?action=remove' % self.device_image.uuid
        response = self.patch_json(path, {},
                                   headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json['bitstream_type'],
                         dconstants.BITSTREAM_TYPE_FUNCTIONAL)
        self.assertEqual(response.json['pci_vendor'], '80ee')
        self.assertEqual(response.json['pci_device'], 'beef')
        self.assertEqual(response.json['bitstream_id'], '12345')

    def test_device_image_remove_by_label(self):
        # Test removing device image by device label

        # Assign label to a device
        self.post_json('/device_labels',
                       [{'pcidevice_uuid': self.pci_device.uuid},
                        {'key1': 'value1'}],
                       headers=self.API_HEADERS)

        # Apply the device image with label
        path = '/device_images/%s?action=apply' % self.device_image.uuid
        response = self.patch_json(path, [{'key1': 'value1'}],
                                   headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Remove the device image with label
        path = '/device_images/%s?action=remove' % self.device_image.uuid
        response = self.patch_json(path, [{'key1': 'value1'}],
                                   headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json['bitstream_type'],
                         dconstants.BITSTREAM_TYPE_FUNCTIONAL)
        self.assertEqual(response.json['pci_vendor'], '80ee')
        self.assertEqual(response.json['pci_device'], 'beef')
        self.assertEqual(response.json['bitstream_id'], '12345')

    def test_device_image_remove_by_label_without_device(self):
        # Test removing device image by label without device

        # Apply the device image with label
        path = '/device_images/%s?action=apply' % self.device_image.uuid
        response = self.patch_json(path, [{'key1': 'value1'}],
                                   headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        # Remove the device image with label
        path = '/device_images/%s?action=remove' % self.device_image.uuid
        response = self.patch_json(path, [{'key1': 'value1'}],
                                   headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)


class TestDelete(TestDeviceImage):

    def test_delete(self):
        # Test deleting a device image

        # Create the device image
        device_image = dbutils.create_test_device_image(
            bitstream_type=dconstants.BITSTREAM_TYPE_FUNCTIONAL,
            pci_vendor='80ee',
            pci_device='beef',
            bitstream_id='12345')

        # Delete the device image
        self.delete('/device_images/%s' % device_image.uuid,
                    headers={'User-Agent': 'sysinv-test'})

        # Verify the device image no longer exists
        response = self.get_json('/device_images/%s' % device_image.uuid,
                                 expect_errors=True)
        self.assertEqual(response.status_int, 404)
        self.assertEqual(response.content_type, 'application/json')
        self.assertTrue(response.json['error_message'])

    def test_delete_not_exist(self):
        # Test deleting a device image

        # Delete the device image
        uuid = uuidutils.generate_uuid()
        response = self.delete('/device_images/%s' % uuid,
                               headers={'User-Agent': 'sysinv-test'},
                               expect_errors=True)
        self.assertEqual(response.status_int, 404)
        self.assertEqual(response.content_type, 'application/json')
        self.assertTrue(response.json['error_message'])
        self.assertIn("Device image %s could not be found" % uuid,
                      response.json['error_message'])
