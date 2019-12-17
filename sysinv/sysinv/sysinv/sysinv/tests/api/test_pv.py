#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / pv / methods.
"""

import mock
import webtest.app
from six.moves import http_client

from oslo_utils import uuidutils
from sysinv.common import constants

from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils


class FakeConductorAPI(object):

    def __init__(self, dbapi):
        self.dbapi = dbapi
        self.create_controller_filesystems = mock.MagicMock()


class TestPV(base.FunctionalTest):

    # can perform API operations on this object at a sublevel of host
    HOST_PREFIX = '/ihosts'

    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # Generic path used when constructing disk objects
    disk_device_path = '/dev/disk/by-path/pci-0000:00:0d.0-ata-1.0'
    # The volume group name must be a member of LVG_ALLOWED_VGS
    # selecting nova local as our default for these tests
    lvm_vg_name = constants.LVG_NOVA_LOCAL

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/ipvs'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'ipvs'

    # COMMON_FIELD is a field that is known to exist for inputs and outputs
    COMMON_FIELD = 'lvm_vg_name'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['uuid',
                           'pv_state',
                           'pv_type',
                           'disk_or_part_uuid',
                           'disk_or_part_device_node',
                           'disk_or_part_device_path',
                           'lvm_pv_name',
                           'lvm_vg_name',
                           'lvm_pv_uuid',
                           'lvm_pv_size',
                           'lvm_pe_total',
                           'lvm_pe_alloced',
                           'ihost_uuid',
                           'forilvgid',
                           'ilvg_uuid',
                           'capabilities']

    # hidden_api_fields are attributes that should not be populated by
    # an API query
    hidden_api_fields = ['forihostid']

    def setUp(self):
        super(TestPV, self).setUp()

        # Mock the conductor API
        self.fake_conductor_api = FakeConductorAPI(self.dbapi)
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

        # Behave as if the API is running on controller-0
        p = mock.patch('socket.gethostname')
        self.mock_socket_gethostname = p.start()
        self.mock_socket_gethostname.return_value = 'controller-0'
        self.addCleanup(p.stop)

        # Behave as if running on a virtual system
        p = mock.patch('sysinv.common.utils.is_virtual')
        self.mock_utils_is_virtual = p.start()
        self.mock_utils_is_virtual.return_value = True
        self.addCleanup(p.stop)

        # Create an isystem and load
        self.system = dbutils.create_test_isystem(
            capabilities={"cinder_backend": constants.CINDER_BACKEND_CEPH,
                          "vswitch_type": constants.VSWITCH_TYPE_NONE,
                          "region_config": False,
                          "sdn_enabled": False,
                          "shared_services": "[]"}
        )
        self.load = dbutils.create_test_load()
        # Create controller-0
        self.ihost = self._create_controller_0()
        # Create disk on the controller
        self.disk = self._create_disk(self.ihost.id)
        # Create logical volume group
        self.lvg = self._create_lvg(self.ihost.id,
                                    self.lvm_vg_name)

    def get_single_url(self, uuid):
        return '%s/%s' % (self.API_PREFIX, uuid)

    def get_host_scoped_url(self, host_uuid):
        return '%s/%s%s' % (self.HOST_PREFIX, host_uuid, self.API_PREFIX)

    def _create_controller_0(self, **kw):
        # The host must be provisioned in order to perform PATCH operations
        ihost = dbutils.create_test_ihost(
            hostname='controller-0',
            mgmt_mac='01:34:67:9A:CD:F0',
            mgmt_ip='192.168.204.3',
            serialid='serial1',
            bm_ip='128.224.150.193',
            invprovision=constants.PROVISIONED,
            config_target='e4ec5ee2-967d-4b2d-8de8-f0a390fcbd35',
            config_applied='e4ec5ee2-967d-4b2d-8de8-f0a390fcbd35',
            **kw)
        return ihost

    def _create_disk(self, ihost_id):
        return dbutils.create_test_idisk(
            device_node='/dev/sda',
            device_path=self.disk_device_path,
            available_mib=256,
            forihostid=ihost_id)

    def _create_lvg(self, ihost_id, lvm_vg_name):
        return dbutils.create_test_lvg(forihostid=ihost_id,
                                       lvm_vg_name=lvm_vg_name)

    # These methods have generic names and are overridden here
    # Future activity: Redo the subclasses to use mixins
    def assert_fields(self, api_object):
        # check the uuid is a uuid
        assert(uuidutils.is_uuid_like(api_object['uuid']))

        # Verify that expected attributes are returned
        for field in self.expected_api_fields:
            self.assertIn(field, api_object)

        # Verify that hidden attributes are not returned
        for field in self.hidden_api_fields:
            self.assertNotIn(field, api_object)

    def get_post_object(self):
        return dbutils.post_get_test_pv(forihostid=self.ihost.id,
                                        forilvgid=self.lvg.id,
                                        idisk_id=self.disk.id,
                                        idisk_uuid=self.disk.uuid,
                                        lvm_vg_name=self.lvm_vg_name,
                                        disk_or_part_uuid=self.disk.uuid)

    def _create_db_object(self, obj_id=None):
        return dbutils.create_test_pv(id=obj_id,
                                      forihostid=self.ihost.id,
                                      forilvgid=self.lvg.id,
                                      idisk_id=self.disk.id,
                                      idisk_uuid=self.disk.uuid,
                                      lvm_vg_name=self.lvm_vg_name,
                                      disk_or_part_uuid=self.disk.uuid)


class TestPostPV(TestPV):

    def setUp(self):
        super(TestPostPV, self).setUp()

    def test_create_success(self):
        # Test creation of object
        ndict = self.get_post_object()
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)

        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        # Check that an expected field matches.
        self.assertEqual(response.json[self.COMMON_FIELD],
                         ndict[self.COMMON_FIELD])

        uuid = response.json['uuid']
        # Verify that the object was created and some basic attribute matches
        response = self.get_json(self.get_single_url(uuid))
        self.assertEqual(response[self.COMMON_FIELD],
                         ndict[self.COMMON_FIELD])

    def test_create_with_invalid_host(self):
        # Test creation with an invalid host
        ndict = self.get_post_object()
        ndict['forihostid'] = 1234567
        self.assertRaises(webtest.app.AppError,
                          self.post_json,
                          self.API_PREFIX,
                          ndict,
                          headers=self.API_HEADERS)

    def test_create_with_invalid_disk(self):
        # Test creation with an invalid disk
        ndict = self.get_post_object()
        ndict['idisk_id'] = 1234567
        self.assertRaises(webtest.app.AppError,
                          self.post_json,
                          self.API_PREFIX,
                          ndict,
                          headers=self.API_HEADERS)

    def test_create_with_invalid_additional_attributes(self):
        # Test creation with an invalid attribute called 'foo'
        ndict = self.get_post_object()
        ndict['foo'] = 'some value'
        self.assertRaises(webtest.app.AppError,
                          self.post_json,
                          self.API_PREFIX,
                          ndict,
                          headers=self.API_HEADERS)


class TestDeletePV(TestPV):
    """ Tests deletion.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """

    def setUp(self):
        super(TestDeletePV, self).setUp()
        # create a partition
        self.delete_object = self._create_db_object()

    # The PV delete is not a blocking operation.
    # Cannot determine if the delete is completed, or has simply set the
    # pv_state to "removing"
    def test_delete(self):
        # Delete the API object
        uuid = self.delete_object.uuid
        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS)

        # Verify the expected API response for the delete
        self.assertEqual(response.status_code, http_client.NO_CONTENT)


class TestListPVs(TestPV):
    """ PV list operations
    """

    def setUp(self):
        super(TestListPVs, self).setUp()

    def test_empty_list(self):
        response = self.get_json(self.API_PREFIX)
        self.assertEqual([], response[self.RESULT_KEY])

    def test_single_entry_unscoped(self):
        # create a single object
        self.single_object = self._create_db_object()
        response = self.get_json(self.API_PREFIX)
        self.assertEqual(1, len(response[self.RESULT_KEY]))

    def test_single_entry_by_host_list(self):
        # create a single object
        self.single_object = self._create_db_object()

        # Querying the URL scoped by host
        response = self.get_json(self.get_host_scoped_url(self.ihost.uuid))

        self.assertEqual(1, len(response[self.RESULT_KEY]))
        # Check the single result
        for result in response[self.RESULT_KEY]:
            # check fields are appropriate
            self.assert_fields(result)

    def test_many_entries_in_list(self):
        result_list = []
        for obj_id in range(100):
            loop_object = self._create_db_object(obj_id=obj_id)
            result_list.append(loop_object['uuid'])

        response = self.get_json(self.get_host_scoped_url(self.ihost.uuid))
        self.assertEqual(len(result_list), len(response[self.RESULT_KEY]))

        # Verify that the sorted list of uuids is the same
        uuids = [n['uuid'] for n in response[self.RESULT_KEY]]
        self.assertEqual(result_list.sort(), uuids.sort())


class TestPatchPV(TestPV):
    patch_path = '/lvm_pe_alloced'
    patch_field = 'lvm_pe_alloced'
    patch_value = 2

    def setUp(self):
        super(TestPatchPV, self).setUp()
        self.patch_object = self._create_db_object()

    def test_patch_invalid_field(self):
        # Pass a non existant field to be patched by the API

        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': '/junk_field',
                                     'value': self.patch_value,
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_patch_valid(self):
        # Update value of patchable field
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path,
                                     'value': self.patch_value,
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the attribute was updated
        response = self.get_json(self.get_single_url(self.patch_object.uuid))
        self.assertEqual(response[self.patch_field], self.patch_value)

    def test_patch_invalid_value(self):
        # Pass a value that fails a semantic check when patched by the API
        # lvm_vg_name is restricted to a value in constants.LVG_ALLOWED_VGS

        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': 'lvm_vg_name',
                                     'value': 'invalid_lvm_vg_name',
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
