#
# Copyright (c) 2013-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /ipartitions/ methods.

Future Work Items:
  Add API links tests
  Add partition list scoped by disk tests
(Some of these will fail unless code changes are made)
"""

import mock
import webtest.app
from six.moves import http_client

from oslo_utils import uuidutils
from sysinv.common import constants
from sysinv.common.exception import HTTPNotFound

from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils


class FakeConductorAPI(object):

    def __init__(self, dbapi):
        self.dbapi = dbapi
        self.create_controller_filesystems = mock.MagicMock()

        # By configuring the host as provisioned, the following must be mocked
        self.update_partition_config = mock.MagicMock()


class TestPartition(base.FunctionalTest):

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/partitions'

    # can perform API operations on partitions at a sublevel of host
    HOST_PREFIX = '/ihosts'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'partitions'

    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    disk_device_path = '/dev/disk/by-path/pci-0000:00:0d.0-ata-1.0'
    partition_device_path = '/dev/disk/by-path/pci-0000:00:0d.0-ata-1.1'

    def setUp(self):
        super(TestPartition, self).setUp()

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
        self.disk = self._create_disk(self.ihost.id)

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


class TestPostPartition(TestPartition):

    def setUp(self):
        super(TestPostPartition, self).setUp()

    def test_create_partition(self):
        # Test creation of partition
        ndict = dbutils.post_get_test_partition(forihostid=self.ihost.id,
                                                idisk_id=self.disk.id,
                                                idisk_uuid=self.disk.uuid,
                                                size_mib=128)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)

        # Verify that no filesystems were created
        self.fake_conductor_api.create_controller_filesystems.\
            assert_not_called()

        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json['size_mib'], ndict['size_mib'])

        uuid = response.json['uuid']
        # Verify that the partition was created and some basic attributes match
        response = self.get_json(self.get_single_url(uuid))
        self.assertEqual(response['size_mib'], ndict['size_mib'])

    def test_create_partition_invalid_host(self):
        # Test creation of partition with an invalid host
        ndict = dbutils.post_get_test_partition(forihostid=1234567,
                                                idisk_id=self.disk.id,
                                                size_mib=128)
        self.assertRaises(webtest.app.AppError,
                          self.post_json,
                          self.API_PREFIX,
                          ndict,
                          headers=self.API_HEADERS)

    def test_create_partition_invalid_disk(self):
        # Test creation of partition with an invalid disk
        ndict = dbutils.post_get_test_partition(forihostid=self.ihost.id,
                                                idisk_id=1234567,
                                                size_mib=128)
        self.assertRaises(webtest.app.AppError,
                          self.post_json,
                          self.API_PREFIX,
                          ndict,
                          headers=self.API_HEADERS)

    def test_create_partition_invalid_size(self):
        # Test creation of partition with an invalid disk

        # Available size is 256. Therefore a 256 partition is considered invalid.
        invalid_sizes = [None, 0, -100, 256, 257, 'xyz']
        for bad_size in invalid_sizes:
            ndict = dbutils.post_get_test_partition(forihostid=self.ihost.id,
                                                    idisk_id=self.disk.id,
                                                    size_mib=bad_size)
            self.assertRaises(webtest.app.AppError,
                              self.post_json,
                              self.API_PREFIX,
                              ndict,
                              headers=self.API_HEADERS)

    def test_create_partition_invalid_additional_attributes(self):
        # Test creation of partition with an invalid attribute called 'foo'
        ndict = dbutils.post_get_test_partition(forihostid=self.ihost.id,
                                                idisk_id=self.disk.id,
                                                foo='some value')
        self.assertRaises(webtest.app.AppError,
                          self.post_json,
                          self.API_PREFIX,
                          ndict,
                          headers=self.API_HEADERS)


class TestDeletePartition(TestPartition):
    """ Tests deletion of partitions.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """

    def setUp(self):
        super(TestDeletePartition, self).setUp()
        # create a partition
        self.partition = dbutils.create_test_partition(
            forihostid=self.ihost.id,
            idisk_id=self.disk.id,
            idisk_uuid=self.disk.uuid,
            size_mib=128)

    def test_delete_partition(self):
        # Delete the partition
        uuid = self.partition.uuid
        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS)

        # Verify the expected API response for the delete
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify that the partition was deleted
        response = self.get_json(self.get_single_url(uuid),
                                 expect_errors=True)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertTrue(response.json['error_message'])

    def test_double_delete_partition(self):
        # Delete the partition
        uuid = self.partition.uuid
        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS)

        # Verify the expected API response for the delete
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify that the partition was deleted
        response = self.get_json(self.get_single_url(uuid),
                                 expect_errors=True)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)

        # Attempt to delete the partition again. This should fail.
        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertEqual(response.content_type, 'application/json')
        self.assertTrue(response.json['error_message'])


class TestListPartitions(TestPartition):
    """ Partition list operations can only performed on
        a host or disk.
        Only user generated partitions are queryable.
        ie: type_guid=constants.USER_PARTITION_PHYSICAL_VOLUME
    """
    expected_api_fields = ['uuid',
                           'capabilities',
                           'created_at',
                           'device_node',
                           'device_path',
                           'end_mib',
                           'idisk_uuid',
                           'ihost_uuid',
                           'ipv_uuid',
                           'links',
                           'size_mib',
                           'start_mib',
                           'status',
                           'type_guid',
                           'type_name',
                           'updated_at']

    hidden_api_fields = ['forihostid',
                         'idisk_id',
                         'foripvid']

    def setUp(self):
        super(TestListPartitions, self).setUp()

    def test_empty_list(self):
        response = self.get_json(self.API_PREFIX)
        self.assertEqual([], response[self.RESULT_KEY])

    def test_unscoped_list_returns_empty(self):
        # create a partition
        self.partition = dbutils.create_test_partition(
            forihostid=self.ihost.id,
            idisk_id=self.disk.id,
            idisk_uuid=self.disk.uuid,
            type_guid=constants.USER_PARTITION_PHYSICAL_VOLUME,
            size_mib=128)

        # Querying the base URL (unscoped)
        response = self.get_json(self.API_PREFIX)
        self.assertEqual(0, len(response[self.RESULT_KEY]))

    def assert_fields(self, api_object):
        # check the uuid is a uuid
        assert(uuidutils.is_uuid_like(api_object['uuid']))

        # Verify that expected attributes are returned
        for field in self.expected_api_fields:
            self.assertIn(field, api_object)

        # Verify that hidden attributes are not returned
        for field in self.hidden_api_fields:
            self.assertNotIn(field, api_object)

    def test_single_entry_by_host_list(self):
        expected_size = 32
        # create a partition
        self.partition = dbutils.create_test_partition(
            forihostid=self.ihost.id,
            idisk_id=self.disk.id,
            idisk_uuid=self.disk.uuid,
            type_guid=constants.USER_PARTITION_PHYSICAL_VOLUME,
            size_mib=expected_size)

        # Querying the URL scoped by host
        response = self.get_json(self.get_host_scoped_url(self.ihost.uuid))

        self.assertEqual(1, len(response[self.RESULT_KEY]))
        # Check the single result
        for result in response[self.RESULT_KEY]:
            # check fields are appropriate
            self.assert_fields(result)
            # check that the partition was created with the input size
            self.assertEqual(expected_size, result['size_mib'])

    def test_many_entries_in_list(self):
        result_list = []
        for obj_id in range(100):
            partition = dbutils.create_test_partition(
                id=obj_id,
                forihostid=self.ihost.id,
                idisk_id=self.disk.id,
                idisk_uuid=self.disk.uuid,
                type_guid=constants.USER_PARTITION_PHYSICAL_VOLUME,
                size_mib=1)
            result_list.append(partition['uuid'])

        response = self.get_json(self.get_host_scoped_url(self.ihost.uuid))
        self.assertEqual(len(result_list), len(response[self.RESULT_KEY]))

        # Verify that the sorted list of uuids is the same
        uuids = [n['uuid'] for n in response[self.RESULT_KEY]]
        self.assertEqual(result_list.sort(), uuids.sort())


class TestPatchPartition(TestPartition):
    """"Patch operations can only be applied to a partition in ready state
    """
    patch_path_size = '/size_mib'
    patch_field = 'size_mib'
    patch_value = 64

    def setUp(self):
        super(TestPatchPartition, self).setUp()
        # Only partition Add/Delete operations are allowed on an unprovisioned host
        # create a partition in ready state
        # device_path is required. Only the last partition can be modified.
        # setting the size small, since patching typically increases it.
        self.partition = dbutils.create_test_partition(
            forihostid=self.ihost.id,
            idisk_id=self.disk.id,
            idisk_uuid=self.disk.uuid,
            type_guid=constants.USER_PARTITION_PHYSICAL_VOLUME,
            status=constants.PARTITION_READY_STATUS,
            device_path=self.partition_device_path,
            size_mib=32)

    def test_patch_invalid_field(self):
        # Pass a non existant field to be patched by the API

        response = self.patch_json(self.get_single_url(self.partition.uuid),
                                   [{'path': '/junk_field',
                                     'value': self.patch_value,
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_patch_size_valid(self):
        # Update value of size field
        response = self.patch_json(self.get_single_url(self.partition.uuid),
                                   [{'path': self.patch_path_size,
                                     'value': self.patch_value,
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the attribute was updated
        response = self.get_json(self.get_single_url(self.partition.uuid))
        self.assertEqual(response[self.patch_field], self.patch_value)

    def test_patch_invalid_size_reduction(self):
        # Pass an invalid size (making it smaller) to be patched by the API
        response = self.patch_json(self.get_single_url(self.partition.uuid),
                                   [{'path': self.patch_path_size,
                                     'value': 32,
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

        # Repeat the test, but passing the value as a 'string' instead of an int.
        response = self.patch_json(self.get_single_url(self.partition.uuid),
                                   [{'path': self.patch_path_size,
                                     'value': '32',
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_patch_invalid_size_negative(self):
        # Pass an invalid size (making it negative) to be patched by the API
        response = self.patch_json(self.get_single_url(self.partition.uuid),
                                   [{'path': self.patch_path_size,
                                     'value': -1,
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

        # Repeat the test, but passing the value as a 'string' instead of an int.
        response = self.patch_json(self.get_single_url(self.partition.uuid),
                                   [{'path': self.patch_path_size,
                                     'value': '-1',
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_patch_invalid_size_string(self):
        # Pass an invalid size (passing a junk string) to be patched by the API
        response = self.patch_json(self.get_single_url(self.partition.uuid),
                                   [{'path': self.patch_path_size,
                                     'value': 'xyz',
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_update_partition_config_fails(self):
        # This is the same code that succeeds in a normal patch API call.
        # Testing when that update_partition_config fails
        self.fake_conductor_api.update_partition_config.side_effect = HTTPNotFound()
        response = self.patch_json(self.get_single_url(self.partition.uuid),
                                   [{'path': self.patch_path_size,
                                     'value': self.patch_value,
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
