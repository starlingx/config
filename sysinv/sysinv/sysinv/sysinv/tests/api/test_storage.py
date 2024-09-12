#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / istors / methods.
"""

import mock

from six.moves import http_client

from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class FakeConductorAPI(object):

    def __init__(self):
        self.disk_prepare = mock.MagicMock()


class FakeException(Exception):
        pass


class ApiStorageTestCaseMixin(base.FunctionalTest,
                              dbbase.ControllerHostTestCase):

    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/istors'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'istors'

    def setUp(self):
        super(ApiStorageTestCaseMixin, self).setUp()

        self.cluster = dbutils.create_test_cluster(system_id=self.system.id, name='ceph_cluster')
        self.disk = self.disks.get(self.host.id)

    def get_single_storage_url(self, uuid):
        return "%s/%s" % (self.API_PREFIX, uuid)

    def _create_istors_db_object(self, **kw):
        return dbutils.create_test_istors(**kw)

    def _create_hostfs_db_object(self,
                                 host_fs_name,
                                 host_fs_size,
                                 host_lv,
                                 fs_state,
                                 capabilities=None,
                                 obj_id=None):
        if capabilities is None:
            capabilities = {"functions": []}
        return dbutils.create_test_host_fs(id=obj_id,
                                           uuid=None,
                                           name=host_fs_name,
                                           forihostid=self.host.id,
                                           size=host_fs_size,
                                           logical_volume=host_lv,
                                           state=fs_state,
                                           capabilities=capabilities)


class ApiStoragePostTestSuiteMixin(ApiStorageTestCaseMixin):
    """ Storage post operations
    """
    def setUp(self):
        super(ApiStoragePostTestSuiteMixin, self).setUp()

    def test_post_osd_storage_rook_sb_case_1(self):
        """ Creating osd storage and checking if ceph hostfs was created
            and if it has the osd function.
        """
        disk_1 = dbutils.create_test_idisk(
                    device_node='/dev/sdb',
                    device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0',
                    forihostid=1)

        # Rook Ceph backend
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        values = {
            'cluster_uuid': self.cluster.uuid,
            'name': 'storage',
            'status': constants.SB_TIER_STATUS_IN_USE
        }
        dbutils.create_test_storage_tier(**values)

        values = {'ihost_uuid': self.host.uuid,
                  'idisk_uuid': disk_1.uuid}
        istors = self.post_json('/istors',
                                values,
                                headers=self.API_HEADERS,
                                expect_errors=False)

        self.assertEqual(istors.content_type, 'application/json')
        self.assertEqual(istors.status_code, http_client.OK)

        host_fs = self.get_json('/host_fs', expect_errors=False)
        for fs in host_fs['host_fs']:
            if fs['name'] == constants.FILESYSTEM_NAME_CEPH:
                capabilities = {"functions": ["osd"]}
                self.assertEqual(fs['capabilities'], capabilities)

    def test_post_osd_storage_rook_sb_case_2(self):
        """ Creating osd storage and checking if the existing ceph hostfs
            now has the monitor and osd functions now.
        """
        disk_1 = dbutils.create_test_idisk(
                    device_node='/dev/sdb',
                    device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0',
                    forihostid=1)
        disk_2 = dbutils.create_test_idisk(
                    device_node='/dev/sdc',
                    device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-3.0',
                    forihostid=1)

        # Rook Ceph backend
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create the ceph hostfs with the monitor function
        values = {
            "host_fs_name": "ceph",
            "host_fs_size": 20,
            "host_lv": "ceph-lv",
            "fs_state": constants.HOST_FS_STATUS_IN_USE,
            "capabilities": {"functions": ["monitor"]}
        }
        self._create_hostfs_db_object(**values)

        # Create storage tier
        values = {
            'cluster_uuid': self.cluster.uuid,
            'name': 'storage',
            'status': constants.SB_TIER_STATUS_IN_USE
        }
        dbutils.create_test_storage_tier(**values)

        # first osd
        values = {'ihost_uuid': self.host.uuid,
                  'idisk_uuid': disk_1.uuid}
        self.post_json('/istors',
                       values,
                       headers=self.API_HEADERS,
                       expect_errors=False)

        # second osd
        values = {'ihost_uuid': self.host.uuid,
                  'idisk_uuid': disk_2.uuid}
        istors = self.post_json('/istors',
                                values,
                                headers=self.API_HEADERS,
                                expect_errors=False)

        self.assertEqual(istors.content_type, 'application/json')
        self.assertEqual(istors.status_code, http_client.OK)

        # checking if the osd function was added
        host_fs = self.get_json('/host_fs', expect_errors=False)
        for fs in host_fs['host_fs']:
            if fs['name'] == constants.FILESYSTEM_NAME_CEPH:
                capabilities = {"functions": ["monitor", "osd"]}
                self.assertEqual(fs['capabilities'], capabilities)


class ApiStorageDeleteTestSuiteMixin(ApiStorageTestCaseMixin):
    """ Storage delete operations
    """
    def setUp(self):
        super(ApiStorageDeleteTestSuiteMixin, self).setUp()

    def test_delete_rook_sb(self):
        """ Delete a osd storage and checking if the osd function
            was removed from ceph host filesystem.
        """
        # Rook Ceph backend
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # creating host-fs with monitor and osd functions
        values = {
            "host_fs_name": "ceph",
            "host_fs_size": 20,
            "host_lv": "ceph-lv",
            "fs_state": constants.HOST_FS_STATUS_IN_USE,
            "capabilities": {"functions": ["monitor", "osd"]}
        }
        self._create_hostfs_db_object(**values)

        # creating storage tier
        values = {
            'cluster_uuid': self.cluster.uuid,
            'name': 'storage',
            'status': constants.SB_TIER_STATUS_IN_USE
        }
        dbutils.create_test_storage_tier(**values)

        # disks
        disk_1 = dbutils.create_test_idisk(
                    device_node='/dev/sdb',
                    device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0',
                    forihostid=1)
        disk_2 = dbutils.create_test_idisk(
                    device_node='/dev/sdc',
                    device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-3.0',
                    forihostid=1)

        # adding osds
        values = {
            'ihost_uuid': self.host.uuid,
            'idisk_uuid': disk_1.uuid
        }
        istors_1 = self.post_json('/istors',
                                  values,
                                  headers=self.API_HEADERS,
                                  expect_errors=False)
        values = {
            'ihost_uuid': self.host.uuid,
            'idisk_uuid': disk_2.uuid
        }
        istors_2 = self.post_json('/istors',
                                  values,
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        # deleting first osd
        response = self.delete(self.get_single_storage_url(istors_1.json['uuid']),
                               headers=self.API_HEADERS,
                               expect_errors=False)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # checking if it was deleted
        response = self.get_json(self.get_single_storage_url(istors_1.json['uuid']),
                                 headers=self.API_HEADERS,
                                 expect_errors=True)
        self.assertIn("could not be found", response.json['error_message'])

        # checking if osd function remains due to it not being the last osd on this host
        host_fs = self.get_json('/host_fs', expect_errors=False)
        for fs in host_fs['host_fs']:
            if fs['name'] == constants.FILESYSTEM_NAME_CEPH:
                capabilities = {"functions": ["monitor", "osd"]}
                self.assertEqual(fs['capabilities'], capabilities)

        # deleting second osd
        response = self.delete(self.get_single_storage_url(istors_2.json['uuid']),
                               headers=self.API_HEADERS,
                               expect_errors=False)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # checking if it was deleted
        response = self.get_json(self.get_single_storage_url(istors_2.json['uuid']),
                                 headers=self.API_HEADERS,
                                 expect_errors=True)
        self.assertIn("could not be found", response.json['error_message'])

        # checking if osd function was removed due to being the last osd on this host
        host_fs = self.get_json('/host_fs', expect_errors=False)
        for fs in host_fs['host_fs']:
            if fs['name'] == constants.FILESYSTEM_NAME_CEPH:
                capabilities = {"functions": ["monitor"]}
                self.assertEqual(fs['capabilities'], capabilities)
