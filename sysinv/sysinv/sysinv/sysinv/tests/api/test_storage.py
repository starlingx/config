#
# Copyright (c) 2024,2026 Wind River Systems, Inc.
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

    def test_post_fail_no_rook_backend(self):
        """Creating OSD storage without any Ceph backend configured
        should return HTTP 400 with a storage backend error."""
        disk_1 = dbutils.create_test_idisk(
                    device_node='/dev/sdb',
                    device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0',
                    forihostid=1)

        # No storage backend created

        values = {'ihost_uuid': self.host.uuid,
                  'idisk_uuid': disk_1.uuid}
        response = self.post_json('/istors',
                                  values,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("must have either",
                      response.json['error_message'])

    def test_post_fail_invalid_disk(self):
        """Creating OSD storage with an invalid disk UUID should
        return HTTP 400 with a disk validation error."""

        # Rook Ceph backend
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # Use a non-existent disk UUID
        fake_disk_uuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

        values = {'ihost_uuid': self.host.uuid,
                  'idisk_uuid': fake_disk_uuid}
        response = self.post_json('/istors',
                                  values,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("failed to create a storage object",
                      response.json['error_message'])

    def test_post_fail_invalid_journal(self):
        """Creating OSD storage with an invalid journal location should
        return HTTP 400 with a journal validation error."""
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

        # Use an invalid (non-UUID) journal location
        values = {'ihost_uuid': self.host.uuid,
                  'idisk_uuid': disk_1.uuid,
                  'journal_location': 'not-a-valid-uuid'}
        response = self.post_json('/istors',
                                  values,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Expected a uuid but received",
                      response.json['error_message'])

    def test_post_fail_invalid_host_state(self):
        """Creating OSD storage with host in incorrect state for the
        deployment model should return HTTP 400 with a host state error."""
        disk_1 = dbutils.create_test_idisk(
                    device_node='/dev/sdb',
                    device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0',
                    forihostid=1)

        # Rook Ceph backend with 'dedicated' deployment model (requires worker node)
        backend = dbutils.get_test_ceph_rook_storage_backend(
            capabilities={
                constants.CEPH_ROOK_BACKEND_DEPLOYMENT_CAP:
                    constants.CEPH_ROOK_DEPLOYMENT_DEDICATED,
                constants.CEPH_ROOK_BACKEND_FAILURE_DOMAIN_CAP:
                    constants.CEPH_ROOK_CLUSTER_HOST_FAIL_DOMAIN,
                constants.CEPH_BACKEND_REPLICATION_CAP: '1',
            }
        )
        self.dbapi.storage_ceph_rook_create(backend)

        # Host is a controller but deployment model requires worker
        values = {'ihost_uuid': self.host.uuid,
                  'idisk_uuid': disk_1.uuid}
        response = self.post_json('/istors',
                                  values,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("does not support osd on host",
                      response.json['error_message'])

    def test_post_fail_no_cluster_or_tier(self):
        """Creating OSD storage without a configured storage tier should
        return HTTP 400 with a cluster/tier configuration error."""
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

        # Create multiple storage tiers to trigger the "multiple tiers" error
        values_1 = {
            'cluster_uuid': self.cluster.uuid,
            'name': 'storage',
            'status': constants.SB_TIER_STATUS_IN_USE
        }
        dbutils.create_test_storage_tier(**values_1)

        values_2 = {
            'cluster_uuid': self.cluster.uuid,
            'name': 'gold',
            'status': constants.SB_TIER_STATUS_IN_USE
        }
        dbutils.create_test_storage_tier(**values_2)

        # POST without specifying tier_uuid (ambiguous with multiple tiers)
        values = {'ihost_uuid': self.host.uuid,
                  'idisk_uuid': disk_1.uuid}
        response = self.post_json('/istors',
                                  values,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("tier is required",
                      response.json['error_message'])

    def test_post_fail_disk_in_use(self):
        """Creating OSD storage on a disk that already has an OSD should
        return HTTP 400 with a disk-in-use error."""
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

        # Create the first OSD successfully
        values = {'ihost_uuid': self.host.uuid,
                  'idisk_uuid': disk_1.uuid}
        first_osd = self.post_json('/istors',
                                   values,
                                   headers=self.API_HEADERS,
                                   expect_errors=False)
        self.assertEqual(first_osd.status_code, http_client.OK)

        # Try to create another OSD on the same disk
        values = {'ihost_uuid': self.host.uuid,
                  'idisk_uuid': disk_1.uuid}
        response = self.post_json('/istors',
                                  values,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("already assigned",
                      response.json['error_message'])

    def test_post_osd_storage_rook_sb_host_locked(self):
        """Creating osd storage on a locked host and checking if ceph
        hostfs was created with the correct state (Creating on unlock)
        and has the osd function."""

        disk_1 = dbutils.create_test_idisk(
                    device_node='/dev/sdb',
                    device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0',
                    forihostid=1)

        # Rook Ceph backend
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # Ensure host is locked + online (default is locked + offduty)
        self.dbapi.ihost_update(self.host.uuid,
                                {'administrative': constants.ADMIN_LOCKED,
                                 'availability': constants.AVAILABILITY_ONLINE})

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

        # Check that ceph hostfs was created with the correct state
        host_fs = self.get_json('/host_fs', expect_errors=False)
        for fs in host_fs['host_fs']:
            if fs['name'] == constants.FILESYSTEM_NAME_CEPH:
                capabilities = {"functions": ["osd"]}
                self.assertEqual(fs['capabilities'], capabilities)
                self.assertEqual(fs['state'],
                                 constants.HOST_FS_STATUS_CREATE_ON_UNLOCK)
                break
        else:
            self.fail("ceph host-fs was not created by stor creation")


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

    def test_delete_force(self):
        """Force deleting an OSD should bypass pool size constraints and
        transition the stor to force-deleting-with-app state."""

        # Rook Ceph backend with replication factor 2
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # creating host-fs with osd function
        values = {
            "host_fs_name": "ceph",
            "host_fs_size": 20,
            "host_lv": "ceph-lv",
            "fs_state": constants.HOST_FS_STATUS_IN_USE,
            "capabilities": {"functions": ["osd"]}
        }
        self._create_hostfs_db_object(**values)

        # creating storage tier
        tier = dbutils.create_test_storage_tier(
            cluster_uuid=self.cluster.uuid,
            name='storage',
            status=constants.SB_TIER_STATUS_IN_USE)

        # Create a disk for the OSD
        disk_1 = dbutils.create_test_idisk(
                    device_node='/dev/sdb',
                    device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0',
                    forihostid=self.host.id)

        # Create OSD directly in DB in 'configured' (active) state
        istor = dbutils.create_test_istors(
            forihostid=self.host.id,
            ihost_uuid=self.host.uuid,
            idisk_uuid=disk_1.uuid,
            fortierid=tier.id,
            tier_uuid=tier.uuid,
            tier_name=tier.name,
            state=constants.SB_STATE_CONFIGURED)

        # DELETE with force=True (path segment after UUID)
        # With only 1 host and replication factor 2, pool size constraint
        # would normally block deletion - but force bypasses it
        response = self.delete(
            self.get_single_storage_url(istor.uuid) + '/True',
            headers=self.API_HEADERS,
            expect_errors=False)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify OSD transitioned to force-deleting-with-app state
        updated_stor = self.dbapi.istor_get(istor.uuid)
        self.assertEqual(updated_stor.state,
                         constants.SB_STATE_FORCE_DELETING_WITH_APP)

    def test_delete_fail_pool_size_constraint(self):
        """Deleting an OSD without force when it would violate pool size
        constraints (replication factor) should return HTTP 400."""

        # Rook Ceph backend with replication factor 2 and host failure domain
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # creating host-fs with osd function
        values = {
            "host_fs_name": "ceph",
            "host_fs_size": 20,
            "host_lv": "ceph-lv",
            "fs_state": constants.HOST_FS_STATUS_IN_USE,
            "capabilities": {"functions": ["osd"]}
        }
        self._create_hostfs_db_object(**values)

        # creating storage tier
        tier = dbutils.create_test_storage_tier(
            cluster_uuid=self.cluster.uuid,
            name='storage',
            status=constants.SB_TIER_STATUS_IN_USE)

        # Create a disk for the OSD
        disk_1 = dbutils.create_test_idisk(
                    device_node='/dev/sdb',
                    device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0',
                    forihostid=self.host.id)

        # Create OSD directly in DB in 'configured' (active) state
        # With only 1 host and replication factor 2 (default), the
        # host count (1) would be less than replication factor (2)
        # after removal, so deletion should be blocked
        istor = dbutils.create_test_istors(
            forihostid=self.host.id,
            ihost_uuid=self.host.uuid,
            idisk_uuid=disk_1.uuid,
            fortierid=tier.id,
            tier_uuid=tier.uuid,
            tier_name=tier.name,
            state=constants.SB_STATE_CONFIGURED)

        # DELETE without force - should fail due to pool size constraint
        response = self.delete(
            self.get_single_storage_url(istor.uuid),
            headers=self.API_HEADERS,
            expect_errors=True)

        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("cannot be removed",
                      response.json['error_message'])

    def test_delete_missing_hostfs_graceful(self):
        """Deleting an OSD when no corresponding host_fs ceph entry exists
        should succeed without unhandled exceptions."""

        # Rook Ceph backend
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # NOTE: No host_fs ceph entry is created

        # creating storage tier
        tier = dbutils.create_test_storage_tier(
            cluster_uuid=self.cluster.uuid,
            name='storage',
            status=constants.SB_TIER_STATUS_IN_USE)

        # Create a disk for the OSD
        disk_1 = dbutils.create_test_idisk(
                    device_node='/dev/sdb',
                    device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0',
                    forihostid=self.host.id)

        # Create OSD directly in DB in 'configuring-with-app' state
        # This state triggers the direct DB deletion path which
        # attempts to update host_fs ceph capabilities
        istor = dbutils.create_test_istors(
            forihostid=self.host.id,
            ihost_uuid=self.host.uuid,
            idisk_uuid=disk_1.uuid,
            fortierid=tier.id,
            tier_uuid=tier.uuid,
            tier_name=tier.name,
            state=constants.SB_STATE_CONFIGURING_WITH_APP)

        # DELETE the OSD - should succeed gracefully even without host_fs ceph
        response = self.delete(
            self.get_single_storage_url(istor.uuid),
            headers=self.API_HEADERS,
            expect_errors=False)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify the OSD was actually deleted
        response = self.get_json(
            self.get_single_storage_url(istor.uuid),
            headers=self.API_HEADERS,
            expect_errors=True)
        self.assertIn("could not be found", response.json['error_message'])

    def test_last_osd_delete_preserves_monitor(self):
        """Test that when the last OSD on a host is deleted, the ceph
        monitor function on host-fs remains intact.

        When all OSDs are removed from a host, only the 'osd' function
        should be removed from the ceph host-fs capabilities. The
        'monitor' function must be preserved.

        Validates: Requirements 11.9
        """

        # Rook Ceph backend
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # Create host-fs with both monitor and osd functions
        values = {
            "host_fs_name": "ceph",
            "host_fs_size": 20,
            "host_lv": "ceph-lv",
            "fs_state": constants.HOST_FS_STATUS_IN_USE,
            "capabilities": {"functions": ["monitor", "osd"]}
        }
        self._create_hostfs_db_object(**values)

        # Create storage tier
        dbutils.create_test_storage_tier(
            cluster_uuid=self.cluster.uuid,
            name='storage',
            status=constants.SB_TIER_STATUS_IN_USE)

        # Create a single disk and OSD
        disk_1 = dbutils.create_test_idisk(
                    device_node='/dev/sdb',
                    device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0',
                    forihostid=self.host.id)

        # Add OSD via POST
        values = {
            'ihost_uuid': self.host.uuid,
            'idisk_uuid': disk_1.uuid
        }
        istor = self.post_json('/istors',
                               values,
                               headers=self.API_HEADERS,
                               expect_errors=False)

        self.assertEqual(istor.status_code, http_client.OK)

        # Delete the last (and only) OSD
        response = self.delete(
            self.get_single_storage_url(istor.json['uuid']),
            headers=self.API_HEADERS,
            expect_errors=False)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify OSD is deleted
        response = self.get_json(
            self.get_single_storage_url(istor.json['uuid']),
            headers=self.API_HEADERS,
            expect_errors=True)
        self.assertIn("could not be found", response.json['error_message'])

        # Verify that monitor function remains on host-fs ceph
        # (only osd function should have been removed)
        host_fs = self.get_json('/host_fs', expect_errors=False)
        for fs in host_fs['host_fs']:
            if fs['name'] == constants.FILESYSTEM_NAME_CEPH:
                # Monitor function must be preserved
                self.assertIn("monitor", fs['capabilities']['functions'])
                # OSD function should be removed since it was the last OSD
                self.assertNotIn("osd", fs['capabilities']['functions'])
