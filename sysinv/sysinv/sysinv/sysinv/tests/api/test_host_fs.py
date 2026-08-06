#
# Copyright (c) 2020,2024,2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / host-fs / methods.
"""

import mock
import uuid
from oslo_serialization import jsonutils
from six.moves import http_client
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
from sysinv.common import constants


class FakeConductorAPI(object):

    def __init__(self):
        self.get_controllerfs_lv_sizes = mock.MagicMock()
        self.update_host_filesystem_config = mock.MagicMock()
        self.update_storage_config = mock.MagicMock()
        self.update_ceph_osd_config = mock.MagicMock()


class FakeException(Exception):
        pass


class ApiHostFSTestCaseMixin(base.FunctionalTest,
                             dbbase.ControllerHostTestCase):

    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/ihosts'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'host_fs'

    def setUp(self):
        super(ApiHostFSTestCaseMixin, self).setUp()
        self.host_fs_first = self._create_db_object('scratch',
                                                    8,
                                                    'scratch-lv',
                                                    constants.HOST_FS_STATUS_IN_USE)
        self.host_fs_second = self._create_db_object('backup',
                                                     20,
                                                     'backup-lv',
                                                     constants.HOST_FS_STATUS_IN_USE)
        self.host_fs_third = self._create_db_object('docker',
                                                    40,
                                                    'docker-lv',
                                                    constants.HOST_FS_STATUS_IN_USE)
        self.fake_conductor_api = FakeConductorAPI()
        p = mock.patch('sysinv.conductor.rpcapiproxy.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

    def get_list_url(self, host_uuid):
        return '%s/%s/host_fs' % (self.API_PREFIX, host_uuid)

    def get_single_fs_url(self, host_fs_uuid):
        return '/host_fs/%s' % (host_fs_uuid)

    def get_post_url(self):
        return '/host_fs' % (self.API_PREFIX)

    def get_detail_url(self):
        return '/host_fs/detail'

    def get_update_many_url(self, host_uuid):
        return '%s/%s/host_fs/update_many' % (self.API_PREFIX, host_uuid)

    def get_sorted_list_url(self, host_uuid, sort_attr, sort_dir):
        return '%s/%s/host_fs/?sort_key=%s&sort_dir=%s' % (self.API_PREFIX,
                                                           host_uuid,
                                                           sort_attr,
                                                           sort_dir)

    def _create_db_object(self, host_fs_name, host_fs_size, host_lv,
                          fs_state, capabilities=None, obj_id=None):
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

    def _create_controller_1(self, subfunction=None, numa_nodes=1, **kw):
        return self._create_test_host(
            personality=constants.CONTROLLER,
            subfunction=subfunction,
            numa_nodes=numa_nodes,
            unit=1,
            **kw)


class ApiHostFSListTestSuiteMixin(ApiHostFSTestCaseMixin):
    """ Host FileSystem List GET operations
    """
    def setUp(self):
        super(ApiHostFSListTestSuiteMixin, self).setUp()

    def test_success_fetch_host_fs_list(self):
        response = self.get_json(self.get_list_url(self.host.uuid),
                                                   headers=self.API_HEADERS)

        # Verify the values of the response with the values stored in database
        result_one = response[self.RESULT_KEY][0]
        result_two = response[self.RESULT_KEY][1]
        self.assertTrue(result_one['name'] == self.host_fs_first.name or
                        result_two['name'] == self.host_fs_first.name)
        self.assertTrue(result_one['name'] == self.host_fs_second.name or
                        result_two['name'] == self.host_fs_second.name)

    def test_success_fetch_host_fs_sorted_list(self):
        response = self.get_json(self.get_sorted_list_url(self.host.uuid,
                                                          'name',
                                                          'asc'))

        # Verify the values of the response are returned in a sorted order
        result_one = response[self.RESULT_KEY][0]
        result_two = response[self.RESULT_KEY][1]
        result_three = response[self.RESULT_KEY][2]
        self.assertEqual(result_one['name'], self.host_fs_second.name)
        self.assertEqual(result_two['name'], self.host_fs_third.name)
        self.assertEqual(result_three['name'], self.host_fs_first.name)

    def test_fetch_list_invalid_host(self):
        # Generate random uuid
        random_uuid = uuid.uuid1()
        response = self.get_json(self.get_list_url(random_uuid),
                                                   headers=self.API_HEADERS,
                                                   expect_errors=True)

        # Verify that no host fs is returned for a non-existant host UUID
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json['host_fs'], [])


class ApiHostFSShowTestSuiteMixin(ApiHostFSTestCaseMixin):
    """ Host FileSystem Show GET operations
    """
    def setUp(self):
        super(ApiHostFSShowTestSuiteMixin, self).setUp()

    def test_fetch_host_fs_object(self):
        url = self.get_single_fs_url(self.host_fs_first.uuid)
        response = self.get_json(url)

        # Verify the values of the response with the values stored in database
        self.assertTrue(response['name'], self.host_fs_first.name)
        self.assertTrue(response['logical_volume'],
                        self.host_fs_first.logical_volume)
        self.assertTrue(response['size'], self.host_fs_first.size)
        self.assertTrue(response['uuid'], self.host_fs_first.uuid)
        self.assertTrue(response['ihost_uuid'], self.host.uuid)


class ApiHostFSPatchSingleTestSuiteMixin(ApiHostFSTestCaseMixin):
    """ Individual Host FileSystem Patch operations
    """

    def setUp(self):
        super(ApiHostFSPatchSingleTestSuiteMixin, self).setUp()

    def test_individual_patch_not_allowed(self):
        url = self.get_single_fs_url(self.host_fs_first.uuid)
        response = self.patch_json(url,
                                   [],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.FORBIDDEN)
        self.assertIn("Operation not permitted.",
                      response.json['error_message'])


class ApiHostFSPutTestSuiteMixin(ApiHostFSTestCaseMixin):
    """ Host FileSystem Put operations
    """

    def setUp(self):
        super(ApiHostFSPutTestSuiteMixin, self).setUp()

    def exception_host_fs(self):
        raise FakeException

    def test_put_invalid_fs_name(self):
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "invalid",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "10",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "scratch",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "100",
                                    "op": "replace"}]],
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("HostFs update failed: invalid filesystem 'invalid'",
                      response.json['error_message'])

    def test_put_invalid_fs_size(self):
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "scratch",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "invalid_size",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "backup",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "100",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("HostFs update failed: filesystem 'scratch' "
                      "size must be an integer", response.json['error_message'])

    def test_put_smaller_than_existing_fs_size(self):
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "scratch",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "7",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "backup",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "100",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("HostFs update failed: size for filesystem \'scratch\' "
                      "should be bigger than 8", response.json['error_message'])

    def test_put_unprovisioned_physical_volume(self):
        # Create an unprovisioned physical volume in database
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='unprovisioned')

        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "scratch",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "10",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "backup",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "100",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("There are still unprovisioned physical volumes "
                      "on \'controller-0\'. Cannot perform operation.",
                      response.json['error_message'])

    def test_put_not_enough_space(self):
        # Create a provisioned physical volume in database
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')
        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id,
                                lvm_vg_size=200,
                                lvm_vg_free_pe=50)

        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "scratch",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "10",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "backup",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "100",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("HostFs update failed: Not enough free space on "
                      "cgts-vg. Current free space 0 GiB, requested total "
                      "increase 82 GiB", response.json['error_message'])

    def test_put_success_with_unprovisioned_host(self):
        # Create a provisioned physical volume in database
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "scratch",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "10",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "backup",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "21",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify a NO CONTENT response is given
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

    def test_put_success_with_provisioned_host(self):
        # Create a provisioned host
        self.host = self._create_test_host(personality=constants.CONTROLLER,
                                           unit=1,
                                           invprovision=constants.PROVISIONED)

        # Add host fs for the new host
        self.host_fs_first = self._create_db_object('scratch',
                                                    8,
                                                    'scratch-lv',
                                                    constants.HOST_FS_STATUS_IN_USE)
        self.host_fs_second = self._create_db_object('backup',
                                                     20,
                                                     'backup-lv',
                                                     constants.HOST_FS_STATUS_IN_USE)
        self.host_fs_third = self._create_db_object('docker',
                                                    40,
                                                    'docker-lv',
                                                    constants.HOST_FS_STATUS_IN_USE)

        # Create a provisioned physical volume in database
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "scratch",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "10",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "backup",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "21",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify a NO CONTENT response is given
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

    def test_put_update_exception(self):
        # Create a provisioned host
        self.host = self._create_test_host(personality=constants.CONTROLLER,
                                           unit=1,
                                           invprovision=constants.PROVISIONED)

        self.host_fs_first = self._create_db_object('scratch',
                                                    8,
                                                    'scratch-lv',
                                                    constants.HOST_FS_STATUS_IN_USE)
        self.host_fs_second = self._create_db_object('backup',
                                                     20,
                                                     'backup-lv',
                                                     constants.HOST_FS_STATUS_IN_USE)
        self.host_fs_third = self._create_db_object('docker',
                                                    40,
                                                    'docker-lv',
                                                    constants.HOST_FS_STATUS_IN_USE)

        # Create a provisioned physical volume in database
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Throw a fake exception
        fake_update = self.fake_conductor_api.update_host_filesystem_config
        fake_update.side_effect = self.exception_host_fs

        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "scratch",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "10",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "backup",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "21",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Failed to update filesystem size for controller-1",
                      response.json['error_message'])

    def test_put_fail_function_for_not_ceph_filesystem(self):
        # Create a provisioned host
        self.host = self._create_test_host(personality=constants.CONTROLLER,
                                           unit=1,
                                           invprovision=constants.PROVISIONED)

        # Rook Ceph or Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Add host fs for the new host
        self.host_fs_first = self._create_db_object('instances',
                                                    10,
                                                    'instances-lv',
                                                    constants.HOST_FS_STATUS_READY)

        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "instances",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": '{"functions": ["monitor"]}',
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("HostFs update failed: update functions are only "
                      "supported for %s filesystem with ceph-rook storage backend." %
                        constants.FILESYSTEM_NAME_CEPH,
                      response.json['error_message'])

    def test_put_fail_function_not_supported(self):
        # Create a provisioned host
        self.host = self._create_test_host(personality=constants.CONTROLLER,
                                           unit=1,
                                           invprovision=constants.PROVISIONED)

        # Rook Ceph or Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Add host fs for the new host
        self.host_fs_first = self._create_db_object('ceph',
                                                    10,
                                                    'ceph-lv',
                                                    constants.HOST_FS_STATUS_READY)

        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": '{"functions": ["invalid"]}',
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("HostFs update failed: only the following functions are supported",
                      response.json['error_message'])

    def test_put_success_add_monitor_function(self):
        # Create a provisioned host
        self.host = self._create_test_host(personality=constants.CONTROLLER,
                                           unit=1,
                                           invprovision=constants.PROVISIONED)

        # Rook Ceph or Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Add host fs for the new host
        self.host_fs_first = self._create_db_object('ceph',
                                                    10,
                                                    'ceph-lv',
                                                    constants.HOST_FS_STATUS_READY,
                                                    {"functions": ["osd"]})

        capabilities = {"functions": ["monitor", "osd"]}
        self.put_json(self.get_update_many_url(self.host.uuid),
                      [[{"path": "/name",
                          "value": "ceph",
                          "op": "replace"},
                        {"path": "/capabilities",
                          "value": jsonutils.dumps(capabilities),
                          "op": "replace"}]],
                      headers=self.API_HEADERS,
                      expect_errors=False)

        url = self.get_single_fs_url(self.host_fs_first.uuid)
        response = self.get_json(url,
                                 headers=self.API_HEADERS,
                                 expect_errors=False)

        self.assertEqual(response['capabilities'], capabilities)

    def test_put_fail_remove_osd_function(self):
        # Create a provisioned host
        self.host = self._create_test_host(personality=constants.CONTROLLER,
                                           unit=1,
                                           invprovision=constants.PROVISIONED)

        # Rook Ceph or Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Add host fs for the new host
        self.host_fs_first = self._create_db_object('ceph',
                                                    10,
                                                    'ceph-lv',
                                                    constants.HOST_FS_STATUS_READY,
                                                    {"functions": ["monitor", "osd"]})

        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": '{"functions": ["monitor"]}',
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("please use the host-stor-delete to remove the osd function",
                      response.json['error_message'])

        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                [[{"path": "/name",
                                  "value": "ceph",
                                  "op": "replace"},
                                {"path": "/capabilities",
                                  "value": '{"functions": []}',
                                  "op": "replace"}]],
                                headers=self.API_HEADERS,
                                expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("please use the host-stor-delete to remove the osd function",
                      response.json['error_message'])

    def test_put_success_remove_monitor_function_case_1(self):
        """ Removing the monitor function from ceph host-fs in ready state.
            Initial functions: monitor and osd.
        """
        # Create a provisioned host
        self.host = self._create_test_host(personality=constants.CONTROLLER,
                                           unit=1,
                                           invprovision=constants.PROVISIONED)

        # Rook Ceph or Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Add host fs for the new host
        self.host_fs_first = self._create_db_object('ceph',
                                                    10,
                                                    'ceph-lv',
                                                    constants.HOST_FS_STATUS_READY,
                                                    {"functions": ["monitor", "osd"]})

        # Create a provisioned physical volume in database
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        capabilities = {"functions": ["osd"]}
        self.put_json(self.get_update_many_url(self.host.uuid),
                      [[{"path": "/name",
                          "value": "ceph",
                          "op": "replace"},
                        {"path": "/capabilities",
                          "value": jsonutils.dumps(capabilities),
                          "op": "replace"}]],
                      headers=self.API_HEADERS,
                      expect_errors=False)

        url = self.get_single_fs_url(self.host_fs_first.uuid)
        response = self.get_json(url,
                                 headers=self.API_HEADERS,
                                 expect_errors=False)

        self.assertEqual(response['capabilities'], capabilities)

    def test_put_success_remove_monitor_function_case_2(self):
        """ Removing the monitor function from ceph host-fs in ready status.
            Initial function: monitor.
        """
        # Create a provisioned host
        self.host = self._create_test_host(personality=constants.CONTROLLER,
                                           unit=1,
                                           invprovision=constants.PROVISIONED)

        # Rook Ceph or Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Add host fs for the new host
        self.host_fs_first = self._create_db_object('ceph',
                                                    10,
                                                    'ceph-lv',
                                                    constants.HOST_FS_STATUS_READY,
                                                    {"functions": ["monitor"]})

        capabilities = {"functions": []}
        self.put_json(self.get_update_many_url(self.host.uuid),
                      [[{"path": "/name",
                          "value": "ceph",
                          "op": "replace"},
                        {"path": "/capabilities",
                          "value": jsonutils.dumps(capabilities),
                          "op": "replace"}]],
                      headers=self.API_HEADERS,
                      expect_errors=False)

        url = self.get_single_fs_url(self.host_fs_first.uuid)
        response = self.get_json(url,
                                 headers=self.API_HEADERS,
                                 expect_errors=False)

        self.assertEqual(response['capabilities'], capabilities)

    def test_put_success_remove_monitor_function_case_3(self):
        """ Removing the last monitor function in use.
            Initial function: monitor.
        """
        # Create a provisioned host
        self.host = self._create_test_host(personality=constants.CONTROLLER,
                                           unit=1,
                                           invprovision=constants.PROVISIONED)

        # Rook Ceph or Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Add host fs for the new host
        self.host_fs_first = self._create_db_object('ceph',
                                                    10,
                                                    'ceph-lv',
                                                    constants.HOST_FS_STATUS_IN_USE,
                                                    {"functions": ["monitor"]})

        capabilities = {"functions": []}
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": jsonutils.dumps(capabilities),
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("it is not possible to remove the last monitor in use",
                      response.json['error_message'])

    def test_put_fail_remove_monitor_function_with_osd_retained(self):
        """ Removing the last monitor function in use while keeping OSD.
            Initial functions: monitor and osd.
            Bug scenario: if not functions: guard was bypassed when OSD retained.
        """
        # Rook Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Add host fs ceph with monitor and osd, state In-Use
        self.host_fs_first = self._create_db_object('ceph',
                                                    10,
                                                    'ceph-lv',
                                                    constants.HOST_FS_STATUS_IN_USE,
                                                    {"functions": ["monitor", "osd"]})

        # Try to remove monitor while keeping osd
        capabilities = {"functions": ["osd"]}
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": jsonutils.dumps(capabilities),
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("it is not possible to remove the last monitor in use",
                      response.json['error_message'])

    def test_put_success_remove_monitor_with_multiple_monitors(self):
        """ Removing a monitor when 2+ monitors exist (not last).
            Should be allowed since it's not the last monitor.
        """
        # Rook Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Add host fs ceph with monitor and osd, state In-Use (this host)
        self.host_fs_first = self._create_db_object('ceph',
                                                    10,
                                                    'ceph-lv',
                                                    constants.HOST_FS_STATUS_IN_USE,
                                                    {"functions": ["monitor", "osd"]})

        # Create a second host with monitor (so count > 1)
        host2 = self._create_test_host(personality=constants.CONTROLLER,
                                       unit=1,
                                       invprovision=constants.PROVISIONED)
        dbutils.create_test_host_fs(id=99,
                                    name='ceph',
                                    forihostid=host2.id,
                                    size=10,
                                    logical_volume='ceph-lv',
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Remove monitor from first host - should succeed (not last mon)
        capabilities = {"functions": ["osd"]}
        self.put_json(self.get_update_many_url(self.host.uuid),
                      [[{"path": "/name",
                         "value": "ceph",
                         "op": "replace"},
                        {"path": "/capabilities",
                         "value": jsonutils.dumps(capabilities),
                         "op": "replace"}]],
                      headers=self.API_HEADERS,
                      expect_errors=False)

    def test_put_success_resizing_and_functions_for_ceph(self):
        # Create a provisioned host
        self.host = self._create_test_host(personality=constants.CONTROLLER,
                                           unit=1,
                                           invprovision=constants.PROVISIONED)

        # Rook Ceph or Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Add host fs for the new host
        self.host_fs_first = self._create_db_object('ceph',
                                                    10,
                                                    'ceph-lv',
                                                    constants.HOST_FS_STATUS_READY)

        # Create a provisioned physical volume in database
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        size = 11
        capabilities = {"functions": []}
        self.put_json(self.get_update_many_url(self.host.uuid),
                      [[{"path": "/name",
                         "value": "ceph",
                         "op": "replace"},
                        {"path": "/size",
                         "value": size,
                         "op": "replace"},
                        {"path": "/capabilities",
                         "value": jsonutils.dumps(capabilities),
                         "op": "replace"}]],
                      headers=self.API_HEADERS,
                      expect_errors=False)

        url = self.get_single_fs_url(self.host_fs_first.uuid)
        response = self.get_json(url,
                                 headers=self.API_HEADERS,
                                 expect_errors=False)

        self.assertEqual(response['capabilities'], capabilities)
        self.assertEqual(response['size'], size)

    def test_put_fail_optional_fs_not_ready(self):
        """Resize of an optional filesystem is rejected when state != READY."""
        # Create a provisioned host
        self.host = self._create_test_host(personality=constants.CONTROLLER,
                                           unit=1,
                                           invprovision=constants.PROVISIONED)

        # Rook Ceph must be configured as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create an optional ceph filesystem in IN_USE state (not READY)
        self.host_fs_first = self._create_db_object('ceph',
                                                    10,
                                                    'ceph-lv',
                                                    constants.HOST_FS_STATUS_IN_USE)

        # Create a provisioned physical volume in database
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "11",
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("resize for optional filesystem",
                      response.json['error_message'])
        self.assertIn("only possible with state",
                      response.json['error_message'])

    def test_put_fail_create_in_svc_state(self):
        """Resize is rejected when a non-optional filesystem is in CREATE_IN_SVC state."""
        # Update the scratch filesystem to CREATE_IN_SVC state to trigger
        # the state check for non-optional filesystems
        self.dbapi.host_fs_update(self.host_fs_first.id,
                                  {'state': constants.HOST_FS_STATUS_CREATE_IN_SVC})

        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "scratch",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "10",
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("It is not possible to resize filesystems",
                      response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.utils.is_drbd_fs_resizing')
    def test_put_fail_drbd_resizing(self, mock_is_drbd_fs_resizing):
        """Resize is rejected when a DRBD filesystem resize is in progress."""
        mock_is_drbd_fs_resizing.return_value = True

        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "scratch",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "10",
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("drdb filesystem resize in progress",
                      response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.utils.is_host_lvg_updated')
    def test_put_fail_pending_lvg_update(self, mock_is_host_lvg_updated):
        """Resize is rejected when LVG update is still pending."""
        mock_is_host_lvg_updated.return_value = False

        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "scratch",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "10",
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("LVG update is still pending",
                      response.json['error_message'])

    def test_put_fail_add_monitor_exceeds_max(self):
        """Adding monitor function is rejected when max monitors reached."""
        # Create a provisioned host
        self.host = self._create_test_host(personality=constants.CONTROLLER,
                                           unit=1,
                                           invprovision=constants.PROVISIONED)

        # Rook Ceph must be configured as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph filesystems with monitor function on multiple hosts
        # to reach FILESYSTEM_CEPH_MONITOR_MAX (5)
        for i in range(constants.FILESYSTEM_CEPH_MONITOR_MAX):
            host = self._create_test_host(personality=constants.WORKER,
                                          unit=i + 2,
                                          numa_nodes=1)
            dbutils.create_test_host_fs(
                id=100 + i,
                name=constants.FILESYSTEM_NAME_CEPH,
                forihostid=host.id,
                size=10,
                logical_volume='ceph-lv',
                state=constants.HOST_FS_STATUS_IN_USE,
                capabilities={"functions": ["monitor"]})

        # Add host fs for the provisioned host without monitor function
        self.host_fs_first = self._create_db_object('ceph',
                                                    10,
                                                    'ceph-lv',
                                                    constants.HOST_FS_STATUS_READY,
                                                    {"functions": ["osd"]})

        # Try to add monitor function, which would exceed max
        capabilities = {"functions": ["monitor", "osd"]}
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": jsonutils.dumps(capabilities),
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Number of monitors cannot exceed",
                      response.json['error_message'])

    def test_put_fail_remove_last_monitor_in_use(self):
        """Removing the last monitor is rejected when it is in use."""
        # Create a provisioned host
        self.host = self._create_test_host(personality=constants.CONTROLLER,
                                           unit=1,
                                           invprovision=constants.PROVISIONED)

        # Rook Ceph must be configured as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create a single ceph filesystem with only monitor function in IN_USE state.
        # This is the last (and only) monitor in the system.
        self.host_fs_first = self._create_db_object('ceph',
                                                    10,
                                                    'ceph-lv',
                                                    constants.HOST_FS_STATUS_IN_USE,
                                                    {"functions": ["monitor"]})

        # Try to remove all functions (removing the last monitor in use)
        capabilities = {"functions": []}
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": jsonutils.dumps(capabilities),
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("it is not possible to remove the last monitor in use",
                      response.json['error_message'])

    def test_host_fs_resize_with_controller_fs(self):
        """Test that resizing a host-fs ceph is validated against
        controller-fs constraints when a controller-fs ceph-float exists.

        When a ceph-float controller-fs depends on the host-fs ceph
        filesystems, the resize operation should validate that the new
        size does not conflict with the controller-fs configuration.

        This test verifies a successful resize of host-fs ceph when a
        controller-fs ceph-float exists, confirming the resize operation
        properly validates against controller-fs constraints.

        Validates: Requirements 11.8
        """
        # Create a provisioned host (separate from the default one
        # to avoid interference with default filesystem entries)
        self.host = self._create_test_host(personality=constants.CONTROLLER,
                                           unit=1,
                                           invprovision=constants.PROVISIONED)

        # Rook Ceph must be configured as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Add host fs entries for the new host (standard set)
        self.host_fs_first = self._create_db_object('scratch',
                                                    8,
                                                    'scratch-lv',
                                                    constants.HOST_FS_STATUS_IN_USE)
        self.host_fs_second = self._create_db_object('backup',
                                                     20,
                                                     'backup-lv',
                                                     constants.HOST_FS_STATUS_IN_USE)
        self.host_fs_third = self._create_db_object('docker',
                                                    40,
                                                    'docker-lv',
                                                    constants.HOST_FS_STATUS_IN_USE)

        # Create host-fs ceph on the provisioned host in READY state
        # (READY is required for resize of optional filesystems)
        self._create_db_object('ceph',
                              10,
                              'ceph-lv',
                              constants.HOST_FS_STATUS_READY,
                              {"functions": ["monitor"]})

        # Create controller-fs ceph-float (the dependent controller-fs)
        dbutils.create_test_controller_fs(
            uuid=None,
            name='ceph-float',
            forisystemid=self.system.id,
            state=str({'status': constants.CONTROLLER_FS_AVAILABLE}),
            capabilities={"functions": ["monitor"]},
            size=20,
            logical_volume='ceph-float-lv',
            replicated=True,
            isystem_uuid=self.system.uuid)

        # Create a provisioned physical volume in database
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        # Create a logical volume (use defaults which give ~48 GiB free)
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Attempt to resize host-fs ceph — should succeed because
        # the resize is compatible with the controller-fs constraints
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "15",
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        # The resize should succeed (HTTP 204 NO CONTENT)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

    def test_put_capabilities_only_state_reconfigure_with_app(self):
        """Test that updating only capabilities (no size change) on host-fs
        sets the state to RECONFIGURE_WITH_APP."""

        # Rook Ceph must be configured as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph host-fs with osd function in READY state
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_READY,
                                         {"functions": ["osd"]})

        # PUT with capability change only (no size field)
        new_capabilities = {"functions": ["monitor", "osd"]}
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": jsonutils.dumps(new_capabilities),
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify state transitioned to RECONFIGURE_WITH_APP
        updated_fs = self.dbapi.host_fs_get(ceph_fs.uuid)
        self.assertEqual(updated_fs.state,
                         constants.HOST_FS_STATUS_RECONFIGURE_WITH_APP)

    def test_put_capabilities_with_size_state_reconfigure_with_app(self):
        """Test that updating both capabilities AND size on host-fs
        sets the state to RECONFIGURE_WITH_APP (not MODIFYING),
        because capabilities take priority."""

        # Rook Ceph must be configured as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create LVG with enough free space for the resize
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Host must be provisioned for the RPC to be called
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED})

        # Create ceph host-fs with osd function in READY state
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_READY,
                                         {"functions": ["osd"]})

        # PUT with both capability AND size change
        new_capabilities = {"functions": ["monitor", "osd"]}
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "25",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": jsonutils.dumps(new_capabilities),
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify state is RECONFIGURE_WITH_APP (capabilities win over size)
        updated_fs = self.dbapi.host_fs_get(ceph_fs.uuid)
        self.assertEqual(updated_fs.state,
                         constants.HOST_FS_STATUS_RECONFIGURE_WITH_APP)

    def test_put_fail_resize_while_reconfigure_with_app(self):
        """Test that resizing an optional host-fs (ceph) is rejected when
        the filesystem is in RECONFIGURE_WITH_APP state (not READY)."""

        # Create a provisioned host
        self.host = self._create_test_host(personality=constants.CONTROLLER,
                                           unit=1,
                                           invprovision=constants.PROVISIONED)

        # Rook Ceph must be configured as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph host-fs in RECONFIGURE_WITH_APP state
        self.host_fs_first = self._create_db_object('ceph',
                                                    20,
                                                    'ceph-lv',
                                                    constants.HOST_FS_STATUS_RECONFIGURE_WITH_APP,
                                                    {"functions": ["monitor"]})

        # Create a provisioned physical volume
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Try to resize — should be rejected because state != READY
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "25",
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("resize for optional filesystem",
                      response.json['error_message'])
        self.assertIn("only possible with state",
                      response.json['error_message'])

    def test_put_fail_add_monitor_while_create_on_unlock(self):
        """Test that adding monitor function to a host-fs ceph in
        CREATE_ON_UNLOCK state is rejected.

        When host-stor-add is executed on a locked host, the host-fs ceph
        is created with CREATE_ON_UNLOCK state. Capability updates must
        not be allowed until the filesystem is physically created after
        unlock."""

        # Rook Ceph must be configured
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph host-fs in CREATE_ON_UNLOCK state with osd function
        # (simulates what host-stor-add does on a locked host)
        self._create_db_object('ceph',
                               20,
                               'ceph-lv',
                               constants.HOST_FS_STATUS_CREATE_ON_UNLOCK,
                               {"functions": ["osd"]})

        # Try to add monitor function via PUT (capability-only update)
        new_capabilities = {"functions": ["monitor", "osd"]}
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": jsonutils.dumps(new_capabilities),
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_put_fail_add_monitor_while_creating(self):
        """Test that adding monitor function to a host-fs ceph in
        CREATE_IN_SVC state is rejected.

        The filesystem is currently being created by the conductor.
        Capability updates must wait until creation completes."""

        # Rook Ceph must be configured
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph host-fs in CREATE_IN_SVC state with osd function
        self._create_db_object('ceph',
                               20,
                               'ceph-lv',
                               constants.HOST_FS_STATUS_CREATE_IN_SVC,
                               {"functions": ["osd"]})

        # Try to add monitor function via PUT
        new_capabilities = {"functions": ["monitor", "osd"]}
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": jsonutils.dumps(new_capabilities),
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_put_fail_modify_capabilities_while_deleting(self):
        """Test that modifying capabilities on a host-fs ceph in
        DELETING state is rejected.

        The filesystem is being deleted. Capability updates must not
        be allowed on a filesystem pending deletion."""

        # Rook Ceph must be configured
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph host-fs in DELETING state with monitor+osd functions
        self._create_db_object('ceph',
                               20,
                               'ceph-lv',
                               constants.HOST_FS_STATUS_DELETING,
                               {"functions": ["monitor", "osd"]})

        # Try to remove monitor function while deleting
        new_capabilities = {"functions": ["osd"]}
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": jsonutils.dumps(new_capabilities),
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_put_fail_add_monitor_while_modifying(self):
        """Test that adding monitor function to a host-fs ceph in
        MODIFYING state (resize in progress) is rejected.

        A resize operation is underway. Capability updates must wait
        until the resize completes."""

        # Rook Ceph must be configured
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph host-fs in MODIFYING state with osd function
        self._create_db_object('ceph',
                               20,
                               'ceph-lv',
                               constants.HOST_FS_STATUS_MODIFYING,
                               {"functions": ["osd"]})

        # Try to add monitor function while resize is in progress
        new_capabilities = {"functions": ["monitor", "osd"]}
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": jsonutils.dumps(new_capabilities),
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_put_fail_add_monitor_backend_applying(self):
        """Test that adding monitor function to a host-fs ceph is rejected
        when the rook-ceph storage backend is in configuring-with-app state
        with task=applying (app is being applied).

        Capability updates should be blocked when the ceph-rook backend
        is in a transitional state because the app cannot process
        concurrent configuration changes."""

        # Rook Ceph backend in CONFIGURING_WITH_APP state with task=applying
        # (simulates: system application-apply rook-ceph in progress)
        backend = dbutils.get_test_ceph_rook_storage_backend(
            state=constants.SB_STATE_CONFIGURING_WITH_APP,
            task=constants.APP_APPLY_IN_PROGRESS)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph host-fs in READY state with osd function
        self._create_db_object('ceph',
                               20,
                               'ceph-lv',
                               constants.HOST_FS_STATUS_READY,
                               {"functions": ["osd"]})

        # Try to add monitor function while app is applying
        new_capabilities = {"functions": ["monitor", "osd"]}
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": jsonutils.dumps(new_capabilities),
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        # Should be rejected because backend is in transitional state
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_put_fail_add_monitor_backend_removing(self):
        """Test that adding monitor function to a host-fs ceph is rejected
        when the rook-ceph storage backend task is 'removing' (app being
        removed).

        Any capability updates should be blocked during app transitions."""

        # Rook Ceph backend in CONFIGURING_WITH_APP with task=removing
        backend = dbutils.get_test_ceph_rook_storage_backend(
            state=constants.SB_STATE_CONFIGURING_WITH_APP,
            task=constants.APP_REMOVE_IN_PROGRESS)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph host-fs in READY state with osd function
        self._create_db_object('ceph',
                               20,
                               'ceph-lv',
                               constants.HOST_FS_STATUS_READY,
                               {"functions": ["osd"]})

        # Try to add monitor function while app is being removed
        new_capabilities = {"functions": ["monitor", "osd"]}
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": jsonutils.dumps(new_capabilities),
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        # Should be rejected because backend/app is in transitional state
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_put_fail_remove_monitor_backend_applying(self):
        """Test that removing monitor function from a host-fs ceph is
        rejected when the rook-ceph backend task is 'applying'.

        Even removing functions should be blocked during app transitions
        because the app needs to be in a stable state to process changes."""

        # Rook Ceph backend in CONFIGURING_WITH_APP with task=applying
        backend = dbutils.get_test_ceph_rook_storage_backend(
            state=constants.SB_STATE_CONFIGURING_WITH_APP,
            task=constants.APP_APPLY_IN_PROGRESS)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph host-fs in IN_USE state with monitor+osd functions
        self._create_db_object('ceph',
                               20,
                               'ceph-lv',
                               constants.HOST_FS_STATUS_IN_USE,
                               {"functions": ["monitor", "osd"]})

        # Try to remove monitor function while app is applying
        new_capabilities = {"functions": ["osd"]}
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": jsonutils.dumps(new_capabilities),
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        # Should be rejected
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_put_no_state_change_when_capabilities_reverted(self):
        """Test that submitting the same capabilities already stored in DB
        does not alter the filesystem state (true no-op).

        If capabilities are identical to current, nothing should change —
        the state must remain exactly as it was."""

        # Rook Ceph must be configured
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph host-fs in READY state with osd function
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_READY,
                                         {"functions": ["osd"]})

        # Submit the exact same capabilities that are already stored
        same_capabilities = {"functions": ["osd"]}
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": jsonutils.dumps(same_capabilities),
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # State must remain READY — no change happened
        final_fs = self.dbapi.host_fs_get(ceph_fs.uuid)
        self.assertEqual(final_fs.state, constants.HOST_FS_STATUS_READY)
        # Must NOT have transitioned to Reconfigure with App
        self.assertNotEqual(final_fs.state,
                            constants.HOST_FS_STATUS_RECONFIGURE_WITH_APP)

    def test_put_fail_remove_monitor_controller_fs_reconfigure(self):
        """Test that removing the monitor function from a host-fs ceph
        entry is blocked when the controller-fs ceph-float is in
        'reconfigure-with-app' state."""

        # Set up Rook Ceph storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Host must be provisioned for the floating monitor check to apply
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED,
                                 'administrative': constants.ADMIN_LOCKED,
                                 'availability': constants.AVAILABILITY_ONLINE})

        # Create host-fs ceph with monitor+osd functions in IN_USE state
        self._create_db_object('ceph',
                               20,
                               'ceph-lv',
                               constants.HOST_FS_STATUS_IN_USE,
                               {"functions": ["monitor", "osd"]})

        # Create controller-fs ceph-float in RECONFIGURE_WITH_APP state
        dbutils.create_test_controller_fs(
            name=constants.FILESYSTEM_NAME_CEPH_DRBD,
            forisystemid=self.system.id,
            state=str({'status': constants.CONTROLLER_FS_RECONFIGURE_WITH_APP}),
            size=20,
            logical_volume='ceph-float-lv',
            replicated=True,
            isystem_uuid=self.system.uuid)

        # Try to REMOVE monitor function — should be blocked because
        # controller-fs ceph-float is in reconfigure-with-app state
        new_capabilities = {"functions": ["osd"]}
        response = self.put_json(self.get_update_many_url(self.host.uuid),
                                 [[{"path": "/name",
                                    "value": "ceph",
                                    "op": "replace"},
                                   {"path": "/capabilities",
                                    "value": jsonutils.dumps(new_capabilities),
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        # Assert HTTP 400 - blocked by controller-fs reconfigure state
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(constants.CONTROLLER_FS_RECONFIGURE_WITH_APP,
                      response.json['error_message'])
        self.assertIn("Please apply the application",
                      response.json['error_message'])


class ApiHostFSDetailTestSuiteMixin(ApiHostFSTestCaseMixin):
    """ Host FileSystem detail operations
    """
    def setUp(self):
        super(ApiHostFSDetailTestSuiteMixin, self).setUp()

    # Test that a valid PATCH operation is blocked by the API
    def test_success_detail(self):
        # Test that a valid PATCH operation is blocked by the API
        response = self.get_json(self.get_detail_url(),
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.status_code, http_client.OK)
        result_one = response.json[self.RESULT_KEY][0]
        result_two = response.json[self.RESULT_KEY][1]
        result_three = response.json[self.RESULT_KEY][2]

        # Response object 1
        self.assertEqual(result_one['size'], self.host_fs_first.size)
        self.assertEqual(result_one['name'], self.host_fs_first.name)
        self.assertEqual(result_one['logical_volume'],
                         self.host_fs_first.logical_volume)
        self.assertEqual(result_one['ihost_uuid'], self.host.uuid)
        self.assertEqual(result_one['uuid'], self.host_fs_first.uuid)

        # Response object 2
        self.assertEqual(result_two['size'], self.host_fs_second.size)
        self.assertEqual(result_two['name'], self.host_fs_second.name)
        self.assertEqual(result_two['logical_volume'],
                         self.host_fs_second.logical_volume)
        self.assertEqual(result_two['ihost_uuid'], self.host.uuid)
        self.assertEqual(result_two['uuid'], self.host_fs_second.uuid)

        # Response object 3
        self.assertEqual(result_three['size'], self.host_fs_third.size)
        self.assertEqual(result_three['name'], self.host_fs_third.name)
        self.assertEqual(result_three['logical_volume'],
                         self.host_fs_third.logical_volume)
        self.assertEqual(result_three['ihost_uuid'], self.host.uuid)
        self.assertEqual(result_three['uuid'], self.host_fs_third.uuid)


class ApiHostFSDeleteTestSuiteMixin(ApiHostFSTestCaseMixin):
    """ Host FileSystem delete operations
    """
    def setUp(self):
        super(ApiHostFSDeleteTestSuiteMixin, self).setUp()

    # Test that a valid DELETE operation is blocked by the API
    # API should return 400 BAD_REQUEST or FORBIDDEN 403
    def test_delete_not_allowed(self):
        uuid = self.host_fs_third.uuid
        response = self.delete(self.get_single_fs_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Unsupported filesystem",
                      response.json['error_message'])

    # Test a valid DELETE operation with an optional filesystem allowed to
    # be deleted
    def test_delete_allowed(self):

        # Rook Ceph or Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_READY)

        uuid = ceph_fs.uuid
        response = self.delete(self.get_single_fs_url(uuid),
                            headers=self.API_HEADERS,
                            expect_errors=False)

        # Verify the expected API response for the delete
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

    def test_delete_ceph_in_use_blocked(self):
        """ Delete of ceph host-fs in In-Use state should be blocked.
            Only Ready, Create on Unlock, and Error states allow deletion.
        """
        # Rook Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph fs in In-Use state
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_IN_USE,
                                         {"functions": ["monitor", "osd"]})

        uuid = ceph_fs.uuid
        response = self.delete(self.get_single_fs_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("only possible for states",
                      response.json['error_message'])

    def test_delete_force_rook_osd_removal(self):
        """Test that force deleting a ceph host_fs with rook-ceph backend
        marks associated OSDs for removal."""

        # Set up Rook Ceph storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph host_fs with OSD function
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_READY,
                                         capabilities={"functions": [
                                             constants.FILESYSTEM_CEPH_FUNCTION_OSD]})

        # Create an OSD associated with this host
        disk = dbutils.create_test_idisk(
            device_node='/dev/sdb',
            device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0',
            forihostid=self.host.id)
        istor = dbutils.create_test_istors(
            forihostid=self.host.id,
            ihost_uuid=self.host.uuid,
            idisk_uuid=disk.uuid,
            state='configured')

        # DELETE with force=True (path segment)
        response = self.delete(self.get_single_fs_url(ceph_fs.uuid) + '/True',
                               headers=self.API_HEADERS,
                               expect_errors=False)

        # Verify HTTP 204 success
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify OSD marked for removal
        updated_stor = self.dbapi.istor_get(istor.uuid)
        self.assertEqual(updated_stor.state,
                         constants.SB_STATE_FORCE_DELETING_WITH_APP)

        # Verify capabilities updated with marked_for_removal
        updated_fs = self.dbapi.host_fs_get(ceph_fs.uuid)
        self.assertTrue(
            updated_fs.capabilities.get(constants.FILESYSTEM_CEPH_MARKED_FOR_REMOVAL))

    def test_delete_provisioning_direct_db(self):
        """Test that deleting a host_fs on a host in PROVISIONING state
        performs a direct DB deletion without RPC calls."""

        # Set up Rook Ceph storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Set host to PROVISIONING state and locked+online (staged=True)
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONING,
                                 'administrative': constants.ADMIN_LOCKED,
                                 'availability': constants.AVAILABILITY_ONLINE})

        # Create ceph host_fs in READY state (allowed for deletion)
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_READY)

        # DELETE the filesystem
        response = self.delete(self.get_single_fs_url(ceph_fs.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=False)

        # Verify HTTP 204 success
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify no RPC call was made
        self.fake_conductor_api.update_host_filesystem_config.assert_not_called()

        # Verify DB record removed
        host_fs_list = self.dbapi.host_fs_get_by_ihost(self.host.uuid)
        ceph_entries = [fs for fs in host_fs_list
                        if fs['name'] == constants.FILESYSTEM_NAME_CEPH]
        self.assertEqual(len(ceph_entries), 0)

    def test_delete_staged_deleting_on_unlock(self):
        """Test that a staged delete on a locked+online host sets the
        filesystem state to DELETING_ON_UNLOCK."""

        # Set up Rook Ceph storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Set host to locked+online with provisioned state
        # (not PROVISIONING so it won't do direct DB destroy)
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED,
                                 'administrative': constants.ADMIN_LOCKED,
                                 'availability': constants.AVAILABILITY_ONLINE})

        # Create ceph host_fs in READY state (allowed for deletion)
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_READY)

        # DELETE the filesystem
        response = self.delete(self.get_single_fs_url(ceph_fs.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=False)

        # Verify HTTP 204 success
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify filesystem state set to DELETING_ON_UNLOCK
        updated_fs = self.dbapi.host_fs_get(ceph_fs.uuid)
        self.assertEqual(updated_fs.state,
                         constants.HOST_FS_STATUS_DELETING_ON_UNLOCK)

    def test_delete_non_staged_available_host(self):
        """Test that a non-staged delete on an available/unlocked host sets
        the filesystem state to DELETING and makes an RPC call to conductor."""

        # Set up Rook Ceph storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Set host to unlocked+available (not locked+online, so staged=False)
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED,
                                 'administrative': constants.ADMIN_UNLOCKED,
                                 'operational': constants.OPERATIONAL_ENABLED,
                                 'availability': constants.AVAILABILITY_AVAILABLE})

        # Create ceph host_fs in READY state (allowed for deletion)
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_READY)

        # DELETE the filesystem
        response = self.delete(self.get_single_fs_url(ceph_fs.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=False)

        # Verify HTTP 204 success
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify filesystem state set to DELETING
        updated_fs = self.dbapi.host_fs_get(ceph_fs.uuid)
        self.assertEqual(updated_fs.state,
                         constants.HOST_FS_STATUS_DELETING)

        # Verify RPC call was made to conductor
        self.fake_conductor_api.update_host_filesystem_config.assert_called_once()

    @mock.patch('sysinv.common.utils.is_floating_monitor_assigned')
    def test_delete_fail_monitor_floating_active(self, mock_floating_monitor):
        """Test that deleting a ceph host_fs with monitor function fails
        when the floating monitor is active."""

        # Mock floating monitor as assigned
        mock_floating_monitor.return_value = True

        # Set up Rook Ceph storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Host must be provisioned for the floating monitor check to apply
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED,
                                 'administrative': constants.ADMIN_LOCKED,
                                 'availability': constants.AVAILABILITY_ONLINE})

        # Create ceph host_fs with monitor function in READY state
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_READY,
                                         capabilities={"functions": [
                                             constants.FILESYSTEM_CEPH_FUNCTION_MONITOR]})

        # DELETE the filesystem
        response = self.delete(self.get_single_fs_url(ceph_fs.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)

        # Verify HTTP 400 indicating deletion is blocked
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("cannot delete a fixed monitor",
                      response.json['error_message'])

    def test_delete_rpc_failure_rollback(self):
        """Test that when an RPC failure occurs during non-staged delete,
        the error is reported to the client and the host_fs entry remains
        in the database (the code attempts rollback via host_fs_create,
        but since the record was only state-updated not destroyed, the
        record persists)."""

        # Set up Rook Ceph storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Set host to unlocked+available (non-staged path)
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED,
                                 'administrative': constants.ADMIN_UNLOCKED,
                                 'operational': constants.OPERATIONAL_ENABLED,
                                 'availability': constants.AVAILABILITY_AVAILABLE})

        # Create ceph host_fs in READY state
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_READY)

        # Mock conductor RPC to raise exception
        self.fake_conductor_api.update_host_filesystem_config.side_effect = \
            Exception("RPC communication failure")

        # DELETE the filesystem
        response = self.delete(self.get_single_fs_url(ceph_fs.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)

        # Verify error response (409 because rollback host_fs_create finds
        # the record still exists — it was only state-updated, not destroyed)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.CONFLICT)
        self.assertIn("already exists",
                      str(response.json))

        # Verify host_fs entry is still present in the DB
        host_fs_list = self.dbapi.host_fs_get_by_ihost(self.host.uuid)
        ceph_entries = [fs for fs in host_fs_list
                        if fs['name'] == constants.FILESYSTEM_NAME_CEPH]
        self.assertEqual(len(ceph_entries), 1)

    @mock.patch('sysinv.common.utils.is_floating_monitor_assigned')
    def test_delete_host_fs_blocked_by_controller_fs(self,
                                                     mock_floating_monitor):
        """Test that deleting a host-fs ceph entry is blocked when a
        controller-fs ceph-float exists that depends on it. The floating
        monitor must be removed first.

        Validates: Requirements 11.3
        """

        # Mock floating monitor as assigned (controller-fs ceph-float exists
        # with monitor function)
        mock_floating_monitor.return_value = True

        # Set up Rook Ceph storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Host must be provisioned for the floating monitor check to apply
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED,
                                 'administrative': constants.ADMIN_LOCKED,
                                 'availability': constants.AVAILABILITY_ONLINE})

        # Create host-fs ceph with monitor function in READY state
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_READY,
                                         capabilities={"functions": [
                                             constants.FILESYSTEM_CEPH_FUNCTION_MONITOR]})

        # DELETE the host-fs ceph entry
        response = self.delete(self.get_single_fs_url(ceph_fs.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)

        # Assert HTTP 400 indicating dependency blocks deletion
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("cannot delete a fixed monitor",
                      response.json['error_message'])
        self.assertIn(constants.FILESYSTEM_NAME_CEPH_DRBD,
                      response.json['error_message'])

    def test_delete_blocked_by_controller_fs_reconfigure_state(self):
        """Test that deleting a host-fs ceph entry is blocked when the
        controller-fs ceph-float is in 'reconfigure-with-app' state.

        The _check_ceph_floating_monitor function checks the controller-fs
        state before checking is_floating_monitor_assigned. If ceph-float
        is in reconfigure-with-app, it means a pending config has not been
        applied and the floating monitor is still effectively active."""

        # Set up Rook Ceph storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Host must be provisioned for the floating monitor check to apply
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED,
                                 'administrative': constants.ADMIN_LOCKED,
                                 'availability': constants.AVAILABILITY_ONLINE})

        # Create host-fs ceph with monitor function in READY state
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_READY,
                                         capabilities={"functions": [
                                             constants.FILESYSTEM_CEPH_FUNCTION_MONITOR]})

        # Create controller-fs ceph-float in RECONFIGURE_WITH_APP state
        dbutils.create_test_controller_fs(
            name=constants.FILESYSTEM_NAME_CEPH_DRBD,
            forisystemid=self.system.id,
            state=str({'status': constants.CONTROLLER_FS_RECONFIGURE_WITH_APP}),
            size=20,
            logical_volume='ceph-float-lv',
            replicated=True,
            isystem_uuid=self.system.uuid)

        # DELETE the host-fs ceph entry
        response = self.delete(self.get_single_fs_url(ceph_fs.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)

        # Assert HTTP 400 - blocked by controller-fs reconfigure state
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(constants.CONTROLLER_FS_RECONFIGURE_WITH_APP,
                      response.json['error_message'])
        self.assertIn("Please apply the application",
                      response.json['error_message'])

    def test_delete_ceph_reconfigure_with_app_blocked(self):
        """Delete of ceph host-fs in Reconfigure with App state should be
        blocked."""

        # Rook Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph fs in Reconfigure with App state
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_RECONFIGURE_WITH_APP,
                                         {"functions": ["monitor"]})

        uuid = ceph_fs.uuid
        response = self.delete(self.get_single_fs_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("only possible for states",
                      response.json['error_message'])

    def test_delete_ceph_modifying_blocked(self):
        """Delete of ceph host-fs in Modifying state should be blocked."""

        # Rook Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph fs in Modifying state
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_MODIFYING,
                                         {"functions": ["monitor"]})

        uuid = ceph_fs.uuid
        response = self.delete(self.get_single_fs_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("only possible for states",
                      response.json['error_message'])

    def test_delete_ceph_creating_blocked(self):
        """Delete of ceph host-fs in Creating state should be blocked."""

        # Rook Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph fs in Creating state
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_CREATE_IN_SVC,
                                         {"functions": ["monitor"]})

        uuid = ceph_fs.uuid
        response = self.delete(self.get_single_fs_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("only possible for states",
                      response.json['error_message'])

    def test_delete_ceph_deleting_blocked(self):
        """Delete of ceph host-fs in Deleting state should be blocked."""

        # Rook Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph fs in Deleting state
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_DELETING,
                                         {"functions": ["monitor"]})

        uuid = ceph_fs.uuid
        response = self.delete(self.get_single_fs_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("only possible for states",
                      response.json['error_message'])

    def test_delete_ceph_with_monitor_function_blocked(self):
        """Delete of ceph host-fs with monitor function in In-Use state
        should be blocked by the state check (In-Use is not in allowed
        states for deletion). The --force flag bypasses _delete() entirely."""

        # Rook Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph fs in In-Use state with monitor function
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_IN_USE,
                                         {"functions": ["monitor"]})

        uuid = ceph_fs.uuid
        response = self.delete(self.get_single_fs_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("only possible for states",
                      response.json['error_message'])

    def test_delete_ceph_with_osd_function_blocked(self):
        """Delete of ceph host-fs with osd function in In-Use state should
        be blocked by the state check."""

        # Rook Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph fs in In-Use state with osd function
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_IN_USE,
                                         {"functions": ["osd"]})

        uuid = ceph_fs.uuid
        response = self.delete(self.get_single_fs_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("only possible for states",
                      response.json['error_message'])

    def test_delete_ceph_ready_with_monitor_succeeds(self):
        """Delete of ceph host-fs in Ready state with monitor function
        should succeed (state allows deletion)."""

        # Rook Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph fs in Ready state with monitor function
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_READY,
                                         {"functions": ["monitor"]})

        uuid = ceph_fs.uuid
        response = self.delete(self.get_single_fs_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=False)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)

    def test_delete_ceph_ready_with_osd_succeeds(self):
        """Delete of ceph host-fs in Ready state with osd function
        should succeed (state allows deletion)."""

        # Rook Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph fs in Ready state with osd function
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_READY,
                                         {"functions": ["osd"]})

        uuid = ceph_fs.uuid
        response = self.delete(self.get_single_fs_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=False)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)

    def test_delete_ceph_create_on_unlock_with_monitor_succeeds(self):
        """Delete of ceph host-fs in Creating (on unlock) state with monitor
        function should succeed."""

        # Rook Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph fs in Create on Unlock state with monitor function
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_CREATE_ON_UNLOCK,
                                         {"functions": ["monitor"]})

        uuid = ceph_fs.uuid
        response = self.delete(self.get_single_fs_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=False)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)

    def test_delete_ceph_update_error_with_monitor_succeeds(self):
        """Delete of ceph host-fs in Error state with monitor function
        should succeed."""

        # Rook Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create ceph fs in Error state with monitor function
        ceph_fs = self._create_db_object('ceph',
                                         20,
                                         'ceph-lv',
                                         constants.HOST_FS_STATUS_UPDATE_ERROR,
                                         {"functions": ["monitor"]})

        uuid = ceph_fs.uuid
        response = self.delete(self.get_single_fs_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=False)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)


class ApiHostFSPostTestSuiteMixin(ApiHostFSTestCaseMixin):
    """ Host FileSystem post operations
    """
    def setUp(self):
        super(ApiHostFSPostTestSuiteMixin, self).setUp()

    # Test that a valid POST operation is blocked by the API
    # API should return 400 BAD_REQUEST or FORBIDDEN 403
    def test_post_not_allowed(self):
        response = self.post_json('/host_fs',
                                  {'name': 'kubelet',
                                   'size': 10,
                                   'logical_volume': 'kubelet-lv',
                                   'state': constants.HOST_FS_STATUS_IN_USE},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Unsupported filesystem",
                      response.json['error_message'])

    # Test a valid POST operation with an optional filesystem
    # allowed to be created.
    def test_post_allowed(self):

        # Rook Ceph or Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/host_fs',
                                  {'ihost_uuid': self.host.uuid,
                                   'name': 'ceph',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        url = self.get_single_fs_url(response.json['uuid'])
        response = self.get_json(url,
                                 headers=self.API_HEADERS,
                                 expect_errors=False)

        capabilities = {"functions": ["monitor"]}
        self.assertEqual(response['capabilities'], capabilities)
        self.assertEqual(response['state'], constants.HOST_FS_STATUS_CREATE_IN_SVC)

    def test_post_allowed_creating_on_unlock(self):
        """Test that creating ceph host-fs on a locked+online host results
        in Creating (on unlock) state with monitor function."""

        # Rook Ceph must be as storage backend for ceph fs
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Update host to locked + online (triggers staged/on-unlock path)
        self.dbapi.ihost_update(self.host.uuid,
                                {'administrative': constants.ADMIN_LOCKED,
                                 'availability': constants.AVAILABILITY_ONLINE})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/host_fs',
                                  {'ihost_uuid': self.host.uuid,
                                   'name': 'ceph',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        url = self.get_single_fs_url(response.json['uuid'])
        response = self.get_json(url,
                                 headers=self.API_HEADERS,
                                 expect_errors=False)

        capabilities = {"functions": ["monitor"]}
        self.assertEqual(response['capabilities'], capabilities)
        self.assertEqual(response['state'], constants.HOST_FS_STATUS_CREATE_ON_UNLOCK)

    def test_post_ceph_float_flow_controller_1_unprovisioned(self):
        """Test the full flow: create host-fs ceph on controller-0, then
        create controller-fs ceph-float (with controller-1 unprovisioned),
        then create host-fs ceph on controller-1.

        When controller-1 is unprovisioned, the fixed monitor check skips
        it, allowing ceph-float creation with only controller-0's monitor.
        """

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create controller-1 as unprovisioned
        controller_1 = self._create_controller_1(
            invprovision=constants.UNPROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Controller-0 must be provisioned for the monitor check
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED})

        # Create a logical volume on controller-0
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Step 1: Create host-fs ceph on controller-0
        response = self.post_json('/host_fs',
                                  {'ihost_uuid': self.host.uuid,
                                   'name': 'ceph',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json['state'],
                         constants.HOST_FS_STATUS_CREATE_IN_SVC)

        # Simulate controller-0's ceph host-fs becoming Ready
        host_fs_c0_uuid = response.json['uuid']
        self.dbapi.host_fs_update(host_fs_c0_uuid,
                                  {'state': constants.HOST_FS_STATUS_READY})

        # Step 2: Create controller-fs ceph-float
        # Controller-1 is unprovisioned, so it is skipped in the
        # fixed monitor check — only controller-0 is validated.
        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)

        # Step 3: Create host-fs ceph on controller-1
        # Create a logical volume on controller-1
        dbutils.create_test_lvg(id=3,
                                lvm_vg_name='cgts-vg',
                                forihostid=controller_1.id)

        response = self.post_json('/host_fs',
                                  {'ihost_uuid': controller_1.uuid,
                                   'name': 'ceph',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)

    def test_post_fail_host_not_locked(self):
        """Test that creating 'instances' filesystem fails when host is
        not in locked state."""

        # Update host to unlocked state (instances requires locked)
        self.dbapi.ihost_update(self.host.uuid,
                                {'administrative': constants.ADMIN_UNLOCKED,
                                 'operational': constants.OPERATIONAL_ENABLED,
                                 'availability': constants.AVAILABILITY_AVAILABLE,
                                 'subfunctions': constants.WORKER})

        response = self.post_json('/host_fs',
                                  {'ihost_uuid': self.host.uuid,
                                   'name': 'instances',
                                   'size': 10},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Host must be locked",
                      response.json['error_message'])

    def test_post_fail_nova_local_lvg_exists(self):
        """Test that creating 'instances' filesystem fails when
        nova-local LVG already exists on the host."""

        # Host must be locked and worker subfunction
        self.dbapi.ihost_update(self.host.uuid,
                                {'administrative': constants.ADMIN_LOCKED,
                                 'subfunctions': constants.WORKER})

        # Create nova-local LVG on the host
        dbutils.create_test_lvg(lvm_vg_name=constants.LVG_NOVA_LOCAL,
                                forihostid=self.host.id)

        response = self.post_json('/host_fs',
                                  {'ihost_uuid': self.host.uuid,
                                   'name': 'instances',
                                   'size': 10},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Cannot create",
                      response.json['error_message'])
        self.assertIn(constants.LVG_NOVA_LOCAL,
                      response.json['error_message'])

    def test_post_fail_image_conversion_unavailable_host(self):
        """Test that creating 'image-conversion' filesystem fails when
        controller host is in unavailable state."""

        # Set host as controller with unavailable availability
        self.dbapi.ihost_update(self.host.uuid,
                                {'administrative': constants.ADMIN_LOCKED,
                                 'availability': constants.AVAILABILITY_OFFLINE,
                                 'subfunctions': constants.CONTROLLER})

        response = self.post_json('/host_fs',
                                  {'ihost_uuid': self.host.uuid,
                                   'name': 'image-conversion',
                                   'size': 10},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("must be available/online/degraded",
                      response.json['error_message'])

    def test_post_fail_ceph_no_rook_backend(self):
        """Test that creating 'ceph' filesystem fails when Rook is not
        configured as the storage backend."""

        # No Rook backend configured (don't call storage_ceph_rook_create)

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/host_fs',
                                  {'ihost_uuid': self.host.uuid,
                                   'name': 'ceph',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("must be configured as the storage backend",
                      response.json['error_message'])

    def test_post_fail_ceph_invalid_personality(self):
        """Test that creating 'ceph' filesystem fails when the host
        personality is storage (not controller or worker)."""

        # Rook Ceph must be configured
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Update host to storage personality (no controller/worker subfunction)
        self.dbapi.ihost_update(self.host.uuid,
                                {'personality': constants.STORAGE,
                                 'subfunctions': constants.STORAGE})

        response = self.post_json('/host_fs',
                                  {'ihost_uuid': self.host.uuid,
                                   'name': 'ceph',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("can not be added on",
                      response.json['error_message'])

    def test_post_fail_already_exists(self):
        """Test that creating a ceph filesystem that already exists on
        the host is rejected."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create ceph host_fs entry in DB first
        self._create_db_object('ceph', 20, 'ceph-lv',
                               constants.HOST_FS_STATUS_IN_USE,
                               capabilities={"functions": ["monitor"]})

        response = self.post_json('/host_fs',
                                  {'ihost_uuid': self.host.uuid,
                                   'name': 'ceph',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("already present",
                      response.json['error_message'])

    def test_post_fail_insufficient_space(self):
        """Test that creating a filesystem fails when there is not enough
        free space on cgts-vg."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create LVG with no free space
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id,
                                lvm_vg_free_pe=0)

        response = self.post_json('/host_fs',
                                  {'ihost_uuid': self.host.uuid,
                                   'name': 'ceph',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Not enough free space",
                      response.json['error_message'])

    def test_post_fail_size_below_minimum(self):
        """Test that creating a filesystem fails when size is below
        the minimum of 1 GiB."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create LVG with sufficient space
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/host_fs',
                                  {'ihost_uuid': self.host.uuid,
                                   'name': 'ceph',
                                   'size': 0},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Minimum FS size is 1 GiB",
                      response.json['error_message'])

    def test_post_fail_max_monitors_exceeded(self):
        """Test that creating a ceph filesystem fails when the maximum
        number of monitors has been reached."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create LVG with sufficient space
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create enough ceph filesystems with monitor function to reach the max
        # FILESYSTEM_CEPH_MONITOR_MAX = 5
        for i in range(constants.FILESYSTEM_CEPH_MONITOR_MAX):
            worker = self._create_test_host(
                constants.WORKER,
                numa_nodes=1,
                unit=i + 1,
                administrative=constants.ADMIN_LOCKED)
            dbutils.create_test_host_fs(
                id=100 + i,
                name='ceph',
                forihostid=worker.id,
                size=20,
                logical_volume='ceph-lv',
                state=constants.HOST_FS_STATUS_IN_USE,
                capabilities={"functions": ["monitor"]})

        response = self.post_json('/host_fs',
                                  {'ihost_uuid': self.host.uuid,
                                   'name': 'ceph',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Number of monitors cannot exceed",
                      response.json['error_message'])

    @mock.patch('sysinv.common.utils.is_floating_monitor_assigned')
    def test_post_fail_ceph_floating_monitor_blocks(self,
                                                    mock_floating_monitor):
        """Test that creating a ceph filesystem fails when the floating
        monitor is configured on a provisioned host."""

        # Mock floating monitor as assigned
        mock_floating_monitor.return_value = True

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Host must be provisioned for the floating monitor check to apply
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED})

        # Create LVG with sufficient space
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/host_fs',
                                  {'ihost_uuid': self.host.uuid,
                                   'name': 'ceph',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("cannot create a fixed monitor",
                      response.json['error_message'])

    @mock.patch('sysinv.agent.rpcapi.AgentAPI.disk_prepare')
    def test_osd_creates_host_fs_ceph(self, mock_disk_prepare):
        """Test that creating an OSD on a host without existing ceph host_fs
        triggers creation of a host_fs ceph entry as a side effect, with
        correct initial state and size values.

        Validates: Requirements 6.1, 6.2, 11.1
        """

        # Set up Rook Ceph storage backend (same pattern as test_storage.py)
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # Create a disk for the OSD
        disk_1 = dbutils.create_test_idisk(
            device_node='/dev/sdb',
            device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0',
            forihostid=self.host.id)

        # Create a logical volume (needed for host_fs creation)
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create a cluster and storage tier (needed for OSD creation)
        cluster = dbutils.create_test_cluster(
            system_id=self.system.id, name='ceph_cluster')
        dbutils.create_test_storage_tier(
            cluster_uuid=cluster.uuid,
            name='storage',
            status=constants.SB_TIER_STATUS_IN_USE)

        # Verify no ceph host_fs entry exists before OSD creation
        host_fs_list = self.dbapi.host_fs_get_by_ihost(self.host.uuid)
        ceph_entries = [fs for fs in host_fs_list
                        if fs['name'] == constants.FILESYSTEM_NAME_CEPH]
        self.assertEqual(len(ceph_entries), 0)

        # Create OSD — this should trigger host_fs ceph creation
        response = self.post_json('/istors',
                                  {'ihost_uuid': self.host.uuid,
                                   'idisk_uuid': disk_1.uuid},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)

        # Verify host_fs ceph entry was created as a side effect
        host_fs_list = self.dbapi.host_fs_get_by_ihost(self.host.uuid)
        ceph_entries = [fs for fs in host_fs_list
                        if fs['name'] == constants.FILESYSTEM_NAME_CEPH]
        self.assertEqual(len(ceph_entries), 1)

        # Verify initial state and size values
        ceph_fs = ceph_entries[0]
        self.assertEqual(ceph_fs['size'], constants.SB_CEPH_MON_GIB)
        # The state should be one of the creation states
        self.assertIn(ceph_fs['state'],
                      [constants.HOST_FS_STATUS_CREATE_IN_SVC,
                       constants.HOST_FS_STATUS_CREATE_ON_UNLOCK])
        # Verify OSD function is assigned
        capabilities = ceph_fs['capabilities']
        self.assertIn(constants.FILESYSTEM_CEPH_FUNCTION_OSD,
                      capabilities.get('functions', []))

    def test_delete_controller_fs_independent_host_fs(self):
        """Test that deleting the controller-fs ceph-float entry does not
        affect the host-fs ceph entry, which can still be modified
        independently afterward.

        Validates: Requirements 11.2
        """

        # Set up Rook Ceph storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create controller-1 for duplex system
        controller_1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Controller-0 must be provisioned
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED})

        # Create host-fs ceph with monitor function on both controllers
        host_fs_c0 = dbutils.create_test_host_fs(
            id=90,
            name='ceph',
            forihostid=self.host.id,
            size=20,
            logical_volume='ceph-lv',
            state=constants.HOST_FS_STATUS_IN_USE,
            capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(
            id=91,
            name='ceph',
            forihostid=controller_1.id,
            size=20,
            logical_volume='ceph-lv',
            state=constants.HOST_FS_STATUS_IN_USE,
            capabilities={"functions": ["monitor"]})

        # Create a logical volume on controller-0
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create controller-fs ceph-float
        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)
        self.assertEqual(response.status_code, http_client.OK)

        # Verify controller-fs ceph-float exists
        controller_fs_list = self.dbapi.controller_fs_get_list()
        ceph_float_entries = [fs for fs in controller_fs_list
                              if fs['name'] == 'ceph-float']
        self.assertEqual(len(ceph_float_entries), 1)

        # Delete the controller-fs ceph-float entry directly via DB
        # (simulating deletion after state was set to CREATING_ON_UNLOCK,
        # which allows direct DB destruction without kube checks)
        self.dbapi.controller_fs_destroy(ceph_float_entries[0].id)

        # Verify controller-fs ceph-float is deleted
        controller_fs_list = self.dbapi.controller_fs_get_list()
        ceph_float_entries = [fs for fs in controller_fs_list
                              if fs['name'] == 'ceph-float']
        self.assertEqual(len(ceph_float_entries), 0)

        # Verify host-fs ceph entry still exists and can be modified
        host_fs = self.dbapi.host_fs_get(host_fs_c0.uuid)
        self.assertEqual(host_fs['name'], constants.FILESYSTEM_NAME_CEPH)

        # Modify the host-fs ceph entry to READY state (confirming it
        # can still be independently modified after controller-fs deletion)
        self.dbapi.host_fs_update(host_fs_c0.uuid,
                                  {'state': constants.HOST_FS_STATUS_READY})
        updated_fs = self.dbapi.host_fs_get(host_fs_c0.uuid)
        self.assertEqual(updated_fs.state, constants.HOST_FS_STATUS_READY)

    def test_post_ceph_float_flow_controller_1_provisioned(self):
        """Test the full flow: create host-fs ceph on controller-0, then
        attempt to create controller-fs ceph-float (with controller-1
        provisioned but without ceph host-fs), which should fail.

        When controller-1 is provisioned, the fixed monitor check validates
        it and fails because it does not have a ceph host-fs configured.
        """

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Create controller-1 as provisioned
        controller_1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Controller-0 must be provisioned for the monitor check
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED})

        # Create a logical volume on controller-0
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Step 1: Create host-fs ceph on controller-0
        response = self.post_json('/host_fs',
                                  {'ihost_uuid': self.host.uuid,
                                   'name': 'ceph',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json['state'],
                         constants.HOST_FS_STATUS_CREATE_IN_SVC)

        # Simulate controller-0's ceph host-fs becoming In-Use
        host_fs_c0_uuid = response.json['uuid']
        self.dbapi.host_fs_update(host_fs_c0_uuid,
                                  {'state': constants.HOST_FS_STATUS_IN_USE})

        # Step 2: Attempt to create controller-fs ceph-float
        # Controller-1 is provisioned but has no ceph host-fs,
        # so the fixed monitor check should fail.
        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("does not have a ceph host-fs configured",
                      response.json['error_message'])

        # Step 3: Create host-fs ceph on controller-1
        # Create a logical volume on controller-1
        dbutils.create_test_lvg(id=3,
                                lvm_vg_name='cgts-vg',
                                forihostid=controller_1.id)

        response = self.post_json('/host_fs',
                                  {'ihost_uuid': controller_1.uuid,
                                   'name': 'ceph',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)

        # Step 4: Create controllerfs ceph-float with both
        # ceph host-fs already created
        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)

    def test_post_fail_ceph_controller_fs_reconfigure_state(self):
        """Test that creating a ceph filesystem fails when the controller-fs
        ceph-float is in 'reconfigure-with-app' state (pending app apply)."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Host must be provisioned for the floating monitor check to apply
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED})

        # Create controller-fs ceph-float in RECONFIGURE_WITH_APP state
        dbutils.create_test_controller_fs(
            name=constants.FILESYSTEM_NAME_CEPH_DRBD,
            forisystemid=self.system.id,
            state=str({'status': constants.CONTROLLER_FS_RECONFIGURE_WITH_APP}),
            size=20,
            logical_volume='ceph-float-lv',
            replicated=True,
            isystem_uuid=self.system.uuid)

        # Create LVG with sufficient space
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/host_fs',
                                  {'ihost_uuid': self.host.uuid,
                                   'name': 'ceph',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(constants.CONTROLLER_FS_RECONFIGURE_WITH_APP,
                      response.json['error_message'])
        self.assertIn("Please apply the application",
                      response.json['error_message'])
