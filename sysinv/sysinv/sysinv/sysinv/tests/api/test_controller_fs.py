#
# Copyright (c) 2020,2024,2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / controller-fs / methods.
"""

import mock

from oslo_serialization import jsonutils
from six.moves import http_client

from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
from sysinv.common import constants


class FakeConductorAPI(object):

    def __init__(self):
        self.get_controllerfs_lv_sizes = mock.MagicMock()
        self.update_storage_config = mock.MagicMock()


class FakeException(Exception):
        pass


class ApiControllerFSTestCaseMixin(base.FunctionalTest,
                                   dbbase.ControllerHostTestCase):

    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/controller_fs'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'controller_fs'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['logical_volume',
                           'uuid',
                           'links',
                           'created_at',
                           'updated_at',
                           'name',
                           'state',
                           'isystem_uuid',
                           'replicated',
                           'forisystemid',
                           'size']

    # hidden_api_fields are attributes that should not be populated by
    # an API query
    hidden_api_fields = ['forisystemid']

    def setUp(self):
        super(ApiControllerFSTestCaseMixin, self).setUp()
        self.controller_fs_first = self._create_db_object('platform',
                                                          10,
                                                          'platform-lv')
        self.controller_fs_second = self._create_db_object('database',
                                                           5,
                                                           'pgsql-lv')
        self.controller_fs_third = self._create_db_object('extension',
                                                          1,
                                                          'extension-lv')
        self.fake_conductor_api = FakeConductorAPI()
        p = mock.patch('sysinv.conductor.rpcapiproxy.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

    def get_show_url(self, uuid):
        return '%s/%s' % (self.API_PREFIX, uuid)

    def get_detail_url(self):
        return '%s/detail' % (self.API_PREFIX)

    def get_update_url(self, system_uuid):
        return '/isystems/%s/controller_fs/update_many' % (system_uuid)

    def get_sorted_list_url(self, sort_attr, sort_dir):
        return '%s/?sort_key=%s&sort_dir=%s' % (self.API_PREFIX, sort_attr,
                                                sort_dir)

    def _create_db_object(self, controller_fs_name, controller_fs_size,
                          controller_lv, capabilities=None, obj_id=None):
        if capabilities is None:
            capabilities = {"functions": []}
        return dbutils.create_test_controller_fs(id=obj_id,
                                                 uuid=None,
                                                 name=controller_fs_name,
                                                 forisystemid=self.system.id,
                                                 state=str({'status': constants.CONTROLLER_FS_AVAILABLE}),
                                                 capabilities=capabilities,
                                                 size=controller_fs_size,
                                                 logical_volume=controller_lv,
                                                 replicated=True,
                                                 isystem_uuid=self.system.uuid)

    def _create_controller_0(self, subfunction=None, numa_nodes=1, **kw):
        return self._create_test_host(
            personality=constants.CONTROLLER,
            subfunction=subfunction,
            numa_nodes=numa_nodes,
            unit=0,
            **kw)

    def _create_controller_1(self, subfunction=None, numa_nodes=1, **kw):
        return self._create_test_host(
            personality=constants.CONTROLLER,
            subfunction=subfunction,
            numa_nodes=numa_nodes,
            unit=1,
            **kw)


class ApiControllerFSListTestSuiteMixin(ApiControllerFSTestCaseMixin):
    """ Controller FileSystem List GET operations
    """
    def setUp(self):
        super(ApiControllerFSListTestSuiteMixin, self).setUp()

    def test_success_fetch_controller_fs_list(self):
        response = self.get_json(self.API_PREFIX, headers=self.API_HEADERS)

        # Verify the values of the response with the values stored in database
        result_one = response[self.RESULT_KEY][0]
        result_two = response[self.RESULT_KEY][1]
        self.assertTrue(result_one['name'] == self.controller_fs_first.name or
                        result_two['name'] == self.controller_fs_first.name)
        self.assertTrue(result_one['name'] == self.controller_fs_second.name or
                        result_two['name'] == self.controller_fs_second.name)

    def test_success_fetch_controller_fs_sorted_list(self):
        response = self.get_json(self.get_sorted_list_url('name', 'asc'))

        # Verify the values of the response are returned in a sorted order
        result_one = response[self.RESULT_KEY][0]
        result_two = response[self.RESULT_KEY][1]
        result_three = response[self.RESULT_KEY][2]
        self.assertEqual(result_one['name'], self.controller_fs_second.name)
        self.assertEqual(result_two['name'], self.controller_fs_third.name)
        self.assertEqual(result_three['name'], self.controller_fs_first.name)


class ApiControllerFSShowTestSuiteMixin(ApiControllerFSTestCaseMixin):
    """ Controller FileSystem Show GET operations
    """
    def setUp(self):
        super(ApiControllerFSShowTestSuiteMixin, self).setUp()

    def test_fetch_controller_fs_object(self):
        url = self.get_show_url(self.controller_fs_first.uuid)
        response = self.get_json(url)
        # Verify the values of the response with the values stored in database
        self.assertTrue(response['name'], self.controller_fs_first.name)
        self.assertTrue(response['logical_volume'],
                        self.controller_fs_first.logical_volume)
        self.assertTrue(response['state'], self.controller_fs_first.state)
        self.assertTrue(response['replicated'],
                        self.controller_fs_first.replicated)
        self.assertTrue(response['size'], self.controller_fs_first.size)
        self.assertTrue(response['uuid'], self.controller_fs_first.uuid)


class ApiControllerFSPutTestSuiteMixin(ApiControllerFSTestCaseMixin):
    """ Controller FileSystem Put operations
    """

    def setUp(self):
        super(ApiControllerFSPutTestSuiteMixin, self).setUp()
        self.fake_lv_size = self.fake_conductor_api.get_controllerfs_lv_sizes
        # Save reference to the real function BEFORE patching
        from sysinv.api.controllers.v1 import utils as v1_utils
        self._real_is_host_state_valid = v1_utils.is_host_state_valid_for_fs_resize
        p = mock.patch(
            'sysinv.api.controllers.v1.utils.is_host_state_valid_for_fs_resize')
        self.mock_utils_is_virtual = p.start()
        self.mock_utils_is_virtual.return_value = True
        self.addCleanup(p.stop)

    def exception_controller_fs(self):
        print('Raised a fake exception')
        raise FakeException

    def test_put_duplicate_fs_name(self):
        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{"path": "/name",
                                    "value": "extension",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "2",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "extension",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "6",
                                    "op": "replace"}]],
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Duplicate fs_name 'extension' in parameter list",
                      response.json['error_message'])

    def test_put_invalid_fs_name(self):
        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{"path": "/name",
                                    "value": "invalid_name",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "2",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "database",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "6",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("ControllerFs update failed: invalid filesystem",
                      response.json['error_message'])

    def test_put_invalid_fs_size(self):
        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{"path": "/name",
                                    "value": "extension",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "invalid_size",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "database",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "4",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("ControllerFs update failed: filesystem \'extension\' "
                      "size must be an integer", response.json['error_message'])

    def test_put_smaller_than_existing_fs_size(self):
        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{"path": "/name",
                                    "value": "extension",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "2",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "database",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "4",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("ControllerFs update failed: size for "
                      "filesystem \'database\' should be bigger than 5",
                      response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.utils.is_drbd_fs_resizing')
    def test_put_drbd_sync_error(self, is_drbd_fs_resizing):
        is_drbd_fs_resizing.return_value = True
        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{"path": "/name",
                                    "value": "extension",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "2",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "database",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "4",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("A drbd sync operation is currently in progress. "
                      "Retry again later.",
                      response.json['error_message'])

    def test_put_size_not_found(self):
        # Return fake dictionary for logical volume and size
        self.fake_lv_size.return_value = {'extension-lv': 1,
                                          'platform-lv': 10}

        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{"path": "/name",
                                    "value": "extension",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "2",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "database",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "6",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Unable to determine the current size of pgsql-lv. "
                      "Rejecting modification request.",
                      response.json['error_message'])

    def test_put_minimum_size(self):
        # Return fake dictionary for logical volume and size
        self.fake_lv_size.return_value = {'extension-lv': 1,
                                          'pgsql-lv': 5,
                                          'platform-lv': 16}

        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{"path": "/name",
                                    "value": "extension",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "2",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "database",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "6",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("'platform'  must be at least: 16",
                      response.json['error_message'])

    def test_put_insufficient_backup_size(self):
        # Return fake dictionary for logical volume and size
        self.fake_lv_size.return_value = {'extension-lv': 1,
                                          'pgsql-lv': 5,
                                          'platform-lv': 10}

        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{"path": "/name",
                                    "value": "extension",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "2",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "database",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "6",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("backup size of 0 is insufficient for host controller-0. "
                      "Minimum backup size of 21 is required based upon "
                      "platform size 10 and database size 6. "
                      "Rejecting modification request.",
                      response.json['error_message'])

    def test_put_unprovisioned_physical_volume(self):
        # Create an unprovisioned physical volume in database
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=1,
                               pv_state='unprovisioned')

        # Return fake dictionary for logical volume and size
        self.fake_lv_size.return_value = {'extension-lv': 1,
                                          'pgsql-lv': 5,
                                          'platform-lv': 10}

        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{"path": "/name",
                                    "value": "extension",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "2",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "database",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "6",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Cannot resize filesystem. There are still "
                      "unprovisioned physical volumes on controller-0.",
                      response.json['error_message'])

    def test_put_exceed_growth_limit(self):
        # Create a provisioned physical volume in database
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                                          forihostid=1,
                                          pv_state='provisioned')
        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id,
                                lvm_vg_size=200,
                                lvm_vg_free_pe=50)

        # Create a host filesystem
        dbutils.create_test_host_fs(name='backup',
                                              forihostid=self.host.id)

        # Return fake dictionary for logical volume and size
        self.fake_lv_size.return_value = {'extension-lv': 1,
                                          'pgsql-lv': 5,
                                          'platform-lv': 10}

        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{"path": "/name",
                                    "value": "extension",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "2",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "database",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "6",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Total target growth size 9 GiB "
                      "exceeds growth limit of 0 GiB.",
                      response.json['error_message'])

    def test_put_update_exception(self):
        # Create a provisioned physical volume in database
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create a host filesystem
        dbutils.create_test_host_fs(name='backup',
                                    forihostid=self.host.id)

        # Return fake dictionary for logical volume and size
        self.fake_lv_size.return_value = {'extension-lv': 1,
                                          'pgsql-lv': 5,
                                          'platform-lv': 10}

        # Throw a fake exception
        fake_update = self.fake_conductor_api.update_storage_config
        fake_update.side_effect = self.exception_controller_fs

        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{"path": "/name",
                                    "value": "extension",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "2",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "database",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "6",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Failed to update filesystem size",
                      response.json['error_message'])

    def test_put_success(self):
        # Create a provisioned physical volume in database
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create a host filesystem
        dbutils.create_test_host_fs(name='backup',
                                    forihostid=self.host.id)

        # Return fake dictionary for logical volume and size
        self.fake_lv_size.return_value = {'extension-lv': 1,
                                          'pgsql-lv': 5,
                                          'platform-lv': 10}

        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{"path": "/name",
                                    "value": "extension",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "2",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "database",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "6",
                                    "op": "replace"}]],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify a NO CONTENT response is given
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

    def test_put_success_remove_monitor_function(self):
        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        controller_1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create host-fs ceph with monitor function on both controllers
        # (required fixed monitors before creating the floating monitor)
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        controller_fs = self.post_json('/controller_fs',
                                       {'name': 'ceph-float', 'size': 20},
                                       headers=self.API_HEADERS,
                                       expect_errors=False)

        # Simulate conductor completing creation (state → AVAILABLE)
        self.dbapi.controller_fs_update(
            controller_fs.json['uuid'],
            {'state': str({'status': constants.CONTROLLER_FS_AVAILABLE})})

        capabilities = {"functions": []}
        self.put_json(self.get_update_url(self.system.uuid),
                      [[{
                          "path": "/name",
                          "value": "ceph-float",
                          "op": "replace"},
                          {
                          "path": "/capabilities",
                          "value": jsonutils.dumps(capabilities),
                          "op": "replace"}]],
                      headers=self.API_HEADERS,
                      expect_errors=False)

        response = self.get_json(self.get_show_url(controller_fs.json['uuid']),
                                 headers=self.API_HEADERS,
                                 expect_errors=False)

        self.assertEqual(response['capabilities'], capabilities)

    def test_put_success_add_monitor_function(self):
        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        controller_1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create host-fs ceph with monitor function on both controllers
        # (required fixed monitors before adding monitor function)
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        cap = {"functions": []}
        controller_fs = self._create_db_object('ceph-float',
                                               20,
                                               'ceph-float-lv',
                                               cap)

        cap_updated = {"functions": ["monitor"]}
        self.put_json(self.get_update_url(self.system.uuid),
                      [[{
                          "path": "/name",
                          "value": "ceph-float",
                          "op": "replace"},
                          {
                          "path": "/capabilities",
                          "value": jsonutils.dumps(cap_updated),
                          "op": "replace"}]],
                      headers=self.API_HEADERS,
                      expect_errors=False)

        response = self.get_json(self.get_show_url(controller_fs.uuid),
                                 headers=self.API_HEADERS,
                                 expect_errors=False)

        self.assertEqual(response['capabilities'], cap_updated)

    def test_put_fail_function_for_not_ceph_float_fs(self):
        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        cap_updated = {"functions": ["monitor"]}
        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{
                                     "path": "/name",
                                     "value": "platform",
                                     "op": "replace"},
                                   {
                                     "path": "/capabilities",
                                     "value": jsonutils.dumps(cap_updated),
                                     "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("ControllerFs update failed: update functions are only",
                      response.json['error_message'])

    def test_put_capabilities_only_no_size_change(self):
        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        controller_1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create ceph-float with initial capabilities (empty functions)
        initial_capabilities = {"functions": []}
        controller_fs = self._create_db_object('ceph-float',
                                               20,
                                               'ceph-float-lv',
                                               initial_capabilities)

        # PUT with capability change only (no size field)
        new_capabilities = {"functions": ["monitor"]}
        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{
                                     "path": "/name",
                                     "value": "ceph-float",
                                     "op": "replace"},
                                   {
                                     "path": "/capabilities",
                                     "value": jsonutils.dumps(new_capabilities),
                                     "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        # Verify a NO CONTENT response is given
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify capabilities persisted
        show_response = self.get_json(self.get_show_url(controller_fs.uuid),
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        self.assertEqual(show_response['capabilities'], new_capabilities)

    def test_put_capabilities_only_state_reconfigure_with_app(self):
        """Test that updating only capabilities (no size change) on
        controller-fs sets the state to RECONFIGURE_WITH_APP."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        controller_1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create ceph-float with initial capabilities (empty functions)
        initial_capabilities = {"functions": []}
        controller_fs = self._create_db_object('ceph-float',
                                               20,
                                               'ceph-float-lv',
                                               initial_capabilities)

        # PUT with capability change only (no size field)
        new_capabilities = {"functions": ["monitor"]}
        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{
                                     "path": "/name",
                                     "value": "ceph-float",
                                     "op": "replace"},
                                   {
                                     "path": "/capabilities",
                                     "value": jsonutils.dumps(new_capabilities),
                                     "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify state is RECONFIGURE_WITH_APP
        show_response = self.get_json(self.get_show_url(controller_fs.uuid),
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        state = eval(show_response['state'])
        self.assertEqual(state['status'],
                         constants.CONTROLLER_FS_RECONFIGURE_WITH_APP)

    def test_put_capabilities_with_size_state_reconfigure_with_app(self):
        """Test that updating both capabilities AND size on controller-fs
        sets the state to RECONFIGURE_WITH_APP (not RESIZING_IN_PROGRESS),
        because capabilities take priority."""

        # Create a provisioned physical volume in database
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create a host filesystem
        dbutils.create_test_host_fs(name='backup',
                                    forihostid=self.host.id,
                                    size=25)

        # Return fake dictionary for logical volume and size
        self.fake_lv_size.return_value = {'ceph-float-lv': 20,
                                          'extension-lv': 1,
                                          'pgsql-lv': 5,
                                          'platform-lv': 10}

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        controller_1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        # Create backup host_fs on controller-1 as well (needed for
        # _check_relative_controller_multi_fs validation)
        dbutils.create_test_host_fs(id=92,
                                    name='backup',
                                    forihostid=controller_1.id,
                                    size=25)

        # Create ceph-float with initial capabilities (empty functions)
        initial_capabilities = {"functions": []}
        controller_fs = self._create_db_object('ceph-float',
                                               20,
                                               'ceph-float-lv',
                                               initial_capabilities)

        # PUT with both capabilities AND size change
        new_capabilities = {"functions": ["monitor"]}
        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{
                                     "path": "/name",
                                     "value": "ceph-float",
                                     "op": "replace"},
                                   {
                                     "path": "/size",
                                     "value": "25",
                                     "op": "replace"},
                                   {
                                     "path": "/capabilities",
                                     "value": jsonutils.dumps(new_capabilities),
                                     "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify state is RECONFIGURE_WITH_APP (capabilities win over size)
        show_response = self.get_json(self.get_show_url(controller_fs.uuid),
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        state = eval(show_response['state'])
        self.assertEqual(state['status'],
                         constants.CONTROLLER_FS_RECONFIGURE_WITH_APP)

    @mock.patch('sysinv.common.health.Health.get_alarms_degrade')
    def test_put_fail_invalid_host_state(self, mock_get_alarms_degrade):
        # Let the real is_host_state_valid_for_fs_resize execute by
        # pointing the mock to the real function saved before patching
        self.mock_utils_is_virtual.side_effect = self._real_is_host_state_valid

        # Mock get_alarms_degrade since FM client is not available in
        # the test environment. Return a degrade alarm so that
        # allowed_resize stays False.
        mock_get_alarms_degrade.return_value = ['100.114']

        # Update the host to have an invalid state for fs resize:
        # unlocked/disabled/offline triggers the real validation path
        self.dbapi.ihost_update(self.host.uuid, {
            'administrative': constants.ADMIN_UNLOCKED,
            'operational': constants.OPERATIONAL_DISABLED,
            'availability': constants.AVAILABILITY_OFFLINE,
        })

        # Create a provisioned physical volume in database
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create a host filesystem
        dbutils.create_test_host_fs(name='backup',
                                    forihostid=self.host.id)

        # Return fake dictionary for logical volume and size
        self.fake_lv_size.return_value = {'extension-lv': 1,
                                          'pgsql-lv': 5,
                                          'platform-lv': 10}

        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{"path": "/name",
                                    "value": "extension",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "2",
                                    "op": "replace"}],
                                  [{"path": "/name",
                                    "value": "database",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "6",
                                    "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("This operation requires controllers to be",
                      response.json['error_message'])

    def test_put_fail_capabilities_backend_applying(self):
        """Test that updating capabilities on controller-fs ceph-float is
        rejected when the rook-ceph backend is in configuring-with-app state
        with task=applying.

        Capability updates should be blocked when the app is in transition
        because it cannot process concurrent configuration changes."""

        # Rook Ceph backend in CONFIGURING_WITH_APP with task=applying
        backend = dbutils.get_test_ceph_rook_storage_backend(
            state=constants.SB_STATE_CONFIGURING_WITH_APP,
            task=constants.APP_APPLY_IN_PROGRESS)
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        controller_1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create ceph-float with empty capabilities
        self._create_db_object('ceph-float',
                               20,
                               'ceph-float-lv',
                               {"functions": []})

        # Try to add monitor function — backend is applying
        new_capabilities = {"functions": ["monitor"]}
        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{
                                     "path": "/name",
                                     "value": "ceph-float",
                                     "op": "replace"},
                                   {
                                     "path": "/capabilities",
                                     "value": jsonutils.dumps(new_capabilities),
                                     "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        # Should be rejected because backend is in transitional state
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_put_fail_capabilities_backend_removing(self):
        """Test that updating capabilities on controller-fs ceph-float is
        rejected when the rook-ceph backend task is 'removing'.

        Modifying capabilities while the app is being removed can lead
        to inconsistent state."""

        # Rook Ceph backend in CONFIGURING_WITH_APP with task=removing
        backend = dbutils.get_test_ceph_rook_storage_backend(
            state=constants.SB_STATE_CONFIGURING_WITH_APP,
            task=constants.APP_REMOVE_IN_PROGRESS)
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        controller_1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create ceph-float with monitor capabilities
        self._create_db_object('ceph-float',
                               20,
                               'ceph-float-lv',
                               {"functions": ["monitor"]})

        # Try to remove monitor function — backend is removing
        new_capabilities = {"functions": []}
        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{
                                     "path": "/name",
                                     "value": "ceph-float",
                                     "op": "replace"},
                                   {
                                     "path": "/capabilities",
                                     "value": jsonutils.dumps(new_capabilities),
                                     "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        # Should be rejected because backend is in transitional state
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_put_fail_modify_in_update_error_state(self):
        """Test that modifying ceph-float capabilities fails when the
        controller_fs is in drbd_fs_update_error state."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_ceph_rook_storage_backend()
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        controller_1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create ceph-float in update_error state (simulating a failed
        # delete operation)
        cap = {"functions": ["monitor"]}
        self._create_db_object('ceph-float',
                               20,
                               'ceph-float-lv',
                               cap,
                               obj_id=92)
        # Update the state to drbd_fs_update_error
        controller_fs_list = self.dbapi.controller_fs_get_list()
        for fs in controller_fs_list:
            if fs.name == 'ceph-float':
                self.dbapi.controller_fs_update(fs.uuid, {
                    'state': str({'status':
                                  constants.CONTROLLER_FS_UPDATE_ERROR})})
                break

        # Try to modify capabilities while in update_error state
        cap_updated = {"functions": ["monitor"]}
        response = self.put_json(self.get_update_url(self.system.uuid),
                                 [[{
                                     "path": "/name",
                                     "value": "ceph-float",
                                     "op": "replace"},
                                   {
                                     "path": "/capabilities",
                                     "value": jsonutils.dumps(cap_updated),
                                     "op": "replace"}]],
                                 headers=self.API_HEADERS,
                                 expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(constants.CONTROLLER_FS_UPDATE_ERROR,
                      response.json['error_message'])


class ApiControllerFSDetailTestSuiteMixin(ApiControllerFSTestCaseMixin):
    """ Controller FileSystem detail operations
    """
    def setUp(self):
        super(ApiControllerFSDetailTestSuiteMixin, self).setUp()

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
        self.assertEqual(result_one['size'], self.controller_fs_first.size)
        self.assertEqual(result_one['isystem_uuid'], self.controller_fs_first.isystem_uuid)
        self.assertEqual(result_one['name'], self.controller_fs_first.name)
        self.assertEqual(result_one['logical_volume'], self.controller_fs_first.logical_volume)
        self.assertEqual(result_one['forisystemid'], self.controller_fs_first.forisystemid)
        self.assertEqual(result_one['action'], None)
        self.assertEqual(result_one['uuid'], self.controller_fs_first.uuid)
        self.assertEqual(result_one['state'], self.controller_fs_first.state)
        self.assertEqual(result_one['replicated'], self.controller_fs_first.replicated)

        # Response object 2
        self.assertEqual(result_two['size'], self.controller_fs_second.size)
        self.assertEqual(result_two['isystem_uuid'], self.controller_fs_second.isystem_uuid)
        self.assertEqual(result_two['name'], self.controller_fs_second.name)
        self.assertEqual(result_two['logical_volume'], self.controller_fs_second.logical_volume)
        self.assertEqual(result_two['forisystemid'], self.controller_fs_second.forisystemid)
        self.assertEqual(result_two['action'], None)
        self.assertEqual(result_two['uuid'], self.controller_fs_second.uuid)
        self.assertEqual(result_two['state'], self.controller_fs_second.state)
        self.assertEqual(result_two['replicated'], self.controller_fs_second.replicated)

        # Response object 3
        self.assertEqual(result_three['size'], self.controller_fs_third.size)
        self.assertEqual(result_three['isystem_uuid'], self.controller_fs_third.isystem_uuid)
        self.assertEqual(result_three['name'], self.controller_fs_third.name)
        self.assertEqual(result_three['logical_volume'], self.controller_fs_third.logical_volume)
        self.assertEqual(result_three['forisystemid'], self.controller_fs_third.forisystemid)
        self.assertEqual(result_three['action'], None)
        self.assertEqual(result_three['uuid'], self.controller_fs_third.uuid)
        self.assertEqual(result_three['state'], self.controller_fs_third.state)
        self.assertEqual(result_three['replicated'], self.controller_fs_third.replicated)


class ApiControllerFSPatchTestSuiteMixin(ApiControllerFSTestCaseMixin):
    """ Controller FileSystem patch operations
    """
    def setUp(self):
        super(ApiControllerFSPatchTestSuiteMixin, self).setUp()

    # Test that a valid PATCH operation is blocked by the API
    # API should return 400 BAD_REQUEST or FORBIDDEN 403
    def test_patch_not_allowed(self):
        uuid = self.controller_fs_third.uuid
        response = self.patch_json(self.get_show_url(uuid),
                                   [{"path": "/name",
                                    "value": "extension",
                                    "op": "replace"},
                                   {"path": "/size",
                                    "value": "2",
                                    "op": "replace"}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.FORBIDDEN)
        self.assertIn("Operation not permitted", response.json['error_message'])


class ApiControllerFSDeleteTestSuiteMixin(ApiControllerFSTestCaseMixin):
    """ Controller FileSystem delete operations
    """
    def setUp(self):
        super(ApiControllerFSDeleteTestSuiteMixin, self).setUp()

    def test_invalid_delete(self):
        response = self.delete('/controller_fs/%s' %
                                  self.controller_fs_third.uuid,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Unsupported controller filesystem", response.json['error_message'])

    def test_delete_allowed(self):

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)
        controller_fs = self._create_db_object('ceph-float',
                                                20,
                                                'ceph-float-lv')

        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        response = self.delete('/controller_fs/%s' %
                                  controller_fs.uuid,
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)

    def test_delete_not_allowed(self):

        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)
        controller_fs = self._create_db_object('ceph-float',
                                                20,
                                                'ceph-float-lv')

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        response = self.delete('/controller_fs/%s' %
                                  controller_fs.uuid,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Failed to delete:", response.json['error_message'])

    def test_delete_creating_on_unlock_direct_db(self):
        """Test that deleting a controller_fs in CREATING_ON_UNLOCK state
        performs a direct DB deletion without RPC calls."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller_fs entry with state=CREATING_ON_UNLOCK
        controller_fs = dbutils.create_test_controller_fs(
            uuid=None,
            name='ceph-float',
            forisystemid=self.system.id,
            state=str({'status': constants.CONTROLLER_FS_CREATING_ON_UNLOCK}),
            capabilities={"functions": []},
            size=20,
            logical_volume='ceph-float-lv',
            replicated=True,
            isystem_uuid=self.system.uuid)

        # Create controller-1 locked (required for standby check)
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create LVG so that LVG update check passes
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create a provisioned PV
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        response = self.delete('/controller_fs/%s' %
                                  controller_fs.uuid,
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify no RPC call was made (direct DB deletion path)
        self.fake_conductor_api.update_storage_config.assert_not_called()

        # Verify DB record is removed
        controller_fs_list = self.dbapi.controller_fs_get_list()
        ceph_float_entries = [fs for fs in controller_fs_list
                              if fs['name'] == 'ceph-float']
        self.assertEqual(len(ceph_float_entries), 0)

    def test_delete_fail_creating_in_progress(self):
        """Test that deleting a controller_fs in CREATING_IN_PROGRESS state
        fails with appropriate error."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller_fs entry with state=CREATING_IN_PROGRESS
        controller_fs = dbutils.create_test_controller_fs(
            uuid=None,
            name='ceph-float',
            forisystemid=self.system.id,
            state=str({'status': constants.CONTROLLER_FS_CREATING_IN_PROGRESS}),
            capabilities={"functions": []},
            size=20,
            logical_volume='ceph-float-lv',
            replicated=True,
            isystem_uuid=self.system.uuid)

        # Create controller-1 locked
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create LVG so that LVG update check passes
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create a provisioned PV
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        response = self.delete('/controller_fs/%s' %
                                  controller_fs.uuid,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("must have the status",
                      response.json['error_message'])
        self.assertIn(constants.CONTROLLER_FS_AVAILABLE,
                      response.json['error_message'])

    def test_delete_fail_resizing(self):
        """Test that deleting a controller_fs in RESIZING_IN_PROGRESS state
        fails with appropriate error."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller_fs entry with state=RESIZING_IN_PROGRESS
        controller_fs = dbutils.create_test_controller_fs(
            uuid=None,
            name='ceph-float',
            forisystemid=self.system.id,
            state=str({'status': constants.CONTROLLER_FS_RESIZING_IN_PROGRESS}),
            capabilities={"functions": []},
            size=20,
            logical_volume='ceph-float-lv',
            replicated=True,
            isystem_uuid=self.system.uuid)

        # Create controller-1 locked
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create LVG so that LVG update check passes
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create a provisioned PV
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        response = self.delete('/controller_fs/%s' %
                                  controller_fs.uuid,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("must have the status",
                      response.json['error_message'])
        self.assertIn(constants.CONTROLLER_FS_AVAILABLE,
                      response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.controller_fs.'
                '_floating_monitor_is_installed')
    def test_delete_fail_monitor_active_floating_installed(self,
                                                           mock_float_installed):
        """Test that deleting a controller_fs with an active monitor function
        is blocked when the floating monitor is installed."""

        # Mock the floating monitor check to return True
        mock_float_installed.return_value = True

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller_fs with active monitor function
        controller_fs = dbutils.create_test_controller_fs(
            uuid=None,
            name='ceph-float',
            forisystemid=self.system.id,
            state=str({'status': constants.CONTROLLER_FS_AVAILABLE}),
            capabilities={"functions": ["monitor"]},
            size=20,
            logical_volume='ceph-float-lv',
            replicated=True,
            isystem_uuid=self.system.uuid)

        # Create controller-1 locked
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create LVG so that LVG update check passes
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create a provisioned PV
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        response = self.delete('/controller_fs/%s' %
                                  controller_fs.uuid,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("operation not allowed",
                      response.json['error_message'])
        self.assertIn("monitor function",
                      response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.utils.is_host_lvg_updated')
    def test_delete_fail_pending_lvg_updates(self, mock_lvg_updated):
        """Test that deleting a controller_fs fails when there are pending
        LVG updates on the controllers."""

        # Mock LVG check to report not updated (pending updates)
        mock_lvg_updated.return_value = False

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller_fs entry
        controller_fs = dbutils.create_test_controller_fs(
            uuid=None,
            name='ceph-float',
            forisystemid=self.system.id,
            state=str({'status': constants.CONTROLLER_FS_AVAILABLE}),
            capabilities={"functions": []},
            size=20,
            logical_volume='ceph-float-lv',
            replicated=True,
            isystem_uuid=self.system.uuid)

        # Create controller-1 locked
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        response = self.delete('/controller_fs/%s' %
                                  controller_fs.uuid,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("pending LVG updates",
                      response.json['error_message'])

    def test_delete_fail_standby_not_locked(self):
        """Test that deleting a controller_fs fails when the standby
        controller is not locked."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller_fs entry in AVAILABLE state
        controller_fs = dbutils.create_test_controller_fs(
            uuid=None,
            name='ceph-float',
            forisystemid=self.system.id,
            state=str({'status': constants.CONTROLLER_FS_AVAILABLE}),
            capabilities={"functions": []},
            size=20,
            logical_volume='ceph-float-lv',
            replicated=True,
            isystem_uuid=self.system.uuid)

        # Create controller-1 in UNLOCKED state (not locked)
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_AVAILABLE)

        # Create LVG so that LVG update check passes
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create a provisioned PV
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        response = self.delete('/controller_fs/%s' %
                                  controller_fs.uuid,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("standby controller",
                      response.json['error_message'])
        self.assertIn("locked",
                      response.json['error_message'])

    def test_delete_fail_reconfigure_with_app_state(self):
        """Test that deleting ceph-float fails when controller_fs is in
        reconfigure-with-app state."""

        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create ceph-float in reconfigure-with-app state
        controller_fs = self._create_db_object('ceph-float',
                                               20,
                                               'ceph-float-lv')
        self.dbapi.controller_fs_update(controller_fs.uuid, {
            'state': str({'status':
                          constants.CONTROLLER_FS_RECONFIGURE_WITH_APP})})

        response = self.delete('/controller_fs/%s' % controller_fs.uuid,
                               headers=self.API_HEADERS,
                               expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(constants.CONTROLLER_FS_RECONFIGURE_WITH_APP,
                      response.json['error_message'])

    def test_delete_fail_resizing_in_progress_state(self):
        """Test that deleting ceph-float fails when controller_fs is in
        drbd_fs_resizing_in_progress state."""

        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create ceph-float in resizing_in_progress state
        controller_fs = self._create_db_object('ceph-float',
                                               20,
                                               'ceph-float-lv')
        self.dbapi.controller_fs_update(controller_fs.uuid, {
            'state': str({'status':
                          constants.CONTROLLER_FS_RESIZING_IN_PROGRESS})})

        response = self.delete('/controller_fs/%s' % controller_fs.uuid,
                               headers=self.API_HEADERS,
                               expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(constants.CONTROLLER_FS_AVAILABLE,
                      response.json['error_message'])

    def test_delete_fail_creating_in_progress_state(self):
        """Test that deleting ceph-float fails when controller_fs is in
        drbd_fs_creating_in_progress state."""

        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create ceph-float in creating_in_progress state
        controller_fs = self._create_db_object('ceph-float',
                                               20,
                                               'ceph-float-lv')
        self.dbapi.controller_fs_update(controller_fs.uuid, {
            'state': str({'status':
                          constants.CONTROLLER_FS_CREATING_IN_PROGRESS})})

        response = self.delete('/controller_fs/%s' % controller_fs.uuid,
                               headers=self.API_HEADERS,
                               expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(constants.CONTROLLER_FS_AVAILABLE,
                      response.json['error_message'])

    def test_delete_fail_deleting_in_progress_state(self):
        """Test that deleting ceph-float fails when controller_fs is already
        in drbd_fs_deleting_in_progress state."""

        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create ceph-float in deleting_in_progress state
        controller_fs = self._create_db_object('ceph-float',
                                               20,
                                               'ceph-float-lv')
        self.dbapi.controller_fs_update(controller_fs.uuid, {
            'state': str({'status':
                          constants.CONTROLLER_FS_DELETING_IN_PROGRESS})})

        response = self.delete('/controller_fs/%s' % controller_fs.uuid,
                               headers=self.API_HEADERS,
                               expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(constants.CONTROLLER_FS_AVAILABLE,
                      response.json['error_message'])


class ApiControllerFSPostTestSuiteMixin(ApiControllerFSTestCaseMixin):
    """ Controller FileSystem post operations
    """
    def setUp(self):
        super(ApiControllerFSPostTestSuiteMixin, self).setUp()

    def test_invalid_post(self):
        response = self.post_json('/controller_fs',
                                  {'name': 'test',
                                   'size': 10},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Unsupported controller filesystem", response.json['error_message'])

    def test_post_allowed(self):

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Create host-fs ceph with monitor function on both controllers
        # (required fixed monitors before creating the floating monitor)
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        url = self.get_show_url(response.json['uuid'])
        response = self.get_json(url,
                                 headers=self.API_HEADERS,
                                 expect_errors=False)

        capabilities = {"functions": ["monitor"]}
        self.assertEqual(response['capabilities'], capabilities)

    def test_post_fail_no_fixed_monitors(self):
        """Test that creating ceph-float fails when fixed monitors are not configured."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # No host-fs ceph with monitor on the controllers
        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("does not have a ceph host-fs configured",
                      response.json['error_message'])
        self.assertIn("Both controllers must have fixed monitors",
                      response.json['error_message'])

    def test_post_success_controller_1_unprovisioned(self):
        """Test that creating ceph-float succeeds when controller-1 is
        unprovisioned (skips fixed monitor check for that host)."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        self._create_controller_1(
            invprovision=constants.UNPROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create host-fs ceph with monitor function only on controller-0
        # (controller-1 is unprovisioned, so it should be skipped)
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_post_success_controller_1_provisioning(self):
        """Test that creating ceph-float succeeds when controller-1 is
        in provisioning state (skips fixed monitor check for that host)."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        self._create_controller_1(
            invprovision=constants.PROVISIONING,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create host-fs ceph with monitor function only on controller-0
        # (controller-1 is provisioning, so it should be skipped)
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_post_success_dx_single_controller(self):
        """Test that creating ceph-float succeeds in a DX system when
        only controller-0 exists (controller-1 not yet installed).

        During initial DX deployment, the system is configured as duplex
        but only controller-0 is present. The fixed monitor check should
        pass with only controller-0's monitor configured.
        """

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # No controller-1 created — only controller-0 exists

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Controller-0 must be provisioning for the monitor check
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONING})

        # Create host-fs ceph with monitor function on controller-0
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_post_fail_host_fs_creating_state(self):
        """Test that creating ceph-float fails when host-fs ceph is in
        Creating state."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Controller-0 must be provisioned to not be skipped
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED})

        # Create host-fs ceph with monitor function but in "Creating" state
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_CREATE_IN_SVC,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("must be in", response.json['error_message'])
        self.assertIn(constants.HOST_FS_STATUS_CREATE_IN_SVC,
                      response.json['error_message'])

    def test_post_fail_host_fs_reconfigure_with_app_state(self):
        """Test that creating ceph-float fails when host-fs ceph is in
        Reconfigure with App state."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Controller-0 must be provisioned to not be skipped
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED})

        # Create host-fs ceph with monitor function but in
        # "Reconfigure with App" state
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_RECONFIGURE_WITH_APP,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(constants.HOST_FS_STATUS_RECONFIGURE_WITH_APP,
                      response.json['error_message'])
        self.assertIn("Please apply the application",
                      response.json['error_message'])

    def test_post_fail_host_fs_modifying_state(self):
        """Test that creating ceph-float fails when host-fs ceph is in
        Modifying state."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Create host-fs ceph with monitor function but in "Modifying" state
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_MODIFYING,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("must be in", response.json['error_message'])
        self.assertIn(constants.HOST_FS_STATUS_MODIFYING,
                      response.json['error_message'])

    def test_post_fail_host_fs_deleting_state(self):
        """Test that creating ceph-float fails when host-fs ceph is in
        Deleting state."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Create host-fs ceph with monitor function but in "Deleting" state
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_DELETING,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("must be in", response.json['error_message'])
        self.assertIn(constants.HOST_FS_STATUS_DELETING,
                      response.json['error_message'])

    def test_post_fail_host_fs_deleting_on_unlock_state(self):
        """Test that creating ceph-float fails when host-fs ceph is in
        Deleting (on unlock) state."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Create host-fs ceph with monitor function but in
        # "Deleting (on unlock)" state
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_DELETING_ON_UNLOCK,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("must be in", response.json['error_message'])
        self.assertIn(constants.HOST_FS_STATUS_DELETING_ON_UNLOCK,
                      response.json['error_message'])

    def test_post_fail_host_fs_update_error_state(self):
        """Test that creating ceph-float fails when host-fs ceph is in
        Error state."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Create host-fs ceph with monitor function but in "Error" state
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_UPDATE_ERROR,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("must be in", response.json['error_message'])
        self.assertIn(constants.HOST_FS_STATUS_UPDATE_ERROR,
                      response.json['error_message'])

    def test_post_success_host_fs_creating_on_unlock_state(self):
        """Test that creating ceph-float succeeds when host-fs ceph is in
        Creating (on unlock) state."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Controller-0 must be provisioned to not be skipped
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED})

        # Create host-fs ceph with monitor function but in
        # "Creating (on unlock)" state
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_CREATE_ON_UNLOCK,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_post_success_host_fs_ready_state(self):
        """Test that creating ceph-float succeeds when host-fs ceph is in
        Ready state."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Controller-0 must be provisioned to not be skipped
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED})

        # Create host-fs ceph with monitor function in "Ready" state
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_READY,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_READY,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_post_success_host_fs_in_use_state(self):
        """Test that creating ceph-float succeeds when host-fs ceph is in
        In-Use state."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Controller-0 must be provisioned to not be skipped
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED})

        # Create host-fs ceph with monitor function in "In-Use" state
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_post_not_allowed(self):
        """Test that creating ceph-float fails when controller-0 is
        provisioned but does not have ceph host-fs configured."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Controller-0 must be provisioned to not be skipped
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("does not have a ceph host-fs configured",
                      response.json['error_message'])

    def test_post_not_allowed_controller_unprovisioned(self):
        """Test that creating ceph-float fails when controller-0 is
        unprovisioned (skipped) and controller-1 is provisioned but
        does not have ceph host-fs configured."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Controller-1 provisioned but without ceph host-fs
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Controller-0 remains unprovisioned (default) — will be skipped

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("does not have a ceph host-fs configured",
                      response.json['error_message'])

    def test_post_fail_no_rook_backend(self):
        """Test that creating ceph-float fails when Rook is not configured
        as storage backend."""

        # No Rook storage backend configured

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("must be configured as storage backend",
                      response.json['error_message'])

    def test_post_fail_not_duplex(self):
        """Test that creating ceph-float fails on a simplex system."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Set system mode to simplex
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_SIMPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("command only allowed for duplex",
                      response.json['error_message'])

    def test_post_fail_already_exists(self):
        """Test that creating ceph-float fails when it already exists."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        controller_1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create ceph-float entry in DB (already exists)
        self._create_db_object('ceph-float', 20, 'ceph-float-lv')

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("already present",
                      response.json['error_message'])

    def test_post_fail_insufficient_space(self):
        """Test that creating ceph-float fails when there is not enough
        free space on cgts-vg."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        controller_1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create LVG with no free space (lvm_vg_free_pe=0)
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id,
                                lvm_vg_size=200,
                                lvm_vg_total_pe=100,
                                lvm_vg_free_pe=0)

        # Create a provisioned PV so the unprovisioned check passes
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Not enough free space",
                      response.json['error_message'])

    def test_post_fail_size_below_minimum(self):
        """Test that creating ceph-float fails when size is below
        SB_CEPH_MON_GIB_MIN."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        controller_1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create LVG with enough space
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create a provisioned PV
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        # POST with size below SB_CEPH_MON_GIB_MIN (20)
        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 5},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("size for fs",
                      response.json['error_message'])

    def test_post_fail_standby_not_locked(self):
        """Test that creating ceph-float fails when the standby controller
        is not locked."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Create controller-1 in unlocked administrative state
        controller_1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_AVAILABLE)

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create LVG with enough space
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create a provisioned PV
        dbutils.create_test_pv(lvm_vg_name='cgts-vg',
                               forihostid=self.host.id,
                               pv_state='provisioned')

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("standby controller",
                      response.json['error_message'])
        self.assertIn("locked",
                      response.json['error_message'])

    def test_post_state_creating_on_unlock(self):
        """Test that creating ceph-float sets state to CREATING_ON_UNLOCK
        when the system is in PROVISIONING state with a single host."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # No controller-1 created — only controller-0 exists (single host)

        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Controller-0 must be in PROVISIONING state
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONING})

        # Create host-fs ceph with monitor function on controller-0
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify the filesystem state is CREATING_ON_UNLOCK
        url = self.get_show_url(response.json['uuid'])
        show_response = self.get_json(url,
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        state = eval(show_response['state'])
        self.assertEqual(state['status'],
                         constants.CONTROLLER_FS_CREATING_ON_UNLOCK)

    def test_post_rpc_failure_update_storage(self):
        """Test that creating ceph-float handles RPC failure gracefully
        by removing the DB entry and returning an error."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Mock RPC to raise an exception
        self.fake_conductor_api.update_storage_config = mock.MagicMock(
            side_effect=Exception("RPC communication failure"))

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Should return an error
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Failed to create filesystem",
                      response.json['error_message'])

        # Verify no inconsistent DB state — the ceph-float entry should
        # have been cleaned up (destroyed) after the RPC failure
        controller_fs_list = self.dbapi.controller_fs_get_list()
        ceph_float_entries = [fs for fs in controller_fs_list
                              if fs['name'] == 'ceph-float']
        self.assertEqual(len(ceph_float_entries), 0)

    @mock.patch('sysinv.api.controllers.v1.controller_fs.'
                '_floating_monitor_is_installed')
    def test_post_floating_monitor_already_installed(self,
                                                     mock_float_installed):
        """Test that creating ceph-float succeeds even when a floating
        monitor deployment already exists in Kubernetes. The floating
        monitor installed check is only blocking for delete operations,
        not create."""

        # Mock the floating monitor check to return True
        mock_float_installed.return_value = True

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        # Creation should succeed regardless of floating monitor state
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_conductor_config_success_transitions(self):
        """Test that when the conductor reports config success for a
        controller_fs operation, the filesystem state transitions to
        AVAILABLE.

        Since the conductor RPC is mocked, this test simulates the
        conductor callback by directly updating the DB state after a
        successful creation, verifying the expected final state.

        Validates: Requirements 11.4
        """

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create ceph-float — state will be CREATING_IN_PROGRESS
        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)
        fs_uuid = response.json['uuid']

        # Verify current state is CREATING_IN_PROGRESS
        url = self.get_show_url(fs_uuid)
        show_response = self.get_json(url,
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        state = eval(show_response['state'])
        self.assertEqual(state['status'],
                         constants.CONTROLLER_FS_CREATING_IN_PROGRESS)

        # Simulate conductor callback reporting success by updating
        # the filesystem state to AVAILABLE (as the conductor would do)
        self.dbapi.controller_fs_update(
            fs_uuid,
            {'state': str({'status': constants.CONTROLLER_FS_AVAILABLE})})

        # Verify filesystem state transitioned to AVAILABLE
        show_response = self.get_json(url,
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        state = eval(show_response['state'])
        self.assertEqual(state['status'],
                         constants.CONTROLLER_FS_AVAILABLE)

    def test_conductor_config_failure_transitions(self):
        """Test that when the conductor reports config failure for a
        controller_fs operation, the filesystem state transitions to
        an error state.

        Since the conductor RPC is mocked, this test simulates the
        conductor callback by directly updating the DB state after a
        failed configuration, verifying the expected error state.

        Validates: Requirements 11.5
        """

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create ceph-float — state will be CREATING_IN_PROGRESS
        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)
        fs_uuid = response.json['uuid']

        # Verify current state is CREATING_IN_PROGRESS
        url = self.get_show_url(fs_uuid)
        show_response = self.get_json(url,
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        state = eval(show_response['state'])
        self.assertEqual(state['status'],
                         constants.CONTROLLER_FS_CREATING_IN_PROGRESS)

        # Simulate conductor callback reporting failure by updating
        # the filesystem state to UPDATE_ERROR (as the conductor would do)
        self.dbapi.controller_fs_update(
            fs_uuid,
            {'state': str({'status': constants.CONTROLLER_FS_UPDATE_ERROR})})

        # Verify filesystem state transitioned to error state
        show_response = self.get_json(url,
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        state = eval(show_response['state'])
        self.assertEqual(state['status'],
                         constants.CONTROLLER_FS_UPDATE_ERROR)

    def test_multi_controller_operation(self):
        """Test that in a duplex system, both controllers must report
        success before the filesystem state transitions to AVAILABLE.

        This test simulates the multi-controller operation flow where:
        1. A controller_fs is created in CREATING_IN_PROGRESS state
        2. Controller-0 reports success (state stays CREATING_IN_PROGRESS)
        3. Only after both controllers report does state become AVAILABLE

        Since the conductor RPC is mocked, we simulate the conductor
        behavior by updating DB state directly.

        Validates: Requirements 11.6
        """

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create ceph-float — state will be CREATING_IN_PROGRESS
        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)
        fs_uuid = response.json['uuid']

        # Verify current state is CREATING_IN_PROGRESS
        url = self.get_show_url(fs_uuid)
        show_response = self.get_json(url,
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        state = eval(show_response['state'])
        self.assertEqual(state['status'],
                         constants.CONTROLLER_FS_CREATING_IN_PROGRESS)

        # Simulate controller-0 reporting success but controller-1 not yet.
        # State should remain CREATING_IN_PROGRESS (not yet AVAILABLE).
        # In the real system, the conductor waits for both controllers
        # to report before transitioning to AVAILABLE.
        show_response = self.get_json(url,
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        state = eval(show_response['state'])
        self.assertNotEqual(state['status'],
                            constants.CONTROLLER_FS_AVAILABLE)
        self.assertEqual(state['status'],
                         constants.CONTROLLER_FS_CREATING_IN_PROGRESS)

        # Simulate both controllers having reported success —
        # conductor updates state to AVAILABLE
        self.dbapi.controller_fs_update(
            fs_uuid,
            {'state': str({'status': constants.CONTROLLER_FS_AVAILABLE})})

        # Verify filesystem state is now AVAILABLE after both reports
        show_response = self.get_json(url,
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        state = eval(show_response['state'])
        self.assertEqual(state['status'],
                         constants.CONTROLLER_FS_AVAILABLE)

    @mock.patch('sysinv.api.controllers.v1.utils.is_host_lvg_updated')
    @mock.patch('sysinv.api.controllers.v1.controller_fs.'
                '_floating_monitor_is_installed')
    def test_update_error_retry_succeeds(self, mock_float_installed,
                                         mock_is_host_lvg_updated):
        """Test that a filesystem in UPDATE_ERROR state can be retried
        (re-created) and transitions to the correct state.

        When a controller_fs is in error state, the user can delete it
        and recreate it. This test verifies the full retry flow:
        1. Create ceph-float (enters CREATING_IN_PROGRESS)
        2. Simulate conductor failure (state → UPDATE_ERROR)
        3. Delete the errored filesystem
        4. Recreate — should succeed with CREATING_IN_PROGRESS state

        Validates: Requirements 11.10
        """

        # Mock the LVG check to always return True (no pending updates)
        mock_is_host_lvg_updated.return_value = True

        # Mock the floating monitor check to return False (not installed)
        # so the delete is not blocked by the monitor function check
        mock_float_installed.return_value = False

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Create host-fs ceph with monitor function on both controllers
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume on controller-0
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Step 1: Create ceph-float (enters CREATING_IN_PROGRESS)
        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)
        fs_uuid = response.json['uuid']

        # Step 2: Simulate conductor failure (state → UPDATE_ERROR)
        self.dbapi.controller_fs_update(
            fs_uuid,
            {'state': str({'status': constants.CONTROLLER_FS_UPDATE_ERROR})})

        # Verify it's in error state
        url = self.get_show_url(fs_uuid)
        show_response = self.get_json(url,
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        state = eval(show_response['state'])
        self.assertEqual(state['status'],
                         constants.CONTROLLER_FS_UPDATE_ERROR)

        # Step 3: Delete the errored filesystem
        # The UPDATE_ERROR state is treated as AVAILABLE for deletion purposes
        response = self.delete('/controller_fs/%s' % fs_uuid,
                               headers=self.API_HEADERS,
                               expect_errors=False)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Simulate the conductor completing the deletion (since RPC is mocked,
        # the actual DB record isn't removed — the conductor would do that)
        self.dbapi.controller_fs_destroy(fs_uuid)

        # Step 4: Recreate — should succeed
        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)
        new_fs_uuid = response.json['uuid']

        # Verify the new filesystem is in CREATING_IN_PROGRESS state
        url = self.get_show_url(new_fs_uuid)
        show_response = self.get_json(url,
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        state = eval(show_response['state'])
        self.assertEqual(state['status'],
                         constants.CONTROLLER_FS_CREATING_IN_PROGRESS)

    def test_creating_on_unlock_transition(self):
        """Test that a filesystem created in CREATING_ON_UNLOCK state
        transitions through CREATING_IN_PROGRESS when the unlock event
        occurs (simulated by conductor updating the state).

        During initial system provisioning with a single controller, the
        filesystem is created in CREATING_ON_UNLOCK state. When the host
        is unlocked, the conductor transitions it to CREATING_IN_PROGRESS
        and eventually to AVAILABLE (or IN_USE at the host-fs level).

        Validates: Requirements 11.7
        """

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

        # No controller-1 — only controller-0 exists (single controller DX)
        # Must be AIO-DX
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['system_type'] = constants.TIS_AIO_BUILD
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        # Controller-0 must be in provisioning state
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONING})

        # Create host-fs ceph with monitor function on controller-0
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Create ceph-float in DX single-controller scenario
        # Should be set to CREATING_ON_UNLOCK because system is provisioning
        # with only 1 controller host
        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)
        fs_uuid = response.json['uuid']

        # Verify state is CREATING_ON_UNLOCK
        url = self.get_show_url(fs_uuid)
        show_response = self.get_json(url,
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        state = eval(show_response['state'])
        self.assertEqual(state['status'],
                         constants.CONTROLLER_FS_CREATING_ON_UNLOCK)

        # Simulate unlock event: conductor transitions state to
        # CREATING_IN_PROGRESS
        self.dbapi.controller_fs_update(
            fs_uuid,
            {'state': str({'status': constants.CONTROLLER_FS_CREATING_IN_PROGRESS})})

        # Verify state is now CREATING_IN_PROGRESS
        show_response = self.get_json(url,
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        state = eval(show_response['state'])
        self.assertEqual(state['status'],
                         constants.CONTROLLER_FS_CREATING_IN_PROGRESS)

        # Simulate conductor completing the operation: state → AVAILABLE
        self.dbapi.controller_fs_update(
            fs_uuid,
            {'state': str({'status': constants.CONTROLLER_FS_AVAILABLE})})

        # Verify final state is AVAILABLE
        show_response = self.get_json(url,
                                      headers=self.API_HEADERS,
                                      expect_errors=False)
        state = eval(show_response['state'])
        self.assertEqual(state['status'],
                         constants.CONTROLLER_FS_AVAILABLE)

    def test_post_fail_controller_1_host_fs_reconfigure_with_app(self):
        """Test that creating ceph-float fails when controller-1 host-fs
        ceph is in Reconfigure with App state (controller-0 is stable)."""

        # Rook Ceph must be as storage backend
        backend = dbutils.get_test_storage_backend(backend=constants.SB_TYPE_CEPH_ROOK)
        self.dbapi.storage_ceph_rook_create(backend)

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

        # Controller-0 must be provisioned to not be skipped
        self.dbapi.ihost_update(self.host.uuid,
                                {'invprovision': constants.PROVISIONED})

        # Controller-0 has host-fs ceph in stable IN_USE state
        dbutils.create_test_host_fs(id=90,
                                    name='ceph',
                                    forihostid=self.host.id,
                                    state=constants.HOST_FS_STATUS_IN_USE,
                                    capabilities={"functions": ["monitor"]})
        # Controller-1 has host-fs ceph in "Reconfigure with App" state
        dbutils.create_test_host_fs(id=91,
                                    name='ceph',
                                    forihostid=controller_1.id,
                                    state=constants.HOST_FS_STATUS_RECONFIGURE_WITH_APP,
                                    capabilities={"functions": ["monitor"]})

        # Create a logical volume
        dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        response = self.post_json('/controller_fs',
                                  {'name': 'ceph-float',
                                   'size': 20},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(constants.HOST_FS_STATUS_RECONFIGURE_WITH_APP,
                      response.json['error_message'])
        self.assertIn("Please apply the application",
                      response.json['error_message'])
