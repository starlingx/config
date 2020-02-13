#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / controller-fs / methods.
"""

import mock
from six.moves import http_client
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


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
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI')
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
                          controller_lv, obj_id=None):
        return dbutils.create_test_controller_fs(id=obj_id,
                                                 uuid=None,
                                                 name=controller_fs_name,
                                                 forisystemid=self.system.id,
                                                 state='available',
                                                 size=controller_fs_size,
                                                 logical_volume=controller_lv,
                                                 replicated=True,
                                                 isystem_uuid=self.system.uuid)


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
        self.assertIn("Total target growth size 9 GiB for database (doubled "
                      "for upgrades), platform, scratch, backup and "
                      "extension exceeds growth limit of 0 GiB.",
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

    # Test that a valid DELETE operation is blocked by the API
    # API should return 400 BAD_REQUEST or FORBIDDEN 403
    def test_delete_not_allowed(self):
        uuid = self.controller_fs_third.uuid
        response = self.delete(self.get_show_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.FORBIDDEN)
        self.assertIn("Operation not permitted", response.json['error_message'])


class ApiControllerFSPostTestSuiteMixin(ApiControllerFSTestCaseMixin):
    """ Controller FileSystem post operations
    """
    def setUp(self):
        super(ApiControllerFSPostTestSuiteMixin, self).setUp()

    # Test that a valid POST operation is blocked by the API
    # API should return 400 BAD_REQUEST or FORBIDDEN 403
    def test_post_not_allowed(self):
        response = self.post_json(self.API_PREFIX,
                                  {'name': 'platform-new',
                                   'size': 10,
                                   'logical_volume': 'platform-lv'},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.FORBIDDEN)
        self.assertIn("Operation not permitted", response.json['error_message'])
