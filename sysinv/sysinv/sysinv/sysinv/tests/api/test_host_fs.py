#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / host-fs / methods.
"""

import mock
import uuid
from six.moves import http_client
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
from sysinv.common import constants


class FakeConductorAPI(object):

    def __init__(self):
        self.get_controllerfs_lv_sizes = mock.MagicMock()
        self.update_host_filesystem_config = mock.MagicMock()


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
                                                    'scratch-lv')
        self.host_fs_second = self._create_db_object('backup',
                                                     20,
                                                     'backup-lv')
        self.host_fs_third = self._create_db_object('docker',
                                                    30,
                                                    'docker-lv')
        self.fake_conductor_api = FakeConductorAPI()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI')
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

    def _create_db_object(self, host_fs_name, host_fs_size,
                          host_lv, obj_id=None):
        return dbutils.create_test_host_fs(id=obj_id,
                                           uuid=None,
                                           name=host_fs_name,
                                           forihostid=self.host.id,
                                           size=host_fs_size,
                                           logical_volume=host_lv)


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
                                                    'scratch-lv')
        self.host_fs_second = self._create_db_object('backup',
                                                     20,
                                                     'backup-lv')
        self.host_fs_third = self._create_db_object('docker',
                                                    30,
                                                    'docker-lv')

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

        # Add host fs for the new host
        self.host_fs_first = self._create_db_object('scratch',
                                                    8,
                                                    'scratch-lv')
        self.host_fs_second = self._create_db_object('backup',
                                                     20,
                                                     'backup-lv')
        self.host_fs_third = self._create_db_object('docker',
                                                    30,
                                                    'docker-lv')

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
                                   'logical_volume': 'kubelet-lv'},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Unsupported filesystem",
                      response.json['error_message'])
