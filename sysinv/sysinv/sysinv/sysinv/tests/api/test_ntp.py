#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / ntp / methods.
"""

import mock
from six.moves import http_client
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class FakeConductorAPI(object):

    def __init__(self):
        self.update_ntp_config = mock.MagicMock()


class FakeException(Exception):
        pass


class ApiNTPTestCaseMixin(object):

    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/intp'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'intps'

    # COMMON_FIELD is a field that is known to exist for inputs and outputs
    COMMON_FIELD = 'ntpservers'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['uuid',
                           'ntpservers',
                           'isystem_uuid']

    # hidden_api_fields are attributes that should not be populated by
    # an API query
    hidden_api_fields = ['forisystemid']

    def setUp(self):
        super(ApiNTPTestCaseMixin, self).setUp()
        self.fake_conductor_api = FakeConductorAPI()
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

    def get_single_url(self, uuid):
        return '%s/%s' % (self.API_PREFIX, uuid)

    def _create_db_object(self, obj_id=None):
        return dbutils.create_test_ntp(id=obj_id,
                                      forisystemid=self.system.id,
                                      ntpservers='0.pool.ntp.org,1.pool.ntp.org')


class ApiNTPPostTestSuiteMixin(ApiNTPTestCaseMixin):
    """ NTP post operations
    """
    def setUp(self):
        super(ApiNTPPostTestSuiteMixin, self).setUp()

    def get_post_object(self):
        return dbutils.post_get_test_ntp(forisystemid=self.system.id,
                                      ntpservers='0.pool.ntp.org,1.pool.ntp.org')

    # Test that a valid POST operation is blocked by the API
    # API should return 400 BAD_REQUEST or FORBIDDEN 403
    def test_create_not_allowed(self):
        ndict = self.get_post_object()
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)
        self.assertEqual(response.status_code, http_client.FORBIDDEN)
        self.assertTrue(response.json['error_message'])
        self.assertIn("Operation not permitted.",
                      response.json['error_message'])


class ApiNTPDeleteTestSuiteMixin(ApiNTPTestCaseMixin):
    """ NTP delete operations
    """
    def setUp(self):
        super(ApiNTPDeleteTestSuiteMixin, self).setUp()
        self.delete_object = self._create_db_object()

    # Test that a valid DELETE operation is blocked by the API
    def test_delete_not_allowed(self):
        # Test that a valid DELETE operation is blocked by the API
        uuid = self.delete_object.uuid
        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)
        self.assertEqual(response.status_code, http_client.FORBIDDEN)
        self.assertTrue(response.json['error_message'])
        self.assertIn("Operation not permitted.",
                      response.json['error_message'])


class ApiNTPPatchTestSuiteMixin(ApiNTPTestCaseMixin):
    """ NTP patch operations
    """
    patch_path_ntpserver = '/ntpservers'
    patch_path_action = '/action'
    patch_field = 'ntpservers'
    patch_value = '0.pool.ntp.org'
    patch_value_no_change = '0.pool.ntp.org,1.pool.ntp.org'
    patch_value_exceeds_max = '0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org'
    patch_value_invalid_hostname = '-invalid.hostname'

    def setUp(self):
        super(ApiNTPPatchTestSuiteMixin, self).setUp()
        self.patch_object = self._create_db_object()

    def exception_ntp(self):
        print('Raised a fake exception')
        raise FakeException

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

    def test_patch_no_change(self):
        # Ensure No NTP Config changes are made when same value is passed
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_ntpserver,
                                     'value': self.patch_value_no_change,
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the attribute remains unchanged
        response = self.get_json(self.get_single_url(self.patch_object.uuid))
        self.assertEqual(response[self.patch_field], self.patch_value_no_change)

        # Verify that the method that updates ntp config is not called
        self.fake_conductor_api.update_ntp_config.assert_not_called()

    def test_patch_exception(self):
        # Raise an exception and ensure the NTP configuration is not updated
        self.fake_conductor_api.update_ntp_config.side_effect = self.exception_ntp
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_ntpserver,
                                     'value': self.patch_value,
                                     'op': 'replace'},
                                     {"path": self.patch_path_action,
                                      "value": "apply",
                                      "op": "replace"}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Failed to update the NTP configuration", response.json['error_message'])

        # Verify that the attribute was not updated
        response = self.get_json(self.get_single_url(self.patch_object.uuid))
        self.assertNotEqual(response[self.patch_field], self.patch_value)

    def test_patch_valid_ntpserver(self):
        # Update value of patchable field
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_ntpserver,
                                     'value': self.patch_value,
                                     'op': 'replace'},
                                    {'path': self.patch_path_action,
                                     'value': 'apply',
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the attribute was updated
        response = self.get_json(self.get_single_url(self.patch_object.uuid))
        self.assertEqual(response[self.patch_field], self.patch_value)

        # Verify that the method that updates ntp config is called once
        self.fake_conductor_api.update_ntp_config.assert_called_once()

    def test_patch_exceeds_max_ntpservers(self):
        # Update value of patchable field
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_ntpserver,
                                     'value': self.patch_value_exceeds_max,
                                     'op': 'replace'},
                                    {'path': self.patch_path_action,
                                     'value': 'apply',
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Maximum NTP servers supported: 3 but provided: 4. Please configure a valid list of NTP servers.",
                      response.json["error_message"])

    def test_patch_invalid_hostname(self):
        # Update value of patchable field
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_ntpserver,
                                     'value': self.patch_value_invalid_hostname,
                                     'op': 'replace'},
                                    {'path': self.patch_path_action,
                                     'value': 'apply',
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Please configure valid hostname.", response.json["error_message"])

    def test_patch_invalid_value(self):
        # Pass a value that fails a semantic check when patched by the API
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_ntpserver,
                                     'value': 'invalid_list',
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Please configure valid hostname.", response.json["error_message"])

    def test_patch_empty_list(self):
        # Pass a value that fails a semantic check when patched by the API
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_ntpserver,
                                     'value': '',
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("No NTP parameters provided.", response.json["error_message"])


class ApiNTPListTestSuiteMixin(ApiNTPTestCaseMixin):
    """ NTP GET operations
    """

    def setUp(self):
        super(ApiNTPListTestSuiteMixin, self).setUp()
        self.ntp_uuid = self.ntp.uuid

    def test_fetch_ntp_object(self):
        response = self.get_json(self.API_PREFIX)
        self.assertEqual(response[self.RESULT_KEY][0]['uuid'], self.ntp_uuid)


#  ============= IPv4 environment tests ==============
# Tests NTP Api operations for a Controller (defaults to IPv4)
class PlatformIPv4ControllerApiNTPPatchTestCase(ApiNTPPatchTestSuiteMixin,
                                               base.FunctionalTest,
                                               dbbase.ControllerHostTestCase):
    pass


class PlatformIPv4ControllerApiNTPListTestCase(ApiNTPListTestSuiteMixin,
                                              base.FunctionalTest,
                                              dbbase.ControllerHostTestCase):
    pass


class PlatformIPv4ControllerApiNTPPostTestCase(ApiNTPPostTestSuiteMixin,
                                              base.FunctionalTest,
                                              dbbase.ControllerHostTestCase):
    pass


class PlatformIPv4ControllerApiNTPDeleteTestCase(ApiNTPDeleteTestSuiteMixin,
                                                base.FunctionalTest,
                                                dbbase.ControllerHostTestCase):
    pass


#  ============= IPv6 environment tests ==============
# Tests NTP Api operations for a Controller (defaults to IPv6)
class PlatformIPv6ControllerApiNTPPatchTestCase(ApiNTPPatchTestSuiteMixin,
                                               dbbase.BaseIPv6Mixin,
                                               base.FunctionalTest,
                                               dbbase.ControllerHostTestCase):
    pass


class PlatformIPv6ControllerApiNTPListTestCase(ApiNTPListTestSuiteMixin,
                                              dbbase.BaseIPv6Mixin,
                                              base.FunctionalTest,
                                              dbbase.ControllerHostTestCase):
    pass


class PlatformIPv6ControllerApiNTPPostTestCase(ApiNTPPostTestSuiteMixin,
                                              dbbase.BaseIPv6Mixin,
                                              base.FunctionalTest,
                                              dbbase.ControllerHostTestCase):
    pass


class PlatformIPv6ControllerApiNTPDeleteTestCase(ApiNTPDeleteTestSuiteMixin,
                                                dbbase.BaseIPv6Mixin,
                                                base.FunctionalTest,
                                                dbbase.ControllerHostTestCase):
    pass
