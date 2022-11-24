#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / dns / methods.
"""

import mock
from six.moves import http_client
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class FakeConductorAPI(object):

    def __init__(self):
        self.update_dns_config = mock.MagicMock()


class FakeException(Exception):
        pass


class ApiDNSTestCaseMixin(object):

    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/idns'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'idnss'

    # COMMON_FIELD is a field that is known to exist for inputs and outputs
    COMMON_FIELD = 'nameservers'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['uuid',
                           'nameservers',
                           'isystem_uuid']

    # hidden_api_fields are attributes that should not be populated by
    # an API query
    hidden_api_fields = ['forisystemid']

    def setUp(self):
        super(ApiDNSTestCaseMixin, self).setUp()
        self.fake_conductor_api = FakeConductorAPI()
        p = mock.patch('sysinv.conductor.rpcapiproxy.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)
        # This field decides if the DNS IP address will be IPv4 or IPv6
        self.is_ipv4 = isinstance(self, PlatformIPv4ControllerApiDNSPatchTestCase)

    def get_single_url(self, uuid):
        return '%s/%s' % (self.API_PREFIX, uuid)

    def _create_db_object(self, obj_id=None):
        if(self.is_ipv4):
            return dbutils.create_test_dns(id=obj_id,
                                      forisystemid=self.system.id,
                                      nameservers='8.8.8.8,8.8.4.4')
        else:
            return dbutils.create_test_dns(id=obj_id,
                                      forisystemid=self.system.id,
                                      nameservers='2001:4860:4860::8888,2001:4860:4860::8844')


class ApiDNSPostTestSuiteMixin(ApiDNSTestCaseMixin):
    """ DNS post operations
    """
    def setUp(self):
        super(ApiDNSPostTestSuiteMixin, self).setUp()

    def get_post_object(self):
        return dbutils.post_get_test_dns(forisystemid=self.system.id,
                                      nameservers='8.8.8.8,8.8.4.4')

    # Test that a valid POST operation is blocked by the API
    # API should return 400 BAD_REQUEST or FORBIDDEN 403
    def test_create_not_allowed(self):
        ndict = self.get_post_object()
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)
        self.assertEqual(response.status_code, http_client.FORBIDDEN)
        self.assertIn("Operation not permitted", response.json['error_message'])


class ApiDNSDeleteTestSuiteMixin(ApiDNSTestCaseMixin):
    """ DNS delete operations
    """
    def setUp(self):
        super(ApiDNSDeleteTestSuiteMixin, self).setUp()
        self.delete_object = self._create_db_object()

    # Test that a valid DELETE operation is blocked by the API
    def test_delete_not_allowed(self):
        # Test that a valid DELETE operation is blocked by the API
        uuid = self.delete_object.uuid
        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)
        self.assertEqual(response.status_code, http_client.FORBIDDEN)
        self.assertIn("Operation not permitted", response.json['error_message'])


class ApiDNSPatchTestSuiteMixin(ApiDNSTestCaseMixin):
    """ DNS patch operations
    """
    patch_path_nameserver = '/nameservers'
    patch_path_action = '/action'
    patch_field = 'nameservers'

    def setUp(self):
        super(ApiDNSPatchTestSuiteMixin, self).setUp()
        if(self.is_ipv4):
            self.patch_value_no_change = '8.8.8.8,8.8.4.4'
            self.patch_value_changed = '8.8.8.8'
            self.patch_value_more_than_permitted = '8.8.8.8,8.8.4.4,9.9.9.9,9.8.8.9'
            self.patch_value_hostname = "dns.google"
        else:
            self.patch_value_no_change = '2001:4860:4860::8888,2001:4860:4860::8844'
            self.patch_value_changed = '2001:4860:4860::8888'
            self.patch_value_more_than_permitted = '2001:4860:4860::8888,2001:4860:4860::8844,'\
                                                   '2001:4860:4860::4444,2001:4860:4860::8888'
            self.patch_value_hostname = "dns.google"
        self.patch_object = self._create_db_object()

    def exception_dns(self):
        print('Raised a fake exception')
        raise FakeException

    def test_patch_invalid_field(self):
        # Pass a non existant field to be patched by the API
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': '/junk_field',
                                     'value': self.patch_value_no_change,
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_patch_no_change(self):
        # Ensure No DNS Config changes are made when same value is passed
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_nameserver,
                                     'value': self.patch_value_no_change,
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the attribute remains unchanged
        response = self.get_json(self.get_single_url(self.patch_object.uuid))
        self.assertEqual(response[self.patch_field], self.patch_value_no_change)

        # Verify that the method that updates dns config is not called
        self.fake_conductor_api.update_dns_config.assert_not_called()

    def test_patch_exception(self):
        # Raise an exception and ensure the DNS configuration is not updated
        self.fake_conductor_api.update_dns_config.side_effect = self.exception_dns
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_nameserver,
                                     'value': self.patch_value_changed,
                                     'op': 'replace'},
                                     {"path": self.patch_path_action,
                                      "value": "apply",
                                      "op": "replace"}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Failed to update the DNS configuration", response.json['error_message'])

        # Verify that the attribute was not updated
        response = self.get_json(self.get_single_url(self.patch_object.uuid))
        self.assertNotEqual(response[self.patch_field], self.patch_value_changed)

    def test_patch_valid_change(self):
        # Update value of patchable field
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_nameserver,
                                     'value': self.patch_value_changed,
                                     'op': 'replace'},
                                     {"path": self.patch_path_action,
                                      "value": "apply",
                                      "op": "replace"}],
                                   headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the attribute was updated
        response = self.get_json(self.get_single_url(self.patch_object.uuid))
        self.assertEqual(response[self.patch_field], self.patch_value_changed)

        # Verify that the method that updates dns config is called once
        self.fake_conductor_api.update_dns_config.assert_called_once()

    def test_patch_invalid_value(self):
        # Pass a value that fails a semantic check when patched by the API
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_nameserver,
                                     'value': 'invalid_list',
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Invalid DNS nameserver target address invalid_list Please configure a valid DNS address.",
                        response.json['error_message'])

    def test_patch_max_dns_server(self):
        # Pass DNS server list which is more than the maximum number supported so that it fails when patched by the API
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_nameserver,
                                     'value': self.patch_value_more_than_permitted,
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Please configure a valid list of DNS nameservers.",
                      response.json['error_message'])

    def test_patch_empty_value(self):
        # Pass an empty DNS server list that fails when patched by the API
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_nameserver,
                                     'value': '',
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("At least  one DNS server must be used when any NTP server address is using FQDN.",
                        response.json['error_message'])

    def test_patch_hostname(self):
        # Pass a hostname that fails when patched by the API
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_nameserver,
                                     'value': self.patch_value_hostname,
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Please configure a valid DNS address.", response.json['error_message'])


class ApiDNSListTestSuiteMixin(ApiDNSTestCaseMixin):
    """ DNS GET operations
    """
    def setUp(self):
        super(ApiDNSListTestSuiteMixin, self).setUp()
        self.dns_uuid = self.dns.uuid

    def test_fetch_dns_object(self):
        response = self.get_json(self.API_PREFIX)
        self.assertEqual(response[self.RESULT_KEY][0]['uuid'], self.dns_uuid)


class PlatformIPv4ControllerApiDNSPatchTestCase(ApiDNSPatchTestSuiteMixin,
                                               base.FunctionalTest,
                                               dbbase.ControllerHostTestCase):
    def test_patch_ip_version_mismatch(self):
        self.is_ipv4 = True
        self.patch_object = self._create_db_object()
        self.patch_value_no_change = '2001:4860:4860::8888,2001:4860:4860::8844'
        self.patch_value_changed = '2001:4860:4860::8888'
        self.patch_value_more_than_permitted = '2001:4860:4860::8888,2001:4860:4860::8844,'\
                                               '2001:4860:4860::4444,2001:4860:4860::8888'
        self.patch_value_hostname = "dns.google"

        # Update value of patchable field
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_nameserver,
                                     'value': self.patch_value_changed,
                                     'op': 'replace'},
                                     {"path": self.patch_path_action,
                                      "value": "apply",
                                      "op": "replace"}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        expected_msg = "IP version mismatch: was expecting IPv4, IPv6 received"
        self.assertIn(expected_msg, response.json['error_message'])


class PlatformIPv4ControllerApiDNSListTestCase(ApiDNSListTestSuiteMixin,
                                              base.FunctionalTest,
                                              dbbase.ControllerHostTestCase):
    pass


class PlatformIPv4ControllerApiDNSPostTestCase(ApiDNSPostTestSuiteMixin,
                                              base.FunctionalTest,
                                              dbbase.ControllerHostTestCase):
    pass


class PlatformIPv4ControllerApiDNSDeleteTestCase(ApiDNSDeleteTestSuiteMixin,
                                                base.FunctionalTest,
                                                dbbase.ControllerHostTestCase):
    pass


#  ============= IPv6 environment tests ==============
# Tests DNS Api operations for a Controller (defaults to IPv6)
class PlatformIPv6ControllerApiDNSPatchTestCase(ApiDNSPatchTestSuiteMixin,
                                               dbbase.BaseIPv6Mixin,
                                               base.FunctionalTest,
                                               dbbase.ControllerHostTestCase):
    def test_patch_ip_version_mismatch(self):
        self.is_ipv4 = False
        self.patch_object = self._create_db_object()
        self.patch_value_no_change = '8.8.8.8,8.8.4.4'
        self.patch_value_changed = '8.8.8.8'
        self.patch_value_more_than_permitted = '8.8.8.8,8.8.4.4,9.9.9.9,9.8.8.9'
        self.patch_value_hostname = "dns.google"

        # Update value of patchable field
        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': self.patch_path_nameserver,
                                     'value': self.patch_value_changed,
                                     'op': 'replace'},
                                     {"path": self.patch_path_action,
                                      "value": "apply",
                                      "op": "replace"}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        expected_msg = "IP version mismatch: was expecting IPv6, IPv4 received"
        self.assertIn(expected_msg, response.json['error_message'])


class PlatformIPv6ControllerApiDNSListTestCase(ApiDNSListTestSuiteMixin,
                                              dbbase.BaseIPv6Mixin,
                                              base.FunctionalTest,
                                              dbbase.ControllerHostTestCase):
    pass


class PlatformIPv6ControllerApiDNSPostTestCase(ApiDNSPostTestSuiteMixin,
                                              dbbase.BaseIPv6Mixin,
                                              base.FunctionalTest,
                                              dbbase.ControllerHostTestCase):
    pass


class PlatformIPv6ControllerApiDNSDeleteTestCase(ApiDNSDeleteTestSuiteMixin,
                                                dbbase.BaseIPv6Mixin,
                                                base.FunctionalTest,
                                                dbbase.ControllerHostTestCase):
    pass
