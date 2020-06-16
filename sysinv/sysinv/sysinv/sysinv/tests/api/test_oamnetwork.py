#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / oamnetwork / methods.
"""

import mock
from six.moves import http_client

from oslo_utils import uuidutils

from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class OAMNetworkTestCase(base.FunctionalTest, dbbase.BaseHostTestCase):

    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/iextoam'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'iextoam'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['uuid',
                           'oam_subnet',
                           'oam_gateway_ip',
                           'oam_floating_ip',
                           'oam_c0_ip',
                           'oam_c1_ip',
                           'region_config',
                           'oam_start_ip',
                           'oam_end_ip',
                           'isystem_uuid',
                           'created_at',
                           'updated_at']

    # hidden_api_fields are attributes that should not be populated by
    # an API query
    hidden_api_fields = []

    def setUp(self):
        super(OAMNetworkTestCase, self).setUp()

    def get_single_url(self, uuid):
        return '%s/%s' % (self.API_PREFIX, uuid)

    def assert_fields(self, api_object):
        # check the uuid is a uuid
        assert(uuidutils.is_uuid_like(api_object['uuid']))

        # Verify that expected attributes are returned
        for field in self.expected_api_fields:
            self.assertIn(field, api_object)

        # Verify that hidden attributes are not returned
        for field in self.hidden_api_fields:
            self.assertNotIn(field, api_object)


class TestPost(OAMNetworkTestCase):

    def setUp(self):
        super(TestPost, self).setUp()

    def test_post_not_allowed(self):
        response = self.post_json(self.API_PREFIX,
                                  {},
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Verify the expected API response
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.FORBIDDEN)
        self.assertIn("Operation not permitted.",
                      response.json['error_message'])


class TestDeleteMixin(OAMNetworkTestCase):
    """ Tests deletion.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """

    def setUp(self):
        super(TestDeleteMixin, self).setUp()

    def test_delete_not_allowed(self):
        # Delete the API object
        response = self.delete(self.get_single_url(self.oam.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)

        # Verify the expected API response
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.FORBIDDEN)
        self.assertIn("Operation not permitted.",
                      response.json['error_message'])


class TestListMixin(OAMNetworkTestCase):

    def setUp(self):
        super(TestListMixin, self).setUp()

    def test_get(self):
        response = self.get_json(self.get_single_url(self.oam.uuid),
                                 headers=self.API_HEADERS)

        # Verify the expected API response
        self.assertEqual(response['oam_start_ip'],
                         str(self.oam_subnet[2]))

    def test_list(self):
        response = self.get_json(self.get_single_url(""),
                                 headers=self.API_HEADERS)
        # Verify the expected API response
        self.assertEqual(response['iextoams'][0]['oam_start_ip'],
                         str(self.oam_subnet[2]))


class TestPatchMixin(OAMNetworkTestCase):

    def setUp(self):
        super(TestPatchMixin, self).setUp()

    def _test_patch_success(self, patch_obj):
        # Patch the API object
        m = mock.Mock()
        update_oam_config = \
            "sysinv.conductor.rpcapi.ConductorAPI.update_oam_config"
        with mock.patch(update_oam_config, m.update_oam_config):
            response = self.patch_dict_json(self.get_single_url(self.oam.uuid),
                                            headers=self.API_HEADERS, **patch_obj)

            # Verify the expected API response
            self.assertEqual(response.content_type, 'application/json')
            self.assertEqual(response.status_code, http_client.OK)
        m.update_oam_config.assert_called_once()

    def _test_patch_fail(self, patch_obj, status_code, error_message):
        # Patch the API object
        m = mock.Mock()
        update_oam_config = \
            "sysinv.conductor.rpcapi.ConductorAPI.update_oam_config"
        with mock.patch(update_oam_config, m.update_oam_config):
            response = self.patch_dict_json(self.get_single_url(self.oam.uuid),
                                            headers=self.API_HEADERS,
                                            expect_errors=True,
                                            **patch_obj)

            # Verify the expected API response
            self.assertEqual(response.content_type, 'application/json')
            self.assertEqual(response.status_code, status_code)
            self.assertIn(error_message, response.json['error_message'])
        m.update_oam_config.assert_not_called()

    def test_patch_same_address(self):
        oam_floating_ip = self.oam_subnet[2]
        oam_c0_ip = self.oam_subnet[3]
        oam_c1_ip = self.oam_subnet[4]
        patch_obj = {
            'oam_floating_ip': str(oam_floating_ip),
            'oam_c0_ip': str(oam_c0_ip),
            'oam_c1_ip': str(oam_c1_ip),
        }
        self._test_patch_success(patch_obj)

    def test_patch_new_address(self):
        oam_floating_ip = self.oam_subnet[2] + 100
        oam_c0_ip = self.oam_subnet[3] + 100
        oam_c1_ip = self.oam_subnet[4] + 100
        patch_obj = {
            'oam_floating_ip': str(oam_floating_ip),
            'oam_c0_ip': str(oam_c0_ip),
            'oam_c1_ip': str(oam_c1_ip),
        }
        self._test_patch_success(patch_obj)

    def test_patch_new_address_in_range(self):
        oam_start_ip = self.oam_subnet[1]
        oam_end_ip = self.oam_subnet[128]
        oam_floating_ip = self.oam_subnet[2] + 100
        oam_c0_ip = self.oam_subnet[3] + 100
        oam_c1_ip = self.oam_subnet[4] + 100
        patch_obj = {
            'oam_start_ip': str(oam_start_ip),
            'oam_end_ip': str(oam_end_ip),
            'oam_floating_ip': str(oam_floating_ip),
            'oam_c0_ip': str(oam_c0_ip),
            'oam_c1_ip': str(oam_c1_ip),
        }
        self._test_patch_success(patch_obj)

    def test_patch_incomplete(self):
        oam_floating_ip = self.oam_subnet[2] + 100
        patch_obj = {
            'oam_floating_ip': str(oam_floating_ip),
        }
        self._test_patch_fail(patch_obj, http_client.BAD_REQUEST,
                              "Invalid address None")

    def test_patch_change_family(self):
        oam_floating_ip = self.change_family_oam_subnet[2]
        oam_c0_ip = self.change_family_oam_subnet[3]
        oam_c1_ip = self.change_family_oam_subnet[4]
        patch_obj = {
            'oam_floating_ip': str(oam_floating_ip),
            'oam_c0_ip': str(oam_c0_ip),
            'oam_c1_ip': str(oam_c1_ip),
        }
        self._test_patch_fail(patch_obj, http_client.BAD_REQUEST,
                              "Invalid IP version")

    def test_patch_duplicate_address(self):
        oam_floating_ip = self.oam_subnet[2]
        oam_c0_ip = self.oam_subnet[3]
        oam_c1_ip = self.oam_subnet[3]
        patch_obj = {
            'oam_floating_ip': str(oam_floating_ip),
            'oam_c0_ip': str(oam_c0_ip),
            'oam_c1_ip': str(oam_c1_ip),
        }
        self._test_patch_fail(patch_obj, http_client.BAD_REQUEST,
                              "must be unique")

    def test_patch_oam_floating_ip_out_of_subnet(self):
        oam_floating_ip = self.oam_subnet[2] - 100
        oam_c0_ip = self.oam_subnet[3]
        oam_c1_ip = self.oam_subnet[4]
        patch_obj = {
            'oam_floating_ip': str(oam_floating_ip),
            'oam_c0_ip': str(oam_c0_ip),
            'oam_c1_ip': str(oam_c1_ip),
        }
        error_message = "IP Address %s is not in subnet" % str(oam_floating_ip)
        self._test_patch_fail(patch_obj, http_client.BAD_REQUEST,
                              error_message)

    def test_patch_oam_c0_ip_out_of_subnet(self):
        oam_floating_ip = self.oam_subnet[2]
        oam_c0_ip = self.oam_subnet[3] - 100
        oam_c1_ip = self.oam_subnet[4]
        patch_obj = {
            'oam_floating_ip': str(oam_floating_ip),
            'oam_c0_ip': str(oam_c0_ip),
            'oam_c1_ip': str(oam_c1_ip),
        }
        error_message = "IP Address %s is not in subnet" % str(oam_c0_ip)
        self._test_patch_fail(patch_obj, http_client.BAD_REQUEST,
                              error_message)

    def test_patch_oam_c1_ip_out_of_subnet(self):
        oam_floating_ip = self.oam_subnet[2]
        oam_c0_ip = self.oam_subnet[3]
        oam_c1_ip = self.oam_subnet[4] - 100
        patch_obj = {
            'oam_floating_ip': str(oam_floating_ip),
            'oam_c0_ip': str(oam_c0_ip),
            'oam_c1_ip': str(oam_c1_ip),
        }
        error_message = "IP Address %s is not in subnet" % str(oam_c1_ip)
        self._test_patch_fail(patch_obj, http_client.BAD_REQUEST,
                              error_message)

    def test_patch_oam_floating_ip_out_of_range(self):
        oam_start_ip = self.oam_subnet[1]
        oam_end_ip = self.oam_subnet[32]
        oam_floating_ip = self.oam_subnet[2] + 100
        oam_c0_ip = self.oam_subnet[3]
        oam_c1_ip = self.oam_subnet[4]
        patch_obj = {
            'oam_start_ip': str(oam_start_ip),
            'oam_end_ip': str(oam_end_ip),
            'oam_floating_ip': str(oam_floating_ip),
            'oam_c0_ip': str(oam_c0_ip),
            'oam_c1_ip': str(oam_c1_ip),
        }
        error_message = ("Invalid oam_floating_ip=%s. Please configure a valid"
                         " IP address in range") % str(oam_floating_ip)
        self._test_patch_fail(patch_obj, http_client.BAD_REQUEST,
                              error_message)

    def test_patch_oam_c0_ip_out_of_range(self):
        oam_start_ip = self.oam_subnet[1]
        oam_end_ip = self.oam_subnet[32]
        oam_floating_ip = self.oam_subnet[2]
        oam_c0_ip = self.oam_subnet[3] + 100
        oam_c1_ip = self.oam_subnet[4]
        patch_obj = {
            'oam_start_ip': str(oam_start_ip),
            'oam_end_ip': str(oam_end_ip),
            'oam_floating_ip': str(oam_floating_ip),
            'oam_c0_ip': str(oam_c0_ip),
            'oam_c1_ip': str(oam_c1_ip),

        }
        error_message = ("Invalid oam_c0_ip=%s. Please configure a valid"
                         " IP address in range") % str(oam_c0_ip)
        self._test_patch_fail(patch_obj, http_client.BAD_REQUEST,
                              error_message)

    def test_patch_oam_c1_ip_out_of_range(self):
        oam_start_ip = self.oam_subnet[1]
        oam_end_ip = self.oam_subnet[32]
        oam_floating_ip = self.oam_subnet[2]
        oam_c0_ip = self.oam_subnet[3]
        oam_c1_ip = self.oam_subnet[4] + 100
        patch_obj = {
            'oam_start_ip': str(oam_start_ip),
            'oam_end_ip': str(oam_end_ip),
            'oam_floating_ip': str(oam_floating_ip),
            'oam_c0_ip': str(oam_c0_ip),
            'oam_c1_ip': str(oam_c1_ip),

        }
        error_message = ("Invalid oam_c1_ip=%s. Please configure a valid"
                         " IP address in range") % str(oam_c1_ip)
        self._test_patch_fail(patch_obj, http_client.BAD_REQUEST,
                              error_message)

    def test_patch_oam_during_platform_upgrade(self):
        oam_floating_ip = self.oam_subnet[2]
        oam_c0_ip = self.oam_subnet[3]
        oam_c1_ip = self.oam_subnet[4]
        patch_obj = {
            'oam_floating_ip': str(oam_floating_ip),
            'oam_c0_ip': str(oam_c0_ip),
            'oam_c1_ip': str(oam_c1_ip),
        }
        dbutils.create_test_upgrade(
            state=constants.UPGRADE_STARTING
        )
        error_message = "Action rejected while a " \
                        "platform upgrade is in progress"
        self._test_patch_fail(patch_obj, http_client.BAD_REQUEST,
                              error_message)

    def test_patch_oam_during_kubernetes_upgrade(self):
        oam_floating_ip = self.oam_subnet[2]
        oam_c0_ip = self.oam_subnet[3]
        oam_c1_ip = self.oam_subnet[4]
        patch_obj = {
            'oam_floating_ip': str(oam_floating_ip),
            'oam_c0_ip': str(oam_c0_ip),
            'oam_c1_ip': str(oam_c1_ip),
        }
        dbutils.create_test_kube_upgrade()
        error_message = "Action rejected while a " \
                        "kubernetes upgrade is in progress"
        self._test_patch_fail(patch_obj, http_client.BAD_REQUEST,
                              error_message)


class IPv4TestDelete(TestDeleteMixin,
                     OAMNetworkTestCase):
    pass


class IPv6TestDelete(TestDeleteMixin,
                     dbbase.BaseIPv6Mixin,
                     OAMNetworkTestCase):
    pass


class IPv4TestList(TestListMixin,
                   OAMNetworkTestCase):
    pass


class IPv6TestList(TestListMixin,
                   dbbase.BaseIPv6Mixin,
                   OAMNetworkTestCase):
    pass


class IPv4TestPatch(TestListMixin,
                    OAMNetworkTestCase):
    pass


class IPv6TestPatch(TestPatchMixin,
                    dbbase.BaseIPv6Mixin,
                    OAMNetworkTestCase):
    pass
