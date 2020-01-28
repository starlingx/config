#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / address / methods.
"""

import netaddr
import unittest
from six.moves import http_client

from oslo_utils import uuidutils
from sysinv.common import constants

from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class AddressTestCase(base.FunctionalTest, dbbase.BaseHostTestCase):
    # can perform API operations on this object at a sublevel of host
    HOST_PREFIX = '/ihosts'

    # can perform API operations on this object at a sublevel of interface
    IFACE_PREFIX = '/iinterfaces'

    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/addresses'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'addresses'

    # COMMON_FIELD is a field that is known to exist for inputs and outputs
    COMMON_FIELD = 'address'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['id',
                           'uuid',
                           'address_pool_id',
                           'address',
                           'pool_uuid',
                           ]

    # hidden_api_fields are attributes that should not be populated by
    # an API query
    hidden_api_fields = ['forihostid']

    def setUp(self):
        super(AddressTestCase, self).setUp()
        self.host = self._create_test_host(constants.CONTROLLER)

    def get_single_url(self, uuid):
        return '%s/%s' % (self.API_PREFIX, uuid)

    def get_host_scoped_url(self, host_uuid):
        return '%s/%s%s' % (self.HOST_PREFIX, host_uuid, self.API_PREFIX)

    def get_iface_scoped_url(self, interface_uuid):
        return '%s/%s%s' % (self.IFACE_PREFIX, interface_uuid, self.API_PREFIX)

    def assert_fields(self, api_object):
        # check the uuid is a uuid
        assert(uuidutils.is_uuid_like(api_object['uuid']))

        # Verify that expected attributes are returned
        for field in self.expected_api_fields:
            self.assertIn(field, api_object)

        # Verify that hidden attributes are not returned
        for field in self.hidden_api_fields:
            self.assertNotIn(field, api_object)

    def get_post_object(self, name='test_address', ip_address='127.0.0.1',
                        prefix=8, address_pool_id=None, interface_id=None):
        addr = netaddr.IPAddress(ip_address)
        addr_db = dbutils.get_test_address(
            address=str(addr),
            prefix=prefix,
            name=name,
            address_pool_id=address_pool_id,
            interface_id=interface_id,
        )

        # pool_uuid in api corresponds to address_pool_id in db
        addr_db['pool_uuid'] = addr_db.pop('address_pool_id')
        addr_db['interface_uuid'] = addr_db.pop('interface_id')
        addr_db.pop('family')

        return addr_db


class TestPostMixin(AddressTestCase):

    def setUp(self):
        super(TestPostMixin, self).setUp()

    def _test_create_address_success(self, name, ip_address, prefix,
                                     address_pool_id, interface_id):
        # Test creation of object

        addr_db = self.get_post_object(name=name, ip_address=ip_address,
                                       prefix=prefix,
                                       address_pool_id=address_pool_id,
                                       interface_id=interface_id)
        response = self.post_json(self.API_PREFIX,
                                  addr_db,
                                  headers=self.API_HEADERS)

        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        # Check that an expected field matches.
        self.assertEqual(response.json[self.COMMON_FIELD],
                         addr_db[self.COMMON_FIELD])

    def _test_create_address_fail(self, name, ip_address, prefix,
                                  address_pool_id, interface_id,
                                  status_code, error_message):
        # Test creation of object

        addr_db = self.get_post_object(name=name, ip_address=ip_address,
                                       prefix=prefix,
                                       address_pool_id=address_pool_id,
                                       interface_id=interface_id)
        response = self.post_json(self.API_PREFIX,
                                  addr_db,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, status_code)
        self.assertIn(error_message, response.json['error_message'])

    def test_create_address(self):
        self._test_create_address_success(
            "fake-address",
            str(self.oam_subnet[25]), self.oam_subnet.prefixlen,
            address_pool_id=self.address_pools[2].uuid,
            interface_id=None,
        )

    def test_create_address_wrong_address_pool(self):
        self._test_create_address_fail(
            "fake-address",
            str(self.oam_subnet[25]), self.oam_subnet.prefixlen,
            address_pool_id=self.address_pools[1].uuid,
            interface_id=None,
            status_code=http_client.CONFLICT,
            error_message="does not match pool network",
        )

    def test_create_address_wrong_prefix_len(self):
        self._test_create_address_fail(
            "fake-address",
            str(self.oam_subnet[25]), self.oam_subnet.prefixlen - 1,
            address_pool_id=self.address_pools[2].uuid,
            interface_id=None,
            status_code=http_client.CONFLICT,
            error_message="does not match pool network",
        )

    def test_create_address_zero_prefix(self):
        error_message = ("Address prefix must be greater than 1 for "
                         "data network type")
        self._test_create_address_fail(
            "fake-address",
            str(self.oam_subnet[25]), 0,
            address_pool_id=self.address_pools[2].uuid,
            interface_id=None,
            status_code=http_client.INTERNAL_SERVER_ERROR,
            error_message=error_message,
        )

    def test_create_address_zero_address(self):
        error_message = ("Address must not be null")
        if self.oam_subnet.version == 4:
            zero_address = "0.0.0.0"
        else:
            zero_address = "::"
        self._test_create_address_fail(
            "fake-address",
            zero_address, self.oam_subnet.prefixlen,
            address_pool_id=self.address_pools[2].uuid,
            interface_id=None,
            status_code=http_client.INTERNAL_SERVER_ERROR,
            error_message=error_message,
        )

    def test_create_address_invalid_name(self):
        self._test_create_address_fail(
            "fake_address",
            str(self.oam_subnet[25]), self.oam_subnet.prefixlen,
            address_pool_id=self.address_pools[2].uuid,
            interface_id=None,
            status_code=http_client.BAD_REQUEST,
            error_message="Please configure valid hostname.",
        )

    def test_create_address_multicast(self):
        self._test_create_address_fail(
            "fake-address",
            str(self.multicast_subnet[1]), self.oam_subnet.prefixlen,
            address_pool_id=self.address_pools[2].uuid,
            interface_id=None,
            status_code=http_client.INTERNAL_SERVER_ERROR,
            error_message="Address must be a unicast address",
        )


class TestDelete(AddressTestCase):
    """ Tests deletion.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """

    def setUp(self):
        super(TestDelete, self).setUp()

    # See https://bugs.launchpad.net/starlingx/+bug/1860186
    @unittest.expectedFailure
    def test_delete(self):
        # Delete the API object
        delete_object = self.mgmt_addresses[0]
        uuid = delete_object.uuid
        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS)

        # Verify the expected API response for the delete
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

    # TODO: Add unit tests to verify deletion is rejected as expected by
    # _check_orphaned_routes, _check_host_state, and _check_from_pool.
    #
    # Currently blocked by bug in dbapi preventing testcase setup:
    #   https://bugs.launchpad.net/starlingx/+bug/1861131


class TestList(AddressTestCase):
    """ Network list operations
    """

    def setUp(self):
        super(TestList, self).setUp()

    def test_list_default_addresses_all(self):
        response = self.get_json(self.API_PREFIX)
        for result in response[self.RESULT_KEY]:
            self.assertIn("address", result)

    def test_list_default_addresses_host(self):
        response = self.get_json(self.get_host_scoped_url(self.host.uuid))
        self.assertEqual([], response[self.RESULT_KEY])

    def test_list_default_addresses_interface(self):
        ifaces = self._create_test_host_platform_interface(self.host)
        interface_id = ifaces[0].uuid
        response = self.get_json(self.get_iface_scoped_url(interface_id))
        self.assertEqual([], response[self.RESULT_KEY])


class TestPatch(AddressTestCase):

    def setUp(self):
        super(TestPatch, self).setUp()

    def test_patch_not_allowed(self):
        # Try and patch an unmodifiable value

        patch_object = self.mgmt_addresses[0]

        response = self.patch_json(self.get_single_url(patch_object.uuid),
                                   [{'path': '/name',
                                     'value': 'test',
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify the expected API response
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.METHOD_NOT_ALLOWED)
        self.assertIn("The method PATCH is not allowed for this resource.",
                      response.json['error_message'])


class IPv4TestPost(TestPostMixin,
                   AddressTestCase):
    pass


class IPv6TestPost(TestPostMixin,
                   dbbase.BaseIPv6Mixin,
                   AddressTestCase):
    pass
