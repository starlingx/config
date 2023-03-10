#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / address pool / methods.
"""

import netaddr
from six.moves import http_client

from oslo_utils import uuidutils

from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class AddressPoolTestCase(base.FunctionalTest, dbbase.BaseHostTestCase):

    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/addrpools'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'addrpools'

    # COMMON_FIELD is a field that is known to exist for inputs and outputs
    COMMON_FIELD = 'network'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['id',
                           'uuid',
                           'name',
                           'network',
                           'prefix',
                           'order',
                           'controller0_address',
                           'controller0_address_id',
                           'controller1_address',
                           'controller1_address_id',
                           'floating_address',
                           'floating_address_id',
                           'gateway_address',
                           'gateway_address_id',
                           'ranges',
                           ]

    def setUp(self):
        super(AddressPoolTestCase, self).setUp()

    def get_single_url(self, uuid):
        return '%s/%s' % (self.API_PREFIX, uuid)

    def assert_fields(self, api_object):
        # check the uuid is a uuid
        assert(uuidutils.is_uuid_like(api_object['uuid']))

        # Verify that expected attributes are returned
        for field in self.expected_api_fields:
            self.assertIn(field, api_object)

    def get_post_object(self, name, network, prefix):
        pool_db = dbutils.get_test_address_pool(
            name=name,
            network=network,
            prefix=prefix
        )

        del pool_db['family']

        return pool_db

    def _create_db_object(self, name='testpool'):
        return self._create_test_address_pool(
            name=name,
            subnet=self.mgmt_subnet
        )


class TestPostMixin(AddressPoolTestCase):

    def setUp(self):
        super(TestPostMixin, self).setUp()

    def _test_create_address_pool_success(self, name, network, prefix):
        # Test creation of object

        ndict = self.get_post_object(name, network, prefix)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)

        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        # Check that an expected field matches.
        self.assertEqual(response.json[self.COMMON_FIELD],
                         ndict[self.COMMON_FIELD])

        uuid = response.json['uuid']

        # Verify that the object was created and some basic attribute matches
        response = self.get_json(self.get_single_url(uuid))
        self.assertEqual(response[self.COMMON_FIELD],
                         ndict[self.COMMON_FIELD])

    def _test_create_address_pool_fail_duplicate(self, name, network, prefix):
        ndict = self.get_post_object(name, network, prefix)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)

        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.CONFLICT)
        self.assertIn("Address pool %s already exists" % name,
                      response.json['error_message'])

    def _test_create_address_pool_address_not_in_subnet(self, addr_type):
        address = str(self.oam_subnet[1])
        network = str(self.mgmt_subnet.network)
        prefix = self.mgmt_subnet.prefixlen

        ndict = self.get_post_object('test', network, prefix)
        ndict['%s_address' % addr_type] = address

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("IP Address %s is not in subnet: %s/%d" % (address, network, prefix),
            response.json['error_message'])

    def _test_create_address_pool_invalid_address_family(self, addr_type):
        if self.mgmt_subnet.version == 6:
            address = netaddr.IPAddress('1.1.1.1')
        else:
            address = netaddr.IPAddress('1111::1')
        network = str(self.mgmt_subnet.network)
        prefix = self.mgmt_subnet.prefixlen

        ndict = self.get_post_object('test', network, prefix)
        ndict['%s_address' % addr_type] = str(address)

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Invalid IP version %s %s" % (address.version, network),
            response.json['error_message'])

    def _test_create_address_pool_invalid_address_network(self, addr_type):

        # network address ie. 192.168.101.0
        address = str(self.mgmt_subnet[0])

        network = str(self.mgmt_subnet.network)
        prefix = self.mgmt_subnet.prefixlen

        ndict = self.get_post_object('test', network, prefix)
        ndict['%s_address' % addr_type] = str(address)

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Invalid IP address: %s. Cannot use network address: %s." % (address, network),
            response.json['error_message'])

    def _test_create_address_pool_invalid_address_broadcast(self, addr_type):

        # broadcast address ie. 192.168.101.255
        address = str(self.mgmt_subnet[-1])

        network = str(self.mgmt_subnet.network)
        prefix = self.mgmt_subnet.prefixlen

        ndict = self.get_post_object('test', network, prefix)
        ndict['%s_address' % addr_type] = str(address)

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Cannot use broadcast address: %s." % address,
            response.json['error_message'])

    def test_address_pool_create_success(self):
        self._test_create_address_pool_success(
            'test', str(self.mgmt_subnet.network), self.mgmt_subnet.prefixlen)

    def test_address_pool_create_fail_duplicate(self):
        self._test_create_address_pool_fail_duplicate(
            'test', str(self.mgmt_subnet.network), self.mgmt_subnet.prefixlen)

    def test_address_pool_create_reversed_ranges(self):
        start = str(self.mgmt_subnet[-2])
        end = str(self.mgmt_subnet[1])
        network = str(self.mgmt_subnet.network)
        prefix = self.mgmt_subnet.prefixlen

        ndict = self.get_post_object('test', network, prefix)
        ndict['ranges'] = [[start, end]]

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.CONFLICT)
        self.assertIn("start address must be less than end address",
            response.json['error_message'])

    def test_address_pool_create_invalid_ranges(self):
        start = str(self.mgmt_subnet[1])
        end = str(self.oam_subnet[-2])
        network = str(self.mgmt_subnet.network)
        prefix = self.mgmt_subnet.prefixlen

        ndict = self.get_post_object('test', network, prefix)
        ndict['ranges'] = [[start, end]]

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.CONFLICT)
        self.assertIn("Address %s is not within network %s/%d" % (end, network, prefix),
            response.json['error_message'])

    def test_address_pool_create_floating_ip_not_in_subnet(self):
        self._test_create_address_pool_address_not_in_subnet('floating')

    def test_address_pool_create_floating_ip_has_invalid_family(self):
        self._test_create_address_pool_invalid_address_family('floating')

    def test_address_pool_create_floating_ip_is_network_address(self):
        self._test_create_address_pool_invalid_address_network('floating')

    def test_address_pool_create_floating_ip_is_broadcast(self):
        self._test_create_address_pool_invalid_address_broadcast('floating')

    def test_address_pool_create_controller0_ip_not_in_subnet(self):
        self._test_create_address_pool_address_not_in_subnet('controller0')

    def test_address_pool_create_controller0_ip_has_invalid_family(self):
        self._test_create_address_pool_invalid_address_family('controller0')

    def test_address_pool_create_controller0_ip_is_network_address(self):
        self._test_create_address_pool_invalid_address_network('controller0')

    def test_address_pool_create_controller0_ip_is_broadcast(self):
        self._test_create_address_pool_invalid_address_broadcast('controller0')

    def test_address_pool_create_controller1_ip_not_in_subnet(self):
        self._test_create_address_pool_address_not_in_subnet('controller1')

    def test_address_pool_create_controller1_ip_has_invalid_family(self):
        self._test_create_address_pool_invalid_address_family('controller1')

    def test_address_pool_create_controller1_ip_is_network_address(self):
        self._test_create_address_pool_invalid_address_network('controller1')

    def test_address_pool_create_controller1_ip_is_broadcast(self):
        self._test_create_address_pool_invalid_address_broadcast('controller1')

    def test_address_pool_create_gateway_ip_not_in_subnet(self):
        self._test_create_address_pool_address_not_in_subnet('gateway')

    def test_address_pool_create_gateway_ip_has_invalid_family(self):
        self._test_create_address_pool_invalid_address_family('gateway')

    def test_address_pool_create_gateway_ip_is_network_address(self):
        self._test_create_address_pool_invalid_address_network('gateway')

    def test_address_pool_create_gateway_ip_is_broadcast(self):
        self._test_create_address_pool_invalid_address_broadcast('gateway')


class TestDelete(AddressPoolTestCase):
    """ Tests deletion.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """

    def setUp(self):
        super(TestDelete, self).setUp()

    def test_address_pool_delete(self):
        # Delete the API object
        self.delete_object = self._create_db_object()
        uuid = self.delete_object.uuid
        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS)

        # Verify the expected API response for the delete
        self.assertEqual(response.status_code, http_client.NO_CONTENT)


class TestList(AddressPoolTestCase):
    """ Address Pool list operations
    """

    def setUp(self):
        super(TestList, self).setUp()

    def test_address_pool_list(self):
        current_pools = self.get_json(self.API_PREFIX)
        num = len(current_pools[self.RESULT_KEY]) + 1

        # create a single object
        self.single_object = self._create_db_object()
        response = self.get_json(self.API_PREFIX)

        self.assertEqual(
            num,
            len(response[self.RESULT_KEY]))


class IPv4TestPost(TestPostMixin,
                   AddressPoolTestCase):
    pass


class IPv6TestPost(TestPostMixin,
                   dbbase.BaseIPv6Mixin,
                   AddressPoolTestCase):
    pass
