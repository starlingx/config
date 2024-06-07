#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / address pool / methods.
"""

import mock
import netaddr
from six.moves import http_client

from oslo_utils import uuidutils

from sysinv.tests.api import base
from sysinv.common import constants
from sysinv.common import exception
from sysinv.api.controllers.v1.address_pool import ADDRESS_FIELDS
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

    def _delete_management_pool(self):
        current_pools = self.get_json(self.API_PREFIX)
        for addrpool in current_pools[self.RESULT_KEY]:
            if addrpool['name'].startswith('management'):
                uuid = addrpool['uuid']
                self.delete(self.get_single_url(uuid),
                    headers=self.API_HEADERS)
                break

    def find_addrpool_by_networktype(self, networktype):
        network = self._find_network_by_type(networktype)
        return self._find_network_address_pools(network.id)[0]


class TestPatchMixin(object):

    def setUp(self):
        super(TestPatchMixin, self).setUp()
        iniconf = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = iniconf.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(iniconf.stop)

    def _get_path(self, path=None):
        if path:
            return '/addrpools/' + path
        else:
            return '/addrpools'

    def create_test_host(self):
        return self._create_test_host(constants.CONTROLLER)

    def get_host(self):
        if self.hosts:
            return self.hosts[0]
        return self.create_test_host()

    def create_test_interface(self):
        host = self.get_host()
        interface = dbutils.create_test_interface(
            ifname='test0',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=host.id,
            ihost_uuid=host.uuid)
        return interface

    def patch_success(self, addrpool, **kwargs):
        response = self.patch_dict_json(self._get_path(addrpool.uuid),
                                        headers=self.API_HEADERS, **kwargs)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        return response

    def patch_fail(self, addrpool, http_code, **kwargs):
        response = self.patch_dict_json(self._get_path(addrpool.uuid), expect_errors=True,
                                        headers=self.API_HEADERS, **kwargs)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_code)
        return response

    def patch_oam_success(self, addrpool, **kwargs):
        m = mock.Mock()
        update_oam_config = "sysinv.conductor.rpcapi.ConductorAPI.update_oam_config"
        with mock.patch(update_oam_config, m.update_oam_config):
            response = self.patch_dict_json(self._get_path(addrpool.uuid),
                                            headers=self.API_HEADERS, **kwargs)
            self.assertEqual(response.content_type, 'application/json')
            self.assertEqual(response.status_code, http_client.OK)
        m.update_oam_config.assert_called_once()
        return response

    def patch_oam_fail(self, addrpool, http_code, **kwargs):
        m = mock.Mock()
        update_oam_config = "sysinv.conductor.rpcapi.ConductorAPI.update_oam_config"
        with mock.patch(update_oam_config, m.update_oam_config):
            response = self.patch_dict_json(self._get_path(addrpool.uuid), expect_errors=True,
                                            headers=self.API_HEADERS, **kwargs)
            self.assertEqual(response.content_type, 'application/json')
            self.assertEqual(response.status_code, http_code)
        m.update_oam_config.assert_not_called()
        return response

    def test_modify_name(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        response = self.patch_oam_success(addrpool, name='new_name')
        self.assertEqual('new_name', response.json['name'])

    def test_fail_invalid_subnet_size(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        max_prefix = 29 if addrpool.family == constants.IPV4_FAMILY else 125
        prefix = str(max_prefix + 1)
        response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST, prefix=prefix)
        self.assertIn(f"Invalid subnet size 4 with {addrpool.network}/{prefix}. "
                      f"Please configure at least size /{max_prefix} subnet",
                      response.json['error_message'])

    def test_fail_invalid_subnet_family(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)

        if addrpool.family == constants.IPV4_FAMILY:
            ip = '4004::'
            prefix = '64'
            version = 6
        else:
            ip = '192.168.208.0'
            prefix = '24'
            version = 4

        response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                       network=ip, prefix=prefix)

        self.assertIn(f"Invalid IP version {version} {ip}/{prefix}. Please configure valid "
                      f"IPv{addrpool.family} subnet", response.json['error_message'])

    def test_fail_subnet_overlap(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        ip = str(self.mgmt_subnet.ip)
        for prefix in range(self.mgmt_subnet.prefixlen - 1, self.mgmt_subnet.prefixlen + 2):
            response = self.patch_oam_fail(addrpool, http_client.CONFLICT,
                                           network=ip,
                                           prefix=str(prefix))
            self.assertIn(f"Address pool {ip}/{prefix} overlaps with "
                          f"management-ipv{addrpool.family} address pool.",
                          response.json['error_message'])

    def test_oam_subnet_overlap_with_sysctl_oam(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        subnet = self.system_controller_oam_subnet
        ip = str(subnet.ip)
        for prefix in range(subnet.prefixlen - 1, subnet.prefixlen + 2):
            self.patch_oam_success(addrpool,
                                   network=ip,
                                   prefix=str(prefix),
                                   gateway_address=str(subnet[1]),
                                   floating_address=str(subnet[2]),
                                   controller0_address=str(subnet[3]),
                                   controller1_address=str(subnet[4]))

    def test_fail_reverse_range(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        ranges = [[str(self.oam_subnet[-2]), str(self.oam_subnet[1])]]
        response = self.patch_oam_fail(addrpool, http_client.CONFLICT,
                                       ranges=ranges)
        self.assertIn("start address must be less than end address",
                      response.json['error_message'])

    def test_fail_address_not_in_subnet(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        address = str(self.mgmt_subnet[2])
        for addr_field in ADDRESS_FIELDS.keys():
            response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                           **{addr_field: address})
            self.assertIn(f"IP Address {address} is not in subnet: {self.oam_subnet.ip}/"
                          f"{self.oam_subnet.prefixlen}. Please configure valid "
                          f"IPv{self.oam_subnet.version} address.",
                          response.json['error_message'])

    def test_fail_address_with_invalid_family(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        if addrpool.family == constants.IPV4_FAMILY:
            address = '4004::'
            version = 6
        else:
            address = '192.168.208.0'
            version = 4
        for addr_field in ADDRESS_FIELDS.keys():
            response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                           **{addr_field: address})
            self.assertIn(f"Invalid IP version {version}: {address}. Please configure valid "
                          f"IPv{addrpool.family} address for "
                          f"subnet {addrpool.network}/{addrpool.prefix}.",
                          response.json['error_message'])

    def test_fail_address_is_network_address(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        address = str(self.oam_subnet[0])
        for addr_field in ADDRESS_FIELDS.keys():
            response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                           **{addr_field: address})
            self.assertIn(f"Invalid IP address: {address}. Cannot use network address: {address}. "
                          f"Please configure valid IPv{addrpool.family} address.",
                          response.json['error_message'])

    def test_fail_address_is_broadcast_address(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        address = str(self.oam_subnet[-1])
        for addr_field in ADDRESS_FIELDS.keys():
            response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                           **{addr_field: address})
            self.assertIn(f"Cannot use broadcast address: {address}. "
                          f"Please configure valid IPv{addrpool.family} address.",
                          response.json['error_message'])

    def test_remove_address(self):
        sysmode = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = sysmode.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(sysmode.stop)

        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        deleted_ids = [addrpool.controller0_address_id, addrpool.controller1_address_id]
        response = self.patch_oam_success(addrpool,
                                          controller0_address='None',
                                          controller1_address='empty')

        self.assertEqual(None, response.json['controller0_address'])
        self.assertEqual(None, response.json['controller0_address_id'])
        self.assertEqual(None, response.json['controller1_address'])
        self.assertEqual(None, response.json['controller1_address_id'])

        for deleted_id in deleted_ids:
            address = None
            try:
                address = self.dbapi.address_get_by_id(deleted_id)
            except exception.AddressNotFoundById:
                pass
            self.assertIsNone(address)

    def test_modify_address(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        new_address = self.oam_subnet[-10]

        for addr_field, id_field in ADDRESS_FIELDS.items():
            address_id = getattr(addrpool, id_field)

            response = self.patch_oam_success(addrpool, **{addr_field: str(new_address)})

            self.assertEqual(str(new_address), response.json[addr_field])
            self.assertEqual(address_id, response.json[id_field])

            address = self.dbapi.address_get_by_id(address_id)
            self.assertEqual(str(new_address), address.address)

            new_address += 1

    def test_modify_prefix(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)

        new_prefix = self.oam_subnet.prefixlen + 2
        address_ids = [addrpool.floating_address_id, addrpool.controller0_address_id,
                       addrpool.controller1_address_id, addrpool.gateway_address_id]

        response = self.patch_oam_success(
            addrpool,
            prefix=str(new_prefix))

        self.assertEqual(new_prefix, response.json['prefix'])

        for address_id in address_ids:
            address = self.dbapi.address_get_by_id(address_id)
            self.assertEqual(new_prefix, address.prefix)

    def test_modify_prefix_and_addresses(self):
        sysmode = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = sysmode.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(sysmode.stop)

        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)

        self.dbapi.address_destroy_by_id(addrpool.controller0_address_id)
        self.dbapi.address_destroy_by_id(addrpool.gateway_address_id)
        self.dbapi.address_pool_update(addrpool.uuid, {'controller0_address_id': None,
                                                       'gateway_address_id': None})
        new_prefix = self.oam_subnet.prefixlen + 2
        new_floating_addr = str(self.oam_subnet[12])
        new_c0_addr = str(self.oam_subnet[13])
        floating_addr_id = addrpool.floating_address_id
        c1_address_id = addrpool.controller1_address_id

        response = self.patch_oam_success(
            addrpool,
            prefix=str(new_prefix),
            floating_address=new_floating_addr,
            controller0_address=new_c0_addr,
            controller1_address='Empty')

        self.assertEqual(new_prefix, response.json['prefix'])
        self.assertEqual(new_floating_addr, response.json['floating_address'])
        self.assertEqual(floating_addr_id, response.json['floating_address_id'])
        self.assertEqual(new_c0_addr, response.json['controller0_address'])
        self.assertIsNone(response.json['controller1_address'])
        self.assertIsNone(response.json['controller1_address_id'])
        self.assertIsNone(response.json['gateway_address'])
        self.assertIsNone(response.json['gateway_address_id'])

        c1_address = None
        try:
            c1_address = self.dbapi.address_get_by_id(c1_address_id)
        except exception.AddressNotFoundById:
            pass
        self.assertIsNone(c1_address)

        c0_address = self.dbapi.address_get_by_id(response.json['controller0_address_id'])
        self.assertEqual(addrpool.uuid, c0_address.pool_uuid)
        self.assertEqual(new_c0_addr, c0_address.address)
        self.assertEqual(new_prefix, c0_address.prefix)

        floating_address = self.dbapi.address_get_by_id(addrpool.floating_address_id)
        self.assertEqual(new_prefix, floating_address.prefix)

    def test_fail_modify_network_and_not_addresses(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        if addrpool.family == constants.IPV4_FAMILY:
            network = '10.30.0.0'
        else:
            network = '5102::'
        response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                       network=network)
        self.assertIn(f"IP Address {addrpool.gateway_address} is not in subnet: {network}/"
                      f"{addrpool.prefix}. Please configure valid "
                      f"IPv{addrpool.family} address.",
                      response.json['error_message'])

    def test_modify_network_and_addresses(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        if addrpool.family == constants.IPV4_FAMILY:
            network = netaddr.IPNetwork('10.30.0.0/24')
        else:
            network = netaddr.IPNetwork('5102::/64')
        response = self.patch_oam_success(addrpool,
                                          network=str(network.ip),
                                          prefix=str(network.prefixlen),
                                          gateway_address=str(network[1]),
                                          floating_address=str(network[2]),
                                          controller0_address=str(network[3]),
                                          controller1_address=str(network[4]))
        self.assertEqual(str(network.ip), response.json['network'])
        self.assertEqual(network.prefixlen, response.json['prefix'])
        self.assertEqual(str(network[1]), response.json['gateway_address'])
        self.assertEqual(str(network[2]), response.json['floating_address'])
        self.assertEqual(str(network[3]), response.json['controller0_address'])
        self.assertEqual(str(network[4]), response.json['controller1_address'])

    def test_fail_duplicate_address_existing(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        field_list = list(ADDRESS_FIELDS.keys())
        for first in range(len(field_list)):  # pylint: disable=consider-using-enumerate
            field1 = field_list[first]
            for second in range(len(field_list)):  # pylint: disable=consider-using-enumerate
                if second == first:
                    continue
                field2 = field_list[second]
                left, right = (field1, field2) if second < first else (field2, field1)
                address = getattr(addrpool, field2)
                response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                               **{field1: address})
                self.assertIn(f"{left} can not be the same as "
                              f"{right}: {address}",
                              response.json['error_message'])

    def test_fail_duplicate_address_new(self):
        new_address = str(self.oam_subnet[20])
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        field_list = list(ADDRESS_FIELDS.keys())
        for first in range(len(field_list)):  # pylint: disable=consider-using-enumerate
            field1 = field_list[first]
            for second in range(first + 1, len(field_list)):
                field2 = field_list[second]
                response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                               **{field1: new_address, field2: new_address})
                self.assertIn(f"{field2} can not be the same as "
                              f"{field1}: {new_address}",
                              response.json['error_message'])

    def test_fail_oam_empty_addresses(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        fields = ['floating_address', 'controller0_address', 'controller1_address']
        for field in fields:
            response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST, **{field: 'None'})
            self.assertIn("The field must not be empty: %s" % field, response.json['error_message'])

        response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                       **{field: 'None' for field in fields})
        self.assertIn("The fields must not be empty: %s" % ', '.join(fields),
                      response.json['error_message'])

    def test_fail_gateway_not_allowed(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        gateway_addr = addrpool.gateway_address
        self.dbapi.address_destroy_by_id(addrpool.gateway_address_id)
        self.dbapi.address_pool_update(addrpool.uuid, {'gateway_address_id': None})
        response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                       gateway_address=gateway_addr)
        self.assertIn(f"OAM gateway IP is not allowed to be configured {gateway_addr}. "
                       "There is already a management gateway address configured.",
                       response.json['error_message'])

    def test_oam_aio_sx_to_dx_migration(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        interface = self.create_test_interface()

        system_dict = self.system.as_dict()
        system_dict['capabilities'].update({'simplex_to_duplex_migration': True})
        self.dbapi.isystem_update(self.system.uuid, system_dict)

        floating_addr = self.dbapi.address_get_by_id(addrpool.floating_address_id)
        self.dbapi.address_update(floating_addr.uuid, {'interface_id': interface.id})

        self.dbapi.address_destroy_by_id(addrpool.controller0_address_id)
        self.dbapi.address_destroy_by_id(addrpool.controller1_address_id)
        self.dbapi.address_pool_update(addrpool.uuid, {'controller0_address_id': None,
                                                       'controller1_address_id': None})
        response = self.patch_oam_success(
            addrpool,
            controller0_address=addrpool.controller0_address,
            controller1_address=addrpool.controller1_address)

        floating_addr = self.dbapi.address_get_by_id(addrpool.floating_address_id)
        self.assertIsNone(floating_addr.ifname)

        c0_address = self.dbapi.address_get_by_id(response.json['controller0_address_id'])
        self.assertEqual(addrpool.uuid, c0_address.pool_uuid)
        self.assertEqual(interface.ifname, c0_address.ifname)

        c1_address = self.dbapi.address_get_by_id(response.json['controller1_address_id'])
        self.assertEqual(addrpool.uuid, c1_address.pool_uuid)
        self.assertIsNone(c1_address.ifname)

    def test_fail_modify_oam_during_platform_upgrade(self):
        dbutils.create_test_upgrade(state=constants.UPGRADE_STARTING)
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                       controller1_address=str(self.oam_subnet[10]))
        self.assertIn("Action rejected while a platform upgrade is in progress",
                      response.json['error_message'])

    def test_fail_modify_oam_during_kubernetes_upgrade(self):
        dbutils.create_test_kube_upgrade()
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                       controller1_address=str(self.oam_subnet[10]))
        self.assertIn("Action rejected while a kubernetes upgrade is in progress",
                      response.json['error_message'])


class TestPatchIPv4(TestPatchMixin,
                    AddressPoolTestCase):
    pass


class TestPatchIPv6(TestPatchMixin,
                    dbbase.BaseIPv6Mixin,
                    AddressPoolTestCase):
    pass


class TestPostMixin(object):

    def setUp(self):
        super(TestPostMixin, self).setUp()
        self._delete_management_pool()

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

    def _test_create_address_pool_fail_overlap(self, name_1, network_1,
            prefix_1, network_2, prefix_2):
        # Test there is overlap between network_1/prefix_1 and
        # network_2/prefix_2 and try to create both address pools.
        ip_set_1 = netaddr.IPSet([f"{network_1}/{prefix_1}"])
        ip_set_2 = netaddr.IPSet([f"{network_2}/{prefix_2}"])
        intersection = ip_set_1 & ip_set_2
        self.assertIsNot(intersection.size, 0, message=f"{network_1}/"
                         f"{prefix_1} and {network_2}/{prefix_2} is not "
                         f"overlapped.")

        ndict_1 = self.get_post_object(name_1, network_1, prefix_1)
        response = self.post_json(self.API_PREFIX,
                                  ndict_1,
                                  headers=self.API_HEADERS)

        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        name_2 = f"{name_1}_2"
        ndict_2 = self.get_post_object(name_2, network_2, prefix_2)
        response = self.post_json(self.API_PREFIX,
                                  ndict_2,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.CONFLICT)
        self.assertIn(f"Address pool {network_2}/{prefix_2} overlaps "
                      f"with {name_1} address pool.",
                      response.json['error_message'])

    def _test_create_address_pool_pass_overlap_with_oam(self, network, prefix):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM)
        netpools = self.dbapi.network_addrpool_get_by_pool_id(addrpool.id)
        for netpool in netpools:
            self.dbapi.network_addrpool_destroy(netpool.uuid)
        self.dbapi.address_pool_destroy(addrpool.uuid)

        oam_pool_name = self._format_pool_name("oam", self.oam_subnet)
        sysctl_oam_pool_name = self._format_pool_name("system-controller-oam-subnet",
                                                      self.oam_subnet)

        # First test with different name, which should fail
        name_1 = f"{sysctl_oam_pool_name}_1"
        ndict_1 = self.get_post_object(name_1, network, prefix)
        response = self.post_json(self.API_PREFIX,
                                  ndict_1,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.CONFLICT)
        self.assertIn(f"Address pool {network}/{prefix} overlaps "
                      f"with {oam_pool_name} address pool.",
                      response.json['error_message'])

        # Now check with the name: system-controller-oam-subnet
        ndict_2 = self.get_post_object(sysctl_oam_pool_name, network, prefix)
        response = self.post_json(self.API_PREFIX,
                                  ndict_2,
                                  headers=self.API_HEADERS)

        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

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
        self.assertIn(f"Invalid IP version {address.version}: {address}. Please configure valid "
                      f"IPv{self.mgmt_subnet.version} address for subnet "
                      f"{self.mgmt_subnet.ip}/{self.mgmt_subnet.prefixlen}.",
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
        self.assertIn("Invalid IP address: %s. Cannot use network address: %s." %
                      (address, network), response.json['error_message'])

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

    def test_create_address_pool_fail_exact_overlap(self):
        self._test_create_address_pool_fail_overlap(
            'test', str(self.mgmt_subnet.network), self.mgmt_subnet.prefixlen,
            str(self.mgmt_subnet.network), self.mgmt_subnet.prefixlen)

    def test_create_address_pool_fail_subset_overlap(self):
        self._test_create_address_pool_fail_overlap(
            'test', str(self.mgmt_subnet.network), self.mgmt_subnet.prefixlen,
            str(self.mgmt_subnet.network), self.mgmt_subnet.prefixlen - 1)

    def test_create_address_pool_fail_superset_overlap(self):
        self._test_create_address_pool_fail_overlap(
            'test', str(self.mgmt_subnet.network), self.mgmt_subnet.prefixlen - 1,
            str(self.mgmt_subnet.network), self.mgmt_subnet.prefixlen)

    def test_create_address_pool_pass_exact_overlap_with_oam(self):
        self._test_create_address_pool_pass_overlap_with_oam(
            str(self.oam_subnet.network), self.oam_subnet.prefixlen)

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

    def test_address_pool_create_fail_address_with_gateway(self):
        p = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = p.start()
        self.mock_utils_get_system_mode.return_value = \
            constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.api.controllers.v1.address_pool.AddressPoolController._check_name_conflict')
        self.mock_check_name_conflict = p.start()
        self.mock_check_name_conflict.return_value = True
        self.addCleanup(p.stop)

        network = str(self.mgmt_subnet.network)
        prefix = self.mgmt_subnet.prefixlen

        name = self._format_pool_name("management", self.mgmt_subnet)
        ndict = self.get_post_object(name, network, prefix)
        ndict['gateway_address'] = str(self.mgmt_subnet[1])

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Gateway address for management network must not be "
                      "specified for standalone AIO-SX",
                      response.json['error_message'])

    def test_address_pool_create_success_address_with_gateway_subloud(self):
        p = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = p.start()
        self.mock_utils_get_system_mode.return_value = \
            constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.api.controllers.v1.utils.get_distributed_cloud_role')
        self.mock_utils_get_distributed_cloud_role = p.start()
        self.mock_utils_get_distributed_cloud_role.return_value = \
            constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD
        self.addCleanup(p.stop)

        current_pools = self.get_json(self.API_PREFIX)
        for addrpool in current_pools[self.RESULT_KEY]:
            if addrpool['name'] == 'management':
                uuid = addrpool['uuid']
                response = self.delete(self.get_single_url(uuid),
                                       headers=self.API_HEADERS)
                break

        network = str(self.mgmt_subnet.network)
        prefix = self.mgmt_subnet.prefixlen

        ndict = self.get_post_object('management', network, prefix)
        ndict['gateway_address'] = str(self.mgmt_subnet[1])

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)


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

    def test_fail_oam_address_pool_delete_primary(self):
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_oam_config')
        self.mock_rpcapi_update_oam_config = p.start()
        self.addCleanup(p.stop)

        # Delete the API object
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        response = self.delete(self.get_single_url(addrpool.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)
        # Verify the expected API response for the delete
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Address pool is the primary for the following network: oam. "
                      "Not possible to delete.",
                      response.json['error_message'])

        self.mock_rpcapi_update_oam_config.assert_not_called()

    def test_oam_address_pool_delete_secondary(self):
        network = self._find_network_by_type(constants.NETWORK_TYPE_OAM)

        oam_subnet6 = netaddr.IPNetwork('fd00::/64')
        addrpool2 = self._create_test_address_pool(name="oam-ipv6", subnet=oam_subnet6)

        netpool = dbutils.create_test_network_addrpool(
            address_pool_id=addrpool2.id,
            network_id=network.id)

        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_oam_config')
        self.mock_rpcapi_update_oam_config = p.start()
        self.addCleanup(p.stop)

        # Delete the API object
        response = self.delete(self.get_single_url(addrpool2.uuid),
                               headers=self.API_HEADERS)
        # Verify the expected API response for the delete
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        deleted_netpool = None
        try:
            deleted_netpool = self.dbapi.network_addrpool_get(netpool.uuid)
        except exception.NetworkAddrpoolNotFound:
            pass

        self.assertIsNone(deleted_netpool)
        self.mock_rpcapi_update_oam_config.assert_called_once()


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
