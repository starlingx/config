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
from sysinv.common.address_pool import ADDRESS_TO_ID_FIELD_INDEX
from sysinv.common.usm_service import UsmUpgrade
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
        assert (uuidutils.is_uuid_like(api_object['uuid']))

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

    def create_test_host(self):
        return self._create_test_host(constants.CONTROLLER)

    def get_host(self):
        if self.hosts:
            return self.hosts[0]
        return self.create_test_host()

    def create_test_interface(self, ifname='test0', host=None):
        if not host:
            host = self.get_host()
        interface = dbutils.create_test_interface(
            ifname=ifname,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=host.id,
            ihost_uuid=host.uuid)
        return interface

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

    def test_fail_subnet_overlap_single_network(self):
        mgmt_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_MGMT)
        oam_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        ip = str(self.mgmt_subnet.ip)
        for prefix in range(self.mgmt_subnet.prefixlen - 1, self.mgmt_subnet.prefixlen + 2):
            response = self.patch_oam_fail(oam_pool, http_client.CONFLICT,
                                           network=ip,
                                           prefix=str(prefix))
            self.assertIn(f"Address pool {ip}/{prefix} overlaps with: '{mgmt_pool.name}' "
                          f"{{{mgmt_pool.uuid}}} assigned to mgmt network",
                          response.json['error_message'])

    def test_fail_subnet_overlap_multiple_networks_and_interfaces(self):
        mgmt_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_MGMT)
        ch_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_CLUSTER_HOST)
        oam_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)

        if self.mgmt_subnet.version == constants.IPV4_FAMILY:
            mgmt_subnet = netaddr.IPNetwork('192.169.1.0/24')
            ch_subnet = netaddr.IPNetwork('192.169.2.0/24')
            other_subnet = netaddr.IPNetwork('192.169.3.0/24')
            oam_subnet = netaddr.IPNetwork('192.169.0.0/16')
        else:
            mgmt_subnet = netaddr.IPNetwork('fdaa:0:0:1:1::/80')
            ch_subnet = netaddr.IPNetwork('fdaa:0:0:1:2::/80')
            other_subnet = netaddr.IPNetwork('fdaa:0:0:1:3::/80')
            oam_subnet = netaddr.IPNetwork('fdaa:0:0:1::/64')

        self.dbapi.address_pool_update(mgmt_pool.uuid,
                                       {'network': str(mgmt_subnet.ip),
                                        'prefix': str(mgmt_subnet.prefixlen),
                                        'ranges': [[str(mgmt_subnet[1]), str(mgmt_subnet[-1])]]})
        self.dbapi.address_pool_update(ch_pool.uuid,
                                       {'network': str(ch_subnet.ip),
                                        'prefix': str(ch_subnet.prefixlen),
                                        'ranges': [[str(ch_subnet[1]), str(ch_subnet[-1])]]})

        c0_if1_pool = dbutils.create_test_address_pool(
            name='c0-if1-pool',
            family=other_subnet.version,
            network=str(other_subnet.ip),
            ranges=[[str(other_subnet[1]), str(other_subnet[-1])]],
            prefix=other_subnet.prefixlen)

        controller0 = self._create_test_host(constants.CONTROLLER)

        c0_if0 = self.create_test_interface('c0-if0', controller0)
        c0_if1 = self.create_test_interface('c0-if1', controller0)

        self.dbapi.address_mode_update(c0_if0.id, {'family': mgmt_pool.family, 'mode': 'pool',
                                                   'address_pool_id': mgmt_pool.id})
        self.dbapi.address_mode_update(c0_if1.id, {'family': c0_if1_pool.family, 'mode': 'pool',
                                                   'address_pool_id': c0_if1_pool.id})

        response = self.patch_oam_fail(oam_pool, http_client.CONFLICT,
                                       network=str(oam_subnet.ip),
                                       prefix=str(oam_subnet.prefixlen))
        self.assertIn(f"Address pool {oam_subnet.ip}/{oam_subnet.prefixlen} overlaps with: "
                      f"'{mgmt_pool.name}' {{{mgmt_pool.uuid}}} assigned to mgmt network and "
                      f"to '{c0_if0.ifname}' interface in host {controller0.hostname}, "
                      f"'{ch_pool.name}' {{{ch_pool.uuid}}} assigned to cluster-host network, "
                      f"'{c0_if1_pool.name}' {{{c0_if1_pool.uuid}}} assigned to '{c0_if1.ifname}' "
                      f"interface in host {controller0.hostname}",
                      response.json['error_message'])

    def test_oam_subnet_overlap_with_sysctl_oam(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        subnet = self.system_controller_oam_subnet
        ip = str(subnet.ip)
        for prefix in range(subnet.prefixlen - 1, subnet.prefixlen + 2):
            self.patch_oam_success(addrpool,
                                   network=ip,
                                   prefix=str(prefix),
                                   ranges=[[str(subnet[1]), str(subnet[62])]],
                                   gateway_address=str(subnet[1]),
                                   floating_address=str(subnet[2]),
                                   controller0_address=str(subnet[3]),
                                   controller1_address=str(subnet[4]))

    def test_fail_reverse_range(self):
        start = str(self.oam_subnet[-2])
        end = str(self.oam_subnet[1])
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        ranges = [[start, end]]
        response = self.patch_oam_fail(addrpool, http_client.CONFLICT,
                                       ranges=ranges)
        self.assertIn("Invalid range: start address %s must be less than end address %s" %
                      (start, end), response.json['error_message'])

    def test_fail_address_not_in_subnet(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        address = str(self.mgmt_subnet[2])
        for addr_field in ADDRESS_TO_ID_FIELD_INDEX.keys():
            response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                           **{addr_field: address})
            self.assertIn(f"IP Address {address} is not in subnet: {self.oam_subnet.ip}/"
                          f"{self.oam_subnet.prefixlen}. Please configure valid "
                          f"IPv{self.oam_subnet.version} address.",
                          response.json['error_message'])

    def test_fail_address_not_in_range(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        address = str(self.oam_subnet[20])
        for addr_field in ADDRESS_TO_ID_FIELD_INDEX.keys():
            response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                           **{addr_field: address,
                                              'ranges': [[str(self.oam_subnet[1]),
                                                          str(self.oam_subnet[10])]]})
            self.assertIn(f"IP Address {address} is not in range: {self.oam_subnet[1]}-"
                          f"{self.oam_subnet[10]}. Please configure valid "
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
        for addr_field in ADDRESS_TO_ID_FIELD_INDEX.keys():
            response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                           **{addr_field: address})
            self.assertIn(f"Invalid IP version {version}: {address}. Please configure valid "
                          f"IPv{addrpool.family} address for "
                          f"subnet {addrpool.network}/{addrpool.prefix}.",
                          response.json['error_message'])

    def test_fail_address_is_network_address(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        address = str(self.oam_subnet[0])
        for addr_field in ADDRESS_TO_ID_FIELD_INDEX.keys():
            response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                           **{addr_field: address})
            self.assertIn(f"Invalid IP address: {address}. Cannot use network address: {address}. "
                          f"Please configure valid IPv{addrpool.family} address.",
                          response.json['error_message'])

    def test_fail_address_is_broadcast_address(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        address = str(self.oam_subnet[-1])
        for addr_field in ADDRESS_TO_ID_FIELD_INDEX.keys():
            response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                           **{addr_field: address})
            self.assertIn(f"Cannot use broadcast address: {address}. "
                          f"Please configure valid IPv{addrpool.family} address.",
                          response.json['error_message'])

    def test_remove_address(self):
        self._set_system_mode(constants.SYSTEM_MODE_SIMPLEX)

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
            self.assertRaises(exception.AddressNotFoundById,
                              self.dbapi.address_get_by_id, deleted_id)

    def test_modify_address(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        new_address = self.oam_subnet[-10]

        for addr_field, id_field in ADDRESS_TO_ID_FIELD_INDEX.items():
            address_id = getattr(addrpool, id_field)

            response = self.patch_oam_success(addrpool, **{addr_field: str(new_address)})

            self.assertEqual(str(new_address), response.json[addr_field])
            self.assertEqual(address_id, response.json[id_field])

            address = self.dbapi.address_get_by_id(address_id)
            self.assertEqual(str(new_address), address.address)

            new_address += 1

    def test_modify_prefix(self):
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        self.dbapi.address_pool_update(addrpool.uuid, {'ranges': [[str(self.oam_subnet[1]),
                                                                   str(self.oam_subnet[62])]]})
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
        self._set_system_mode(constants.SYSTEM_MODE_SIMPLEX)

        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)

        self.dbapi.address_destroy_by_id(addrpool.controller0_address_id)
        self.dbapi.address_destroy_by_id(addrpool.gateway_address_id)
        self.dbapi.address_pool_update(addrpool.uuid, {'ranges': [[str(self.oam_subnet[1]),
                                                                   str(self.oam_subnet[62])]],
                                                       'controller0_address_id': None,
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

        self.assertRaises(exception.AddressNotFoundById,
                          self.dbapi.address_get_by_id, c1_address_id)

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
            ranges = [['10.30.0.1', '10.30.0.254']]
        else:
            network = '5102::'
            ranges = [['5102::1', '5102::ffff']]
        response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                       network=network, ranges=ranges)
        self.assertIn(f"IP Address {addrpool.floating_address} is not in subnet: {network}/"
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
                                          ranges=[[str(network[1]), str(network[-2])]],
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
        field_list = list(ADDRESS_TO_ID_FIELD_INDEX.keys())
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
        field_list = list(ADDRESS_TO_ID_FIELD_INDEX.keys())
        for first in range(len(field_list)):  # pylint: disable=consider-using-enumerate
            field1 = field_list[first]
            for second in range(first + 1, len(field_list)):
                field2 = field_list[second]
                response = self.patch_oam_fail(addrpool, http_client.BAD_REQUEST,
                                               **{field1: new_address, field2: new_address})
                self.assertIn(f"{field2} can not be the same as "
                              f"{field1}: {new_address}",
                              response.json['error_message'])

    def _test_fail_empty_addresses(self, network_type, only_floating=False):
        self.mock_utils_is_initial_config_complete.return_value = False
        addrpool = self.find_addrpool_by_networktype(network_type)
        fields = ['floating_address']
        if not only_floating:
            fields.extend(['controller0_address', 'controller1_address'])
        for field in fields:
            response = self.patch_fail(addrpool, http_client.BAD_REQUEST, **{field: 'None'})
            self.assertIn("The field must not be empty: %s" % field, response.json['error_message'])

        response = self.patch_fail(addrpool, http_client.BAD_REQUEST,
                                   **{field: 'None' for field in fields})
        suffix = 's' if len(fields) > 1 else ''
        self.assertIn("The field%s must not be empty: %s" % (suffix, ', '.join(fields)),
                      response.json['error_message'])

    def test_fail_empty_addresses_oam(self):
        self._test_fail_empty_addresses(constants.NETWORK_TYPE_OAM)

    def test_fail_empty_addresses_oam_aio_sx(self):
        self._set_system_mode(constants.SYSTEM_MODE_SIMPLEX)
        self._test_fail_empty_addresses(constants.NETWORK_TYPE_OAM, True)

    def test_fail_empty_addresses_mgmt(self):
        self._test_fail_empty_addresses(constants.NETWORK_TYPE_MGMT)

    def test_fail_empty_addresses_admin(self):
        self._test_fail_empty_addresses(constants.NETWORK_TYPE_ADMIN)

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

    @mock.patch('sysinv.common.usm_service.is_usm_authapi_ready', lambda: True)
    @mock.patch('sysinv.common.usm_service.get_platform_upgrade')
    def test_fail_modify_oam_during_platform_upgrade(self, mock_get_platform_upgrade):
        usm_deploy = UsmUpgrade("in_progress",
                                "0.0",
                                "0.0")
        mock_get_platform_upgrade.return_value = usm_deploy
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

    def test_fail_modify_range_with_allocated_addresses(self):
        controller0 = self._create_test_host(constants.CONTROLLER)
        c0_if0 = self.create_test_interface('c0-if0', controller0)

        if self.mgmt_subnet.version == constants.IPV4_FAMILY:
            subnet = netaddr.IPNetwork('192.167.1.0/24')
        else:
            subnet = netaddr.IPNetwork('fda1::/64')

        pool = dbutils.create_test_address_pool(
            name='c1-if0-pool',
            family=subnet.version,
            network=str(subnet.ip),
            ranges=[[str(subnet[1]), str(subnet[150])]],
            prefix=subnet.prefixlen)

        c0_addr0 = dbutils.create_test_address(
            name="c0-addr0",
            family=subnet.version,
            address=str(subnet[20]),
            prefix=subnet.prefixlen,
            address_pool_id=pool.id,
            interface_id=c0_if0.id)

        dbutils.create_test_address(
            name="c0-addr1",
            family=subnet.version,
            address=str(subnet[120]),
            prefix=subnet.prefixlen,
            address_pool_id=pool.id)

        c0_addr2 = dbutils.create_test_address(
            name="c0-addr2",
            family=subnet.version,
            address=str(subnet[30]),
            prefix=subnet.prefixlen,
            address_pool_id=pool.id)

        response = self.patch_fail(pool, http_client.CONFLICT,
                                   ranges=[[str(subnet[100]), str(subnet[-1])]])

        msg = ("The new address pool ranges excludes addresses that have "
               "already been allocated: {}/{} for interface '{}' on host {}, {}/{}").format(
                   c0_addr0.address, c0_addr0.prefix, c0_if0.ifname, c0_if0.forihostid,
                   c0_addr2.address, c0_addr2.prefix)
        self.assertIn(msg, response.json['error_message'])

    def test_add_new_addresses_existing_unassigned(self):
        self.mock_utils_is_initial_config_complete.return_value = False

        values = {}
        mgmt_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_MGMT)
        for id_field in ADDRESS_TO_ID_FIELD_INDEX.values():
            addr_id = getattr(mgmt_pool, id_field)
            self.assertIsNotNone(addr_id)
            self.dbapi.address_update(addr_id, {'address_pool_id': None, 'name': id_field})
            values[id_field] = None

        self.dbapi.address_pool_update(mgmt_pool.id, values)

        response = self.patch_success(
            mgmt_pool,
            floating_address=mgmt_pool.floating_address,
            gateway_address=mgmt_pool.gateway_address,
            controller0_address=mgmt_pool.controller0_address,
            controller1_address=mgmt_pool.controller1_address)

        self.assertEqual(mgmt_pool.floating_address_id, response.json['floating_address_id'])
        self.assertEqual(mgmt_pool.gateway_address_id, response.json['gateway_address_id'])
        self.assertEqual(mgmt_pool.controller0_address_id, response.json['controller0_address_id'])
        self.assertEqual(mgmt_pool.controller1_address_id, response.json['controller1_address_id'])

        floating_address = self.dbapi.address_get(mgmt_pool.floating_address_id)
        gateway_address = self.dbapi.address_get(mgmt_pool.gateway_address_id)
        controller0_address = self.dbapi.address_get(mgmt_pool.controller0_address_id)
        controller1_address = self.dbapi.address_get(mgmt_pool.controller1_address_id)

        self.assertEqual(mgmt_pool.uuid, floating_address.pool_uuid)
        self.assertEqual(mgmt_pool.uuid, gateway_address.pool_uuid)
        self.assertEqual(mgmt_pool.uuid, controller0_address.pool_uuid)
        self.assertEqual(mgmt_pool.uuid, controller1_address.pool_uuid)

        self.assertEqual('controller-mgmt', floating_address.name)
        self.assertEqual('controller-gateway-mgmt', gateway_address.name)
        self.assertEqual('controller-0-mgmt', controller0_address.name)
        self.assertEqual('controller-1-mgmt', controller1_address.name)

    def test_add_new_addresses_existing_assigned(self):
        self.mock_utils_is_initial_config_complete.return_value = False

        mgmt_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_MGMT)

        subnet = self.mgmt_subnet
        test_pool = dbutils.create_test_address_pool(
            name='test-pool',
            family=subnet.version,
            network=str(subnet.ip),
            prefix=subnet.prefixlen,
            ranges=[[str(subnet[1]), str(subnet[-1])]],
            floating_address=mgmt_pool.floating_address,
            gateway_address=mgmt_pool.gateway_address,
            controller0_address=mgmt_pool.controller0_address,
            controller1_address=mgmt_pool.controller1_address)

        values = {}
        for id_field in ADDRESS_TO_ID_FIELD_INDEX.values():
            addr_id = getattr(mgmt_pool, id_field)
            self.assertIsNotNone(addr_id)
            self.dbapi.address_update(addr_id, {'address_pool_id': test_pool.id, 'name': id_field})
            values[id_field] = None

        self.dbapi.address_pool_update(mgmt_pool.id, values)

        response = self.patch_success(
            mgmt_pool,
            floating_address=mgmt_pool.floating_address,
            gateway_address=mgmt_pool.gateway_address,
            controller0_address=mgmt_pool.controller0_address,
            controller1_address=mgmt_pool.controller1_address)

        self.assertEqual(mgmt_pool.floating_address_id, response.json['floating_address_id'])
        self.assertEqual(mgmt_pool.gateway_address_id, response.json['gateway_address_id'])
        self.assertEqual(mgmt_pool.controller0_address_id, response.json['controller0_address_id'])
        self.assertEqual(mgmt_pool.controller1_address_id, response.json['controller1_address_id'])

        floating_address = self.dbapi.address_get(mgmt_pool.floating_address_id)
        gateway_address = self.dbapi.address_get(mgmt_pool.gateway_address_id)
        controller0_address = self.dbapi.address_get(mgmt_pool.controller0_address_id)
        controller1_address = self.dbapi.address_get(mgmt_pool.controller1_address_id)

        self.assertEqual(mgmt_pool.uuid, floating_address.pool_uuid)
        self.assertEqual(mgmt_pool.uuid, gateway_address.pool_uuid)
        self.assertEqual(mgmt_pool.uuid, controller0_address.pool_uuid)
        self.assertEqual(mgmt_pool.uuid, controller1_address.pool_uuid)

        self.assertEqual('controller-mgmt', floating_address.name)
        self.assertEqual('controller-gateway-mgmt', gateway_address.name)
        self.assertEqual('controller-0-mgmt', controller0_address.name)
        self.assertEqual('controller-1-mgmt', controller1_address.name)

        test_pool = self.dbapi.address_pool_get(test_pool.id)
        for id_field in ADDRESS_TO_ID_FIELD_INDEX.values():
            self.assertIsNone(getattr(test_pool, id_field))

    def test_fail_add_new_addresses_existing(self):
        self.mock_utils_is_initial_config_complete.return_value = False

        mgmt_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_MGMT)

        controller0 = self._create_test_host(constants.CONTROLLER, unit=0)
        c0_if0 = self.create_test_interface('c0-if0', controller0)
        c0_if1 = self.create_test_interface('c0-if1', controller0)

        subnet = self.mgmt_subnet

        if1_pool = dbutils.create_test_address_pool(
            name='if1-pool',
            family=subnet.version,
            network=str(subnet.ip),
            ranges=[[str(subnet[1]), str(subnet[-1])]],
            prefix=subnet.prefixlen)

        test_pool = dbutils.create_test_address_pool(
            name='test-pool',
            family=subnet.version,
            network=str(subnet.ip),
            ranges=[[str(subnet[1]), str(subnet[-1])]],
            prefix=subnet.prefixlen)

        mgmt_addr = dbutils.create_test_address(
            name="mgmt-addr",
            family=subnet.version,
            address=str(subnet[20]),
            prefix=subnet.prefixlen,
            address_pool_id=mgmt_pool.id)

        if0_addr = dbutils.create_test_address(
            name="if0-addr",
            family=subnet.version,
            address=str(subnet[21]),
            prefix=subnet.prefixlen,
            interface_id=c0_if0.id)

        if1_addr = dbutils.create_test_address(
            name="if1-addr",
            family=subnet.version,
            address=str(subnet[22]),
            prefix=subnet.prefixlen,
            address_pool_id=if1_pool.id)

        self.dbapi.address_mode_update(c0_if1.id, {'family': if1_pool.family, 'mode': 'pool',
                                                   'address_pool_id': if1_pool.id})

        msg = ("Address {} already assigned to the following address pool: {}".format(
            mgmt_addr.address, mgmt_pool.uuid))
        for addr_field in ADDRESS_TO_ID_FIELD_INDEX.keys():
            response = self.patch_fail(test_pool, http_client.BAD_REQUEST,
                                       **{addr_field: mgmt_addr.address})
            self.assertIn(msg, response.json['error_message'])

        msg = ("Address {} already assigned to the following address pool: {}".format(
            if1_addr.address, if1_pool.uuid))
        for addr_field in ADDRESS_TO_ID_FIELD_INDEX.keys():
            response = self.patch_fail(test_pool, http_client.BAD_REQUEST,
                                       **{addr_field: if1_addr.address})
            self.assertIn(msg, response.json['error_message'])

        msg = ("Address {} already assigned to the {} interface in host {}".format(
            if0_addr.address, if0_addr.ifname, if0_addr.forihostid))
        for addr_field in ADDRESS_TO_ID_FIELD_INDEX.keys():
            response = self.patch_fail(test_pool, http_client.BAD_REQUEST,
                                       **{addr_field: if0_addr.address})
            self.assertIn(msg, response.json['error_message'])

    def test_swap_addresses(self):
        self.mock_utils_is_initial_config_complete.return_value = False

        mgmt_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_MGMT)

        response = self.patch_success(
            mgmt_pool,
            floating_address=mgmt_pool.gateway_address,
            gateway_address=mgmt_pool.controller0_address,
            controller0_address=mgmt_pool.controller1_address,
            controller1_address=mgmt_pool.floating_address)

        self.assertEqual(mgmt_pool.gateway_address, response.json['floating_address'])
        self.assertEqual(mgmt_pool.controller0_address, response.json['gateway_address'])
        self.assertEqual(mgmt_pool.controller1_address, response.json['controller0_address'])
        self.assertEqual(mgmt_pool.floating_address, response.json['controller1_address'])

        floating_address = self.dbapi.address_get(mgmt_pool.floating_address_id)
        gateway_address = self.dbapi.address_get(mgmt_pool.gateway_address_id)
        controller0_address = self.dbapi.address_get(mgmt_pool.controller0_address_id)
        controller1_address = self.dbapi.address_get(mgmt_pool.controller1_address_id)

        self.assertEqual(mgmt_pool.gateway_address, floating_address.address)
        self.assertEqual(mgmt_pool.controller0_address, gateway_address.address)
        self.assertEqual(mgmt_pool.controller1_address, controller0_address.address)
        self.assertEqual(mgmt_pool.floating_address, controller1_address.address)

    def test_modify_admin(self):
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_admin_config')
        self.mock_rpcapi_update_admin_config = p.start()
        self.addCleanup(p.stop)

        controller0 = self._create_test_host(constants.CONTROLLER, unit=0)
        c0_if0 = self.create_test_interface('c0-if0', controller0)
        network = self._find_network_by_type(constants.NETWORK_TYPE_ADMIN)
        admin_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_ADMIN)

        dbutils.create_test_interface_network(interface_id=c0_if0.id, network_id=network.id)
        self.dbapi.address_update(admin_pool.controller0_address_id, {'interface_id': c0_if0.id})

        subnet = self.admin_subnet
        self.patch_success(admin_pool, controller0_address=str(subnet[20]))

        self.mock_rpcapi_update_admin_config.assert_called_once()
        self.assertEqual(False, self.mock_rpcapi_update_admin_config.call_args.kwargs['disable'])

    def test_modify_systemcontroller_oam(self):
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_dnsmasq_config')
        self.mock_rpcapi_update_dnsmasq_config = p.start()
        self.addCleanup(p.stop)

        self._create_test_host(constants.CONTROLLER, unit=0)
        sc_oam_network = self._find_network_by_type(constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM)
        sc_oam_pool = self.dbapi.address_pool_get(sc_oam_network.pool_uuid)
        sc_oam_pool_start = sc_oam_pool.ranges[0][0]

        self.patch_success(sc_oam_pool, floating_address=sc_oam_pool_start)

        self.mock_rpcapi_update_dnsmasq_config.assert_called_once()

    def test_change_admin_gateway_in_subcloud(self):
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_admin_config')
        self.mock_rpcapi_update_admin_config = p.start()
        self.addCleanup(p.stop)

        self._set_dc_role(constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD)
        controller0 = self._create_test_host(constants.CONTROLLER, unit=0)
        c0_if0 = self.create_test_interface('c0-if0', controller0)
        network = self._find_network_by_type(constants.NETWORK_TYPE_ADMIN)
        admin_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_ADMIN)
        sc_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_SYSTEM_CONTROLLER)

        dbutils.create_test_interface_network(interface_id=c0_if0.id, network_id=network.id)
        self.dbapi.address_update(admin_pool.controller0_address_id, {'interface_id': c0_if0.id})

        old_route = dbutils.create_test_route(
            interface_id=c0_if0.id,
            family=sc_pool.family,
            network=sc_pool.network,
            prefix=sc_pool.prefix,
            gateway=admin_pool.gateway_address,
            metric=1)

        subnet = self.admin_subnet
        new_gateway = str(subnet[20])
        self.patch_success(admin_pool, gateway_address=new_gateway)

        self.assertRaises(exception.RouteNotFound, self.dbapi.route_get, old_route.uuid)

        new_route = self.dbapi.routes_get_by_interface(c0_if0.id)[0]
        self.assertEqual(new_gateway, new_route.gateway)

        self.mock_rpcapi_update_admin_config.assert_called_once()
        self.assertEqual(False, self.mock_rpcapi_update_admin_config.call_args.kwargs['disable'])

    def test_remove_admin_gateway_in_subcloud(self):
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_admin_config')
        self.mock_rpcapi_update_admin_config = p.start()
        self.addCleanup(p.stop)

        self._set_dc_role(constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD)
        controller0 = self._create_test_host(constants.CONTROLLER, unit=0)
        admin0 = self.create_test_interface('admin0', controller0)
        mgmt0 = self.create_test_interface('mgm0', controller0)
        admin_network = self._find_network_by_type(constants.NETWORK_TYPE_ADMIN)
        mgmt_network = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        admin_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_ADMIN)
        mgmt_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_MGMT)
        sc_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_SYSTEM_CONTROLLER)

        dbutils.create_test_interface_network(interface_id=admin0.id, network_id=admin_network.id)
        dbutils.create_test_interface_network(interface_id=mgmt0.id, network_id=mgmt_network.id)
        self.dbapi.address_update(admin_pool.controller0_address_id, {'interface_id': admin0.id})
        self.dbapi.address_update(mgmt_pool.controller0_address_id, {'interface_id': mgmt0.id})

        old_cc_routes = []
        old_random_routes = []
        for ip, iface in {str(self.mgmt_subnet[30]): mgmt0, str(self.admin_subnet[30]): admin0}.items():
            old_cc_routes.append(dbutils.create_test_route(
                interface_id=iface.id,
                family=sc_pool.family,
                network=sc_pool.network,
                prefix=sc_pool.prefix,
                gateway=ip,
                metric=1))
            old_random_routes.append(dbutils.create_test_route(
                interface_id=iface.id,
                family=sc_pool.family,
                network=str(self.cluster_host_subnet.ip),
                prefix=str(self.cluster_host_subnet.prefixlen),
                gateway=ip,
                metric=1))

        self.patch_success(admin_pool, gateway_address='None')

        for old_cc_route in old_cc_routes:
            self.assertRaises(exception.RouteNotFound, self.dbapi.route_get, old_cc_route.uuid)

        for old_random_route in old_random_routes:
            self.dbapi.route_get(old_random_route.uuid)

        self.mock_rpcapi_update_admin_config.assert_called_once()
        self.assertEqual(False, self.mock_rpcapi_update_admin_config.call_args.kwargs['disable'])

    def test_change_mgmt_gateway_in_subcloud(self):
        self.mock_utils_is_initial_config_complete.return_value = False

        self._set_dc_role(constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD)

        controller0 = self._create_test_host(constants.CONTROLLER, unit=0)
        c0_mgmt0 = self.create_test_interface('c0_mgm0', controller0)

        controller1 = self._create_test_host(constants.CONTROLLER, unit=1)
        c1_mgmt0 = self.create_test_interface('c1_mgm0', controller1)

        admin_network = self._find_network_by_type(constants.NETWORK_TYPE_ADMIN)
        self.dbapi.network_destroy(admin_network.id)

        mgmt_network = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        mgmt_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_MGMT)
        sc_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_SYSTEM_CONTROLLER)

        dbutils.create_test_interface_network(interface_id=c0_mgmt0.id,
                                              network_id=mgmt_network.id)
        dbutils.create_test_interface_network(interface_id=c1_mgmt0.id,
                                              network_id=mgmt_network.id)
        self.dbapi.address_update(mgmt_pool.controller0_address_id, {'interface_id': c0_mgmt0.id})
        self.dbapi.address_update(mgmt_pool.controller0_address_id, {'interface_id': c1_mgmt0.id})

        subnet = self.mgmt_subnet
        new_gateway = str(subnet[20])

        c0_old_route = dbutils.create_test_route(
            interface_id=c0_mgmt0.id,
            family=sc_pool.family,
            network=sc_pool.network,
            prefix=sc_pool.prefix,
            gateway=new_gateway,
            metric=1)

        c1_old_route = dbutils.create_test_route(
            interface_id=c1_mgmt0.id,
            family=sc_pool.family,
            network=sc_pool.network,
            prefix=sc_pool.prefix,
            gateway=mgmt_pool.gateway_address,
            metric=1)

        self.patch_success(mgmt_pool, gateway_address=new_gateway)

        self.dbapi.route_get(c0_old_route.uuid)
        self.assertRaises(exception.RouteNotFound, self.dbapi.route_get, c1_old_route.uuid)

        c1_new_route = self.dbapi.routes_get_by_interface(c1_mgmt0.id)[0]
        self.assertEqual(new_gateway, c1_new_route.gateway)

    def test_modify_mgmt_update_no_proxy_list(self):
        self._set_system_mode(constants.SYSTEM_MODE_SIMPLEX)

        network = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_MGMT)

        controller0 = self._create_test_host(constants.CONTROLLER, unit=0)
        c0_mgmt0 = self.create_test_interface('c0_mgm0', controller0)

        dbutils.create_test_interface_network(interface_id=c0_mgmt0.id, network_id=network.id)

        old_floating = addrpool.floating_address
        new_floating = str(self.mgmt_subnet[12])
        old_c0 = addrpool.controller0_address
        new_c0 = str(self.mgmt_subnet[13])

        def _get_ip_list(ips):
            if self.mgmt_subnet.version == constants.IPV6_FAMILY:
                return ','.join(['[' + ip + ']' for ip in ips])
            return ','.join(ips)

        param_values = {'service': constants.SERVICE_TYPE_DOCKER,
                        'section': constants.SERVICE_PARAM_SECTION_DOCKER_PROXY,
                        'name': constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY,
                        'value': _get_ip_list([old_floating, old_c0])}

        dbutils.create_test_service_parameter(**param_values)

        self.patch_success(addrpool, floating_address=new_floating, controller0_address=new_c0)

        no_proxy_entry = self.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_DOCKER,
            section=constants.SERVICE_PARAM_SECTION_DOCKER_PROXY,
            name=constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY)

        self.assertEqual(_get_ip_list([new_floating, new_c0]), no_proxy_entry.value)


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

    def _test_create_address_pool_ip_out_of_range(self, addr_type):

        address = str(self.mgmt_subnet[-1])

        network = str(self.mgmt_subnet.network)
        prefix = self.mgmt_subnet.prefixlen

        ndict = self.get_post_object('test', network, prefix)
        ndict['%s_address' % addr_type] = str(address)

        start = str(self.mgmt_subnet[1])
        end = str(self.mgmt_subnet[10])
        ndict['ranges'] = [[start, end]]

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
        self.assertIn("Invalid range: start address %s must be less than end address %s" %
                      (start, end), response.json['error_message'])

    def test_address_pool_create_invalid_ranges(self):
        network = str(self.mgmt_subnet.network)
        prefix = self.mgmt_subnet.prefixlen

        ndict = self.get_post_object('test', network, prefix)

        start = str(self.oam_subnet[1])
        end = str(self.mgmt_subnet[-2])

        ndict['ranges'] = [[start, end]]

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.CONFLICT)
        self.assertIn("Range start address %s is not within network %s/%d" %
                      (start, network, prefix), response.json['error_message'])

        start = str(self.mgmt_subnet[1])
        end = str(self.oam_subnet[-2])

        ndict['ranges'] = [[start, end]]

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.CONFLICT)
        self.assertIn("Range end address %s is not within network %s/%d" % (end, network, prefix),
            response.json['error_message'])

    def test_address_pool_create_range_has_network_address(self):
        start = str(self.mgmt_subnet[0])
        end = str(self.mgmt_subnet[-2])
        network = str(self.mgmt_subnet.network)
        prefix = self.mgmt_subnet.prefixlen

        ndict = self.get_post_object('test', network, prefix)
        ndict['ranges'] = [[start, end]]

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.CONFLICT)
        self.assertIn("Address pool range cannot include network address: %s" % start,
                      response.json['error_message'])

    def test_address_pool_create_range_has_broadcast_address(self):
        start = str(self.mgmt_subnet[1])
        end = str(self.mgmt_subnet[-1])
        network = str(self.mgmt_subnet.network)
        prefix = self.mgmt_subnet.prefixlen

        ndict = self.get_post_object('test', network, prefix)
        ndict['ranges'] = [[start, end]]

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.CONFLICT)
        self.assertIn("Address pool range cannot include broadcast address: %s" % end,
                      response.json['error_message'])

    def test_address_pool_create_floating_ip_not_in_subnet(self):
        self._test_create_address_pool_address_not_in_subnet('floating')

    def test_address_pool_create_floating_ip_has_invalid_family(self):
        self._test_create_address_pool_invalid_address_family('floating')

    def test_address_pool_create_floating_ip_is_network_address(self):
        self._test_create_address_pool_invalid_address_network('floating')

    def test_address_pool_create_floating_ip_is_broadcast(self):
        self._test_create_address_pool_invalid_address_broadcast('floating')

    def test_address_pool_create_floating_ip_out_of_range(self):
        self._test_create_address_pool_ip_out_of_range('floating')

    def test_address_pool_create_controller0_ip_not_in_subnet(self):
        self._test_create_address_pool_address_not_in_subnet('controller0')

    def test_address_pool_create_controller0_ip_has_invalid_family(self):
        self._test_create_address_pool_invalid_address_family('controller0')

    def test_address_pool_create_controller0_ip_is_network_address(self):
        self._test_create_address_pool_invalid_address_network('controller0')

    def test_address_pool_create_controller0_ip_is_broadcast(self):
        self._test_create_address_pool_invalid_address_broadcast('controller0')

    def test_address_pool_create_controller0_ip_out_of_range(self):
        self._test_create_address_pool_ip_out_of_range('controller0')

    def test_address_pool_create_controller1_ip_not_in_subnet(self):
        self._test_create_address_pool_address_not_in_subnet('controller1')

    def test_address_pool_create_controller1_ip_has_invalid_family(self):
        self._test_create_address_pool_invalid_address_family('controller1')

    def test_address_pool_create_controller1_ip_is_network_address(self):
        self._test_create_address_pool_invalid_address_network('controller1')

    def test_address_pool_create_controller1_ip_is_broadcast(self):
        self._test_create_address_pool_invalid_address_broadcast('controller1')

    def test_address_pool_create_controller1_ip_out_of_range(self):
        self._test_create_address_pool_ip_out_of_range('controller1')

    def test_address_pool_create_gateway_ip_not_in_subnet(self):
        self._test_create_address_pool_address_not_in_subnet('gateway')

    def test_address_pool_create_gateway_ip_has_invalid_family(self):
        self._test_create_address_pool_invalid_address_family('gateway')

    def test_address_pool_create_gateway_ip_is_network_address(self):
        self._test_create_address_pool_invalid_address_network('gateway')

    def test_address_pool_create_gateway_ip_is_broadcast(self):
        self._test_create_address_pool_invalid_address_broadcast('gateway')

    def test_address_pool_create_gateway_ip_out_of_range(self):
        self._test_create_address_pool_ip_out_of_range('gateway')

    def test_fail_create_with_duplicate_address(self):
        subnet = self.mgmt_subnet
        new_address = str(subnet[20])

        base_addrpool = dbutils.get_test_address_pool(
            name='test_pool',
            network=str(subnet.ip),
            prefix=str(subnet.prefixlen),
            gateway_address=str(subnet[1]),
            floating_address=str(subnet[2]),
            controller0_address=str(subnet[3]),
            controller1_address=str(subnet[4]))

        field_list = list(ADDRESS_TO_ID_FIELD_INDEX.keys())
        for first in range(len(field_list)):  # pylint: disable=consider-using-enumerate
            field1 = field_list[first]
            for second in range(first + 1, len(field_list)):
                field2 = field_list[second]
                addrpool = base_addrpool.copy()
                addrpool[field1] = new_address
                addrpool[field2] = new_address
                response = self.post_json(self.API_PREFIX,
                                          addrpool,
                                          headers=self.API_HEADERS,
                                          expect_errors=True)
                self.assertIn(f"{field2} can not be the same as "
                              f"{field1}: {new_address}",
                              response.json['error_message'])

    def test_addresses_existing_unassigned(self):
        if self.mgmt_subnet.version == constants.IPV4_FAMILY:
            subnet = netaddr.IPNetwork('192.167.1.0/24')
        else:
            subnet = netaddr.IPNetwork('fda1::/64')

        addresses = {}
        addr_fields = {}
        ip_addr = subnet[1]
        for addr_field, id_field in ADDRESS_TO_ID_FIELD_INDEX.items():
            addr = dbutils.create_test_address(
                name=id_field,
                family=subnet.version,
                address=str(ip_addr),
                prefix=subnet.prefixlen)
            ip_addr += 1
            addresses[addr_field] = addr
            addr_fields[addr_field] = addr.address

        ndict = dbutils.get_test_address_pool(
            name='test-pool',
            network=str(subnet.ip),
            prefix=str(subnet.prefixlen),
            **addr_fields)

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        self.assertEqual(addresses['floating_address'].id,
                         response.json['floating_address_id'])
        self.assertEqual(addresses['gateway_address'].id,
                         response.json['gateway_address_id'])
        self.assertEqual(addresses['controller0_address'].id,
                         response.json['controller0_address_id'])
        self.assertEqual(addresses['controller1_address'].id,
                         response.json['controller1_address_id'])

        floating_address = self.dbapi.address_get(addresses['floating_address'].id)
        gateway_address = self.dbapi.address_get(addresses['gateway_address'].id)
        controller0_address = self.dbapi.address_get(addresses['controller0_address'].id)
        controller1_address = self.dbapi.address_get(addresses['controller1_address'].id)

        new_pool = self.dbapi.address_pool_get(response.json['id'])

        self.assertEqual(new_pool.uuid, floating_address.pool_uuid)
        self.assertEqual(new_pool.uuid, gateway_address.pool_uuid)
        self.assertEqual(new_pool.uuid, controller0_address.pool_uuid)
        self.assertEqual(new_pool.uuid, controller1_address.pool_uuid)

        self.assertEqual('test-pool-floating_address', floating_address.name)
        self.assertEqual('test-pool-gateway_address', gateway_address.name)
        self.assertEqual('test-pool-controller0_address', controller0_address.name)
        self.assertEqual('test-pool-controller1_address', controller1_address.name)

    def test_addresses_existing_assigned(self):
        if self.mgmt_subnet.version == constants.IPV4_FAMILY:
            subnet = netaddr.IPNetwork('192.167.1.0/24')
        else:
            subnet = netaddr.IPNetwork('fda1::/64')

        existing_pool = dbutils.create_test_address_pool(
            name='existing-pool',
            family=subnet.version,
            network=str(subnet.ip),
            prefix=subnet.prefixlen,
            ranges=[[str(subnet[1]), str(subnet[-1])]])

        addresses = {}
        addr_fields = {}
        addr_id_fields = {}
        ip_addr = subnet[1]
        for addr_field, id_field in ADDRESS_TO_ID_FIELD_INDEX.items():
            addr = dbutils.create_test_address(
                name=id_field,
                family=subnet.version,
                address=str(ip_addr),
                prefix=subnet.prefixlen,
                address_pool_id=existing_pool.id)
            ip_addr += 1
            addresses[addr_field] = addr
            addr_fields[addr_field] = addr.address
            addr_id_fields[id_field] = addr.id

        self.dbapi.address_pool_update(existing_pool.id, addr_id_fields)

        ndict = dbutils.get_test_address_pool(
            name='test-pool',
            network=str(subnet.ip),
            prefix=str(subnet.prefixlen),
            **addr_fields)

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        self.assertEqual(addresses['floating_address'].id,
                         response.json['floating_address_id'])
        self.assertEqual(addresses['gateway_address'].id,
                         response.json['gateway_address_id'])
        self.assertEqual(addresses['controller0_address'].id,
                         response.json['controller0_address_id'])
        self.assertEqual(addresses['controller1_address'].id,
                         response.json['controller1_address_id'])

        floating_address = self.dbapi.address_get(addresses['floating_address'].id)
        gateway_address = self.dbapi.address_get(addresses['gateway_address'].id)
        controller0_address = self.dbapi.address_get(addresses['controller0_address'].id)
        controller1_address = self.dbapi.address_get(addresses['controller1_address'].id)

        new_pool = self.dbapi.address_pool_get(response.json['id'])

        self.assertEqual(new_pool.uuid, floating_address.pool_uuid)
        self.assertEqual(new_pool.uuid, gateway_address.pool_uuid)
        self.assertEqual(new_pool.uuid, controller0_address.pool_uuid)
        self.assertEqual(new_pool.uuid, controller1_address.pool_uuid)

        self.assertEqual('test-pool-floating_address', floating_address.name)
        self.assertEqual('test-pool-gateway_address', gateway_address.name)
        self.assertEqual('test-pool-controller0_address', controller0_address.name)
        self.assertEqual('test-pool-controller1_address', controller1_address.name)

        existing_pool = self.dbapi.address_pool_get(existing_pool.id)
        for id_field in ADDRESS_TO_ID_FIELD_INDEX.values():
            self.assertIsNone(getattr(existing_pool, id_field))

    def test_addresses_new_and_existing(self):
        if self.mgmt_subnet.version == constants.IPV4_FAMILY:
            subnet = netaddr.IPNetwork('192.167.1.0/24')
        else:
            subnet = netaddr.IPNetwork('fda1::/64')

        existing_pool = dbutils.create_test_address_pool(
            name='existing-pool',
            family=subnet.version,
            network=str(subnet.ip),
            prefix=subnet.prefixlen,
            ranges=[[str(subnet[1]), str(subnet[-1])]])

        c0_addr = dbutils.create_test_address(
            name='controller0_address_id',
            family=subnet.version,
            address=str(subnet[3]),
            prefix=subnet.prefixlen,
            address_pool_id=existing_pool.id)

        self.dbapi.address_pool_update(existing_pool.id, {'controller0_address_id': c0_addr.id})

        ndict = dbutils.get_test_address_pool(
            name='test-pool',
            network=str(subnet.ip),
            prefix=str(subnet.prefixlen),
            controller0_address=c0_addr.address,
            controller1_address=str(subnet[4]))

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        self.assertEqual(c0_addr.id, response.json['controller0_address_id'])

        c0_addr = self.dbapi.address_get(c0_addr.id)
        new_pool = self.dbapi.address_pool_get(response.json['id'])

        self.assertEqual(new_pool.uuid, c0_addr.pool_uuid)
        self.assertEqual('test-pool-controller0_address', c0_addr.name)

        existing_pool = self.dbapi.address_pool_get(existing_pool.id)
        self.assertIsNone(existing_pool.controller0_address_id)

    def test_fail_existing_addresses(self):
        mgmt_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_MGMT)

        controller0 = self._create_test_host(constants.CONTROLLER, unit=0)
        c0_if0 = self.create_test_interface('c0-if0', controller0)
        c0_if1 = self.create_test_interface('c0-if1', controller0)

        subnet = self.mgmt_subnet

        if1_pool = dbutils.create_test_address_pool(
            name='if1-pool',
            family=subnet.version,
            network=str(subnet.ip),
            ranges=[[str(subnet[1]), str(subnet[-1])]],
            prefix=subnet.prefixlen)

        mgmt_addr = dbutils.create_test_address(
            name="mgmt-addr",
            family=subnet.version,
            address=str(subnet[20]),
            prefix=subnet.prefixlen,
            address_pool_id=mgmt_pool.id)

        if0_addr = dbutils.create_test_address(
            name="if0-addr",
            family=subnet.version,
            address=str(subnet[21]),
            prefix=subnet.prefixlen,
            interface_id=c0_if0.id)

        if1_addr = dbutils.create_test_address(
            name="if1-addr",
            family=subnet.version,
            address=str(subnet[22]),
            prefix=subnet.prefixlen,
            address_pool_id=if1_pool.id)

        self.dbapi.address_mode_update(c0_if1.id, {'family': if1_pool.family, 'mode': 'pool',
                                                   'address_pool_id': if1_pool.id})
        ndict = dbutils.get_test_address_pool(
            name='test-pool',
            network=str(subnet.ip),
            prefix=str(subnet.prefixlen))

        for addr_field in ADDRESS_TO_ID_FIELD_INDEX.keys():
            del ndict[addr_field]

        msg = ("Address {} already assigned to the following address pool: {}".format(
            mgmt_addr.address, mgmt_pool.uuid))
        for addr_field in ADDRESS_TO_ID_FIELD_INDEX.keys():
            ndict[addr_field] = mgmt_addr.address
            response = self.post_json(self.API_PREFIX, ndict,
                                      headers=self.API_HEADERS, expect_errors=True)
            del ndict[addr_field]
            self.assertEqual('application/json', response.content_type)
            self.assertEqual(response.status_code, http_client.BAD_REQUEST)
            self.assertIn(msg, response.json['error_message'])

        msg = ("Address {} already assigned to the following address pool: {}".format(
            if1_addr.address, if1_pool.uuid))
        for addr_field in ADDRESS_TO_ID_FIELD_INDEX.keys():
            ndict[addr_field] = if1_addr.address
            response = self.post_json(self.API_PREFIX, ndict,
                                      headers=self.API_HEADERS, expect_errors=True)
            del ndict[addr_field]
            self.assertEqual('application/json', response.content_type)
            self.assertEqual(response.status_code, http_client.BAD_REQUEST)
            self.assertIn(msg, response.json['error_message'])

        msg = ("Address {} already assigned to the {} interface in host {}".format(
            if0_addr.address, if0_addr.ifname, if0_addr.forihostid))
        for addr_field in ADDRESS_TO_ID_FIELD_INDEX.keys():
            ndict[addr_field] = if0_addr.address
            response = self.post_json(self.API_PREFIX, ndict,
                                      headers=self.API_HEADERS, expect_errors=True)
            del ndict[addr_field]
            self.assertEqual('application/json', response.content_type)
            self.assertEqual(response.status_code, http_client.BAD_REQUEST)
            self.assertIn(msg, response.json['error_message'])


class TestDelete(AddressPoolTestCase):
    """ Tests deletion.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """

    def setUp(self):
        super(TestDelete, self).setUp()
        iniconf = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = iniconf.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(iniconf.stop)

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

        response = self.delete(self.get_single_url(addrpool2.uuid), headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        self.assertRaises(exception.NetworkAddrpoolNotFound,
                          self.dbapi.network_addrpool_get, netpool.uuid)

        self.mock_rpcapi_update_oam_config.assert_called_once()

    def test_system_controller_oam_address_pool_delete(self):
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_dnsmasq_config')
        self.mock_rpcapi_update_dnsmasq_config = p.start()
        self.addCleanup(p.stop)

        pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM)

        response = self.delete(self.get_single_url(pool.uuid), headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        self.mock_rpcapi_update_dnsmasq_config.assert_not_called()

    def test_mgmt_address_pool_delete_secondary(self):
        self._set_system_mode(constants.SYSTEM_MODE_SIMPLEX)

        network = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        primary_addrpool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_MGMT)

        controller0 = self._create_test_host(constants.CONTROLLER, unit=0)
        c0_mgmt0 = self.create_test_interface('c0-mgmt0', controller0)
        dbutils.create_test_interface_network(interface_id=c0_mgmt0.id, network_id=network.id)

        subnet = netaddr.IPNetwork('fd02::/64')

        addrpool = self._create_test_address_pool(name="oam-ipv6", subnet=subnet)

        mgmt_floating = dbutils.create_test_address(
            name="mgmt-floating",
            family=subnet.version,
            address=str(subnet[1]),
            prefix=subnet.prefixlen,
            address_pool_id=addrpool.id)

        mgmt_c0 = dbutils.create_test_address(
            name="mgmt-c0-address",
            family=subnet.version,
            address=str(subnet[2]),
            prefix=subnet.prefixlen,
            address_pool_id=addrpool.id)

        self.dbapi.address_pool_update(addrpool.uuid, {'floating_address_id': mgmt_floating.id,
                                                       'controller0_address_id': mgmt_c0.id})

        netpool = dbutils.create_test_network_addrpool(
            address_pool_id=addrpool.id,
            network_id=network.id)

        param_values = {'service': constants.SERVICE_TYPE_DOCKER,
                        'section': constants.SERVICE_PARAM_SECTION_DOCKER_PROXY,
                        'name': constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY,
                        'value': ','.join([primary_addrpool.floating_address,
                                           primary_addrpool.controller0_address,
                                           '[' + mgmt_floating.address + ']',
                                           '[' + mgmt_c0.address + ']'])}

        dbutils.create_test_service_parameter(**param_values)

        response = self.delete(self.get_single_url(addrpool.uuid), headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        self.assertRaises(exception.NetworkAddrpoolNotFound,
                          self.dbapi.network_addrpool_get, netpool.uuid)

        no_proxy_entry = self.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_DOCKER,
            section=constants.SERVICE_PARAM_SECTION_DOCKER_PROXY,
            name=constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY)

        self.assertEqual(','.join([primary_addrpool.floating_address,
                                   primary_addrpool.controller0_address]),
                         no_proxy_entry.value)

    def test_admin_address_pool_delete_primary(self):
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_admin_config')
        self.mock_rpcapi_update_admin_config = p.start()
        self.addCleanup(p.stop)

        self._set_dc_role(constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD)

        mgmt_net = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        admin_net = self._find_network_by_type(constants.NETWORK_TYPE_ADMIN)
        mgmt_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_MGMT)
        admin_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_ADMIN)
        admin_netpool = self.dbapi.network_addrpool_query({'network_id': admin_net.id,
                                                           'address_pool_id': admin_pool.id})

        controller0 = self._create_test_host(constants.CONTROLLER, unit=0)
        c0_mgmt0 = self.create_test_interface('c0-mgmt0', controller0)
        c0_admin0 = self.create_test_interface('c0-admin0', controller0)
        dbutils.create_test_interface_network(interface_id=c0_mgmt0.id, network_id=mgmt_net.id)
        c0_ifnet = dbutils.create_test_interface_network(interface_id=c0_admin0.id,
                                                         network_id=admin_net.id)

        controller1 = self._create_test_host(constants.CONTROLLER, unit=1)
        c1_mgmt0 = self.create_test_interface('c1-mgmt0', controller1)
        c1_admin0 = self.create_test_interface('c1-admin0', controller1)
        dbutils.create_test_interface_network(interface_id=c1_mgmt0.id, network_id=mgmt_net.id)
        c1_ifnet = dbutils.create_test_interface_network(interface_id=c1_admin0.id,
                                                         network_id=admin_net.id)

        admin_subnet_2 = dbbase.ADMIN_SUBNET_IPV6
        admin_pool_2 = dbutils.create_test_address_pool(
            name='admin-ipv6',
            family=admin_subnet_2.version,
            network=str(admin_subnet_2.ip),
            ranges=[[str(admin_subnet_2[1]), str(admin_subnet_2[-1])]],
            prefix=admin_subnet_2.prefixlen)

        admin_2_addresses = {}
        for field, ip_address, interface_id in (
                ('controller0_address_id', str(admin_subnet_2[3]), c0_admin0.id),
                ('controller1_address_id', str(admin_subnet_2[4]), c1_admin0.id)):
            address = dbutils.create_test_address(
                name="admin-ipv6-{}".format(field),
                family=admin_subnet_2.version,
                address=ip_address,
                prefix=admin_subnet_2.prefixlen,
                address_pool_id=admin_pool_2.id,
                interface_id=interface_id)
            admin_2_addresses[field] = address.id

        self.dbapi.address_pool_update(admin_pool_2.id, admin_2_addresses)
        admin_netpool_2 = dbutils.create_test_network_addrpool(
            address_pool_id=admin_pool_2.id, network_id=admin_net.id)

        sc_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_SYSTEM_CONTROLLER)
        admin_routes = []
        for iface in [c0_admin0, c1_admin0]:
            route = dbutils.create_test_route(
                interface_id=iface.id,
                family=sc_pool.family,
                network=sc_pool.network,
                prefix=sc_pool.prefix,
                gateway=admin_pool.gateway_address,
                metric=1)
            admin_routes.append(route)

        response = self.delete(self.get_single_url(admin_pool.uuid),
                               headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        self.assertRaises(exception.NetworkAddrpoolNotFound,
                          self.dbapi.network_addrpool_get, admin_netpool.uuid)

        self.assertRaises(exception.NetworkAddrpoolNotFound,
                          self.dbapi.network_addrpool_get, admin_netpool_2.uuid)

        self.assertRaises(exception.NetworkNotFound,
                          self.dbapi.network_get, admin_net.uuid)

        self.assertRaises(exception.InterfaceNetworkNotFound,
                          self.dbapi.interface_network_get, c0_ifnet.uuid)

        self.assertRaises(exception.InterfaceNetworkNotFound,
                          self.dbapi.interface_network_get, c1_ifnet.uuid)

        for route in admin_routes:
            self.assertRaises(exception.RouteNotFound,
                              self.dbapi.route_get, route.uuid)

        for iface in [c0_mgmt0, c1_mgmt0]:
            routes = self.dbapi.routes_get_by_interface(iface.id)
            self.assertEqual(1, len(routes))
            route = routes[0]
            self.assertEqual(mgmt_pool.gateway_address, route.gateway)

        secondary_addresses = self.dbapi.addresses_get_by_pool(admin_pool_2.id)
        self.assertEqual(2, len(secondary_addresses))
        for address in secondary_addresses:
            self.assertIsNone(address.interface_id)

        self.mock_rpcapi_update_admin_config.assert_called()
        self.assertEqual(2, self.mock_rpcapi_update_admin_config.call_count)
        for call in self.mock_rpcapi_update_admin_config.call_args_list:
            self.assertEqual(True, call.kwargs['disable'])


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

    def test_address_pool_list_by_network_type_secondary_ipv6(self):
        path = f"{self.API_PREFIX}?network_type=oam"
        oam_pools = self.get_json(path)
        self.assertEqual(1, len(oam_pools[self.RESULT_KEY]))

        # add secondary oam pool to oam network.
        network = self._find_network_by_type(constants.NETWORK_TYPE_OAM)
        oam_pool_secondary_name = "oam-ipv6"
        addrpool2 = self._create_test_address_pool(
            name=oam_pool_secondary_name, subnet=dbbase.OAM_SUBNET_IPV6
        )
        dbutils.create_test_network_addrpool(
            address_pool_id=addrpool2.id, network_id=network.id
        )

        # test address pools by network type
        # secondary address pool is always as second entry.
        oam_pools = self.get_json(path)
        self.assertEqual(2, len(oam_pools[self.RESULT_KEY]))
        self.assertEqual(oam_pool_secondary_name, oam_pools[self.RESULT_KEY][1]['name'])

    def test_address_pool_list_by_network_type_secondary_ipv4(self):
        path = f"{self.API_PREFIX}?network_type=oam"

        # delete oam network and pools
        oam_pool = self.find_addrpool_by_networktype(constants.NETWORK_TYPE_OAM)
        network = self._find_network_by_type(constants.NETWORK_TYPE_OAM)
        self.dbapi.network_destroy(network.id)
        self.delete(self.get_single_url(oam_pool.uuid), headers=self.API_HEADERS)

        # create IPv4 address pool before creating IPv6 address pool
        oam_pool_secondary_name = "oam-ipv4"
        addrpool2 = self._create_test_address_pool(
            name=oam_pool_secondary_name, subnet=dbbase.OAM_SUBNET_IPV4
        )

        # validate there are still no address pools associated to oam.
        oam_pools = self.get_json(path)
        self.assertEqual(0, len(oam_pools[self.RESULT_KEY]))

        # recreate oam network with primary IPv6 address pool
        self._create_test_network(
            'oam', constants.NETWORK_TYPE_OAM,
            [dbbase.OAM_SUBNET_IPV6], link_addresses=True
        )
        network = self._find_network_by_type(constants.NETWORK_TYPE_OAM)

        # validate there is only primary address pool on oam.
        oam_pools = self.get_json(path)
        self.assertEqual(1, len(oam_pools[self.RESULT_KEY]))

        # add IPv4 address pool to oam network as secondary
        dbutils.create_test_network_addrpool(
            address_pool_id=addrpool2.id, network_id=network.id
        )

        # validate list by network_type is not based upon creation order.
        # i.e. secondary address pool is always as second entry.
        oam_pools = self.get_json(path)
        self.assertEqual(2, len(oam_pools[self.RESULT_KEY]))
        self.assertEqual(oam_pool_secondary_name, oam_pools[self.RESULT_KEY][1]['name'])


class IPv4TestPost(TestPostMixin,
                   AddressPoolTestCase):
    pass


class IPv6TestPost(TestPostMixin,
                   dbbase.BaseIPv6Mixin,
                   AddressPoolTestCase):
    pass
