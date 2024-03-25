#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / network_addresspools / methods.
"""

import mock

import netaddr
from six.moves import http_client

from oslo_utils import uuidutils
from sysinv.common import constants

from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class NetworkAddrpoolTestCase(base.FunctionalTest, dbbase.BaseHostTestCase):

    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/network_addresspools'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'network_addresspools'

    # COMMON_FIELD is a field that is known to exist for inputs and outputs
    COMMON_FIELD = 'network_uuid'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['id',
                           'uuid',
                           'network_uuid',
                           'network_name',
                           'addresspool_uuid',
                           'addresspool_name',
                           ]

    # hidden_api_fields are attributes that should not be populated by
    # an API query
    hidden_api_fields = ['forihostid']

    def setUp(self):
        super(NetworkAddrpoolTestCase, self).setUp()

        self.networks = dict()
        network_table = dbutils.get_network_table()
        for net in network_table:
            self.networks.update({net.type: net})

        self.create_ipv6_pools()
        self.address_pools = dict()
        address_pool_table = dbutils.get_address_pool_table()
        for pool in address_pool_table:
            self.address_pools.update({pool.name: pool})

    def get_single_url(self, uuid):
        return '%s/%s' % (self.API_PREFIX, uuid)

    def get_single_network_url(self, uuid):
        return '%s/%s' % ("/networks", uuid)

    def assert_fields(self, api_object):
        # check the uuid is a uuid
        assert (uuidutils.is_uuid_like(api_object['uuid']))

        # Verify that expected attributes are returned
        for field in self.expected_api_fields:
            self.assertIn(field, api_object)

        # Verify that hidden attributes are not returned
        for field in self.hidden_api_fields:
            self.assertNotIn(field, api_object)

    def get_post_object(self, network_uuid, address_pool_uuid):
        net_pool_db = dbutils.get_post_network_addrpool(
            address_pool_uuid=address_pool_uuid,
            network_uuid=network_uuid
        )
        return net_pool_db

    def create_ipv6_pools(self):
        mgmt_subnet6 = netaddr.IPNetwork('fd01::/64')
        oam_subnet6 = netaddr.IPNetwork('fd00::/64')
        cluster_host_subnet6 = netaddr.IPNetwork('fd02::/64')
        cluster_pod_subnet6 = netaddr.IPNetwork('fd03::/64')
        cluster_service_subnet6 = netaddr.IPNetwork('fd04::/112')
        multicast_subnet6 = netaddr.IPNetwork('ff08::1:1:0/124')
        storage_subnet6 = netaddr.IPNetwork('fd05::/64')
        admin_subnet6 = netaddr.IPNetwork('fd09::/64')
        self._create_test_address_pool(name="management-ipv6", subnet=mgmt_subnet6)
        self._create_test_address_pool(name="oam-ipv6", subnet=oam_subnet6)
        self._create_test_address_pool(name="cluster-host-ipv6", subnet=cluster_host_subnet6)
        self._create_test_address_pool(name="cluster-pod-ipv6", subnet=cluster_pod_subnet6)
        self._create_test_address_pool(name="cluster-service-ipv6", subnet=cluster_service_subnet6)
        self._create_test_address_pool(name="multicast-ipv6", subnet=multicast_subnet6)
        self._create_test_address_pool(name="storage-ipv6", subnet=storage_subnet6)
        self._create_test_address_pool(name="admin-ipv6", subnet=admin_subnet6)

    def create_network(self, **kw):
        network = dbutils.create_test_network(**kw)
        return network

    def _setup_context(self):
        self.host0 = self._create_test_host(personality=constants.CONTROLLER, unit=0,
                                            id=1, mgmt_ip="1.1.1.1")
        self.c0_oam_if = dbutils.create_test_interface(ifname='enp0s3', forihostid=self.host0.id)
        dbutils.create_test_interface_network_type_assign(self.c0_oam_if.id,
                                                          constants.NETWORK_TYPE_OAM)

        self.c0_mgmt_if = dbutils.create_test_interface(ifname='enp0s8', forihostid=self.host0.id)
        dbutils.create_test_interface_network_type_assign(self.c0_mgmt_if.id,
                                                          constants.NETWORK_TYPE_MGMT)
        dbutils.create_test_interface_network_type_assign(self.c0_mgmt_if.id,
                                                          constants.NETWORK_TYPE_CLUSTER_HOST)

        self.host1 = self._create_test_host(personality=constants.CONTROLLER, unit=1,
                                            id=2, mgmt_ip="1.1.1.2")
        self.c1_oam_if = dbutils.create_test_interface(ifname='enp0s3', forihostid=self.host1.id)
        dbutils.create_test_interface_network_type_assign(self.c1_oam_if.id,
                                                          constants.NETWORK_TYPE_OAM)

        self.c1_mgmt_if = dbutils.create_test_interface(ifname='enp0s8',
                                                   forihostid=self.host1.id)
        dbutils.create_test_interface_network_type_assign(self.c1_mgmt_if.id,
                                                          constants.NETWORK_TYPE_MGMT)
        dbutils.create_test_interface_network_type_assign(self.c1_mgmt_if.id,
                                                          constants.NETWORK_TYPE_CLUSTER_HOST)


class TestPostMixin(NetworkAddrpoolTestCase):

    def setUp(self):
        super(TestPostMixin, self).setUp()
        dbutils.cleanup_network_addrpool_table()
        dbutils.cleanup_address_table()

    def test_success_create_network_addrpool_primary(self):
        self._setup_context()
        # Test creation of object
        net_type = constants.NETWORK_TYPE_MGMT
        ndict = self.get_post_object(self.networks[net_type].uuid,
                                     self.address_pools['management-ipv4'].uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)
        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)
        # Check that an expected field matches.
        self.assertEqual(response.json['address_pool_name'],
                         self.address_pools['management-ipv4'].name)
        self.assertEqual(response.json['address_pool_id'],
                         self.address_pools['management-ipv4'].id)
        self.assertEqual(response.json['address_pool_uuid'],
                         self.address_pools['management-ipv4'].uuid)
        self.assertEqual(response.json['network_name'], self.networks[net_type].name)
        self.assertEqual(response.json['network_id'], self.networks[net_type].id)
        self.assertEqual(response.json['network_uuid'], self.networks[net_type].uuid)

        uuid = response.json['uuid']
        # Verify that the object was created and some basic attribute matches
        response = self.get_json(self.get_single_url(uuid))
        self.assertEqual(response['address_pool_name'], self.address_pools['management-ipv4'].name)
        self.assertEqual(response['address_pool_id'], self.address_pools['management-ipv4'].id)
        self.assertEqual(response['address_pool_uuid'], self.address_pools['management-ipv4'].uuid)
        self.assertEqual(response['network_name'], self.networks[net_type].name)
        self.assertEqual(response['network_id'], self.networks[net_type].id)
        self.assertEqual(response['network_uuid'], self.networks[net_type].uuid)

        addr_list = dbutils.get_address_table()
        self.assertEqual(3, len(addr_list))
        for addr in addr_list:
            self.assertIn(addr.name,
                          [f"{constants.CONTROLLER_HOSTNAME}-{constants.NETWORK_TYPE_MGMT}",
                           f"{constants.CONTROLLER_0_HOSTNAME}-{constants.NETWORK_TYPE_MGMT}",
                           f"{constants.CONTROLLER_1_HOSTNAME}-{constants.NETWORK_TYPE_MGMT}"])
            if addr.name == f"{constants.CONTROLLER_HOSTNAME}-{constants.NETWORK_TYPE_MGMT}":
                self.assertEqual(addr.interface_id, None)
            elif addr.name == f"{constants.CONTROLLER_0_HOSTNAME}-{constants.NETWORK_TYPE_MGMT}":
                self.assertEqual(addr.interface_id, self.c0_mgmt_if.id)
            elif addr.name == f"{constants.CONTROLLER_1_HOSTNAME}-{constants.NETWORK_TYPE_MGMT}":
                self.assertEqual(addr.interface_id, self.c1_mgmt_if.id)

    def test_success_create_network_addrpool_secondary(self):
        self._setup_context()
        # add primary
        net_type = constants.NETWORK_TYPE_MGMT
        ndict = self.get_post_object(self.networks[net_type].uuid,
                                     self.address_pools['management-ipv4'].uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)
        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        # add secondary
        ndict = self.get_post_object(self.networks[net_type].uuid,
                                     self.address_pools['management-ipv6'].uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)
        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        uuid = response.json['uuid']
        # Verify that the object was created and some basic attribute matches
        response = self.get_json(self.get_single_url(uuid))
        self.assertEqual(response['address_pool_name'], self.address_pools['management-ipv6'].name)
        self.assertEqual(response['address_pool_id'], self.address_pools['management-ipv6'].id)
        self.assertEqual(response['address_pool_uuid'], self.address_pools['management-ipv6'].uuid)
        self.assertEqual(response['network_name'], self.networks[net_type].name)
        self.assertEqual(response['network_id'], self.networks[net_type].id)
        self.assertEqual(response['network_uuid'], self.networks[net_type].uuid)

        addr_list = dbutils.get_address_table()
        self.assertEqual(6, len(addr_list))
        ip4_list = list()
        ip6_list = list()
        for addr in addr_list:
            self.assertIn(addr.name,
                          [f"{constants.CONTROLLER_HOSTNAME}-{constants.NETWORK_TYPE_MGMT}",
                           f"{constants.CONTROLLER_0_HOSTNAME}-{constants.NETWORK_TYPE_MGMT}",
                           f"{constants.CONTROLLER_1_HOSTNAME}-{constants.NETWORK_TYPE_MGMT}"])
            if addr.name == f"{constants.CONTROLLER_HOSTNAME}-{constants.NETWORK_TYPE_MGMT}":
                self.assertEqual(addr.interface_id, None)
            elif addr.name == f"{constants.CONTROLLER_0_HOSTNAME}-{constants.NETWORK_TYPE_MGMT}":
                self.assertEqual(addr.interface_id, self.c0_mgmt_if.id)
            elif addr.name == f"{constants.CONTROLLER_1_HOSTNAME}-{constants.NETWORK_TYPE_MGMT}":
                self.assertEqual(addr.interface_id, self.c1_mgmt_if.id)

            if addr.family == constants.IPV6_FAMILY:
                ip6_list.append(addr)
            elif addr.family == constants.IPV4_FAMILY:
                ip4_list.append(addr)

        self.assertEqual(3, len(ip4_list))
        self.assertEqual(3, len(ip6_list))

    def test_success_create_network_addrpool_secondary_oam(self):
        self._setup_context()
        # add primary
        net_type = constants.NETWORK_TYPE_OAM
        ndict = self.get_post_object(self.networks[net_type].uuid,
                                     self.address_pools['oam-ipv4'].uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)
        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        # add secondary
        ndict = self.get_post_object(self.networks[net_type].uuid,
                                     self.address_pools['oam-ipv6'].uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)
        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        uuid = response.json['uuid']
        # Verify that the object was created and some basic attribute matches
        response = self.get_json(self.get_single_url(uuid))
        self.assertEqual(response['address_pool_name'], self.address_pools['oam-ipv6'].name)
        self.assertEqual(response['address_pool_id'], self.address_pools['oam-ipv6'].id)
        self.assertEqual(response['address_pool_uuid'], self.address_pools['oam-ipv6'].uuid)
        self.assertEqual(response['network_name'], self.networks[net_type].name)
        self.assertEqual(response['network_id'], self.networks[net_type].id)
        self.assertEqual(response['network_uuid'], self.networks[net_type].uuid)

    def test_success_create_network_addrpool_primary_subcloud(self):
        self._setup_context()
        net_type = constants.NETWORK_TYPE_MGMT

        p = mock.patch('sysinv.api.controllers.v1.utils.get_distributed_cloud_role')
        self.mock_utils_get_system_mode = p.start()
        self.mock_utils_get_system_mode.return_value = constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD
        self.addCleanup(p.stop)

        mgmt_subnet = netaddr.IPNetwork('3001::/64')
        ranges = [(str(mgmt_subnet[2]), str(mgmt_subnet[-2]))]

        c0_address = dbutils.create_test_address(
            name=f"{constants.CONTROLLER_0_HOSTNAME}-{net_type}",
            family=mgmt_subnet.version, prefix=mgmt_subnet.prefixlen,
            address="3001::3")

        c1_address = dbutils.create_test_address(
            name=f"{constants.CONTROLLER_1_HOSTNAME}-{net_type}",
            family=mgmt_subnet.version, prefix=mgmt_subnet.prefixlen,
            address="3001::4")

        float_address = dbutils.create_test_address(
            name=f"{constants.CONTROLLER_HOSTNAME}-{net_type}",
            family=mgmt_subnet.version, prefix=mgmt_subnet.prefixlen,
            address="3001::2")

        gw_address = dbutils.create_test_address(
            name=f"{constants.SYSTEM_CONTROLLER_GATEWAY_IP_NAME}-{net_type}",
            family=mgmt_subnet.version, prefix=mgmt_subnet.prefixlen,
            address="3001::1")

        test_pool = dbutils.create_test_address_pool(
            name="subcloud-mgmt-ipv6", network=str(mgmt_subnet.network),
            family=mgmt_subnet.version, prefix=mgmt_subnet.prefixlen,
            ranges=ranges,
            floating_address=float_address.address,
            controller0_address=c0_address.address,
            controller1_address=c1_address.address,
            gateway_address=gw_address.address)

        # Test creation of object
        ndict = self.get_post_object(self.networks[net_type].uuid,
                                     test_pool.uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)
        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)
        # Check that an expected field matches.
        self.assertEqual(response.json['address_pool_name'], test_pool.name)
        self.assertEqual(response.json['address_pool_id'], test_pool.id)
        self.assertEqual(response.json['address_pool_uuid'], test_pool.uuid)
        self.assertEqual(response.json['network_name'], self.networks[net_type].name)
        self.assertEqual(response.json['network_id'], self.networks[net_type].id)
        self.assertEqual(response.json['network_uuid'], self.networks[net_type].uuid)

        uuid = response.json['uuid']
        # Verify that the object was created and some basic attribute matches
        response = self.get_json(self.get_single_url(uuid))
        self.assertEqual(response['address_pool_name'], test_pool.name)
        self.assertEqual(response['address_pool_id'], test_pool.id)
        self.assertEqual(response['address_pool_uuid'], test_pool.uuid)
        self.assertEqual(response['network_name'], self.networks[net_type].name)
        self.assertEqual(response['network_id'], self.networks[net_type].id)
        self.assertEqual(response['network_uuid'], self.networks[net_type].uuid)

        addr_list = dbutils.get_address_table()
        self.assertEqual(4, len(addr_list))
        for addr in addr_list:
            self.assertIn(addr.name,
                          [c0_address.name, c1_address.name, gw_address.name, float_address.name])
            if (addr.name == gw_address.name):
                self.assertEqual(gw_address.address, addr.address)

            if addr.name == f"{constants.CONTROLLER_HOSTNAME}-{constants.NETWORK_TYPE_MGMT}":
                self.assertEqual(addr.interface_id, None)
            elif addr.name == f"{constants.CONTROLLER_0_HOSTNAME}-{constants.NETWORK_TYPE_MGMT}":
                self.assertEqual(addr.interface_id, self.c0_mgmt_if.id)
            elif addr.name == f"{constants.CONTROLLER_1_HOSTNAME}-{constants.NETWORK_TYPE_MGMT}":
                self.assertEqual(addr.interface_id, self.c1_mgmt_if.id)

    def test_error_create_network_addrpool_secondary_same_family(self):
        # add primary
        net_type = constants.NETWORK_TYPE_MGMT
        ndict = self.get_post_object(self.networks[net_type].uuid,
                                     self.address_pools['management-ipv4'].uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)
        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        # add secondary
        ndict = self.get_post_object(self.networks[net_type].uuid,
                                     self.address_pools['oam-ipv4'].uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)
        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_error_create_pxeboot_network_addrpool_secondary_ipv6(self):
        # add primary
        net_type = constants.NETWORK_TYPE_PXEBOOT
        ndict = self.get_post_object(self.networks[net_type].uuid,
                                     self.address_pools['pxeboot-ipv4'].uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)
        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        # add secondary
        ndict = self.get_post_object(self.networks[net_type].uuid,
                                     self.address_pools['oam-ipv6'].uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)
        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_error_create_network_addrpool_tertiary(self):
        # add primary
        net_type = constants.NETWORK_TYPE_MGMT
        ndict = self.get_post_object(self.networks[net_type].uuid,
                                     self.address_pools['management-ipv4'].uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)
        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        # add secondary
        ndict = self.get_post_object(self.networks[net_type].uuid,
                                     self.address_pools['management-ipv6'].uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)
        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        # add tertiary
        ndict = self.get_post_object(self.networks[net_type].uuid,
                                     self.address_pools['oam-ipv6'].uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)
        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_error_create_network_addrpool_primary_duplicate(self):
        net_type = constants.NETWORK_TYPE_MGMT
        ndict = self.get_post_object(self.networks[net_type].uuid,
                                     self.address_pools['management-ipv4'].uuid)
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
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)


class TestDelete(NetworkAddrpoolTestCase):
    """ Tests deletion.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """

    def setUp(self):
        super(TestDelete, self).setUp()
        dbutils.cleanup_network_addrpool_table()

    def test_error_delete_mgmt_network_addrpool_primary_aio_sx_config_complete(self):
        p = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = p.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = p.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(p.stop)

        net_type = constants.NETWORK_TYPE_MGMT
        net_pool = dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pools['management-ipv4'].id,
            network_id=self.networks[net_type].id)

        response = self.delete(self.get_single_url(net_pool.uuid),
                                                   headers=self.API_HEADERS,
                                                   expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_error_delete_mgmt_network_addrpool_primary_aio_dx_config_complete(self):
        p = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = p.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_DUPLEX
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = p.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(p.stop)

        net_type = constants.NETWORK_TYPE_MGMT
        net_pool = dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pools['management-ipv4'].id,
            network_id=self.networks[net_type].id)

        response = self.delete(self.get_single_url(net_pool.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_success_delete_mgmt_network_addrpool_secondary(self):
        p = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = p.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = p.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(p.stop)

        net_type = constants.NETWORK_TYPE_MGMT
        net_pool_1 = dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pools['management-ipv4'].id,
            network_id=self.networks[net_type].id)
        net_pool_2 = dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pools['management-ipv6'].id,
            network_id=self.networks[net_type].id)

        response = self.delete(self.get_single_url(net_pool_2.uuid),
                               headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Test deletion of net_pool_2
        response = self.get_json(self.get_single_url(net_pool_2.uuid),
                                 expect_errors=True)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)

        # Test presence of net_pool_1
        response = self.get_json(self.get_single_url(net_pool_1.uuid),
                                 expect_errors=True)
        self.assertEqual(response.status_code, http_client.OK)

        # check that pool_uuid is filled since it was the secondary pool
        response = self.get_json(self.get_single_network_url(self.networks[net_type].uuid))
        self.assertEqual(response['pool_uuid'], self.address_pools['management-ipv4'].uuid)
        self.assertEqual(response['type'], self.networks[net_type].type)
        self.assertEqual(response['primary_pool_family'],
                         self.networks[net_type].primary_pool_family)

    def test_error_delete_oam_network_addrpool_primary(self):
        p = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = p.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = p.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(p.stop)

        net_type = constants.NETWORK_TYPE_OAM
        net_pool = dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pools['oam-ipv4'].id,
            network_id=self.networks[net_type].id)

        response = self.delete(self.get_single_url(net_pool.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_error_delete_pxeboot_network_addrpool_primary(self):
        p = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = p.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = p.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(p.stop)

        net_type = constants.NETWORK_TYPE_PXEBOOT
        net_pool = dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pools['pxeboot-ipv4'].id,
            network_id=self.networks[net_type].id)

        response = self.delete(self.get_single_url(net_pool.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_error_delete_cluster_host_network_addrpool_primary(self):
        p = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = p.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = p.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(p.stop)

        net_type = constants.NETWORK_TYPE_CLUSTER_HOST
        net_pool = dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pools['cluster-host-ipv4'].id,
            network_id=self.networks[net_type].id)

        response = self.delete(self.get_single_url(net_pool.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_error_delete_cluster_pod_network_addrpool_primary(self):
        p = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = p.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = p.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(p.stop)

        net_type = constants.NETWORK_TYPE_CLUSTER_HOST
        net_pool = dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pools['cluster-pod-ipv4'].id,
            network_id=self.networks[net_type].id)

        response = self.delete(self.get_single_url(net_pool.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_error_delete_cluster_service_network_addrpool_primary(self):
        p = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = p.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = p.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(p.stop)

        net_type = constants.NETWORK_TYPE_CLUSTER_SERVICE
        net_pool = dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pools['cluster-service-ipv4'].id,
            network_id=self.networks[net_type].id)

        response = self.delete(self.get_single_url(net_pool.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_error_delete_storage_network_addrpool_primary(self):
        p = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = p.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = p.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(p.stop)

        net_type = constants.NETWORK_TYPE_STORAGE
        net_pool = dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pools['storage-ipv4'].id,
            network_id=self.networks[net_type].id)

        response = self.delete(self.get_single_url(net_pool.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)


class TestList(NetworkAddrpoolTestCase):
    """ Network Addrpool list operations
    """

    def setUp(self):
        super(TestList, self).setUp()

    def test_get_all(self):
        response = self.get_json(self.API_PREFIX)
        self.assertEqual(10, len(response[self.RESULT_KEY]))

    def test_empty_list(self):
        dbutils.cleanup_network_addrpool_table()
        response = self.get_json(self.API_PREFIX)
        self.assertEqual([], response[self.RESULT_KEY])

    def test_get_list_with_one(self):
        dbutils.cleanup_network_addrpool_table()
        dbutils.create_test_network_addrpool(address_pool_id=1,
                                             network_id=1)
        response = self.get_json(self.API_PREFIX)
        self.assertEqual(1, len(response[self.RESULT_KEY]))


class TestPatch(NetworkAddrpoolTestCase):
    patch_path = '/dynamic'
    patch_field = 'dynamic'
    patch_value = False

    def setUp(self):
        super(TestPatch, self).setUp()
        dbutils.cleanup_network_addrpool_table()
        self.patch_object = dbutils.create_test_network_addrpool(address_pool_id=1,
                                             network_id=1)

    def test_patch_not_allowed(self):
        # Try and patch an unmodifiable value

        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': '/junk_field',
                                     'value': self.patch_value,
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify the expected API response
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.METHOD_NOT_ALLOWED)
        self.assertIn("The method PATCH is not allowed for this resource.",
                      response.json['error_message'])
