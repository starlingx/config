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

    def create_test_interface(self, ifname='test0', host=None):
        if not host:
            host = self.get_host()
        interface = dbutils.create_test_interface(
            ifname=ifname,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=host.id,
            ihost_uuid=host.uuid)
        return interface


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

        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_oam_config')
        self.mock_rpcapi_update_oam_config = p.start()
        self.addCleanup(p.stop)

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
        self.mock_rpcapi_update_oam_config.assert_called_once()

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

    def test_fail_address_pool_overlap(self):
        oamnet = self._find_network_by_type(constants.NETWORK_TYPE_OAM)
        mgmtnet = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        chnet = self._find_network_by_type(constants.NETWORK_TYPE_CLUSTER_HOST)

        oam_pool = self._find_network_address_pools(oamnet.id)[0]
        mgmt_pool = self._find_network_address_pools(mgmtnet.id)[0]
        ch_pool = self._find_network_address_pools(chnet.id)[0]

        if self.mgmt_subnet.version == constants.IPV4_FAMILY:
            oam_subnet = netaddr.IPNetwork('192.169.1.0/24')
            ch_subnet = netaddr.IPNetwork('192.169.2.0/24')
            mgmt_subnet = netaddr.IPNetwork('192.169.0.0/16')
        else:
            oam_subnet = netaddr.IPNetwork('fdaa:0:0:1:1::/80')
            ch_subnet = netaddr.IPNetwork('fdaa:0:0:1:2::/80')
            mgmt_subnet = netaddr.IPNetwork('fdaa:0:0:1::/64')

        self.dbapi.address_pool_update(oam_pool.uuid,
                                       {'network': str(oam_subnet.ip),
                                        'prefix': str(oam_subnet.prefixlen),
                                        'ranges': [[str(oam_subnet[1]), str(oam_subnet[-1])]]})
        self.dbapi.address_pool_update(ch_pool.uuid,
                                       {'network': str(ch_subnet.ip),
                                        'prefix': str(ch_subnet.prefixlen),
                                        'ranges': [[str(ch_subnet[1]), str(ch_subnet[-1])]]})
        self.dbapi.address_pool_update(mgmt_pool.uuid,
                                       {'network': str(mgmt_subnet.ip),
                                        'prefix': str(mgmt_subnet.prefixlen),
                                        'ranges': [[str(mgmt_subnet[1]), str(mgmt_subnet[-1])]]})

        controller0 = self._create_test_host(constants.CONTROLLER)

        dbutils.create_test_network_addrpool(address_pool_id=oam_pool.id, network_id=oamnet.id)
        dbutils.create_test_network_addrpool(address_pool_id=ch_pool.id, network_id=chnet.id)

        c0_if0 = self.create_test_interface('c0-if0', controller0)
        self.dbapi.address_mode_update(c0_if0.id, {'family': oam_pool.family, 'mode': 'pool',
                                                   'address_pool_id': oam_pool.id})

        ndict = self.get_post_object(mgmtnet.uuid, mgmt_pool.uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.CONFLICT)
        msg = (f"Address pool '{mgmt_pool.name}' {{{mgmt_pool.uuid}}} "
               f"{mgmt_subnet.ip}/{mgmt_subnet.prefixlen} overlaps with: "
               f"'{oam_pool.name}' {{{oam_pool.uuid}}} assigned to oam network and "
               f"to '{c0_if0.ifname}' interface in host {controller0.hostname}, "
               f"'{ch_pool.name}' {{{ch_pool.uuid}}} assigned to cluster-host network")
        self.assertIn(msg, response.json['error_message'])

    def test_create_management_secondary_for_aio_sx(self):
        sysmode = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = sysmode.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(sysmode.stop)

        iniconf = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = iniconf.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(iniconf.stop)

        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.set_mgmt_network_reconfig_flag')
        self.mock_rpcapi_set_mgmt_network_reconfig_flag = p.start()
        self.addCleanup(p.stop)

        controller0 = self._create_test_host(constants.CONTROLLER)

        c0_mgmt0 = dbutils.create_test_interface(
            ifname='c0-mgmt0', id=1,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=controller0.id,
            ihost_uuid=controller0.uuid)

        mgmt_net = self.networks[constants.NETWORK_TYPE_MGMT]
        mgmt_ipv4 = self.address_pools['management-ipv4']
        mgmt_ipv6 = self.address_pools['management-ipv6']

        subnet_ipv4 = netaddr.IPNetwork('{}/{}'.format(mgmt_ipv4.network, mgmt_ipv4.prefix))
        subnet_ipv6 = netaddr.IPNetwork('{}/{}'.format(mgmt_ipv6.network, mgmt_ipv6.prefix))

        mgmt_floating_ipv4 = dbutils.create_test_address(
            name="mgmt-floating-ipv4",
            family=subnet_ipv4.version,
            address=str(subnet_ipv4[2]),
            prefix=subnet_ipv4.prefixlen,
            address_pool_id=mgmt_ipv4.id)

        mgmt_controller0_ipv4 = dbutils.create_test_address(
            name="mgmt-controller0-ipv4",
            family=subnet_ipv4.version,
            address=str(subnet_ipv4[3]),
            prefix=subnet_ipv4.prefixlen,
            interface_id=c0_mgmt0.id,
            address_pool_id=mgmt_ipv4.id)

        mgmt_floating_ipv6 = dbutils.create_test_address(
            name="mgmt-floating-ipv6",
            family=subnet_ipv6.version,
            address=str(subnet_ipv6[2]),
            prefix=subnet_ipv6.prefixlen,
            address_pool_id=mgmt_ipv6.id)

        mgmt_controller0_ipv6 = dbutils.create_test_address(
            name="mgmt-controller0-ipv6",
            family=subnet_ipv6.version,
            address=str(subnet_ipv6[3]),
            prefix=subnet_ipv6.prefixlen,
            interface_id=c0_mgmt0.id,
            address_pool_id=mgmt_ipv6.id)

        self.dbapi.address_pool_update(mgmt_ipv4.uuid,
                                       {'floating_address_id': mgmt_floating_ipv4.id,
                                        'controller0_address_id': mgmt_controller0_ipv4.id})

        self.dbapi.address_pool_update(mgmt_ipv6.uuid,
                                       {'floating_address_id': mgmt_floating_ipv6.id,
                                        'controller0_address_id': mgmt_controller0_ipv6.id})

        dbutils.create_test_interface_network(interface_id=c0_mgmt0.id, network_id=mgmt_net.id)

        dbutils.create_test_network_addrpool(address_pool_id=mgmt_ipv4.id, network_id=mgmt_net.id)

        param_values = {'service': constants.SERVICE_TYPE_DOCKER,
                        'section': constants.SERVICE_PARAM_SECTION_DOCKER_PROXY,
                        'name': constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY,
                        'value': ','.join([mgmt_floating_ipv4.address,
                                           mgmt_controller0_ipv4.address])}

        dbutils.create_test_service_parameter(**param_values)

        ndict = self.get_post_object(mgmt_net.uuid, mgmt_ipv6.uuid)
        response = self.post_json(self.API_PREFIX, ndict, headers=self.API_HEADERS)

        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        no_proxy_entry = self.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_DOCKER,
            section=constants.SERVICE_PARAM_SECTION_DOCKER_PROXY,
            name=constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY)

        self.assertEqual(','.join([mgmt_floating_ipv4.address,
                                   mgmt_controller0_ipv4.address,
                                   '[' + mgmt_floating_ipv6.address + ']',
                                   '[' + mgmt_controller0_ipv6.address + ']']),
                         no_proxy_entry.value)

        self.mock_rpcapi_set_mgmt_network_reconfig_flag.assert_called_once()

    def test_fail_create_management_secondary_for_aio_sx_host_unlocked(self):
        sysmode = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = sysmode.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(sysmode.stop)

        iniconf = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = iniconf.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(iniconf.stop)

        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.set_mgmt_network_reconfig_flag')
        self.mock_rpcapi_set_mgmt_network_reconfig_flag = p.start()
        self.addCleanup(p.stop)

        controller0 = self._create_test_host(constants.CONTROLLER,
                                             administrative=constants.ADMIN_UNLOCKED)

        mgmt_net = self.networks[constants.NETWORK_TYPE_MGMT]
        mgmt_ipv4 = self.address_pools['management-ipv4']
        mgmt_ipv6 = self.address_pools['management-ipv6']

        dbutils.create_test_network_addrpool(address_pool_id=mgmt_ipv4.id, network_id=mgmt_net.id)

        ndict = self.get_post_object(mgmt_net.uuid, mgmt_ipv6.uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        msg = ("Cannot complete the action because Host {} "
               "is in administrative state = unlocked").format(controller0.hostname)
        self.assertIn(msg, response.json['error_message'])

        self.mock_rpcapi_set_mgmt_network_reconfig_flag.assert_not_called()

    def test_create_management_existing_addresses(self):
        mgmt_net = self.networks[constants.NETWORK_TYPE_MGMT]
        mgmt_pool = self.address_pools['management-ipv4']
        subnet = netaddr.IPNetwork('{}/{}'.format(mgmt_pool.network, mgmt_pool.prefix))

        other_pool = dbutils.create_test_address_pool(
            name='existing-pool',
            family=subnet.version,
            network=str(subnet.ip),
            prefix=subnet.prefixlen,
            ranges=[[str(subnet[1]), str(subnet[-1])]])

        updates = {}
        addresses = {}
        ip_address = subnet[2]
        fields = ['floating_address_id', 'controller0_address_id', 'controller1_address_id']
        for id_field in fields:
            address = dbutils.create_test_address(
                name=id_field,
                family=subnet.version,
                address=str(ip_address),
                prefix=subnet.prefixlen,
                address_pool_id=other_pool.id)
            ip_address += 1
            updates[id_field] = address.id
            addresses[id_field] = address

        gateway_address = dbutils.create_test_address(
            name='gateway_address',
            family=subnet.version,
            address=str(subnet[1]),
            prefix=subnet.prefixlen,
            address_pool_id=mgmt_pool.id)

        self.dbapi.address_pool_update(other_pool.uuid, updates)

        self.dbapi.address_pool_update(mgmt_pool.uuid,
                                       {'gateway_address_id': gateway_address.id,
                                        'floating_address_id': None,
                                        'controller0_address_id': None,
                                        'controller1_address_id': None})

        ndict = self.get_post_object(mgmt_net.uuid, mgmt_pool.uuid)
        response = self.post_json(self.API_PREFIX, ndict, headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        gateway_address = self.dbapi.address_get(gateway_address.id)
        floating_address = self.dbapi.address_get(addresses['floating_address_id'].id)
        c0_address = self.dbapi.address_get(addresses['controller0_address_id'].id)
        c1_address = self.dbapi.address_get(addresses['controller1_address_id'].id)

        self.assertEqual(mgmt_pool.uuid, floating_address.pool_uuid)
        self.assertEqual(mgmt_pool.uuid, c0_address.pool_uuid)
        self.assertEqual(mgmt_pool.uuid, c1_address.pool_uuid)

        self.assertEqual('controller-gateway-mgmt', gateway_address.name)
        self.assertEqual('controller-mgmt', floating_address.name)
        self.assertEqual('controller-0-mgmt', c0_address.name)
        self.assertEqual('controller-1-mgmt', c1_address.name)

    def test_success_create_network_addrpool_secondary_admin(self):
        p = mock.patch('sysinv.api.controllers.v1.utils.get_distributed_cloud_role')
        self.mock_utils_get_system_mode = p.start()
        self.mock_utils_get_system_mode.return_value = constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_admin_config')
        self.mock_rpcapi_update_admin_config = p.start()
        self.addCleanup(p.stop)

        admin_network = self._find_network_by_type(constants.NETWORK_TYPE_ADMIN)
        admin_pool_ipv4 = self.address_pools['admin-ipv4']
        admin_pool_ipv6 = self.address_pools['admin-ipv6']

        controller0 = self._create_test_host(constants.CONTROLLER, unit=0)
        c0_admin0 = self.create_test_interface('c0_admin0', controller0)

        controller1 = self._create_test_host(constants.CONTROLLER, unit=1)
        c1_admin0 = self.create_test_interface('c1_admin0', controller1)

        dbutils.create_test_network_addrpool(address_pool_id=admin_pool_ipv4.id,
                                             network_id=admin_network.id)

        dbutils.create_test_interface_network(interface_id=c0_admin0.id,
                                              network_id=admin_network.id)
        dbutils.create_test_interface_network(interface_id=c1_admin0.id,
                                              network_id=admin_network.id)

        ndict = self.get_post_object(admin_network.uuid, admin_pool_ipv6.uuid)
        response = self.post_json(self.API_PREFIX, ndict, headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        updated_ipv6_pool = self.dbapi.address_pool_get(admin_pool_ipv6.id)
        self.assertIsNotNone(updated_ipv6_pool.floating_address)
        self.assertIsNotNone(updated_ipv6_pool.controller0_address)
        self.assertIsNotNone(updated_ipv6_pool.controller1_address)

        self.mock_rpcapi_update_admin_config.assert_called()
        self.assertEqual(2, self.mock_rpcapi_update_admin_config.call_count)
        for call in self.mock_rpcapi_update_admin_config.call_args_list:
            self.assertEqual(False, call.kwargs['disable'])


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

    def test_success_delete_oam_network_addrpool_secondary(self):
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_oam_config')
        self.mock_rpcapi_update_oam_config = p.start()
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = p.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = p.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(p.stop)

        net_type = constants.NETWORK_TYPE_OAM
        net_pool_1 = dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pools['oam-ipv4'].id,
            network_id=self.networks[net_type].id)
        net_pool_2 = dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pools['oam-ipv6'].id,
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
        self.assertEqual(response['pool_uuid'], self.address_pools['oam-ipv4'].uuid)
        self.assertEqual(response['type'], self.networks[net_type].type)
        self.assertEqual(response['primary_pool_family'],
                         self.networks[net_type].primary_pool_family)
        self.mock_rpcapi_update_oam_config.assert_called_once()

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

    def test_delete_management_secondary_aio_sx(self):
        sysmode = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = sysmode.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(sysmode.stop)

        iniconf = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = iniconf.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(iniconf.stop)

        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.set_mgmt_network_reconfig_flag')
        self.mock_rpcapi_set_mgmt_network_reconfig_flag = p.start()
        self.addCleanup(p.stop)

        controller0 = self._create_test_host(constants.CONTROLLER)

        c0_mgmt0 = dbutils.create_test_interface(
            ifname='c0-mgmt0', id=1,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=controller0.id,
            ihost_uuid=controller0.uuid)

        mgmt_net = self.networks[constants.NETWORK_TYPE_MGMT]
        mgmt_ipv4 = self.address_pools['management-ipv4']
        mgmt_ipv6 = self.address_pools['management-ipv6']

        subnet_ipv6 = netaddr.IPNetwork('{}/{}'.format(mgmt_ipv6.network, mgmt_ipv6.prefix))

        mgmt_floating_ipv6 = dbutils.create_test_address(
            name="mgmt-floating-ipv6",
            family=subnet_ipv6.version,
            address=str(subnet_ipv6[2]),
            prefix=subnet_ipv6.prefixlen,
            address_pool_id=mgmt_ipv6.id)

        mgmt_controller0_ipv6 = dbutils.create_test_address(
            name="mgmt-controller0-ipv6",
            family=subnet_ipv6.version,
            address=str(subnet_ipv6[3]),
            prefix=subnet_ipv6.prefixlen,
            interface_id=c0_mgmt0.id,
            address_pool_id=mgmt_ipv6.id)

        self.dbapi.address_pool_update(mgmt_ipv6.uuid,
                                       {'floating_address_id': mgmt_floating_ipv6.id,
                                        'controller0_address_id': mgmt_controller0_ipv6.id})

        dbutils.create_test_interface_network(interface_id=c0_mgmt0.id, network_id=mgmt_net.id)

        dbutils.create_test_network_addrpool(address_pool_id=mgmt_ipv4.id, network_id=mgmt_net.id)

        nw_addrpool = dbutils.create_test_network_addrpool(address_pool_id=mgmt_ipv6.id,
                                                           network_id=mgmt_net.id)

        param_values = {'service': constants.SERVICE_TYPE_DOCKER,
                        'section': constants.SERVICE_PARAM_SECTION_DOCKER_PROXY,
                        'name': constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY,
                        'value': ','.join([mgmt_ipv4.floating_address,
                                           mgmt_ipv4.controller0_address,
                                           '[' + mgmt_floating_ipv6.address + ']',
                                           '[' + mgmt_controller0_ipv6.address + ']'])}

        dbutils.create_test_service_parameter(**param_values)

        response = self.delete(self.get_single_url(nw_addrpool.uuid), headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        no_proxy_entry = self.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_DOCKER,
            section=constants.SERVICE_PARAM_SECTION_DOCKER_PROXY,
            name=constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY)

        self.assertEqual(','.join([mgmt_ipv4.floating_address,
                                   mgmt_ipv4.controller0_address]),
                         no_proxy_entry.value)

        self.mock_rpcapi_set_mgmt_network_reconfig_flag.assert_called_once()

    def test_fail_delete_management_secondary_aio_sx_host_unlocked(self):
        sysmode = mock.patch('sysinv.api.controllers.v1.utils.get_system_mode')
        self.mock_utils_get_system_mode = sysmode.start()
        self.mock_utils_get_system_mode.return_value = constants.SYSTEM_MODE_SIMPLEX
        self.addCleanup(sysmode.stop)

        iniconf = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = iniconf.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(iniconf.stop)

        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.set_mgmt_network_reconfig_flag')
        self.mock_rpcapi_set_mgmt_network_reconfig_flag = p.start()
        self.addCleanup(p.stop)

        controller0 = self._create_test_host(constants.CONTROLLER,
                                             administrative=constants.ADMIN_UNLOCKED)

        mgmt_net = self.networks[constants.NETWORK_TYPE_MGMT]
        mgmt_ipv4 = self.address_pools['management-ipv4']
        mgmt_ipv6 = self.address_pools['management-ipv6']

        dbutils.create_test_network_addrpool(address_pool_id=mgmt_ipv4.id, network_id=mgmt_net.id)

        nw_addrpool = dbutils.create_test_network_addrpool(address_pool_id=mgmt_ipv6.id,
                                                           network_id=mgmt_net.id)

        response = self.delete(self.get_single_url(nw_addrpool.uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        msg = ("Cannot complete the action because Host {} "
               "is in administrative state = unlocked").format(controller0.hostname)
        self.assertIn(msg, response.json['error_message'])

        self.mock_rpcapi_set_mgmt_network_reconfig_flag.assert_not_called()

    def test_success_delete_admin_network_addrpool_secondary(self):
        p = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = p.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_admin_config')
        self.mock_rpcapi_update_admin_config = p.start()
        self.addCleanup(p.stop)

        net_type = constants.NETWORK_TYPE_ADMIN
        network = self.networks[net_type]
        dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pools['admin-ipv4'].id,
            network_id=network.id)
        net_pool_2 = dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pools['admin-ipv6'].id,
            network_id=network.id)

        controller0 = self._create_test_host(constants.CONTROLLER, unit=0)
        c0_admin0 = self.create_test_interface('c0_admin0', controller0)

        controller1 = self._create_test_host(constants.CONTROLLER, unit=1)
        c1_admin0 = self.create_test_interface('c1_admin0', controller1)

        dbutils.create_test_interface_network(interface_id=c0_admin0.id, network_id=network.id)
        dbutils.create_test_interface_network(interface_id=c1_admin0.id, network_id=network.id)

        response = self.delete(self.get_single_url(net_pool_2.uuid), headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        self.assertEqual(2, self.mock_rpcapi_update_admin_config.call_count)
        for call in self.mock_rpcapi_update_admin_config.call_args_list:
            self.assertEqual(False, call.kwargs['disable'])


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
