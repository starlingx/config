# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Tests for manipulating Network objects via the DB API"""

# from oslo_utils import uuidutils

from sysinv.common import constants
from sysinv.common import exception
from sysinv.db import api as dbapi
from sysinv.tests.db import base
# from sysinv.tests.db import utils
import netaddr


class DbNetworkTestCaseIPv4(base.BaseHostTestCase):

    def setUp(self):
        super(DbNetworkTestCaseIPv4, self).setUp()
        self.dbapi = dbapi.get_instance()

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

    def _db_dump(self):
        print("==============================================================")
        address_pools = self.dbapi.address_pools_get_all()
        for pool in address_pools:
            print(type(pool), vars(pool))
        print("==============================================================")
        networks = self.dbapi.networks_get_all()
        for net in networks:
            print(type(net), vars(net))
        print("==============================================================")
        addresses = self.dbapi.addresses_get_all()
        for addr in addresses:
            print(type(addr), vars(addr))
        print("==============================================================")
        net_pools = self.dbapi.network_addrpool_get_all()
        for net_pool in net_pools:
            print(type(net_pool), vars(net_pool))
        print("==============================================================")

    def test_network_addrpool_db(self):

        to_add = [
            (constants.NETWORK_TYPE_MGMT, ('management-ipv4', 'management-ipv6')),
            (constants.NETWORK_TYPE_OAM, ('oam-ipv4', 'oam-ipv6')),
            (constants.NETWORK_TYPE_ADMIN, ('admin-ipv4', 'admin-ipv6')),
            (constants.NETWORK_TYPE_CLUSTER_HOST, ('cluster-host-ipv4', 'cluster-host-ipv6')),
            (constants.NETWORK_TYPE_CLUSTER_POD, ('cluster-pod-ipv4', 'cluster-pod-ipv6')),
            (constants.NETWORK_TYPE_CLUSTER_SERVICE, ('cluster-service-ipv4',
                                                      'cluster-service-ipv6')),
            (constants.NETWORK_TYPE_STORAGE, ('storage-ipv4', 'storage-ipv6'))
        ]

        # test network_addrpool_create()
        try:
            for net_pool in to_add:
                net = self.dbapi.network_get_by_type(net_pool[0])

                pool6 = self.dbapi.address_pool_query({'name': net_pool[1][1]})
                net_pool_obj = self.dbapi.network_addrpool_create({"address_pool_id": pool6.id,
                                                                   "network_id": net.id})
                self.assertEqual(net_pool_obj.address_pool_id, pool6.id)
                self.assertEqual(net_pool_obj.network_id, net.id)

                # network-addrpool objects already created in the parent test class
                pool4 = self.dbapi.address_pool_query({'name': net_pool[1][0]})
                net_pool_obj = self.dbapi.network_addrpool_query({"address_pool_id": pool4.id,
                                                                   "network_id": net.id})
                self.assertEqual(net_pool_obj.address_pool_id, pool4.id)
                self.assertEqual(net_pool_obj.network_id, net.id)

        except Exception as e:
            print(e)

        # test network_addrpool_get_all()
        net_pools = self.dbapi.network_addrpool_get_all()
        self.assertEqual(len(net_pools), 17)

        # test network_addrpool_get_by_network_id()
        net = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        net_pools = self.dbapi.network_addrpool_get_by_network_id(net.id)
        self.assertEqual(len(net_pools), 2)
        self.assertEqual(net_pools[0].network_type, constants.NETWORK_TYPE_MGMT)
        self.assertEqual(net_pools[0].address_pool_name, "management-ipv4")
        self.assertEqual(net_pools[1].network_type, constants.NETWORK_TYPE_MGMT)
        self.assertEqual(net_pools[1].address_pool_name, "management-ipv6")

        # test network_addrpool_get_by_pool_id()
        pool4 = self.dbapi.address_pool_query({'name': 'management-ipv4'})
        net_pools = self.dbapi.network_addrpool_get_by_pool_id(pool4.id)
        self.assertEqual(len(net_pools), 1)
        self.assertEqual(net_pools[0].address_pool_id, pool4.id)
        self.assertEqual(net_pools[0].address_pool_name, 'management-ipv4')

        # test network_addrpool_query()
        net_pool_q = self.dbapi.network_addrpool_query({'address_pool_id': pool4.id,
                                                       'network_id': net.id})
        self.assertEqual(net_pool_q.address_pool_id, pool4.id)
        self.assertEqual(net_pool_q.network_id, net.id)

        # test network_addrpool_get()
        net_pool_q2 = self.dbapi.network_addrpool_get(net_pool_q.uuid)
        self.assertEqual(net_pool_q.address_pool_id, net_pool_q2.address_pool_id)
        self.assertEqual(net_pool_q.network_id, net_pool_q2.network_id)

        # test network_addrpool_destroy()
        pool6 = self.dbapi.address_pool_query({'name': 'management-ipv6'})
        net_pool_d = self.dbapi.network_addrpool_query({'address_pool_id': pool6.id,
                                                        'network_id': net.id})
        self.dbapi.network_addrpool_destroy(net_pool_d.uuid)
        self.assertRaises(exception.NetworkAddrpoolNotFound,
                          self.dbapi.network_addrpool_get, net_pool_d.uuid)

        # test invalid network id
        self.assertEqual(self.dbapi.network_addrpool_get_by_network_id(1000), [])

        # test invalid pool id
        self.assertEqual(self.dbapi.network_addrpool_get_by_pool_id(1000), [])

        # test duplicate network-addrpool entry
        self.assertRaises(exception.NetworkAddrpoolAlreadyExists,
                          self.dbapi.network_addrpool_create, {"address_pool_id": pool4.id,
                                                               "network_id": net.id})

        addr = self.dbapi.address_get_by_name_and_family('controller-mgmt',
                                                         constants.IPV4_FAMILY)
        self.assertEqual(addr.name, 'controller-mgmt')
        self.assertEqual(addr.family, constants.IPV4_FAMILY)

        self.assertRaises(exception.AddressNotFoundByNameAndFamily,
                          self.dbapi.address_get_by_name_and_family,
                          'controller-mgmt', constants.IPV6_FAMILY)

        self._create_test_addresses(hostnames=[constants.CONTROLLER_HOSTNAME],
                                    subnets=[netaddr.IPNetwork('fd01::/64')],
                                    network_type=constants.NETWORK_TYPE_MGMT)

        addr = self.dbapi.address_get_by_name_and_family('controller-mgmt',
                                                         constants.IPV6_FAMILY)
        self.assertEqual(addr.name, 'controller-mgmt')
        self.assertEqual(addr.family, constants.IPV6_FAMILY)

        addresses = self.dbapi.address_get_by_name('controller-mgmt')
        self.assertEqual(len(addresses), 2)

        # check parameter delete cascading
        new_net_pool6 = self.dbapi.network_addrpool_create({'address_pool_id': pool6.id,
                                                            'network_id': net.id})
        self.dbapi.address_pool_destroy(pool6.uuid)

        net_pool_query = self.dbapi.network_addrpool_get(new_net_pool6.uuid)
        self.assertEqual(net_pool_query.address_pool_uuid, None)
        self.assertEqual(net_pool_query.address_pool_name, None)
        self.assertEqual(net_pool_query.address_pool_id, None)
        self.assertEqual(net_pool_query.network_id, net.id)
        self.assertEqual(net_pool_query.network_uuid, net.uuid)
        self.assertEqual(net_pool_query.network_type, net.type)

        self.dbapi.network_destroy(net.uuid)
        net_pool_query = self.dbapi.network_addrpool_get(new_net_pool6.uuid)
        self.assertEqual(net_pool_query.address_pool_uuid, None)
        self.assertEqual(net_pool_query.address_pool_name, None)
        self.assertEqual(net_pool_query.address_pool_id, None)
        self.assertEqual(net_pool_query.network_id, None)
        self.assertEqual(net_pool_query.network_uuid, None)
        self.assertEqual(net_pool_query.network_type, None)
