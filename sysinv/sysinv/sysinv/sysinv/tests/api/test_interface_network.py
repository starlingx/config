# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
#
#
# Copyright (c) 2013-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
import netaddr
from six.moves import http_client

from sysinv.tests.api import base
from sysinv.api.controllers.v1 import interface as api_if_v1
from sysinv.common import constants
from sysinv.common import exception
from sysinv.tests.db import utils as dbutils
from sysinv.db import api as dbapi


class InterfaceNetworkTestCase(base.FunctionalTest):
    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    def setUp(self):
        super(InterfaceNetworkTestCase, self).setUp()
        self.dbapi = dbapi.get_instance()

        p = mock.patch.object(api_if_v1, '_get_lower_interface_macs')
        self.mock_lower_macs = p.start()
        self.mock_lower_macs.return_value = {'enp0s18': '08:00:27:8a:87:48',
                                             'enp0s19': '08:00:27:ea:93:8e'}
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.common.utils.is_aio_simplex_system')
        self.mock_utils_is_aio_simplex_system = p.start()
        self.mock_utils_is_aio_simplex_system.return_value = True
        self.addCleanup(p.stop)

        self.system = dbutils.create_test_isystem()
        self.controller = dbutils.create_test_ihost(
            id='1',
            uuid=None,
            forisystemid=self.system.id,
            hostname='controller-0',
            personality=constants.CONTROLLER,
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
        )
        self.worker = dbutils.create_test_ihost(
            id='2',
            uuid=None,
            forisystemid=self.system.id,
            hostname='worker-0',
            personality=constants.WORKER,
            subfunctions=constants.WORKER,
            mgmt_mac='01:02.03.04.05.C0',
            mgmt_ip='192.168.24.12',
            invprovision=constants.PROVISIONED,
        )
        self.address_pool_mgmt = dbutils.create_test_address_pool(
            id=1,
            network='192.168.204.0',
            name='management',
            ranges=[['192.168.204.2', '192.168.204.254']],
            prefix=24)
        self.mgmt_network = dbutils.create_test_network(
            id=1,
            name='mgmt',
            type=constants.NETWORK_TYPE_MGMT,
            link_capacity=1000,
            vlan_id=2,
            address_pool_id=self.address_pool_mgmt.id)
        dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pool_mgmt.id,
            network_id=self.mgmt_network.id)
        self.mgmt_c0_address = dbutils.create_test_address(
                family=constants.IPV4_FAMILY,
                address='192.168.204.2',
                prefix=24,
                name='controller-0-mgmt',
                address_pool_id=self.address_pool_mgmt.id)
        self.controller['mgmt_ip'] = self.mgmt_c0_address.address
        self.mgmt_w0_address = dbutils.create_test_address(
                family=constants.IPV4_FAMILY,
                address='192.168.204.3',
                prefix=24,
                name='worker-0-mgmt',
                address_pool_id=self.address_pool_mgmt.id)
        self.worker['mgmt_ip'] = self.mgmt_w0_address.address
        self.address_pool_cluster_host = dbutils.create_test_address_pool(
            id=2,
            network='192.168.206.0',
            name='cluster-host',
            ranges=[['192.168.206.2', '192.168.206.254']],
            prefix=24)
        self.cluster_host_network = dbutils.create_test_network(
            id=2,
            name='cluster-host',
            type=constants.NETWORK_TYPE_CLUSTER_HOST,
            link_capacity=10000,
            vlan_id=3,
            address_pool_id=self.address_pool_cluster_host.id)
        dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pool_cluster_host.id,
            network_id=self.cluster_host_network.id)
        self.address_pool_oam = dbutils.create_test_address_pool(
            id=3,
            network='128.224.150.0',
            name='oam',
            ranges=[['128.224.150.1', '128.224.151.254']],
            prefix=23)
        self.oam_network = dbutils.create_test_network(
            id=3,
            name='oam',
            type=constants.NETWORK_TYPE_OAM,
            address_pool_id=self.address_pool_oam.id)
        dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pool_oam.id,
            network_id=self.oam_network.id)
        self.oam_address = dbutils.create_test_address(
                family=constants.IPV4_FAMILY,
                address='10.10.10.3',
                prefix=24,
                name='controller-0-oam',
                address_pool_id=self.address_pool_oam.id)
        self.address_pool_pxeboot = dbutils.create_test_address_pool(
            id=4,
            network='192.168.202.0',
            name='pxeboot',
            ranges=[['192.168.202.2', '192.168.202.254']],
            prefix=23)
        self.pxeboot_network = dbutils.create_test_network(
            id=4,
            type=constants.NETWORK_TYPE_PXEBOOT,
            address_pool_id=self.address_pool_pxeboot.id)
        dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pool_pxeboot.id,
            network_id=self.pxeboot_network.id)
        self.pxeboot_address = dbutils.create_test_address(
                family=constants.IPV4_FAMILY,
                address='192.168.202.3',
                prefix=24,
                name='controller-0-pxeboot',
                address_pool_id=self.address_pool_pxeboot.id)
        self.address_pool_admin = dbutils.create_test_address_pool(
            id=5,
            network='192.168.208.0',
            name='admin',
            ranges=[['192.168.208.2', '192.168.208.254']],
            prefix=24)
        self.admin_network = dbutils.create_test_network(
            id=5,
            name='admin',
            type=constants.NETWORK_TYPE_ADMIN,
            link_capacity=10000,
            vlan_id=8,
            address_pool_id=self.address_pool_admin.id)
        dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pool_admin.id,
            network_id=self.admin_network.id)
        self.address_pool_storage = dbutils.create_test_address_pool(
            id=6,
            network='192.168.209.0',
            name='storage',
            ranges=[['192.168.209.2', '192.168.209.254']],
            prefix=24)
        self.storage_network = dbutils.create_test_network(
            id=6,
            type=constants.NETWORK_TYPE_STORAGE,
            address_pool_id=self.address_pool_storage.id)
        dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pool_storage.id,
            network_id=self.storage_network.id)
        self.address_pool_ironic = dbutils.create_test_address_pool(
            id=7,
            network='192.168.210.0',
            name='ironic',
            ranges=[['192.168.210.2', '192.168.210.254']],
            prefix=24)
        self.ironic_network = dbutils.create_test_network(
            id=7,
            type=constants.NETWORK_TYPE_IRONIC,
            address_pool_id=self.address_pool_ironic.id)
        dbutils.create_test_network_addrpool(
            address_pool_id=self.address_pool_ironic.id,
            network_id=self.ironic_network.id)
        self.network_index = {constants.NETWORK_TYPE_OAM: self.oam_network,
                              constants.NETWORK_TYPE_MGMT: self.mgmt_network,
                              constants.NETWORK_TYPE_CLUSTER_HOST: self.cluster_host_network,
                              constants.NETWORK_TYPE_STORAGE: self.storage_network,
                              constants.NETWORK_TYPE_ADMIN: self.admin_network,
                              constants.NETWORK_TYPE_IRONIC: self.ironic_network}

    def _post_and_check(self, ndict, expect_errors=False):
        response = self.post_json('%s' % self._get_path(), ndict,
                                  expect_errors)
        if expect_errors:
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])
        else:
            self.assertEqual(http_client.OK, response.status_int)
        return response

    def _get_path(self, path=None):
        if path:
            return '/interface_networks/' + path
        else:
            return '/interface_networks'

    def _get_interface_path(self, path=None):
        if path:
            return '/iinterfaces/' + path
        else:
            return '/iinterfaces'

    def _get_addrpool_path(self, path=None):
        if path:
            return '/addrpools/' + path
        else:
            return '/addrpools'

    def _delete_interface_and_check(self, iface_uuid, expect_errors=False, error_message=None):
        response = self.delete('%s' % self._get_interface_path(iface_uuid),
                                  expect_errors)
        if expect_errors:
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])
            if error_message:
                self.assertIn(error_message, response.json['error_message'])
        else:
            self.assertEqual(http_client.NO_CONTENT, response.status_int)
        return response

    IPV6_SUBNETS = {constants.NETWORK_TYPE_OAM: netaddr.IPNetwork('fd00::/64'),
                    constants.NETWORK_TYPE_MGMT: netaddr.IPNetwork('fd01::/64'),
                    constants.NETWORK_TYPE_CLUSTER_HOST: netaddr.IPNetwork('fd02::/64'),
                    constants.NETWORK_TYPE_STORAGE: netaddr.IPNetwork('fd05::/64'),
                    constants.NETWORK_TYPE_ADMIN: netaddr.IPNetwork('fd09::/64'),
                    constants.NETWORK_TYPE_IRONIC: netaddr.IPNetwork('fd0a::/64')}

    def _create_secondary_addrpool(self, networktype):
        subnet = self.IPV6_SUBNETS[networktype]
        network = self.network_index[networktype]
        addrpool = dbutils.create_test_address_pool(
            network=str(subnet.ip),
            family=subnet.version,
            name=f"{networktype}-ipv{subnet.version}",
            ranges=[[str(subnet[1]), str(subnet[-1])]],
            prefix=subnet.prefixlen)
        dbutils.create_test_network_addrpool(
            address_pool_id=addrpool.id,
            network_id=network.id)
        return addrpool

    def _create_controller_address(self, addrpool, networktype):
        subnet = netaddr.IPNetwork(f"{addrpool.network}/{addrpool.prefix}")
        if networktype == constants.NETWORK_TYPE_STORAGE:
            name = 'storage-pool-controller0_address'
        else:
            name = 'controller-0-{}'.format(networktype)
        c0_address = dbutils.create_test_address(
            family=addrpool.family,
            address=str(subnet[3]),
            prefix=addrpool.prefix,
            name=name,
            address_pool_id=addrpool.id)
        self.dbapi.address_pool_update(addrpool.uuid, {'controller0_address_id': c0_address.id})
        return c0_address

    def _create_controller_floating_address(self, addrpool, networktype):
        subnet = netaddr.IPNetwork(f"{addrpool.network}/{addrpool.prefix}")
        floating_address = dbutils.create_test_address(
            family=addrpool.family,
            address=str(subnet[2]),
            prefix=addrpool.prefix,
            name='controller-{}'.format(networktype),
            address_pool_id=addrpool.id)
        self.dbapi.address_pool_update(addrpool.uuid, {'floating_address_id': floating_address.id})
        return floating_address

    def set_system_mode(self, system_mode):
        system = self.dbapi.isystem_get_one()
        self.dbapi.isystem_update(system.uuid, {'system_mode': system_mode})


class InterfaceNetworkCreateTestCase(InterfaceNetworkTestCase):

    def setUp(self):
        super(InterfaceNetworkCreateTestCase, self).setUp()

    def test_create_mgmt_interface_network_standalone(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)

        pool_ipv4 = self.address_pool_mgmt
        pool_ipv6 = self._create_secondary_addrpool(constants.NETWORK_TYPE_MGMT)
        pools = {pool_ipv4.family: pool_ipv4, pool_ipv6.family: pool_ipv6}

        controller_addresses = {}
        for family, pool in pools.items():
            controller_addresses[family] = self._create_controller_address(
                pool, constants.NETWORK_TYPE_MGMT)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.mgmt_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        for family, address in controller_addresses.items():
            updated_address = self.dbapi.address_get(address.id)
            self.assertEqual(controller_interface.id, updated_address.interface_id)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.mgmt_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=False)

        worker_addresses = self.dbapi.addresses_get_by_interface(worker_interface.id)
        self.assertEqual(2, len(worker_addresses))
        for worker_address in worker_addresses:
            self.assertEqual(pools[worker_address.family].uuid, worker_address.pool_uuid)

    def test_create_mgmt_dualstack_cluster_host_singlestack_interface_network_standalone(self):
        """ Test a scenario where management is dual-stack (prim:IPv4, sec:IPv6) and cluster-host
            is single-stack (prin:IPv4). Both are using the same interface (enp0s8).

            Observe that the controller-0-[net_type] addresses are correctly created
            in the database
        """
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)

        mgmt_pool_ipv4 = self.address_pool_mgmt
        mgmt_pool_ipv6 = self._create_secondary_addrpool(constants.NETWORK_TYPE_MGMT)
        mgmt_pools = {mgmt_pool_ipv4.family: mgmt_pool_ipv4, mgmt_pool_ipv6.family: mgmt_pool_ipv6}

        controller_mgmt_addresses = {}
        for family, pool in mgmt_pools.items():
            controller_mgmt_addresses[family] = self._create_controller_address(pool,
                                                        constants.NETWORK_TYPE_MGMT)

        chost_pool_ipv4 = self.address_pool_cluster_host
        chost_pools = {chost_pool_ipv4.family: chost_pool_ipv4}

        controller_chost_addresses = {}
        for family, pool in chost_pools.items():
            controller_chost_addresses[family] = self._create_controller_address(pool,
                                                        constants.NETWORK_TYPE_CLUSTER_HOST)

        controller_interface_network_mgmt = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.mgmt_network.uuid)
        self._post_and_check(controller_interface_network_mgmt, expect_errors=False)

        controller_interface_network_chost = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.cluster_host_network.uuid)
        self._post_and_check(controller_interface_network_chost, expect_errors=False)

        for family, address in controller_mgmt_addresses.items():
            updated_address = self.dbapi.address_get(address.id)
            self.assertEqual(controller_interface.id, updated_address.interface_id)

    def test_create_mgmt_interface_network_system_controller(self):
        controller0 = self.controller
        c0_mgmt0 = dbutils.create_test_interface(ifname='c0_mgm0', forihostid=controller0.id)

        controller1 = dbutils.create_test_ihost(
            mgmt_mac='04:11:22:33:44:55',
            forisystemid=self.system.id,
            hostname='controller-1',
            personality=constants.CONTROLLER,
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED)
        c1_mgmt0 = dbutils.create_test_interface(ifname='c1_mgm0', forihostid=controller1.id)

        subcloud_subnets = [netaddr.IPNetwork('192.167.101.0/24'),
                            netaddr.IPNetwork('192.167.102.0/24'),
                            netaddr.IPNetwork('192.167.103.0/24')]
        c1_routes = {}
        for subnet in subcloud_subnets:
            route = dbutils.create_test_route(
                interface_id=c1_mgmt0.id,
                family=subnet.version,
                network=str(subnet.ip),
                prefix=subnet.prefixlen,
                gateway='192.167.0.1',
                metric=1)
            c1_routes[route.network] = route

        network = self.mgmt_network
        dbutils.create_test_interface_network(interface_id=c1_mgmt0.id,
                                              network_id=network.id)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=c0_mgmt0.uuid, network_uuid=network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        c0_routes = self.dbapi.routes_get_by_interface(c0_mgmt0.id)
        self.assertTrue(c0_routes)
        for route in c0_routes:
            c1_route = c1_routes.get(route.network, None)
            self.assertIsNotNone(c1_route)
            for field in ['family', 'prefix', 'gateway', 'metric']:
                self.assertEqual(c1_route[field], route[field])

    def test_create_mgmt_interface_network_subcloud(self):
        controller0 = self.controller
        c0_mgmt0 = dbutils.create_test_interface(ifname='c0_mgm0', forihostid=controller0.id)

        cc_subnet = netaddr.IPNetwork('192.168.104.0/24')
        cc_addrpool = dbutils.create_test_address_pool(
            network=str(cc_subnet.ip),
            name='system-controller-ipv4',
            ranges=[[str(cc_subnet[1]), str(cc_subnet[-1])]],
            prefix=cc_subnet.prefixlen)
        dbutils.create_test_network(
            name=constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
            type=constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
            address_pool_id=cc_addrpool.id)

        mgmt_subnet = netaddr.IPNetwork("{}/{}".format(self.address_pool_mgmt.network,
                                                       self.address_pool_mgmt.prefix))
        gateway_addr = dbutils.create_test_address(
            name="controller-gateway-mgmt",
            family=self.address_pool_mgmt.family,
            address=str(mgmt_subnet[1]),
            prefix=self.address_pool_mgmt.prefix,
            address_pool_id=self.address_pool_mgmt.id)

        self.dbapi.network_destroy(self.admin_network.id)
        self.dbapi.address_pool_update(self.address_pool_mgmt.id,
                                       {'gateway_address_id': gateway_addr.id})

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=c0_mgmt0.uuid, network_uuid=self.mgmt_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        c0_routes = self.dbapi.routes_get_by_interface(c0_mgmt0.id)
        self.assertEqual(1, len(c0_routes))
        c0_route = c0_routes[0]
        self.assertEqual(str(cc_addrpool.family), c0_route.family)
        self.assertEqual(cc_addrpool.prefix, c0_route.prefix)
        self.assertEqual(cc_addrpool.network, c0_route.network)
        self.assertEqual(gateway_addr.address, c0_route.gateway)
        self.assertEqual(1, c0_route.metric)

    def test_create_cluster_host_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)

        pool_ipv4 = self.address_pool_cluster_host
        pool_ipv6 = self._create_secondary_addrpool(constants.NETWORK_TYPE_CLUSTER_HOST)
        pools = {pool_ipv4.family: pool_ipv4, pool_ipv6.family: pool_ipv6}

        controller_addresses = {}
        for family, pool in pools.items():
            controller_addresses[family] = self._create_controller_address(
                pool, constants.NETWORK_TYPE_CLUSTER_HOST)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.cluster_host_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        for family, address in controller_addresses.items():
            updated_address = self.dbapi.address_get(address.id)
            self.assertEqual(controller_interface.id, updated_address.interface_id)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.cluster_host_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=False)

        worker_addresses = self.dbapi.addresses_get_by_interface(worker_interface.id)
        self.assertEqual(2, len(worker_addresses))
        for worker_address in worker_addresses:
            self.assertEqual(pools[worker_address.family].uuid, worker_address.pool_uuid)

    def test_create_oam_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)

        pool_ipv4 = self.address_pool_oam
        pool_ipv6 = self._create_secondary_addrpool(constants.NETWORK_TYPE_OAM)
        pools = {pool_ipv4.family: pool_ipv4, pool_ipv6.family: pool_ipv6}

        controller_addresses = {}
        for family, pool in pools.items():
            controller_addresses[family] = self._create_controller_address(
                pool, constants.NETWORK_TYPE_OAM)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.oam_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        for family, address in controller_addresses.items():
            updated_address = self.dbapi.address_get(address.id)
            self.assertEqual(controller_interface.id, updated_address.interface_id)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.oam_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=True)

    def test_create_pxeboot_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)

        controller_address = self._create_controller_address(
            self.address_pool_pxeboot, constants.NETWORK_TYPE_PXEBOOT)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.pxeboot_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        controller_address = self.dbapi.address_get(controller_address.id)
        self.assertEqual(controller_interface.id, controller_address.interface_id)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.pxeboot_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=False)

        worker_addresses = self.dbapi.addresses_get_by_interface(worker_interface.id)
        self.assertEqual(0, len(worker_addresses))

    def test_create_mgmt_cluster_host_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        dbutils.create_test_interface_network(
            interface_id=controller_interface.id,
            network_id=self.mgmt_network.id)

        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)
        dbutils.create_test_interface_network(
            interface_id=worker_interface.id,
            network_id=self.mgmt_network.id)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.cluster_host_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.cluster_host_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=False)

    def test_create_storage_interface_network(self):
        self.set_system_mode(constants.SYSTEM_MODE_SIMPLEX)
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_storage_net_config')
        self.mock_rpcapi_update_storage_net_config = p.start()
        self.addCleanup(p.stop)

        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)

        pool_ipv4 = self.address_pool_storage
        pool_ipv6 = self._create_secondary_addrpool(constants.NETWORK_TYPE_STORAGE)
        pools = {pool_ipv4.family: pool_ipv4, pool_ipv6.family: pool_ipv6}

        controller_floating_address = {}
        for family, pool in pools.items():
            addr = self._create_controller_floating_address(pool, constants.NETWORK_TYPE_STORAGE)
            controller_floating_address[family] = addr

        controller_addresses = {}
        for family, pool in pools.items():
            addr = self._create_controller_address(pool, constants.NETWORK_TYPE_STORAGE)
            controller_addresses[family] = addr

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.storage_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)
        self.mock_rpcapi_update_storage_net_config.assert_called_once()
        self.mock_rpcapi_update_storage_net_config.reset_mock()

        for family, address in controller_addresses.items():
            updated_address = self.dbapi.address_get(address.id)
            self.assertEqual(None, updated_address.interface_id)

        for family, address in controller_floating_address.items():
            updated_address = self.dbapi.address_get(address.id)
            self.assertEqual(controller_interface.id, updated_address.interface_id)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.storage_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=False)
        self.mock_rpcapi_update_storage_net_config.assert_called_once()
        controller_addresses = self.dbapi.addresses_get_by_interface(controller_interface.id)

        worker_addresses = self.dbapi.addresses_get_by_interface(worker_interface.id)
        self.assertEqual(2, len(controller_addresses))
        self.assertEqual(2, len(worker_addresses))
        for worker_address in worker_addresses:
            self.assertEqual(pools[worker_address.family].uuid, worker_address.pool_uuid)

    def test_create_admin_interface_network(self):
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_admin_config')
        self.mock_rpcapi_update_admin_config = p.start()
        self.addCleanup(p.stop)

        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)

        pool_ipv4 = self.address_pool_admin
        pool_ipv6 = self._create_secondary_addrpool(constants.NETWORK_TYPE_ADMIN)
        pools = {pool_ipv4.family: pool_ipv4, pool_ipv6.family: pool_ipv6}

        controller_addresses = {}
        for family, pool in pools.items():
            controller_addresses[family] = self._create_controller_address(
                pool, constants.NETWORK_TYPE_ADMIN)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.admin_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        for family, address in controller_addresses.items():
            updated_address = self.dbapi.address_get(address.id)
            self.assertEqual(controller_interface.id, updated_address.interface_id)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.admin_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=True)

        self.mock_rpcapi_update_admin_config.assert_called_once()
        self.assertEqual(False, self.mock_rpcapi_update_admin_config.call_args.args[2])

    def test_create_mgmt_admin_interface_network(self):
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_admin_config')
        self.mock_rpcapi_update_admin_config = p.start()
        self.addCleanup(p.stop)

        controller0 = self.controller

        c0_mgmt0 = dbutils.create_test_interface(ifname='c0_mgmt0', forihostid=controller0.id)
        mgmt_subnet = netaddr.IPNetwork("{}/{}".format(self.address_pool_mgmt.network,
                                                       self.address_pool_mgmt.prefix))
        gateway_mgmt_addr = dbutils.create_test_address(
            name="controller-gateway-mgmt",
            family=self.address_pool_mgmt.family,
            address=str(mgmt_subnet[1]),
            prefix=self.address_pool_mgmt.prefix,
            address_pool_id=self.address_pool_mgmt.id)
        self.dbapi.address_pool_update(self.address_pool_mgmt.id,
                                       {'gateway_address_id': gateway_mgmt_addr.id})

        c0_admin0 = dbutils.create_test_interface(ifname='c0_admin0', forihostid=controller0.id)

        admin_subnet = netaddr.IPNetwork("{}/{}".format(self.address_pool_admin.network,
                                                       self.address_pool_admin.prefix))
        gateway_addr = dbutils.create_test_address(
            name="controller-gateway-admin",
            family=self.address_pool_admin.family,
            address=str(admin_subnet[1]),
            prefix=self.address_pool_admin.prefix,
            address_pool_id=self.address_pool_admin.id)

        self.dbapi.address_pool_update(self.address_pool_admin.id,
                                       {'gateway_address_id': gateway_addr.id})

        cc_subnet = netaddr.IPNetwork('192.168.104.0/24')
        dbutils.create_test_route(
            interface_id=c0_mgmt0.id,
            family=cc_subnet.version,
            network=str(cc_subnet.ip),
            prefix=cc_subnet.prefixlen,
            gateway=gateway_mgmt_addr.address,
            metric=1)

        c0_routes = self.dbapi.routes_get_by_interface(c0_mgmt0.id)
        self.assertEqual(1, len(c0_routes))
        c0_route = c0_routes[0]
        self.assertEqual(gateway_mgmt_addr.address, c0_route.gateway)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=c0_admin0.uuid, network_uuid=self.admin_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        c0_routes = self.dbapi.routes_get_by_interface(c0_mgmt0.id)
        self.assertEqual(1, len(c0_routes))
        c0_route = c0_routes[0]
        self.assertEqual(gateway_mgmt_addr.address, c0_route.gateway)
        self.assertEqual(1, c0_route.metric)

        self.mock_rpcapi_update_admin_config.assert_called_once()
        self.assertEqual(False, self.mock_rpcapi_update_admin_config.call_args.args[2])

    def test_create_admin_interface_network_subcloud(self):
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_admin_config')
        self.mock_rpcapi_update_admin_config = p.start()
        self.addCleanup(p.stop)

        controller0 = self.controller
        c0_admin0 = dbutils.create_test_interface(ifname='c0_admin0', forihostid=controller0.id)

        cc_subnet = netaddr.IPNetwork('192.168.104.0/24')
        cc_addrpool = dbutils.create_test_address_pool(
            network=str(cc_subnet.ip),
            name='system-controller-ipv4',
            ranges=[[str(cc_subnet[1]), str(cc_subnet[-1])]],
            prefix=cc_subnet.prefixlen)
        dbutils.create_test_network(
            name=constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
            type=constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
            address_pool_id=cc_addrpool.id)

        admin_subnet = netaddr.IPNetwork("{}/{}".format(self.address_pool_admin.network,
                                                       self.address_pool_admin.prefix))
        gateway_addr = dbutils.create_test_address(
            name="controller-gateway-admin",
            family=self.address_pool_admin.family,
            address=str(admin_subnet[1]),
            prefix=self.address_pool_admin.prefix,
            address_pool_id=self.address_pool_admin.id)

        self.dbapi.address_pool_update(self.address_pool_admin.id,
                                       {'gateway_address_id': gateway_addr.id})

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=c0_admin0.uuid, network_uuid=self.admin_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        c0_routes = self.dbapi.routes_get_by_interface(c0_admin0.id)
        self.assertEqual(1, len(c0_routes))
        c0_route = c0_routes[0]
        self.assertEqual(str(cc_addrpool.family), c0_route.family)
        self.assertEqual(cc_addrpool.prefix, c0_route.prefix)
        self.assertEqual(cc_addrpool.network, c0_route.network)
        self.assertEqual(gateway_addr.address, c0_route.gateway)
        self.assertEqual(1, c0_route.metric)

        self.mock_rpcapi_update_admin_config.assert_called_once()
        self.assertEqual(False, self.mock_rpcapi_update_admin_config.call_args.args[2])

    def test_create_mgmt_admin_interface_network_subcloud(self):
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_admin_config')
        self.mock_rpcapi_update_admin_config = p.start()
        self.addCleanup(p.stop)

        controller0 = self.controller

        cc_subnet = netaddr.IPNetwork('192.168.104.0/24')
        cc_addrpool = dbutils.create_test_address_pool(
            network=str(cc_subnet.ip),
            name='system-controller-ipv4',
            ranges=[[str(cc_subnet[1]), str(cc_subnet[-1])]],
            prefix=cc_subnet.prefixlen)
        dbutils.create_test_network(
            name=constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
            type=constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
            address_pool_id=cc_addrpool.id)

        c0_mgmt0 = dbutils.create_test_interface(ifname='c0_mgmt0', forihostid=controller0.id)
        mgmt_subnet = netaddr.IPNetwork("{}/{}".format(self.address_pool_mgmt.network,
                                                       self.address_pool_mgmt.prefix))
        gateway_mgmt_addr = dbutils.create_test_address(
            name="controller-gateway-mgmt",
            family=self.address_pool_mgmt.family,
            address=str(mgmt_subnet[1]),
            prefix=self.address_pool_mgmt.prefix,
            address_pool_id=self.address_pool_mgmt.id)
        self.dbapi.address_pool_update(self.address_pool_mgmt.id,
                                       {'gateway_address_id': gateway_mgmt_addr.id})

        c0_admin0 = dbutils.create_test_interface(ifname='c0_admin0', forihostid=controller0.id)

        admin_subnet = netaddr.IPNetwork("{}/{}".format(self.address_pool_admin.network,
                                                       self.address_pool_admin.prefix))
        gateway_addr = dbutils.create_test_address(
            name="controller-gateway-admin",
            family=self.address_pool_admin.family,
            address=str(admin_subnet[1]),
            prefix=self.address_pool_admin.prefix,
            address_pool_id=self.address_pool_admin.id)

        self.dbapi.address_pool_update(self.address_pool_admin.id,
                                       {'gateway_address_id': gateway_addr.id})

        dbutils.create_test_route(
            interface_id=c0_mgmt0.id,
            family=cc_subnet.version,
            network=str(cc_subnet.ip),
            prefix=cc_subnet.prefixlen,
            gateway=gateway_mgmt_addr.address,
            metric=1)

        c0_routes = self.dbapi.routes_get_by_interface(c0_mgmt0.id)
        self.assertEqual(1, len(c0_routes))
        c0_route = c0_routes[0]
        self.assertEqual(gateway_mgmt_addr.address, c0_route.gateway)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=c0_admin0.uuid, network_uuid=self.admin_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        c0_routes = self.dbapi.routes_get_by_interface(c0_admin0.id)
        self.assertEqual(1, len(c0_routes))
        c0_route = c0_routes[0]
        self.assertEqual(str(cc_addrpool.family), c0_route.family)
        self.assertEqual(cc_addrpool.prefix, c0_route.prefix)
        self.assertEqual(cc_addrpool.network, c0_route.network)
        self.assertEqual(gateway_addr.address, c0_route.gateway)
        self.assertEqual(1, c0_route.metric)

        self.mock_rpcapi_update_admin_config.assert_called_once()
        self.assertEqual(False, self.mock_rpcapi_update_admin_config.call_args.args[2])

    def test_create_ironic_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)

        pool_ipv4 = self.address_pool_ironic
        pool_ipv6 = self._create_secondary_addrpool(constants.NETWORK_TYPE_IRONIC)
        pools = {pool_ipv4.family: pool_ipv4, pool_ipv6.family: pool_ipv6}

        controller_addresses = {}
        for family, pool in pools.items():
            controller_addresses[family] = self._create_controller_address(
                pool, constants.NETWORK_TYPE_IRONIC)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.ironic_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        for family, address in controller_addresses.items():
            updated_address = self.dbapi.address_get(address.id)
            self.assertEqual(controller_interface.id, updated_address.interface_id)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.ironic_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=False)

        worker_addresses = self.dbapi.addresses_get_by_interface(worker_interface.id)
        self.assertEqual(0, len(worker_addresses))

    # Expected error:
    # You cannot assign a network of type 'oam' to an interface
    # which is already assigned with a different network
    def test_create_invalid_mgmt_oam_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        dbutils.create_test_interface_network(
            interface_id=controller_interface.id,
            network_id=self.mgmt_network.id)

        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)
        dbutils.create_test_interface_network(
            interface_id=worker_interface.id,
            network_id=self.mgmt_network.id)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.oam_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=True)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.oam_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=True)

    # Expected error:
    # You cannot assign a network of type 'pxeboot' to an interface
    # which is already assigned with a different network
    def test_create_invalid_mgmt_pxeboot_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        dbutils.create_test_interface_network(
            interface_id=controller_interface.id,
            network_id=self.mgmt_network.id)

        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)
        dbutils.create_test_interface_network(
            interface_id=worker_interface.id,
            network_id=self.mgmt_network.id)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.pxeboot_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=True)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.pxeboot_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=True)

    # Expected error:
    # Interface network with interface ID '%s' and
    # network ID '%s' already exists."
    def test_create_invalid_duplicate_mgmt_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        dbutils.create_test_interface_network(
            interface_id=controller_interface.id,
            network_id=self.mgmt_network.id)

        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)
        dbutils.create_test_interface_network(
            interface_id=worker_interface.id,
            network_id=self.mgmt_network.id)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.mgmt_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=True)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.mgmt_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=True)

    # Expected error: The oam network type is only supported on controller nodes
    def test_invalid_oam_on_worker(self):
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s3',
            forihostid=self.worker.id)
        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.oam_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=True)

    # Expected error: The admin network type is only supported on controller nodes
    def test_invalid_admin_on_worker(self):
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s3',
            forihostid=self.worker.id)
        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.admin_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=True)

    # Expected message: An interface with \'oam\' network type is already
    # provisioned on this node
    def test_create_invalid_duplicate_networktype(self):
        controller_interface1 = dbutils.create_test_interface(
            ifname='enp0s3',
            forihostid=self.controller.id)
        dbutils.create_test_interface_network(
            interface_id=controller_interface1.id,
            network_id=self.oam_network.id)
        controller_interface2 = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface2.uuid,
            network_uuid=self.oam_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=True)

    # Expected error: Interface ___ does not have associated cluster-host
    # interface on controller.
    def test_no_cluster_host_on_controller(self):
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s3',
            forihostid=self.worker.id)
        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.cluster_host_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=True)

    # Expected error: An interface with interface class data cannot
    # assign platform networks.
    def test_create_invalid_network_on_data_interface(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s3',
            ifclass=constants.NETWORK_TYPE_DATA,
            forihostid=self.controller.id)
        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.cluster_host_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=True)

    # Expected error: Device interface with network type ___, and interface type
    #  'aggregated ethernet' must be in mode '802.3ad'
    def test_aemode_invalid_mgmt(self):
        controller_interface = dbutils.create_test_interface(
            ifname='name',
            forihostid=self.controller.id,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='balanced',
            txhashpolicy='layer2')
        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.mgmt_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=True)

    # Expected error: Device interface with network type ___, and interface type
    #  'aggregated ethernet' must be in mode '802.3ad'
    def test_aemode_invalid_admin(self):
        controller_interface = dbutils.create_test_interface(
            ifname='name',
            forihostid=self.controller.id,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='balanced',
            txhashpolicy='layer2')
        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.admin_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=True)

    # In case of aio-simplex, interface bound to admin-network can be deleted without removing admin-address-pool.
    def test_aiosx_delete_interface_adminnetwork(self):
        interface = dbutils.create_test_interface(
                ifname='admin', id=1,
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                forihostid=self.controller.id,
                ihost_uuid=self.controller.uuid)

        admin_interface = dbutils.create_test_interface(
            ifname='admin0', id=2,
            iftype=constants.INTERFACE_TYPE_VLAN,
            uses=[interface.ifname],
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid)

        admin_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=admin_interface.uuid,
            network_uuid=self.admin_network.uuid)
        self._post_and_check(admin_interface_network, expect_errors=False)

        # system host-if-delete controller-0 admin_interface
        self._delete_interface_and_check(admin_interface.uuid, expect_errors=False)

    # In case of non aio-simplex, interface bound to admin-network can not be deleted without
    # removing admin-address-pool.
    def test_non_aiosx_delete_interface_adminetwork(self):
        self.mock_utils_is_aio_simplex_system.return_value = False

        interface = dbutils.create_test_interface(
                ifname='admin', id=1,
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                forihostid=self.controller.id,
                ihost_uuid=self.controller.uuid)

        admin_interface = dbutils.create_test_interface(
            ifname='admin0', id=2,
            iftype=constants.INTERFACE_TYPE_VLAN,
            vlan_id=100,
            uses=[interface.ifname],
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid)

        admin_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=admin_interface.uuid,
            network_uuid=self.admin_network.uuid)
        self._post_and_check(admin_interface_network, expect_errors=False)

        # system host-if-delete controller-0 admin_interface
        self._delete_interface_and_check(admin_interface.uuid, expect_errors=True,
            error_message="Cannot delete an interface still assigned to a network of")

        # delete address pool and then admin interface, no error expected
        self.dbapi.address_pool_destroy(self.address_pool_admin.uuid)
        self._delete_interface_and_check(admin_interface.uuid, expect_errors=False)

    def test_create_mgmt_update_no_proxy_list(self):
        self.set_system_mode(constants.SYSTEM_MODE_SIMPLEX)

        iniconf = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = iniconf.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(iniconf.stop)

        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.set_mgmt_network_reconfig_flag')
        self.mock_rpcapi_set_mgmt_network_reconfig_flag = p.start()
        self.addCleanup(p.stop)

        c0_mgmt0 = dbutils.create_test_interface(
            ifname='c0-mgmt0', id=2,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid)

        mgmt_subnet = netaddr.IPNetwork('{}/{}'.format(self.address_pool_mgmt.network,
                                                       self.address_pool_mgmt.prefix))
        mgmt_floating = dbutils.create_test_address(
            name="mgmt-floating",
            family=mgmt_subnet.version,
            address=str(mgmt_subnet[2]),
            prefix=mgmt_subnet.prefixlen,
            address_pool_id=self.address_pool_mgmt.id)

        mgmt_controller0 = dbutils.create_test_address(
            name="mgmt-controller0",
            family=mgmt_subnet.version,
            address=str(mgmt_subnet[3]),
            prefix=mgmt_subnet.prefixlen,
            address_pool_id=self.address_pool_mgmt.id)

        self.dbapi.address_pool_update(self.address_pool_mgmt.uuid,
                                       {'floating_address_id': mgmt_floating.id,
                                        'controller0_address_id': mgmt_controller0.id})

        param_values = {'service': constants.SERVICE_TYPE_DOCKER,
                        'section': constants.SERVICE_PARAM_SECTION_DOCKER_PROXY,
                        'name': constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY,
                        'value': ''}

        dbutils.create_test_service_parameter(**param_values)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=c0_mgmt0.uuid,
            network_uuid=self.mgmt_network.uuid)

        self._post_and_check(controller_interface_network)

        no_proxy_entry = self.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_DOCKER,
            section=constants.SERVICE_PARAM_SECTION_DOCKER_PROXY,
            name=constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY)

        self.assertEqual(','.join([mgmt_floating.address,
                                   mgmt_controller0.address]),
                         no_proxy_entry.value)

        self.mock_rpcapi_set_mgmt_network_reconfig_flag.assert_called_once()


class InterfaceNetworkDeleteTestCase(InterfaceNetworkTestCase):

    def setUp(self):
        super(InterfaceNetworkDeleteTestCase, self).setUp()

    def test_delete_mgmt_update_no_proxy_list(self):
        self.set_system_mode(constants.SYSTEM_MODE_SIMPLEX)

        iniconf = mock.patch('sysinv.common.utils.is_initial_config_complete')
        self.mock_utils_is_initial_config_complete = iniconf.start()
        self.mock_utils_is_initial_config_complete.return_value = True
        self.addCleanup(iniconf.stop)

        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.set_mgmt_network_reconfig_flag')
        self.mock_rpcapi_set_mgmt_network_reconfig_flag = p.start()
        self.addCleanup(p.stop)

        c0_mgmt0 = dbutils.create_test_interface(
            ifname='c0-mgmt0', id=2,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid)

        mgmt_subnet = netaddr.IPNetwork('{}/{}'.format(self.address_pool_mgmt.network,
                                                       self.address_pool_mgmt.prefix))
        mgmt_floating = dbutils.create_test_address(
            name="mgmt-floating",
            family=mgmt_subnet.version,
            address=str(mgmt_subnet[2]),
            prefix=mgmt_subnet.prefixlen,
            address_pool_id=self.address_pool_mgmt.id)

        mgmt_controller0 = dbutils.create_test_address(
            name="mgmt-controller0",
            family=mgmt_subnet.version,
            address=str(mgmt_subnet[3]),
            prefix=mgmt_subnet.prefixlen,
            interface_id=c0_mgmt0.id,
            address_pool_id=self.address_pool_mgmt.id)

        self.dbapi.address_pool_update(self.address_pool_mgmt.uuid,
                                       {'floating_address_id': mgmt_floating.id,
                                        'controller0_address_id': mgmt_controller0.id})

        param_values = {'service': constants.SERVICE_TYPE_DOCKER,
                        'section': constants.SERVICE_PARAM_SECTION_DOCKER_PROXY,
                        'name': constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY,
                        'value': ','.join([mgmt_floating.address, mgmt_controller0.address])}

        dbutils.create_test_service_parameter(**param_values)

        ifnw = dbutils.create_test_interface_network(interface_id=c0_mgmt0.id,
                                                     network_id=self.mgmt_network.id)

        response = self.delete(self._get_path(ifnw.uuid), headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        no_proxy_entry = self.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_DOCKER,
            section=constants.SERVICE_PARAM_SECTION_DOCKER_PROXY,
            name=constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY)

        self.assertEqual('', no_proxy_entry.value)

        self.mock_rpcapi_set_mgmt_network_reconfig_flag.assert_called_once()

    def test_delete_admin_in_subcloud(self):
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_admin_config')
        self.mock_rpcapi_update_admin_config = p.start()
        self.addCleanup(p.stop)

        controller0 = self.controller
        c0_admin0 = dbutils.create_test_interface(ifname='c0_admin0',
                                                  forihostid=controller0.id,
                                                  vlan_id=10, iftype='vlan')

        cc_subnet = netaddr.IPNetwork('192.168.104.0/24')
        cc_addrpool = dbutils.create_test_address_pool(
            network=str(cc_subnet.ip),
            name='system-controller-ipv4',
            ranges=[[str(cc_subnet[1]), str(cc_subnet[-1])]],
            prefix=cc_subnet.prefixlen)
        dbutils.create_test_network(
            name=constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
            type=constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
            address_pool_id=cc_addrpool.id)

        admin_subnet = netaddr.IPNetwork("{}/{}".format(self.address_pool_admin.network,
                                                        self.address_pool_admin.prefix))
        gateway_addr = dbutils.create_test_address(
            name="controller-gateway-admin",
            family=self.address_pool_admin.family,
            address=str(admin_subnet[1]),
            prefix=self.address_pool_admin.prefix,
            address_pool_id=self.address_pool_admin.id)

        route = dbutils.create_test_route(
            interface_id=c0_admin0.id,
            family=cc_subnet.version,
            network=str(cc_subnet.ip),
            prefix=cc_subnet.prefixlen,
            gateway=gateway_addr.address,
            metric=1)

        self.dbapi.address_pool_update(self.address_pool_admin.id,
                                       {'gateway_address_id': gateway_addr.id})

        ifnw = dbutils.create_test_interface_network(interface_id=c0_admin0.id,
                                                     network_id=self.admin_network.id)

        response = self.delete(self._get_path(ifnw.uuid), headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        self.assertRaises(exception.RouteNotFound, self.dbapi.route_get, route.uuid)

        self.mock_rpcapi_update_admin_config.assert_called_once()
        self.assertEqual(True, self.mock_rpcapi_update_admin_config.call_args.args[2])

        ifnw = dbutils.create_test_interface_network_assign(c0_admin0.id,
                                                            self.admin_network.
                                                            id)

        self.dbapi.address_update(gateway_addr.uuid, {'interface_id': c0_admin0.id})
        gateway_addr_db = self.dbapi.address_get(gateway_addr.uuid)
        self.assertEqual(1, gateway_addr_db.interface_id)

        self._delete_interface_and_check(c0_admin0.uuid, expect_errors=False)

        gateway_addr_db = self.dbapi.address_get(gateway_addr.uuid)
        self.assertEqual(None, gateway_addr_db.interface_id)

    def test_delete_admin_update_to_mgmt_in_subcloud(self):
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_admin_config')
        self.mock_rpcapi_update_admin_config = p.start()
        self.addCleanup(p.stop)

        cc_subnet = netaddr.IPNetwork('192.168.104.0/24')
        cc_addrpool = dbutils.create_test_address_pool(
            network=str(cc_subnet.ip),
            name='system-controller-ipv4',
            ranges=[[str(cc_subnet[1]), str(cc_subnet[-1])]],
            prefix=cc_subnet.prefixlen)
        dbutils.create_test_network(
            name=constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
            type=constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
            address_pool_id=cc_addrpool.id)

        controller0 = self.controller
        c0_mgmt0 = dbutils.create_test_interface(ifname='c0_mgmt0',
                                                 ifclass=constants.INTERFACE_CLASS_PLATFORM,
                                                 forihostid=controller0.id)
        mgmt_subnet = netaddr.IPNetwork('{}/{}'.format(self.address_pool_mgmt.network,
                                                       self.address_pool_mgmt.prefix))
        gateway_mgmt_addr = dbutils.create_test_address(
            name="controller-gateway-mgmt",
            family=mgmt_subnet.version,
            address=str(mgmt_subnet[1]),
            prefix=mgmt_subnet.prefixlen,
            address_pool_id=self.address_pool_mgmt.id)
        self.dbapi.address_pool_update(self.address_pool_mgmt.uuid,
                                       {'gateway_address_id': gateway_mgmt_addr.id})
        ifnw = dbutils.create_test_interface_network(interface_id=c0_mgmt0.id,
                                                     network_id=self.mgmt_network.id)

        c0_admin0 = dbutils.create_test_interface(ifname='c0_admin0',
                                                  forihostid=controller0.id,
                                                  vlan_id=10, iftype='vlan')
        admin_subnet = netaddr.IPNetwork("{}/{}".format(self.address_pool_admin.network,
                                                        self.address_pool_admin.prefix))
        gateway_addr = dbutils.create_test_address(
            name="controller-gateway-admin",
            family=self.address_pool_admin.family,
            address=str(admin_subnet[1]),
            prefix=self.address_pool_admin.prefix,
            address_pool_id=self.address_pool_admin.id)
        self.dbapi.address_pool_update(self.address_pool_admin.id,
                                       {'gateway_address_id': gateway_addr.id})

        dbutils.create_test_route(interface_id=c0_admin0.id,
                                  family=cc_subnet.version,
                                  network=str(cc_subnet.ip),
                                  prefix=cc_subnet.prefixlen,
                                  gateway=gateway_addr.address,
                                  metric=1)
        ifnw = dbutils.create_test_interface_network(interface_id=c0_admin0.id,
                                                     network_id=self.admin_network.id)
        response = self.delete(self._get_path(ifnw.uuid), headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        self.mock_rpcapi_update_admin_config.assert_called_once()
        self.assertEqual(True, self.mock_rpcapi_update_admin_config.call_args.args[2])
