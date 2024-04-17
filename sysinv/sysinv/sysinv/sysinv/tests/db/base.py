# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 NTT DOCOMO, INC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Sysinv DB test base class."""

import abc
import itertools
import os

import netaddr
import six

from oslo_context import context
from oslo_utils import uuidutils

from sysinv.common import constants
from sysinv.common import utils

from sysinv.tests import base
from sysinv.tests.db import utils as dbutils


PXEBOOT_SUBNET = netaddr.IPNetwork('192.168.202.0/24')

MGMT_SUBNET_IPV4 = netaddr.IPNetwork('192.168.204.0/24')
OAM_SUBNET_IPV4 = netaddr.IPNetwork('10.10.10.0/24')
CLUSTER_HOST_SUBNET_IPV4 = netaddr.IPNetwork('192.168.206.0/24')
CLUSTER_POD_SUBNET_IPV4 = netaddr.IPNetwork('172.16.0.0/16')
CLUSTER_SERVICE_SUBNET_IPV4 = netaddr.IPNetwork('10.96.0.0/12')
MULTICAST_SUBNET_IPV4 = netaddr.IPNetwork('239.1.1.0/28')
STORAGE_SUBNET_IPV4 = netaddr.IPNetwork('10.10.20.0/24')
ADMIN_SUBNET_IPV4 = netaddr.IPNetwork('10.10.30.0/24')
SYSTEM_CONTROLLER_SUBNET_IPV4 = netaddr.IPNetwork('192.168.104.0/24')
SYSTEM_CONTROLLER_OAM_SUBNET_IPV4 = netaddr.IPNetwork('10.10.50.0/24')
NAMESERVERS_IPV4 = ['8.8.8.8', '8.8.4.4']

MGMT_SUBNET_IPV6 = netaddr.IPNetwork('fd01::/64')
OAM_SUBNET_IPV6 = netaddr.IPNetwork('fd00::/64')
CLUSTER_HOST_SUBNET_IPV6 = netaddr.IPNetwork('fd02::/64')
CLUSTER_POD_SUBNET_IPV6 = netaddr.IPNetwork('fd03::/64')
CLUSTER_SERVICE_SUBNET_IPV6 = netaddr.IPNetwork('fd04::/112')
MULTICAST_SUBNET_IPV6 = netaddr.IPNetwork('ff08::1:1:0/124')
STORAGE_SUBNET_IPV6 = netaddr.IPNetwork('fd05::/64')
ADMIN_SUBNET_IPV6 = netaddr.IPNetwork('fd09::/64')
SYSTEM_CONTROLLER_SUBNET_IPV6 = netaddr.IPNetwork('fd07::/64')
SYSTEM_CONTROLLER_OAM_SUBNET_IPV6 = netaddr.IPNetwork('fd06::/64')
NAMESERVERS_IPV6 = ['2001:4860:4860::8888', '2001:4860:4860::8844']


@six.add_metaclass(abc.ABCMeta)
class DbTestCase(base.TestCase):

    def setUp(self):
        super(DbTestCase, self).setUp()
        self.admin_context = context.get_admin_context()


class BaseIPv4Mixin(object):

    primary_address_family = constants.IPV4_FAMILY
    secondary_address_family = None

    pxeboot_subnet = PXEBOOT_SUBNET
    mgmt_subnet = MGMT_SUBNET_IPV4
    oam_subnet = OAM_SUBNET_IPV4
    cluster_host_subnet = CLUSTER_HOST_SUBNET_IPV4
    cluster_pod_subnet = CLUSTER_POD_SUBNET_IPV4
    cluster_service_subnet = CLUSTER_SERVICE_SUBNET_IPV4
    multicast_subnet = MULTICAST_SUBNET_IPV4
    storage_subnet = STORAGE_SUBNET_IPV4
    admin_subnet = ADMIN_SUBNET_IPV4
    system_controller_subnet = SYSTEM_CONTROLLER_SUBNET_IPV4
    system_controller_oam_subnet = SYSTEM_CONTROLLER_OAM_SUBNET_IPV4

    pxeboot_subnets = [PXEBOOT_SUBNET]
    mgmt_subnets = [MGMT_SUBNET_IPV4]
    oam_subnets = [OAM_SUBNET_IPV4]
    cluster_host_subnets = [CLUSTER_HOST_SUBNET_IPV4]
    cluster_pod_subnets = [CLUSTER_POD_SUBNET_IPV4]
    cluster_service_subnets = [CLUSTER_SERVICE_SUBNET_IPV4]
    multicast_subnets = [MULTICAST_SUBNET_IPV4]
    storage_subnets = [STORAGE_SUBNET_IPV4]
    admin_subnets = [ADMIN_SUBNET_IPV4]
    system_controller_subnets = [SYSTEM_CONTROLLER_SUBNET_IPV4]
    system_controller_oam_subnets = [SYSTEM_CONTROLLER_OAM_SUBNET_IPV4]

    nameservers = NAMESERVERS_IPV4

    # Used to test changing oam from ipv4 to ipv6
    change_family_oam_subnet = netaddr.IPNetwork('fd00::/64')


class BaseIPv6Mixin(object):

    primary_address_family = constants.IPV6_FAMILY
    secondary_address_family = None

    pxeboot_subnet = PXEBOOT_SUBNET
    mgmt_subnet = MGMT_SUBNET_IPV6
    oam_subnet = OAM_SUBNET_IPV6
    cluster_host_subnet = CLUSTER_HOST_SUBNET_IPV6
    cluster_pod_subnet = CLUSTER_POD_SUBNET_IPV6
    cluster_service_subnet = CLUSTER_SERVICE_SUBNET_IPV6
    multicast_subnet = MULTICAST_SUBNET_IPV6
    storage_subnet = STORAGE_SUBNET_IPV6
    admin_subnet = ADMIN_SUBNET_IPV6
    system_controller_subnet = SYSTEM_CONTROLLER_SUBNET_IPV6
    system_controller_oam_subnet = SYSTEM_CONTROLLER_OAM_SUBNET_IPV6

    pxeboot_subnets = [PXEBOOT_SUBNET]
    mgmt_subnets = [MGMT_SUBNET_IPV6]
    oam_subnets = [OAM_SUBNET_IPV6]
    cluster_host_subnets = [CLUSTER_HOST_SUBNET_IPV6]
    cluster_pod_subnets = [CLUSTER_POD_SUBNET_IPV6]
    cluster_service_subnets = [CLUSTER_SERVICE_SUBNET_IPV6]
    multicast_subnets = [MULTICAST_SUBNET_IPV6]
    storage_subnets = [STORAGE_SUBNET_IPV6]
    admin_subnets = [ADMIN_SUBNET_IPV6]
    system_controller_subnets = [SYSTEM_CONTROLLER_SUBNET_IPV6]
    system_controller_oam_subnets = [SYSTEM_CONTROLLER_OAM_SUBNET_IPV6]

    nameservers = NAMESERVERS_IPV6

    # Used to test changing oam from ipv6 to ipv4
    change_family_oam_subnet = netaddr.IPNetwork('10.10.10.0/24')


class BaseDualStackPrimaryIPv4Mixin(BaseIPv4Mixin):

    secondary_address_family = constants.IPV6_FAMILY

    mgmt_subnets = [MGMT_SUBNET_IPV4, MGMT_SUBNET_IPV6]
    oam_subnets = [OAM_SUBNET_IPV4, OAM_SUBNET_IPV6]
    cluster_host_subnets = [CLUSTER_HOST_SUBNET_IPV4, CLUSTER_HOST_SUBNET_IPV6]
    cluster_pod_subnets = [CLUSTER_POD_SUBNET_IPV4, CLUSTER_POD_SUBNET_IPV6]
    cluster_service_subnets = [CLUSTER_SERVICE_SUBNET_IPV4, CLUSTER_SERVICE_SUBNET_IPV6]
    multicast_subnets = [MULTICAST_SUBNET_IPV4, MULTICAST_SUBNET_IPV6]
    storage_subnets = [STORAGE_SUBNET_IPV4, STORAGE_SUBNET_IPV6]
    admin_subnets = [ADMIN_SUBNET_IPV4, ADMIN_SUBNET_IPV6]
    system_controller_subnets = [SYSTEM_CONTROLLER_SUBNET_IPV4, SYSTEM_CONTROLLER_SUBNET_IPV6]
    system_controller_oam_subnets = [SYSTEM_CONTROLLER_OAM_SUBNET_IPV4,
                                     SYSTEM_CONTROLLER_OAM_SUBNET_IPV6]

    nameservers = NAMESERVERS_IPV4 + NAMESERVERS_IPV6


class BaseDualStackPrimaryIPv6Mixin(BaseIPv6Mixin):

    secondary_address_family = constants.IPV4_FAMILY

    mgmt_subnets = [MGMT_SUBNET_IPV6, MGMT_SUBNET_IPV4]
    oam_subnets = [OAM_SUBNET_IPV6, OAM_SUBNET_IPV4]
    cluster_host_subnets = [CLUSTER_HOST_SUBNET_IPV6, CLUSTER_HOST_SUBNET_IPV4]
    cluster_pod_subnets = [CLUSTER_POD_SUBNET_IPV6, CLUSTER_POD_SUBNET_IPV4]
    cluster_service_subnets = [CLUSTER_SERVICE_SUBNET_IPV6, CLUSTER_SERVICE_SUBNET_IPV4]
    multicast_subnets = [MULTICAST_SUBNET_IPV6, MULTICAST_SUBNET_IPV4]
    storage_subnets = [STORAGE_SUBNET_IPV6, STORAGE_SUBNET_IPV4]
    admin_subnets = [ADMIN_SUBNET_IPV6, ADMIN_SUBNET_IPV4]
    system_controller_subnets = [SYSTEM_CONTROLLER_SUBNET_IPV6, SYSTEM_CONTROLLER_SUBNET_IPV4]
    system_controller_oam_subnets = [SYSTEM_CONTROLLER_OAM_SUBNET_IPV6,
                                     SYSTEM_CONTROLLER_OAM_SUBNET_IPV4]

    nameservers = NAMESERVERS_IPV6 + NAMESERVERS_IPV4


class BaseCephStorageBackendMixin(object):

    def setUp(self):
        super(BaseCephStorageBackendMixin, self).setUp()
        self.backend_id = '54321'
        self.tier = self._setup_ceph_storage_tier()
        self._setup_ceph_backend()
        # setup one or more storage monitors
        self.mon_index = 0
        self._create_storage_mon(self.host.hostname, self.host.id)

    def tearDown(self):
        super(BaseCephStorageBackendMixin, self).tearDown()

    def _setup_ceph_storage_tier(self, **kwargs):
        kwargs['forbackendid'] = self.backend_id
        return dbutils.create_test_storage_tier(**kwargs)

    def _setup_ceph_backend(self, **kwargs):
        kwargs['forisystemid'] = self.system['id']
        kwargs['tier_id'] = self.tier['id']
        kwargs['id'] = self.backend_id
        n = dbutils.get_test_ceph_storage_backend(**kwargs)
        self.dbapi.storage_ceph_create(n)

    def _create_storage_mon(self, hostname, ihost_id):
        self.mon_index += 1
        ceph_mon_dict = dbutils.get_test_mon(
            id=self.mon_index,
            uuid=uuidutils.generate_uuid(),
            state=constants.SB_STATE_CONFIGURED,
            task=constants.SB_TASK_NONE,
            forihostid=ihost_id,
            hostname=hostname)
        return self.dbapi.ceph_mon_create(ceph_mon_dict)


@six.add_metaclass(abc.ABCMeta)
class BaseSystemTestCase(BaseIPv4Mixin, DbTestCase):
    system_type = constants.TIS_STD_BUILD
    system_mode = constants.SYSTEM_MODE_DUPLEX

    ntpservers = ['0.pool.ntp.org', '1.pool.ntp.org']

    def setUp(self):
        super(BaseSystemTestCase, self).setUp()
        self.hosts = []
        self.address_pools = []
        self.networks_by_type = {}
        self.networks_by_id = {}
        self.address_pools_by_network_id = {}
        self.addresses_by_id = {}
        self.network_addrpools = []
        self.datanetworks = []
        self._create_test_common()

    def tearDown(self):
        super(BaseSystemTestCase, self).tearDown()
        self.system = None
        self.load = None
        self.drbd = None
        self.remotelogging = None
        self.user = None
        self.dns = None
        self.ntp = None
        self.ptp = None
        self.hosts = []
        self.address_pools = []
        self.networks_by_type = {}
        self.networks_by_id = {}
        self.address_pools_by_network_id = {}
        self.network_addrpools = []
        self.datanetworks = []
        self.oam = None

    def _create_test_common(self):
        self._create_test_system()
        self._create_test_load()
        self._create_test_drbd()
        self._create_test_remotelogging()
        self._create_test_user()
        self._create_test_dns()
        self._create_test_ntp()
        self._create_test_ptp()
        self._create_test_static_ips()
        self._create_test_networks()
        self._create_test_datanetworks()
        self._create_test_oam()
        self._create_test_multicast_ips()

    def _create_test_system(self):
        self.system = dbutils.create_test_isystem(
            system_type=self.system_type,
            system_mode=self.system_mode)

    def _create_test_load(self):
        self.load = dbutils.create_test_load()

    def _create_test_drbd(self):
        self.drbd = dbutils.create_test_drbd(
            forisystemid=self.system.id)

    def _create_test_remotelogging(self):
        self.remotelogging = dbutils.create_test_remotelogging(
            system_id=self.system.id)

    def _create_test_user(self):
        self.user = dbutils.create_test_user(
            forisystemid=self.system.id)

    def _create_test_dns(self):
        nameservers = ','.join(self.nameservers)
        self.dns = dbutils.create_test_dns(
            forisystemid=self.system.id,
            nameservers=nameservers)

    def _create_test_ntp(self):
        ntpservers = ','.join(self.ntpservers)
        self.ntp = dbutils.create_test_ntp(
            forisystemid=self.system.id,
            ntpservers=ntpservers)

    def _create_test_ptp(self):
        self.ptp = dbutils.create_test_ptp(
            system_id=self.system.id)

    def _format_pool_name(self, network_name, subnet):
        if subnet.version == constants.IPV6_FAMILY:
            family = 'ipv6'
        else:
            family = 'ipv4'
        return network_name + '-' + family

    def _create_test_network(self, name, network_type, subnets, link_addresses=False):

        address_pools = []
        for subnet in subnets:
            pool_name = self._format_pool_name(name, subnet)
            address_pool = self._create_test_address_pool(
                pool_name, subnet, link_addresses=link_addresses)
            address_pools.append(address_pool)

        primary_pool_family = constants.IP_FAMILIES[subnets[0].version]

        network = dbutils.create_test_network(
            type=network_type,
            address_pool_id=address_pools[0].id,
            primary_pool_family=primary_pool_family)

        self._add_network_to_index(network)

        for address_pool in address_pools:
            network_addrpool = dbutils.create_test_network_addrpool(
                address_pool_id=address_pool.id, network_id=network.id)
            self.network_addrpools.append(network_addrpool)
            self._add_address_pool_to_index(address_pool, network)

        return network

    def _add_network_to_index(self, network):
        self.networks_by_type[network.type] = network
        self.networks_by_id[network.id] = network

    def _add_address_pool_to_index(self, addrpool, network):
        pools = self.address_pools_by_network_id.get(network.id, None)
        if not pools:
            pools = []
            self.address_pools_by_network_id[network.id] = pools
        pools.append(addrpool)

    def _create_test_route(self, interface, gateway, family=4, network='10.10.10.0', prefix=24):
        route = dbutils.create_test_route(
            interface_id=interface.id,
            gateway=gateway,
            family=family,
            network=network,
            prefix=prefix,
        )

        return route

    def _create_test_datanetwork(self, name, network_type):
        datanetwork = dbutils.create_test_datanetwork(name=name, network_type=network_type)
        self.datanetworks.append(datanetwork)
        return datanetwork

    def _create_test_address_pool(self, name, subnet, ranges=None, append=True,
                                  link_addresses=False):
        if not ranges:
            ranges = [(str(subnet[2]), str(subnet[-2]))]
        base_address = netaddr.IPAddress(subnet[1])
        gateway_address = None
        floating_address = None
        controller0_address = None
        controller1_address = None
        if link_addresses:
            gateway_address = base_address
            floating_address = base_address + 1
            controller0_address = base_address + 2
            controller1_address = base_address + 3

        pool = dbutils.create_test_address_pool(
            name=name,
            network=str(subnet.network),
            family=subnet.version,
            prefix=subnet.prefixlen,
            ranges=ranges,
            gateway_address=str(gateway_address),
            floating_address=str(floating_address),
            controller0_address=str(controller0_address),
            controller1_address=str(controller1_address))
        if append:
            self.address_pools.append(pool)
        return pool

    def _create_test_networks(self):

        self._create_test_network('pxeboot',
                                  constants.NETWORK_TYPE_PXEBOOT,
                                  self.pxeboot_subnets,
                                  link_addresses=True)

        self._create_test_network('management',
                                  constants.NETWORK_TYPE_MGMT,
                                  self.mgmt_subnets,
                                  link_addresses=True)

        self._create_test_network('oam',
                                  constants.NETWORK_TYPE_OAM,
                                  self.oam_subnets,
                                  link_addresses=True)

        self._create_test_network('cluster-host',
                                  constants.NETWORK_TYPE_CLUSTER_HOST,
                                  self.cluster_host_subnets,
                                  link_addresses=True)

        self._create_test_network('cluster-pod',
                                  constants.NETWORK_TYPE_CLUSTER_POD,
                                  self.cluster_pod_subnets)

        self._create_test_network('cluster-service',
                                  constants.NETWORK_TYPE_CLUSTER_SERVICE,
                                  self.cluster_service_subnets)

        self._create_test_network('storage',
                                  constants.NETWORK_TYPE_STORAGE,
                                  self.storage_subnets,
                                  link_addresses=True)

        self._create_test_network('admin',
                                  constants.NETWORK_TYPE_ADMIN,
                                  self.admin_subnets,
                                  link_addresses=True)

        self._create_test_network('system-controller',
                                  constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
                                  self.system_controller_subnets)

        self._create_test_network('system-controller-oam',
                                  constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM,
                                  self.system_controller_oam_subnets)

    def _create_test_datanetworks(self):

        self._create_test_datanetwork('data0',
                                      constants.DATANETWORK_TYPE_VLAN)

        self._create_test_datanetwork('data1',
                                      constants.DATANETWORK_TYPE_VLAN)

    def _add_address_to_index(self, address):
        self.addresses_by_id[address.id] = address

    def _create_test_address(self, **kwargs):
        address = dbutils.create_test_address(**kwargs)
        self._add_address_to_index(address)
        return address

    def _create_test_addresses(self, hostnames, subnets, network_type,
                               start=1, stop=None):
        addresses = []
        for subnet in subnets:
            ips = itertools.islice(subnet, start, stop)
            for name in hostnames:
                address = self._create_test_address(
                            name=utils.format_address_name(name, network_type),
                            family=subnet.version,
                            prefix=subnet.prefixlen,
                            address=str(next(ips)))
                addresses.append(address)
        return addresses

    def _create_test_static_ips(self):
        hostnames = [
            constants.CONTROLLER_GATEWAY,
            constants.CONTROLLER_HOSTNAME,
            constants.CONTROLLER_0_HOSTNAME,
            constants.CONTROLLER_1_HOSTNAME
        ]

        self._create_test_addresses(
            hostnames, self.pxeboot_subnets,
            constants.NETWORK_TYPE_PXEBOOT)

        self.mgmt_addresses = self._create_test_addresses(
            hostnames, self.mgmt_subnets,
            constants.NETWORK_TYPE_MGMT)

        self._create_test_addresses(
            hostnames, self.oam_subnets,
            constants.NETWORK_TYPE_OAM)

        self._create_test_addresses(
            hostnames, self.cluster_host_subnets,
            constants.NETWORK_TYPE_CLUSTER_HOST)

        self._create_test_addresses(
            hostnames, self.storage_subnets,
            constants.NETWORK_TYPE_STORAGE)

        self._create_test_addresses(
            hostnames, self.admin_subnets,
            constants.NETWORK_TYPE_ADMIN)

        self._create_test_addresses(
            hostnames, self.system_controller_subnets,
            constants.NETWORK_TYPE_SYSTEM_CONTROLLER)

        self._create_test_addresses(
            hostnames, self.system_controller_oam_subnets,
            constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM)

    def _create_test_oam(self):
        self.oam = dbutils.create_test_oam()

    def _create_test_multicast_ips(self):

        hostnames = [
            constants.SM_MULTICAST_MGMT_IP_NAME,
            constants.PATCH_CONTROLLER_MULTICAST_MGMT_IP_NAME,
            constants.PATCH_AGENT_MULTICAST_MGMT_IP_NAME,
            constants.MTCE_MULTICAST_MGMT_IP_NAME
        ]

        self._create_test_addresses(
            hostnames, self.multicast_subnets,
            constants.NETWORK_TYPE_MULTICAST)

    def _get_all_networks(self):
        return self.networks_by_id.values()

    def _find_network_by_type(self, networktype):
        return self.networks_by_type.get(networktype, None)

    def _find_network_by_id(self, network_id):
        return self.networks_by_id.get(network_id, None)

    def _find_network_address_pools(self, network_id):
        return self.address_pools_by_network_id.get(network_id, [])

    def _find_address_by_id(self, address_id):
        return self.addresses_by_id.get(address_id, None)


@six.add_metaclass(abc.ABCMeta)
class BaseHostTestCase(BaseSystemTestCase):

    root_disk_device_node = '/dev/sda'
    root_disk_device_type = constants.DEVICE_TYPE_SSD

    def setUp(self):
        super(BaseHostTestCase, self).setUp()
        self.disks = {}

    def tearDown(self):
        super(BaseHostTestCase, self).tearDown()
        self.disks = {}

    def _create_test_host(self, personality, subfunction=None, numa_nodes=1,
                          unit=0, **kw):
        subfunctions = [personality]
        if subfunction:
            subfunctions.append(subfunction)

        if personality == constants.CONTROLLER:
            hostname = '%s-%s' % (personality, unit)
            name = utils.format_address_name(hostname, constants.NETWORK_TYPE_MGMT)
            address = dbutils.get_primary_address_by_name(name, constants.NETWORK_TYPE_MGMT)
            if address:
                mgmt_ipaddr = address.address
            else:
                mgmt_ipaddr = kw.get("mgmt_ip", "0.0.0.0")
                if 'mgmt_ip' in kw:
                    del kw['mgmt_ip']

            host = dbutils.create_test_ihost(
                uuid=uuidutils.generate_uuid(),
                personality=personality,
                hostname='%s-%s' % (personality, unit),
                mgmt_mac='03:11:22:33:44:' + str(10 + len(self.hosts)),
                mgmt_ip=mgmt_ipaddr,
                forisystemid=self.system.id,
                subfunctions=",".join(subfunctions),
                **kw
            )
        else:
            host = dbutils.create_test_ihost(
                uuid=uuidutils.generate_uuid(),
                personality=personality,
                hostname='%s-%s' % (personality, unit),
                mgmt_mac='03:11:22:33:44:' + str(10 + len(self.hosts)),
                forisystemid=self.system.id,
                subfunctions=",".join(subfunctions),
                **kw
            )

        for numa_node in range(0, numa_nodes):
            node = self.dbapi.inode_create(host.id,
                dbutils.get_test_node(numa_node=numa_node, forhostid=host.id))

            self.dbapi.imemory_create(host.id,
                dbutils.get_test_imemory(forinodeid=node.id))

        disk = self.dbapi.idisk_create(host.id,
            dbutils.get_test_idisk(device_node=self.root_disk_device_node,
                                   device_type=self.root_disk_device_type))
        self.disks[host.id] = disk

        self.hosts.append(host)

        return host

    def _get_test_host_by_hostname(self, hostname):
        return self.dbapi.ihost_get_by_hostname(hostname)

    def _create_test_host_cpus(self, host,
                               platform=0, vswitch=0, application=0,
                               threads=1):
        counts = [platform, vswitch, application]
        functions = [constants.PLATFORM_FUNCTION,
                     constants.VSWITCH_FUNCTION,
                     constants.APPLICATION_FUNCTION]

        nodes = self.dbapi.inode_get_by_ihost(host.id)
        for node in nodes:
            cpu = 0
            for count, function in zip(counts, functions):
                for _ in range(0, count):
                    for thread in range(0, threads):
                        self.dbapi.icpu_create(host.id,
                            dbutils.get_test_icpu(
                                forinodeid=node.id,
                                cpu=cpu, thread=thread,
                                allocated_function=function))
                    cpu = cpu + 1

    def _create_test_host_addresses(self, hostname):
        self._create_test_addresses(
            [hostname], self.mgmt_subnets,
            constants.NETWORK_TYPE_MGMT, start=10)
        self._create_test_addresses(
            [hostname], self.cluster_host_subnets,
            constants.NETWORK_TYPE_CLUSTER_HOST, start=10)

    def _create_test_host_platform_interface(self, host):
        network_types = [constants.NETWORK_TYPE_OAM,
                         constants.NETWORK_TYPE_MGMT,
                         constants.NETWORK_TYPE_CLUSTER_HOST,
                         constants.NETWORK_TYPE_STORAGE,
                         constants.NETWORK_TYPE_ADMIN]
        ifnames = ['oam', 'mgmt', 'cluster', 'storage', 'admin']
        index = 0
        ifaces = []
        for nt, name in zip(network_types, ifnames):
            if (host.personality == constants.WORKER and
                    nt == constants.NETWORK_TYPE_OAM):
                continue
            interface = dbutils.create_test_interface(
                ifname=name,
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                forihostid=host['id'],
                ihost_uuid=host['uuid'])
            dbutils.create_test_ethernet_port(
                name='eth%s' % index,
                host_id=host['id'],
                interface_id=interface['id'],
                pciaddr='0000:00:00.%s' % index,
                dev_id=0)
            iface = self.dbapi.iinterface_get(interface['uuid'])
            ifaces.append(iface)
            network = self.dbapi.network_get_by_type(nt)
            dbutils.create_test_interface_network(
                interface_id=iface.id,
                network_id=network.id)
            index = index + 1
        return ifaces

    def _create_test_ptp_instance(self):
        services = [constants.PTP_INSTANCE_TYPE_PTP4L,
                    constants.PTP_INSTANCE_TYPE_PHC2SYS]
        names = ['test-ptp4l', 'test-phc2sys']
        ptp_instances = []
        for svc, nm in zip(services, names):
            instance = dbutils.create_test_ptp_instance(
                name=nm, service=svc)
            ptp_instances.append(instance)
        return ptp_instances

    def _create_test_ptp_interface(self,
                                   ptp_instances):
        ptp_interfaces = []
        for ptp_instance in ptp_instances:
            name = 'test%s' % ptp_instances.index(ptp_instance)
            ptp_interface = dbutils.create_test_ptp_interface(
                name=name,
                ptp_instance_id=ptp_instance['id'],
                ptp_instance_uuid=ptp_instance['uuid'])
            ptp_interfaces.append(ptp_interface)
        return ptp_interfaces


class ControllerHostTestCase(BaseHostTestCase):

    def setUp(self):
        super(ControllerHostTestCase, self).setUp()
        self.host = self._create_test_host(constants.CONTROLLER)
        self._create_test_host_cpus(self.host, platform=16)


class ProvisionedControllerHostTestCase(BaseHostTestCase):

    def setUp(self):
        super(ProvisionedControllerHostTestCase, self).setUp()
        self.host = self._create_test_host(constants.CONTROLLER,
                                           administrative=constants.ADMIN_UNLOCKED,
                                           operational=constants.OPERATIONAL_ENABLED,
                                           availability=constants.AVAILABILITY_AVAILABLE,
                                           invprovision=constants.PROVISIONED,
                                           vim_progress_status=constants.VIM_SERVICES_ENABLED)
        self._create_test_host_cpus(self.host, platform=16)


class WorkerHostTestCase(BaseHostTestCase):

    def setUp(self):
        super(WorkerHostTestCase, self).setUp()
        self.host = self._create_test_host(constants.WORKER)
        self._create_test_host_cpus(self.host, platform=1, vswitch=2, application=12)
        self._create_test_host_addresses(self.host.hostname)


class StorageHostTestCase(BaseHostTestCase):

    def setUp(self):
        super(StorageHostTestCase, self).setUp()
        self.host = self._create_test_host(constants.STORAGE)
        self._create_test_host_cpus(self.host, platform=8)
        self._create_test_host_addresses(self.host.hostname)


class AIOHostTestCase(BaseHostTestCase):

    system_type = constants.TIS_AIO_BUILD

    def setUp(self):
        super(AIOHostTestCase, self).setUp()
        self.host = self._create_test_host(constants.CONTROLLER, constants.WORKER)
        self._create_test_host_cpus(self.host, platform=2, vswitch=2, application=11)


class ProvisionedAIOHostTestCase(BaseHostTestCase):

    system_type = constants.TIS_AIO_BUILD

    def setUp(self):
        super(ProvisionedAIOHostTestCase, self).setUp()
        self.host = self._create_test_host(constants.CONTROLLER, constants.WORKER,
                                           administrative=constants.ADMIN_UNLOCKED,
                                           operational=constants.OPERATIONAL_ENABLED,
                                           availability=constants.AVAILABILITY_AVAILABLE,
                                           vim_progress_status=constants.VIM_SERVICES_ENABLED,
                                           invprovision=constants.PROVISIONED)
        self._create_test_host_cpus(self.host, platform=2, vswitch=2, application=11)


class AIOSimplexHostTestCase(AIOHostTestCase):
    system_mode = constants.SYSTEM_MODE_SIMPLEX


class AIODuplexHostTestCase(AIOHostTestCase):
    system_mode = constants.SYSTEM_MODE_DUPLEX


class AIODuplexDirectHostTestCase(AIOHostTestCase):
    system_mode = constants.SYSTEM_MODE_DUPLEX_DIRECT


class AIODuplexSystemTestCase(AIODuplexHostTestCase):

    def setUp(self):
        super(AIODuplexSystemTestCase, self).setUp()
        self.host2 = self._create_test_host(constants.CONTROLLER,
                                            constants.WORKER,
                                            unit=1)
        self._create_test_host_cpus(self.host2, platform=2, vswitch=2,
                                    application=11)


class ProvisionedAIODuplexSystemTestCase(ProvisionedAIOHostTestCase):
    system_mode = constants.SYSTEM_MODE_DUPLEX

    def setUp(self):
        super(ProvisionedAIODuplexSystemTestCase, self).setUp()
        self.host2 = self._create_test_host(constants.CONTROLLER,
                                            constants.WORKER,
                                            unit=1,
                                            administrative=constants.ADMIN_UNLOCKED,
                                            operational=constants.OPERATIONAL_ENABLED,
                                            availability=constants.AVAILABILITY_AVAILABLE,
                                            vim_progress_status=constants.VIM_SERVICES_ENABLED,
                                            invprovision=constants.PROVISIONED)
        self._create_test_host_cpus(self.host2, platform=2, vswitch=2,
                                    application=11)


class AppTestCase(ProvisionedAIODuplexSystemTestCase):

    def _create_app(self, name, version, manifest_name, manifest_file, status, active, **kwargs):
        return dbutils.create_test_kube_app(
            name=name,
            app_version=version,
            manifest_name=manifest_name,
            manifest_file=manifest_file,
            status=status,
            active=active,
            **kwargs
        )

    def setUp(self):
        super(AppTestCase, self).setUp()

    def tearDown(self):
        super(AppTestCase, self).tearDown()


class OpenstackTestCase(AppTestCase):

    def _create_openstack_app(self):
        return self._create_app(
            name='stx-openstack',
            version='6.0',
            manifest_name='application-manifest',
            manifest_file='application-manifest.yaml',
            status='applied',
            active=True
        )

    def _create_test_host_data_interface(self, host):
        ifs_to_network = {
            'data-if0': 'data0',
            'data-if1': 'data1',
        }
        # Platform ifaces were created previously, so start from interface_id=4
        index = 4
        ifaces = []
        for ifname, datanetwork in ifs_to_network.items():
            interface = dbutils.create_test_interface(
                ifname=ifname,
                ifclass=constants.INTERFACE_CLASS_DATA,
                forihostid=host['id'],
                ihost_uuid=host['uuid'],
            )
            dbutils.create_test_ethernet_port(
                name='eth%s' % index,
                host_id=host['id'],
                interface_id=interface['id'],
                pciaddr='0000:00:00.%s' % index,
                dev_id=1)
            iface = self.dbapi.iinterface_get(interface['uuid'])
            ifaces.append(iface)
            network = self.dbapi.datanetwork_get_by_name(datanetwork)
            dbutils.create_test_interface_network(
                interface_id=iface.id,
                network_id=network.id)
            index = index + 1
        return ifaces

    def setUp(self):
        super(OpenstackTestCase, self).setUp()
        self._create_openstack_app()
        self._create_test_host_platform_interface(self.host)
        self._create_test_host_data_interface(self.host)
        self._create_test_host_platform_interface(self.host2)
        self._create_test_host_data_interface(self.host2)
        self.fake_hieradata = ""
        with open(os.path.join(os.getcwd(), "sysinv", "tests",
                               "puppet", "fake_hieradata.yaml")) as fake_data:
            self.fake_hieradata = fake_data.read()


class PlatformUpgradeTestCase(OpenstackTestCase):

    def _create_platform_upgrade(self):
        self.upgrade = dbutils.create_test_upgrade(
            state=constants.UPGRADE_STARTING
        )

    def setUp(self):
        super(PlatformUpgradeTestCase, self).setUp()
        self._create_platform_upgrade()

    def tearDown(self):
        super(PlatformUpgradeTestCase, self).tearDown()
