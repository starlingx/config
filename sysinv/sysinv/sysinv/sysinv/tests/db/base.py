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

"""Sysinv DB test base class."""

import abc
import itertools
import netaddr
import six

from sysinv.common import constants
from sysinv.common import utils

from sysinv.openstack.common import context

from sysinv.tests import base
from sysinv.tests.db import utils as dbutils


@six.add_metaclass(abc.ABCMeta)
class DbTestCase(base.TestCase):

    def setUp(self):
        super(DbTestCase, self).setUp()
        self.admin_context = context.get_admin_context()


class BaseIPv4Mixin(object):

    pxeboot_subnet = netaddr.IPNetwork('192.168.202.0/24')
    mgmt_subnet = netaddr.IPNetwork('192.168.204.0/24')
    oam_subnet = netaddr.IPNetwork('10.10.10.0/24')
    cluster_host_subnet = netaddr.IPNetwork('192.168.206.0/24')
    cluster_pod_subnet = netaddr.IPNetwork('172.16.0.0/16')
    cluster_service_subnet = netaddr.IPNetwork('10.96.0.0/12')
    multicast_subnet = netaddr.IPNetwork('239.1.1.0/28')

    nameservers = ['8.8.8.8', '8.8.4.4']


class BaseIPv6Mixin(object):

    pxeboot_subnet = netaddr.IPNetwork('192.168.202.0/24')
    mgmt_subnet = netaddr.IPNetwork('fd01::/64')
    oam_subnet = netaddr.IPNetwork('fd00::/64')
    cluster_host_subnet = netaddr.IPNetwork('fd02::/64')
    cluster_pod_subnet = netaddr.IPNetwork('fd03::/64')
    cluster_service_subnet = netaddr.IPNetwork('fd04::/112')
    multicast_subnet = netaddr.IPNetwork('ff08::1:1:0/124')

    nameservers = ['2001:4860:4860::8888', '2001:4860:4860::8844']


@six.add_metaclass(abc.ABCMeta)
class BaseSystemTestCase(BaseIPv4Mixin, DbTestCase):
    system_type = constants.TIS_STD_BUILD
    system_mode = constants.SYSTEM_MODE_DUPLEX

    ntpservers = ['0.pool.ntp.org', '1.pool.ntp.org']

    def setUp(self):
        super(BaseSystemTestCase, self).setUp()
        self.hosts = []
        self.address_pools = []
        self.networks = []

    def _create_test_common(self):
        self._create_test_system()
        self._create_test_load()
        self._create_test_drbd()
        self._create_test_remotelogging()
        self._create_test_user()
        self._create_test_dns()
        self._create_test_ntp()
        self._create_test_ptp()
        self._create_test_networks()
        self._create_test_static_ips()
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

    def _create_test_network(self, name, nettype, subnet, ranges=None):
        if not ranges:
            ranges = [(str(subnet[2]), str(subnet[-2]))]

        pool = dbutils.create_test_address_pool(
            name=name,
            network=str(subnet.network),
            prefix=subnet.prefixlen,
            ranges=ranges)
        self.address_pools.append(pool)

        network = dbutils.create_test_network(
            type=nettype,
            address_pool_id=pool.id)

        self.networks.append(network)
        return network

    def _create_test_networks(self):

        self._create_test_network('pxeboot',
                                  constants.NETWORK_TYPE_PXEBOOT,
                                  self.pxeboot_subnet)

        self._create_test_network('management',
                                  constants.NETWORK_TYPE_MGMT,
                                  self.mgmt_subnet)

        self._create_test_network('oam',
                                  constants.NETWORK_TYPE_OAM,
                                  self.oam_subnet)

        self._create_test_network('cluster-host',
                                  constants.NETWORK_TYPE_CLUSTER_HOST,
                                  self.cluster_host_subnet)

        self._create_test_network('cluster-pod',
                                  constants.NETWORK_TYPE_CLUSTER_POD,
                                  self.cluster_pod_subnet)

        self._create_test_network('cluster-service',
                                  constants.NETWORK_TYPE_CLUSTER_SERVICE,
                                  self.cluster_service_subnet)

    def _create_test_addresses(self, hostnames, subnet, network_type,
                               start=1, stop=None):
        ips = itertools.islice(subnet, start, stop)
        for name in hostnames:
            dbutils.create_test_address(
                name=utils.format_address_name(name, network_type),
                family=subnet.version,
                prefix=subnet.prefixlen,
                address=str(next(ips)))

    def _create_test_static_ips(self):
        hostnames = [
            constants.CONTROLLER_GATEWAY,
            constants.CONTROLLER_HOSTNAME,
            constants.CONTROLLER_0_HOSTNAME,
            constants.CONTROLLER_1_HOSTNAME
        ]

        platform_hostnames = [
            constants.CONTROLLER_PLATFORM_NFS,
        ]

        self._create_test_addresses(
            hostnames, self.pxeboot_subnet,
            constants.NETWORK_TYPE_PXEBOOT)

        self._create_test_addresses(
            hostnames + platform_hostnames,
            self.mgmt_subnet,
            constants.NETWORK_TYPE_MGMT)

        self._create_test_addresses(
            hostnames, self.oam_subnet,
            constants.NETWORK_TYPE_OAM)

        self._create_test_addresses(
            hostnames, self.cluster_host_subnet,
            constants.NETWORK_TYPE_CLUSTER_HOST)

    def _create_test_multicast_ips(self):

        hostnames = [
            constants.SM_MULTICAST_MGMT_IP_NAME,
            constants.PATCH_CONTROLLER_MULTICAST_MGMT_IP_NAME,
            constants.PATCH_AGENT_MULTICAST_MGMT_IP_NAME,
            constants.MTCE_MULTICAST_MGMT_IP_NAME
        ]

        self._create_test_addresses(
            hostnames, self.pxeboot_subnet,
            constants.NETWORK_TYPE_MULTICAST)


@six.add_metaclass(abc.ABCMeta)
class BaseHostTestCase(BaseSystemTestCase):

    root_disk_device_node = '/dev/sda'
    root_disk_device_type = constants.DEVICE_TYPE_SSD

    def _create_test_host(self, personality, subfunction=None, numa_nodes=1):
        subfunctions = [personality]
        if subfunction:
            subfunctions.append(subfunction)

        host = dbutils.create_test_ihost(
            personality=personality,
            hostname='%s-0' % personality,
            forisystemid=self.system.id,
            subfunctions=",".join(subfunctions)
        )

        for numa_node in range(0, numa_nodes):
            node = self.dbapi.inode_create(host.id,
                dbutils.get_test_node(numa_node=numa_node))

            self.dbapi.imemory_create(host.id,
                dbutils.get_test_imemory(forinodeid=node.id))

        self.dbapi.idisk_create(host.id,
            dbutils.get_test_idisk(device_node=self.root_disk_device_node,
                                   device_type=self.root_disk_device_type))

        self.hosts.append(host)

        return host

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

    def _create_test_host_addresses(self, host):
        self._create_test_addresses(
            [host.hostname], self.mgmt_subnet,
            constants.NETWORK_TYPE_MGMT, start=10)


class ControllerHostTestCase(BaseHostTestCase):

    def setUp(self):
        super(ControllerHostTestCase, self).setUp()
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER)
        self._create_test_host_cpus(self.host, platform=16)


class WorkerHostTestCase(BaseHostTestCase):

    def setUp(self):
        super(WorkerHostTestCase, self).setUp()
        self._create_test_common()
        self.host = self._create_test_host(constants.WORKER)
        self._create_test_host_cpus(self.host, platform=1, vswitch=2, application=12)
        self._create_test_host_addresses(self.host)


class StorageHostTestCase(BaseHostTestCase):

    def setUp(self):
        super(StorageHostTestCase, self).setUp()
        self._create_test_common()
        self.host = self._create_test_host(constants.STORAGE)
        self._create_test_host_cpus(self.host, platform=8)
        self._create_test_host_addresses(self.host)


class AIOHostTestCase(BaseHostTestCase):

    system_mode = constants.TIS_AIO_BUILD

    def setUp(self):
        super(AIOHostTestCase, self).setUp()
        self._create_test_common()
        self.host = self._create_test_host(constants.CONTROLLER, constants.WORKER)
        self._create_test_host_cpus(self.host, platform=2, vswitch=2, application=11)


class AIOSimplexHostTestCase(AIOHostTestCase):
    system_mode = constants.SYSTEM_MODE_SIMPLEX


class AIODuplexHostTestCase(AIOHostTestCase):
    system_mode = constants.SYSTEM_MODE_DUPLEX


class AIODuplexDirectHostTestCase(AIOHostTestCase):
    system_mode = constants.SYSTEM_MODE_DUPLEX_DIRECT
