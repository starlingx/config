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

from oslo_utils import uuidutils

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
    storage_subnet = netaddr.IPNetwork('10.10.20.0/24')
    system_controller_subnet = netaddr.IPNetwork('192.168.104.0/24')
    system_controller_oam_subnet = netaddr.IPNetwork('10.10.50.0/24')

    nameservers = ['8.8.8.8', '8.8.4.4']

    # Used to test changing oam from ipv4 to ipv6
    change_family_oam_subnet = netaddr.IPNetwork('fd00::/64')


class BaseIPv6Mixin(object):

    pxeboot_subnet = netaddr.IPNetwork('192.168.202.0/24')
    mgmt_subnet = netaddr.IPNetwork('fd01::/64')
    oam_subnet = netaddr.IPNetwork('fd00::/64')
    cluster_host_subnet = netaddr.IPNetwork('fd02::/64')
    cluster_pod_subnet = netaddr.IPNetwork('fd03::/64')
    cluster_service_subnet = netaddr.IPNetwork('fd04::/112')
    multicast_subnet = netaddr.IPNetwork('ff08::1:1:0/124')
    storage_subnet = netaddr.IPNetwork('fd05::/64')
    system_controller_subnet = netaddr.IPNetwork('fd07::/64')
    system_controller_oam_subnet = netaddr.IPNetwork('fd06::/64')

    nameservers = ['2001:4860:4860::8888', '2001:4860:4860::8844']

    # Used to test changing oam from ipv6 to ipv4
    change_family_oam_subnet = netaddr.IPNetwork('10.10.10.0/24')


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
        self.networks = []
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
        self.networks = []
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
        self._create_test_networks()
        self._create_test_static_ips()
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

    def _create_test_network(self, name, network_type, subnet, ranges=None):
        address_pool_id = self._create_test_address_pool(name, subnet, ranges).id

        network = dbutils.create_test_network(
            type=network_type,
            address_pool_id=address_pool_id)

        self.networks.append(network)
        return network

    def _create_test_address_pool(self, name, subnet, ranges=None):
        if not ranges:
            ranges = [(str(subnet[2]), str(subnet[-2]))]
        pool = dbutils.create_test_address_pool(
            name=name,
            network=str(subnet.network),
            family=subnet.version,
            prefix=subnet.prefixlen,
            ranges=ranges)
        self.address_pools.append(pool)
        return pool

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

        self._create_test_network('storage',
                                  constants.NETWORK_TYPE_STORAGE,
                                  self.storage_subnet)

        self._create_test_network('system-controller',
                                  constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
                                  self.system_controller_subnet)

        self._create_test_network('system-controller-oam',
                                  constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM,
                                  self.system_controller_oam_subnet)

    def _create_test_addresses(self, hostnames, subnet, network_type,
                               start=1, stop=None):
        ips = itertools.islice(subnet, start, stop)
        addresses = []
        for name in hostnames:
            address = dbutils.create_test_address(
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

        platform_hostnames = [
            constants.CONTROLLER_PLATFORM_NFS,
        ]

        self._create_test_addresses(
            hostnames, self.pxeboot_subnet,
            constants.NETWORK_TYPE_PXEBOOT)

        self.mgmt_addresses = self._create_test_addresses(
            hostnames + platform_hostnames,
            self.mgmt_subnet,
            constants.NETWORK_TYPE_MGMT)

        self._create_test_addresses(
            hostnames, self.oam_subnet,
            constants.NETWORK_TYPE_OAM)

        self._create_test_addresses(
            hostnames, self.cluster_host_subnet,
            constants.NETWORK_TYPE_CLUSTER_HOST)

        self._create_test_addresses(
            hostnames, self.storage_subnet,
            constants.NETWORK_TYPE_STORAGE)

        self._create_test_addresses(
            hostnames, self.system_controller_subnet,
            constants.NETWORK_TYPE_SYSTEM_CONTROLLER)

        self._create_test_addresses(
            hostnames, self.system_controller_oam_subnet,
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
            hostnames, self.pxeboot_subnet,
            constants.NETWORK_TYPE_MULTICAST)


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
            address = self.dbapi.address_get_by_name(name)
            mgmt_ipaddr = address.address

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

    def _create_test_host_addresses(self, host):
        self._create_test_addresses(
            [host.hostname], self.mgmt_subnet,
            constants.NETWORK_TYPE_MGMT, start=10)

    def _create_test_host_platform_interface(self, host):
        network_types = [constants.NETWORK_TYPE_OAM,
                         constants.NETWORK_TYPE_MGMT,
                         constants.NETWORK_TYPE_CLUSTER_HOST,
                         constants.NETWORK_TYPE_STORAGE]
        ifnames = ['oam', 'mgmt', 'cluster', 'storage']
        index = 0
        ifaces = []
        for nt, name in zip(network_types, ifnames):
            if (host.personality == constants.WORKER and
                    nt == constants.NETWORK_TYPE_OAM):
                continue
            dbutils.create_test_ethernet_port(
                name='eth%s' % index,
                host_id=host['id'],
                interface_id=index,
                pciaddr='0000:00:00.%s' % index,
                dev_id=0)
            interface = dbutils.create_test_interface(
                ifname=name,
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                forihostid=host['id'],
                ihost_uuid=host['uuid'])
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
        names = [constants.PTP_INSTANCE_DEFAULT_PTP4L,
                 constants.PTP_INSTANCE_DEFAULT_PHC2SYS]
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
        self._create_test_host_addresses(self.host)


class StorageHostTestCase(BaseHostTestCase):

    def setUp(self):
        super(StorageHostTestCase, self).setUp()
        self.host = self._create_test_host(constants.STORAGE)
        self._create_test_host_cpus(self.host, platform=8)
        self._create_test_host_addresses(self.host)


class AIOHostTestCase(BaseHostTestCase):

    system_mode = constants.TIS_AIO_BUILD

    def setUp(self):
        super(AIOHostTestCase, self).setUp()
        self.host = self._create_test_host(constants.CONTROLLER, constants.WORKER)
        self._create_test_host_cpus(self.host, platform=2, vswitch=2, application=11)


class ProvisionedAIOHostTestCase(BaseHostTestCase):

    system_mode = constants.TIS_AIO_BUILD

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
