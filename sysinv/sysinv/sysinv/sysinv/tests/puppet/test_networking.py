# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid
import os
import yaml

import netaddr
from sysinv.tests.puppet import base
from sysinv.puppet import puppet
from sysinv.tests.db import base as dbbase
from sysinv.common import constants
from sysinv.tests.db import utils as dbutils
from sysinv.db import api as db_api


class NetworkingTestCaseMixin(base.PuppetTestCaseMixin):
    """ This PlatformFirewallTestCaseMixin needs to be used with a subclass
        of BaseHostTestCase
    """
    @puppet.puppet_context
    def _update_context(self):
        # interface is added as an operator by systemconfig.puppet_plugins
        self.context = self.operator.interface._create_interface_context(self.host)  # pylint: disable=no-member

        # Update the puppet context with generated interface context
        self.operator.context.update(self.context)

    def _setup_context(self):
        self.ports = []
        self.interfaces = []
        self.addresses = []
        self.routes = []
        self._setup_configuration()
        self._update_context()

    def _setup_configuration(self):
        pass

    def _create_hieradata_directory(self):
        hiera_path = os.path.join(os.environ['VIRTUAL_ENV'], 'hieradata')
        if not os.path.exists(hiera_path):
            os.mkdir(hiera_path, 0o755)
        return hiera_path

    def _get_config_filename(self, hiera_directory):
        class_name = self.__class__.__name__
        return os.path.join(hiera_directory, class_name) + ".yaml"

    def _get_network_ids_by_type(self, networktype):
        if isinstance(networktype, list):
            networktypelist = networktype
        elif networktype:
            networktypelist = [networktype]
        else:
            networktypelist = []
        networks = []
        for network_type in networktypelist:
            network = self._find_network_by_type(network_type)
            networks.append(str(network['id']))
        return networks

    def _create_ethernet_test(self, ifname=None, ifclass=None,
                              networktype=None, host_id=None, **kwargs):
        if not host_id:
            host_id = self.host.id
        interface_id = len(self.interfaces)
        if not ifname:
            ifname = (networktype or 'eth') + str(interface_id)
        if not ifclass:
            ifclass = constants.INTERFACE_CLASS_NONE
        if ifclass == constants.INTERFACE_CLASS_PLATFORM:
            networks = self._get_network_ids_by_type(networktype)
        else:
            networks = []
        interface = {'id': interface_id,
                     'uuid': str(uuid.uuid4()),
                     'forihostid': host_id,
                     'ifname': ifname,
                     'iftype': constants.INTERFACE_TYPE_ETHERNET,
                     'imac': '02:11:22:33:44:' + str(10 + interface_id),
                     'uses': [],
                     'used_by': [],
                     'ifclass': ifclass,
                     'networks': networks,
                     'networktype': networktype,
                     'imtu': 1500,
                     'sriov_numvfs': kwargs.get('sriov_numvfs', 0),
                     'sriov_vf_driver': kwargs.get('iface_sriov_vf_driver', None)}
        db_interface = dbutils.create_test_interface(**interface)
        for network in networks:
            dbutils.create_test_interface_network_assign(db_interface['id'], network)
        self.interfaces.append(db_interface)

        port_id = len(self.ports)
        port = {'id': port_id,
                'uuid': str(uuid.uuid4()),
                'name': 'eth' + str(port_id),
                'interface_id': interface_id,
                'host_id': host_id,
                'mac': interface['imac'],
                'driver': kwargs.get('driver', 'ixgbe'),
                'dpdksupport': kwargs.get('dpdksupport', True),
                'pdevice': kwargs.get('pdevice',
                                      "Ethernet Controller X710 for 10GbE SFP+ [1572]"),
                'pciaddr': kwargs.get('pciaddr',
                                      '0000:00:00.' + str(port_id + 1)),
                'dev_id': kwargs.get('dev_id', 0),
                'sriov_vf_driver': kwargs.get('port_sriov_vf_driver', None),
                'sriov_vf_pdevice_id': kwargs.get('sriov_vf_pdevice_id', None),
                'sriov_vfs_pci_address': kwargs.get('sriov_vfs_pci_address', '')}
        db_port = dbutils.create_test_ethernet_port(**port)
        self.ports.append(db_port)
        return db_port, db_interface


class NetworkingTestTestCaseControllerDualStackIPv4Primary(NetworkingTestCaseMixin,
                                                           dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(NetworkingTestTestCaseControllerDualStackIPv4Primary, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(NetworkingTestTestCaseControllerDualStackIPv4Primary, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.

        self.host.save(self.admin_context)
        super(NetworkingTestTestCaseControllerDualStackIPv4Primary, self)._update_context()

    def _setup_configuration(self):
        # Create a single port/interface for basic function testing
        print("=== _setup_configuration")
        self.host = self._create_test_host(personality=constants.CONTROLLER)

        _, c0_oam = self._create_ethernet_test("oam0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_OAM, self.host.id)

        _, c0_mgmt = self._create_ethernet_test("mgmt0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_MGMT, self.host.id)

        _, c0_clhost = self._create_ethernet_test("cluster0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_CLUSTER_HOST, self.host.id)

        _, c0_pxe = self._create_ethernet_test("pxe0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT, self.host.id)

        self.host_c1 = self._create_test_host(personality=constants.CONTROLLER,
                                              unit=1)

        port, c1_oam = self._create_ethernet_test("oam0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_OAM, self.host_c1.id)

        port, c1_mgmt = self._create_ethernet_test("mgmt0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_MGMT, self.host_c1.id)

        port, c1_clhost = self._create_ethernet_test("cluster0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_CLUSTER_HOST, self.host_c1.id)

        port, c1_pxe = self._create_ethernet_test("pxe0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT, self.host_c1.id)

        self.create_ipv6_pools()

        # associate addresses with its interfaces
        addresses = self.dbapi.addresses_get_all()
        for addr in addresses:
            for hostname in [self.host.hostname, self.host_c1.hostname]:
                if addr.name == f"{hostname}-{constants.NETWORK_TYPE_OAM}":
                    if hostname == constants.CONTROLLER_0_HOSTNAME:
                        values = {'interface_id': c0_oam.id}
                        self.dbapi.address_update(addr.uuid, values)
                    elif hostname == constants.CONTROLLER_1_HOSTNAME:
                        values = {'interface_id': c1_oam.id}
                        self.dbapi.address_update(addr.uuid, values)
                elif addr.name == f"{hostname}-{constants.NETWORK_TYPE_MGMT}":
                    if hostname == constants.CONTROLLER_0_HOSTNAME:
                        values = {'interface_id': c0_mgmt.id}
                        self.dbapi.address_update(addr.uuid, values)
                    elif hostname == constants.CONTROLLER_1_HOSTNAME:
                        values = {'interface_id': c1_mgmt.id}
                        self.dbapi.address_update(addr.uuid, values)
                elif addr.name == f"{hostname}-{constants.NETWORK_TYPE_CLUSTER_HOST}":
                    if hostname == constants.CONTROLLER_0_HOSTNAME:
                        values = {'interface_id': c0_clhost.id}
                        self.dbapi.address_update(addr.uuid, values)
                    elif hostname == constants.CONTROLLER_1_HOSTNAME:
                        values = {'interface_id': c1_clhost.id}
                        self.dbapi.address_update(addr.uuid, values)
                elif addr.name == f"{hostname}-{constants.NETWORK_TYPE_PXEBOOT}":
                    if hostname == constants.CONTROLLER_0_HOSTNAME:
                        values = {'interface_id': c0_pxe.id}
                        self.dbapi.address_update(addr.uuid, values)
                    elif hostname == constants.CONTROLLER_1_HOSTNAME:
                        values = {'interface_id': c1_pxe.id}
                        self.dbapi.address_update(addr.uuid, values)

        # associate addresses with its pools
        for net_type in [constants.NETWORK_TYPE_OAM,
                         constants.NETWORK_TYPE_MGMT,
                         constants.NETWORK_TYPE_CLUSTER_HOST,
                         constants.NETWORK_TYPE_PXEBOOT]:
            net = self.dbapi.network_get_by_type(net_type)
            net_pools = self.dbapi.network_addrpool_get_by_network_id(net.id)
            for net_pool in net_pools:
                address_pool = self.dbapi.address_pool_get(net_pool.address_pool_uuid)
                addresses = self.dbapi.addresses_get_all()
                for addr in addresses:
                    if (addr.name.endswith(f"-{net_type}")) \
                            and (addr.family == address_pool.family):
                                values = {'address_pool_id': address_pool.id}
                                self.dbapi.address_update(addr.uuid, values)

    def create_ipv6_pools(self):
        to_add = [
            (constants.NETWORK_TYPE_MGMT, (netaddr.IPNetwork('fd01::/64'),
                                           'management-ipv6')),
            (constants.NETWORK_TYPE_OAM, (netaddr.IPNetwork('fd00::/64'),
                                          'oam-ipv6')),
            (constants.NETWORK_TYPE_ADMIN, (netaddr.IPNetwork('fd09::/64'),
                                            'admin-ipv6')),
            (constants.NETWORK_TYPE_CLUSTER_HOST, (netaddr.IPNetwork('fd03::/64'),
                                                   'cluster-host-ipv6')),
            (constants.NETWORK_TYPE_CLUSTER_POD, (netaddr.IPNetwork('fd03::/64'),
                                                  'cluster-pod-ipv6')),
            (constants.NETWORK_TYPE_CLUSTER_SERVICE, (netaddr.IPNetwork('fd04::/112'),
                                                      'cluster-service-ipv6')),
            (constants.NETWORK_TYPE_STORAGE, (netaddr.IPNetwork('fd05::/64'),
                                              'storage-ipv6'))
        ]

        hosts = [constants.CONTROLLER_HOSTNAME,
                 constants.CONTROLLER_0_HOSTNAME,
                 constants.CONTROLLER_1_HOSTNAME]

        for cfgdata in to_add:
            net = self.dbapi.network_get_by_type(cfgdata[0])
            pool = self._create_test_address_pool(name=cfgdata[1][1],
                                                  subnet=cfgdata[1][0])
            network_addrpool = dbutils.create_test_network_addrpool(address_pool_id=pool.id,
                                                                    network_id=net.id)
            self._create_test_addresses(hostnames=hosts, subnets=[cfgdata[1][0]],
                                        network_type=cfgdata[0], start=2)
            if cfgdata[0] in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_OAM]:
                self._create_test_addresses(hostnames=[constants.CONTROLLER_GATEWAY],
                                            subnets=[cfgdata[1][0]],
                                            network_type=cfgdata[0], start=1, stop=2)
            self.network_addrpools.append(network_addrpool)

    def test_generate_networking_host_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.networking.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)
        print(config_filename)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        for family in ['ipv4', 'ipv6']:
            for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST,
                             constants.NETWORK_TYPE_PXEBOOT, constants.NETWORK_TYPE_OAM]:
                type = net_type.replace('-', '_')
                for field in ["interface_address"]:
                    test_key = f'platform::network::{type}::{family}::params::interface_address'
                    if net_type == constants.NETWORK_TYPE_PXEBOOT and family == 'ipv6':
                        # there are no ipv6 allocations for pxe
                        self.assertNotIn(test_key, hiera_data.keys())
                    else:
                        self.assertIn(test_key, hiera_data.keys())

        for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST,
                         constants.NETWORK_TYPE_PXEBOOT, constants.NETWORK_TYPE_OAM]:
            for field in ["interface_address", "interface_devices", "interface_name", "mtu"]:
                test_key = f'platform::network::{type}::params::{field}'
                self.assertIn(test_key, hiera_data.keys())

        # ipv4 is the primary, chack the addresses match
        for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST,
                         constants.NETWORK_TYPE_PXEBOOT, constants.NETWORK_TYPE_OAM]:
            self.assertEqual(hiera_data[f'platform::network::{type}::params::interface_address'],
                             hiera_data[f'platform::network::{type}::ipv4::params::interface_address'])

    def test_generate_networking_system_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.networking.get_system_config()  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)
        print(config_filename)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        for family in ['ipv4', 'ipv6']:
            for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_ADMIN,
                            constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_PXEBOOT,
                            constants.NETWORK_TYPE_STORAGE, constants.NETWORK_TYPE_OAM]:
                type = net_type.replace('-', '_')
                for field in ["controller0_address", "controller1_address", "controller_address",
                              "controller_address_url", "subnet_end", "subnet_netmask", "subnet_network",
                              "subnet_network_url", "subnet_prefixlen", "subnet_start", "subnet_version"]:
                    test_key = f'platform::network::{type}::{family}::params::{field}'
                    if net_type == constants.NETWORK_TYPE_PXEBOOT and family == 'ipv6':
                        # there are no ipv6 allocations for pxe
                        self.assertNotIn(test_key, hiera_data.keys())
                    else:
                        self.assertIn(test_key, hiera_data.keys())

        # check the primary pool (no family indication) presence
        for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_ADMIN,
                         constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_PXEBOOT,
                         constants.NETWORK_TYPE_STORAGE, constants.NETWORK_TYPE_OAM]:
            for field in ["controller0_address", "controller1_address", "controller_address",
                          "controller_address_url", "subnet_end", "subnet_netmask", "subnet_network",
                          "subnet_network_url", "subnet_prefixlen", "subnet_start", "subnet_version"]:
                test_key = f'platform::network::{type}::params::{field}'
                self.assertIn(test_key, hiera_data.keys())

        # check if the the primary pool subnet_version is with the correct value
        for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_ADMIN,
                         constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_PXEBOOT,
                         constants.NETWORK_TYPE_STORAGE, constants.NETWORK_TYPE_OAM]:
            for field in ["subnet_version"]:
                test_key = f'platform::network::{type}::params::{field}'
                self.assertEqual(constants.IPV4_FAMILY, hiera_data[test_key])


class NetworkingTestTestCaseControllerDualStackIPv6Primary(NetworkingTestCaseMixin,
                                                           dbbase.BaseIPv6Mixin,
                                                           dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(NetworkingTestTestCaseControllerDualStackIPv6Primary, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(NetworkingTestTestCaseControllerDualStackIPv6Primary, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.

        self.host.save(self.admin_context)
        super(NetworkingTestTestCaseControllerDualStackIPv6Primary, self)._update_context()

    def create_ipv4_pools(self):

        to_add = [
            (constants.NETWORK_TYPE_MGMT, (netaddr.IPNetwork('192.168.204.0/24'),
                                           'management-ipv4')),
            (constants.NETWORK_TYPE_OAM, (netaddr.IPNetwork('10.10.10.0/24'),
                                          'oam-ipv4')),
            (constants.NETWORK_TYPE_ADMIN, (netaddr.IPNetwork('10.10.30.0/24'),
                                            'admin-ipv4')),
            (constants.NETWORK_TYPE_CLUSTER_HOST, (netaddr.IPNetwork('192.168.206.0/24'),
                                                   'cluster-host-ipv4')),
            (constants.NETWORK_TYPE_CLUSTER_POD, (netaddr.IPNetwork('172.16.0.0/16'),
                                                  'cluster-pod-ipv4')),
            (constants.NETWORK_TYPE_CLUSTER_SERVICE, (netaddr.IPNetwork('10.96.0.0/12'),
                                                      'cluster-service-ipv4')),
            (constants.NETWORK_TYPE_STORAGE, (netaddr.IPNetwork('10.10.20.0/24'),
                                              'storage-ipv4'))
        ]

        hosts = [constants.CONTROLLER_HOSTNAME,
                 constants.CONTROLLER_0_HOSTNAME,
                 constants.CONTROLLER_1_HOSTNAME]

        for cfgdata in to_add:
            net = self.dbapi.network_get_by_type(cfgdata[0])
            pool = self._create_test_address_pool(name=cfgdata[1][1],
                                                  subnet=cfgdata[1][0])
            network_addrpool = dbutils.create_test_network_addrpool(address_pool_id=pool.id,
                                                                    network_id=net.id)
            self._create_test_addresses(hostnames=hosts, subnets=[cfgdata[1][0]],
                                        network_type=cfgdata[0], start=2)
            if cfgdata[0] in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_OAM]:
                self._create_test_addresses(hostnames=[constants.CONTROLLER_GATEWAY],
                                            subnets=[cfgdata[1][0]],
                                            network_type=cfgdata[0], start=1, stop=2)
            self.network_addrpools.append(network_addrpool)

    def _setup_configuration(self):
        self.host = self._create_test_host(personality=constants.CONTROLLER)

        _, c0_oam = self._create_ethernet_test("oam0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_OAM, self.host.id)

        _, c0_mgmt = self._create_ethernet_test("mgmt0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_MGMT, self.host.id)

        _, c0_clhost = self._create_ethernet_test("cluster0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_CLUSTER_HOST, self.host.id)

        _, c0_pxe = self._create_ethernet_test("pxe0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT, self.host.id)

        self.host_c1 = self._create_test_host(personality=constants.CONTROLLER,
                                              unit=1)

        _, c1_oam = self._create_ethernet_test("oam0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_OAM, self.host_c1.id)

        _, c1_mgmt = self._create_ethernet_test("mgmt0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_MGMT, self.host_c1.id)

        _, c1_clhost = self._create_ethernet_test("cluster0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_CLUSTER_HOST, self.host_c1.id)

        _, c1_pxe = self._create_ethernet_test("pxe0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT, self.host_c1.id)

        self.create_ipv4_pools()

        # associate addresses with its interfaces
        addresses = self.dbapi.addresses_get_all()
        for addr in addresses:
            for hostname in [self.host.hostname, self.host_c1.hostname]:
                if addr.name == f"{hostname}-{constants.NETWORK_TYPE_OAM}":
                    if hostname == constants.CONTROLLER_0_HOSTNAME:
                        values = {'interface_id': c0_oam.id}
                        self.dbapi.address_update(addr.uuid, values)
                    elif hostname == constants.CONTROLLER_1_HOSTNAME:
                        values = {'interface_id': c1_oam.id}
                        self.dbapi.address_update(addr.uuid, values)
                elif addr.name == f"{hostname}-{constants.NETWORK_TYPE_MGMT}":
                    if hostname == constants.CONTROLLER_0_HOSTNAME:
                        values = {'interface_id': c0_mgmt.id}
                        self.dbapi.address_update(addr.uuid, values)
                    elif hostname == constants.CONTROLLER_1_HOSTNAME:
                        values = {'interface_id': c1_mgmt.id}
                        self.dbapi.address_update(addr.uuid, values)
                elif addr.name == f"{hostname}-{constants.NETWORK_TYPE_CLUSTER_HOST}":
                    if hostname == constants.CONTROLLER_0_HOSTNAME:
                        values = {'interface_id': c0_clhost.id}
                        self.dbapi.address_update(addr.uuid, values)
                    elif hostname == constants.CONTROLLER_1_HOSTNAME:
                        values = {'interface_id': c1_clhost.id}
                        self.dbapi.address_update(addr.uuid, values)
                elif addr.name == f"{hostname}-{constants.NETWORK_TYPE_PXEBOOT}":
                    if hostname == constants.CONTROLLER_0_HOSTNAME:
                        values = {'interface_id': c0_pxe.id}
                        self.dbapi.address_update(addr.uuid, values)
                    elif hostname == constants.CONTROLLER_1_HOSTNAME:
                        values = {'interface_id': c1_pxe.id}
                        self.dbapi.address_update(addr.uuid, values)

        # associate addresses with its pools
        for net_type in [constants.NETWORK_TYPE_OAM,
                         constants.NETWORK_TYPE_MGMT,
                         constants.NETWORK_TYPE_CLUSTER_HOST,
                         constants.NETWORK_TYPE_PXEBOOT]:
            net = self.dbapi.network_get_by_type(net_type)
            net_pools = self.dbapi.network_addrpool_get_by_network_id(net.id)
            for net_pool in net_pools:
                address_pool = self.dbapi.address_pool_get(net_pool.address_pool_uuid)
                addresses = self.dbapi.addresses_get_all()
                for addr in addresses:
                    if (addr.name.endswith(f"-{net_type}")) \
                            and (addr.family == address_pool.family):
                                values = {'address_pool_id': address_pool.id}
                                self.dbapi.address_update(addr.uuid, values)

    def test_generate_networking_system_config(self):

        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.networking.get_system_config()  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)
        print(config_filename)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        for family in ['ipv4', 'ipv6']:
            for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_ADMIN,
                            constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_PXEBOOT,
                            constants.NETWORK_TYPE_STORAGE, constants.NETWORK_TYPE_OAM]:
                type = net_type.replace('-', '_')
                for field in ["controller0_address", "controller1_address", "controller_address",
                              "controller_address_url", "subnet_end", "subnet_netmask", "subnet_network",
                              "subnet_network_url", "subnet_prefixlen", "subnet_start", "subnet_version"]:
                    test_key = f'platform::network::{type}::{family}::params::{field}'
                    if net_type == constants.NETWORK_TYPE_PXEBOOT and family == 'ipv6':
                        # there are no ipv6 allocations for pxe
                        self.assertNotIn(test_key, hiera_data.keys())
                    else:
                        self.assertIn(test_key, hiera_data.keys())

        # check the primary pool (no family indication) presence
        for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_ADMIN,
                         constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_PXEBOOT,
                         constants.NETWORK_TYPE_STORAGE, constants.NETWORK_TYPE_OAM]:
            for field in ["controller0_address", "controller1_address", "controller_address",
                          "controller_address_url", "subnet_end", "subnet_netmask", "subnet_network",
                          "subnet_network_url", "subnet_prefixlen", "subnet_start", "subnet_version"]:
                test_key = f'platform::network::{type}::params::{field}'
                self.assertIn(test_key, hiera_data.keys())

        # check if the the primary pool subnet_version is with the correct value
        for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_ADMIN,
                         constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_PXEBOOT,
                         constants.NETWORK_TYPE_STORAGE, constants.NETWORK_TYPE_OAM]:
            for field in ["subnet_version"]:
                test_key = f'platform::network::{type}::params::{field}'
                self.assertEqual(constants.IPV6_FAMILY, hiera_data[test_key])

    def test_generate_networking_system_config_no_net_pool_object(self):
        """This test aims to validate if a system can operate without network-addrpool
           objects since this can happen if an upgrade is executed and the data-migration
           for the diual-stack feature is not implemented yet;
        """

        net_pools = self.dbapi.network_addrpool_get_all()
        for net_pool in net_pools:
            self.dbapi.network_addrpool_destroy(net_pool.uuid)

        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.networking.get_system_config()  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)
        print(config_filename)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        for family in ['ipv6']:
            for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_ADMIN,
                            constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_PXEBOOT,
                            constants.NETWORK_TYPE_STORAGE, constants.NETWORK_TYPE_OAM]:
                type = net_type.replace('-', '_')
                for field in ["controller0_address", "controller1_address", "controller_address",
                              "controller_address_url", "subnet_end", "subnet_netmask", "subnet_network",
                              "subnet_network_url", "subnet_prefixlen", "subnet_start", "subnet_version"]:
                    test_key = f'platform::network::{type}::{family}::params::{field}'
                    if net_type == constants.NETWORK_TYPE_PXEBOOT and family == 'ipv6':
                        # there are no ipv6 allocations for pxe
                        self.assertNotIn(test_key, hiera_data.keys())
                    else:
                        self.assertIn(test_key, hiera_data.keys())

        # check the primary pool (no family indication) presence
        for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_ADMIN,
                         constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_PXEBOOT,
                         constants.NETWORK_TYPE_STORAGE, constants.NETWORK_TYPE_OAM]:
            for field in ["controller0_address", "controller1_address", "controller_address",
                          "controller_address_url", "subnet_end", "subnet_netmask", "subnet_network",
                          "subnet_network_url", "subnet_prefixlen", "subnet_start", "subnet_version"]:
                test_key = f'platform::network::{type}::params::{field}'
                self.assertIn(test_key, hiera_data.keys())

        # check if the the primary pool subnet_version is with the correct value
        for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_ADMIN,
                         constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_PXEBOOT,
                         constants.NETWORK_TYPE_STORAGE, constants.NETWORK_TYPE_OAM]:
            for field in ["subnet_version"]:
                test_key = f'platform::network::{type}::params::{field}'
                self.assertEqual(constants.IPV6_FAMILY, hiera_data[test_key])

    def test_generate_networking_host_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.networking.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)
        print(config_filename)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        for family in ['ipv4', 'ipv6']:
            for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST,
                             constants.NETWORK_TYPE_PXEBOOT, constants.NETWORK_TYPE_OAM]:
                type = net_type.replace('-', '_')
                for field in ["interface_address"]:
                    test_key = f'platform::network::{type}::{family}::params::interface_address'
                    if net_type == constants.NETWORK_TYPE_PXEBOOT and family == 'ipv6':
                        # there are no ipv6 allocations for pxe
                        self.assertNotIn(test_key, hiera_data.keys())
                    else:
                        self.assertIn(test_key, hiera_data.keys())

        for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST,
                         constants.NETWORK_TYPE_PXEBOOT, constants.NETWORK_TYPE_OAM]:
            for field in ["interface_address", "interface_devices", "interface_name", "mtu"]:
                test_key = f'platform::network::{type}::params::{field}'
                self.assertIn(test_key, hiera_data.keys())

        # ipv6 is the primary, check the addresses match
        for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST,
                         constants.NETWORK_TYPE_PXEBOOT, constants.NETWORK_TYPE_OAM]:
            self.assertEqual(hiera_data[f'platform::network::{type}::params::interface_address'],
                             hiera_data[f'platform::network::{type}::ipv6::params::interface_address'])

    def test_generate_networking_host_config_no_net_pool_objects(self):
        """This test aims to validate if a system can operate without network-addrpool
           objects since this can happen if an upgrade is executed and the data-migration
           for the diual-stack feature is not implemented yet;
        """

        net_pools = self.dbapi.network_addrpool_get_all()
        for net_pool in net_pools:
            self.dbapi.network_addrpool_destroy(net_pool.uuid)

        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.networking.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)
        print(config_filename)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        for family in ['ipv4', 'ipv6']:
            for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST,
                             constants.NETWORK_TYPE_PXEBOOT, constants.NETWORK_TYPE_OAM]:
                type = net_type.replace('-', '_')
                for field in ["interface_address"]:
                    test_key = f'platform::network::{type}::{family}::params::interface_address'
                    if net_type == constants.NETWORK_TYPE_PXEBOOT and family == 'ipv6':
                        # there are no ipv6 allocations for pxe
                        self.assertNotIn(test_key, hiera_data.keys())
                    else:
                        self.assertIn(test_key, hiera_data.keys())

        for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST,
                         constants.NETWORK_TYPE_PXEBOOT, constants.NETWORK_TYPE_OAM]:
            for field in ["interface_address", "interface_devices", "interface_name", "mtu"]:
                test_key = f'platform::network::{type}::params::{field}'
                self.assertIn(test_key, hiera_data.keys())

        # ipv6 is the primary, check the addresses match
        for net_type in [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST,
                         constants.NETWORK_TYPE_PXEBOOT, constants.NETWORK_TYPE_OAM]:
            self.assertEqual(hiera_data[f'platform::network::{type}::params::interface_address'],
                             hiera_data[f'platform::network::{type}::ipv6::params::interface_address'])
