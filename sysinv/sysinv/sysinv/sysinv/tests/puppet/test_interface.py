# Copyright (c) 2017-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import print_function

import os
import uuid
import yaml
import mock
import netaddr
import json

from sysinv.common import utils
from sysinv.common import constants
from sysinv.puppet import interface
from sysinv.puppet import puppet
from sysinv.objects import base as objbase

from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
from sysinv.tests.puppet import base
from sysinv.db import api as db_api
from collections import defaultdict


NETWORKTYPES_WITH_V4_ADDRESSES = [constants.NETWORK_TYPE_MGMT,
                                  constants.NETWORK_TYPE_OAM,
                                  constants.NETWORK_TYPE_CLUSTER_HOST,
                                  constants.NETWORK_TYPE_PXEBOOT]

NETWORKTYPES_WITH_V6_ADDRESSES = [constants.NETWORK_TYPE_DATA]

NETWORKTYPES_WITH_V4_ROUTES = [constants.NETWORK_TYPE_DATA]

NETWORKTYPES_WITH_V6_ROUTES = [constants.NETWORK_TYPE_DATA]


class InterfaceTestCaseMixin(base.PuppetTestCaseMixin):
    """ This InterfaceTestCaseMixin needs to be used with a subclass
        of BaseHostTestCase
    """

    def assertIn(self, needle, haystack, message=''):
        """Custom assertIn that handles object comparison"""
        if isinstance(needle, objbase.SysinvObject):
            # compare objects based on unique DB identifier
            needle = needle.id
            haystack = [o.id for o in haystack]
        super(InterfaceTestCaseMixin, self).assertIn(needle, haystack, message)

    def assertEqual(self, expected, observed, message=''):
        """Custom assertEqual that handles object comparison"""
        if (isinstance(expected, objbase.SysinvObject) and
                isinstance(observed, objbase.SysinvObject)):
            expected = expected.id
            observed = observed.id
        super(InterfaceTestCaseMixin, self).assertEqual(expected, observed, message)

    def _get_network_type_list(self, networktype):
        if isinstance(networktype, list):
            networktypelist = networktype
        elif networktype:
            networktypelist = [networktype]
        else:
            networktypelist = []
        return networktypelist

    def _get_network_ids_by_type(self, networktype):
        networktypelist = self._get_network_type_list(networktype)
        networks = []
        for network_type in networktypelist:
            network = self._find_network_by_type(network_type)
            if network:
                networks.append(str(network['id']))
        return networks

    def _create_ethernet_test(self, ifname=None, ifclass=None,
                              networktype=None, hostname=None,
                              **kwargs):
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
                     'forihostid': self.host.id,
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
                     'sriov_vf_driver': kwargs.get('iface_sriov_vf_driver', None),
                     'max_tx_rate': kwargs.get('max_tx_rate', None),
                     'max_rx_rate': kwargs.get('max_rx_rate', None),
                     'ipv4_mode': kwargs.get('ipv4_mode', None),
                     'ipv6_mode': kwargs.get('ipv6_mode', None),
                     'ipv4_pool': kwargs.get('ipv4_pool', None),
                     'ipv6_pool': kwargs.get('ipv6_pool', None)}
        db_interface = dbutils.create_test_interface(**interface)
        for network in networks:
            dbutils.create_test_interface_network_assign(db_interface['id'], network)
        self.interfaces.append(db_interface)

        port_id = len(self.ports)
        port = {'id': port_id,
                'uuid': str(uuid.uuid4()),
                'name': 'eth' + str(port_id),
                'interface_id': interface_id,
                'host_id': self.host.id,
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
        if hostname:
            self._assign_addresses_to_interface(hostname, db_interface, networktype)
        db_interface.networktypelist = self._get_network_type_list(networktype)
        return db_port, db_interface

    def _create_vlan_test(self, ifname, ifclass, networktype, vlan_id,
                          lower_iface=None, hostname=None, **kwargs):
        if not lower_iface:
            lower_port, lower_iface = self._create_ethernet_test()
        if not ifname:
            ifname = 'vlan' + str(vlan_id)
        if not ifclass:
            ifclass = constants.INTERFACE_CLASS_NONE
        if ifclass == constants.INTERFACE_CLASS_PLATFORM:
            networks = self._get_network_ids_by_type(networktype)
        else:
            networks = []
        interface_id = len(self.interfaces)
        interface = {'id': interface_id,
                     'uuid': str(uuid.uuid4()),
                     'forihostid': self.host.id,
                     'ifname': ifname,
                     'iftype': constants.INTERFACE_TYPE_VLAN,
                     'vlan_id': vlan_id,
                     'imac': '02:11:22:33:44:' + str(10 + interface_id),
                     'uses': [lower_iface['ifname']],
                     'used_by': [],
                     'ifclass': ifclass,
                     'networks': networks,
                     'networktype': networktype,
                     'imtu': 1500,
                     'ipv4_mode': kwargs.get('ipv4_mode', None),
                     'ipv6_mode': kwargs.get('ipv6_mode', None),
                     'ipv4_pool': kwargs.get('ipv4_pool', None),
                     'ipv6_pool': kwargs.get('ipv6_pool', None),
                     'max_tx_rate': kwargs.get('max_tx_rate', None),
                     'max_rx_rate': kwargs.get('max_rx_rate', None)}
        lower_iface['used_by'].append(interface['ifname'])
        db_interface = dbutils.create_test_interface(**interface)
        for network in networks:
            dbutils.create_test_interface_network_assign(db_interface['id'], network)
        self.interfaces.append(db_interface)
        if hostname:
            self._assign_addresses_to_interface(hostname, db_interface, networktype)
        db_interface.networktypelist = self._get_network_type_list(networktype)
        return db_interface

    def _create_bond_test(self, ifname, ifclass=None, networktype=None, hostname=None, **kwargs):
        iface1 = kwargs.get('iface1', None)
        if not iface1:
            port1, iface1 = self._create_ethernet_test()
        iface2 = kwargs.get('iface2', None)
        if not iface2:
            port2, iface2 = self._create_ethernet_test()
        interface_id = len(self.interfaces)
        if not ifname:
            ifname = 'bond' + str(interface_id)
        if not ifclass:
            ifclass = constants.INTERFACE_CLASS_NONE
        if ifclass == constants.INTERFACE_CLASS_PLATFORM:
            networks = self._get_network_ids_by_type(networktype)
        else:
            networks = []
        interface = {'id': interface_id,
                     'uuid': str(uuid.uuid4()),
                     'forihostid': self.host.id,
                     'ifname': ifname,
                     'iftype': constants.INTERFACE_TYPE_AE,
                     'imac': '02:11:22:33:44:' + str(10 + interface_id),
                     'uses': [iface1['ifname'], iface2['ifname']],
                     'used_by': [],
                     'ifclass': ifclass,
                     'networks': networks,
                     'networktype': networktype,
                     'imtu': 1500,
                     'txhashpolicy': 'layer2',
                     'primary_reselect': kwargs.get('primary_reselect', None),
                     'ipv4_mode': kwargs.get('ipv4_mode', None),
                     'ipv6_mode': kwargs.get('ipv6_mode', None),
                     'ipv4_pool': kwargs.get('ipv4_pool', None),
                     'ipv6_pool': kwargs.get('ipv6_pool', None),
                     'max_tx_rate': kwargs.get('max_tx_rate', None),
                     'max_rx_rate': kwargs.get('max_rx_rate', None)}

        aemode = kwargs.get('aemode', None)
        if aemode:
            interface['aemode'] = aemode
        else:
            lacp_types = [constants.NETWORK_TYPE_MGMT,
                        constants.NETWORK_TYPE_PXEBOOT]
            if networktype in lacp_types:
                interface['aemode'] = '802.3ad'
            else:
                interface['aemode'] = 'balanced'

        iface1['used_by'].append(interface['ifname'])
        iface2['used_by'].append(interface['ifname'])
        db_interface = dbutils.create_test_interface(**interface)
        for network in networks:
            dbutils.create_test_interface_network_assign(db_interface['id'], network)
        self.interfaces.append(db_interface)
        if hostname:
            self._assign_addresses_to_interface(hostname, db_interface, networktype)
        db_interface.networktypelist = self._get_network_type_list(networktype)
        return db_interface

    def _create_vf_test(self, ifname, num_vfs, vf_driver=None,
                        lower_iface=None, max_tx_rate=None):
        if not lower_iface:
            lower_port, lower_iface = self._create_ethernet_test(
                'sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
                constants.NETWORK_TYPE_PCI_SRIOV)
        if not ifname:
            ifname = 'vf-' + lower_iface['ifname']
        if not num_vfs:
            num_vfs = 1

        networks = []

        ifclass = constants.INTERFACE_CLASS_PCI_SRIOV
        interface_id = len(self.interfaces)
        interface = {'id': interface_id,
                     'uuid': str(uuid.uuid4()),
                     'forihostid': self.host.id,
                     'ifname': ifname,
                     'iftype': constants.INTERFACE_TYPE_VF,
                     'imac': '02:11:22:33:44:' + str(10 + interface_id),
                     'uses': [lower_iface['ifname']],
                     'used_by': [],
                     'ifclass': ifclass,
                     'networks': networks,
                     'networktype': constants.NETWORK_TYPE_PCI_SRIOV,
                     'imtu': 1500,
                     'sriov_numvfs': num_vfs,
                     'sriov_vf_driver': vf_driver,
                     'max_tx_rate': max_tx_rate}
        lower_iface['used_by'].append(interface['ifname'])
        db_interface = dbutils.create_test_interface(**interface)
        self.interfaces.append(db_interface)
        return db_interface

    def _create_test_host(self, personality, subfunction=None):
        subfunctions = [personality]
        if subfunction:
            subfunctions.append(subfunction)

        host = {'personality': personality,
                'hostname': '%s-0' % personality,
                'forisystemid': self.system.id,
                'subfunctions': ",".join(subfunctions)}

        return dbutils.create_test_ihost(**host)

    def _create_address_for_interface(self, iface, networktype=None, family=None):

        if not networktype:
            if len(iface.networktypelist) > 0:
                networktype = iface.networktypelist[0]

        network = None
        if networktype:
            network = self._find_network_by_type(networktype)

        addrpool = None
        if network:
            addrpools = self._find_network_address_pools(network.id)
            if family:
                for pool in addrpools:
                    if pool.family == family:
                        addrpool = pool
                        break
            elif len(addrpools) > 0:
                addrpool = addrpools[0]

        if addrpool:
            next_address = netaddr.IPAddress(addrpool.network) + 10
            address_fields = {'interface_id': iface['id'],
                              'address_pool_id': addrpool.id,
                              'family': addrpool.family,
                              'prefix': addrpool.prefix,
                              'address': str(next_address)}
        else:
            if family == constants.IPV6_FAMILY:
                address_fields = {'family': constants.IPV6_FAMILY,
                                  'prefix': 64,
                                  'address': 'fd08::a'}
            else:
                address_fields = {'family': constants.IPV4_FAMILY,
                                  'prefix': 24,
                                  'address': '192.168.1.10'}
            address_fields['interface_id'] = iface['id']

        address = dbutils.create_test_address(**address_fields)
        self.addresses.append(address)

        return network, address

    def _assign_addresses_to_pool(self):

        dbapi = db_api.get_instance()

        network_names = {
            'oam': 'oam',
            'mgmt': 'management',
            'cluster-host': 'cluster-host',
            'pxeboot': 'pxeboot',
            'admin': 'admin'
        }

        addrpool_index = {}
        addrpools = dbapi.address_pools_get_all()
        for addrpool in addrpools:
            if addrpool.name:
                addrpool_index[addrpool.name] = (
                    addrpool,
                    netaddr.IPNetwork(str(addrpool.network) + '/' + str(addrpool.prefix))
                )

        addresses = dbapi.addresses_get_all()
        for addr in addresses:
            if not addr.name:
                continue
            for network_type, network_name in network_names.items():
                if addr.name.endswith("-" + network_type):
                    pool_name = f"{network_name}-ipv{addr.family}"
                    addrpool = addrpool_index.get(pool_name, None)
                    if not addrpool:
                        break
                    ipaddr = netaddr.IPAddress(addr.address)
                    if ipaddr not in addrpool[1]:
                        break
                    dbapi.address_update(addr.uuid, {'address_pool_id': addrpool[0].id})
                    break

    def _assign_addresses_to_interface(self, hostname, interface, networktypes):
        if isinstance(networktypes, list):
            networktypelist = networktypes
        elif networktypes:
            networktypelist = [networktypes]
        else:
            networktypelist = []

        dbapi = db_api.get_instance()

        addresses = dbapi.addresses_get_all()

        name_index = {
            hostname + "-oam": constants.NETWORK_TYPE_OAM,
            hostname + "-mgmt": constants.NETWORK_TYPE_MGMT,
            hostname + "-cluster-host": constants.NETWORK_TYPE_CLUSTER_HOST,
            hostname + "-pxeboot": constants.NETWORK_TYPE_PXEBOOT,
            hostname + "-admin": constants.NETWORK_TYPE_ADMIN,
        }

        for network_type in networktypelist:
            for addr in addresses:
                if not (addr.name):
                    continue
                try:
                    if (name_index.get(addr.name, None) == network_type
                            or (addr.ifname == interface.ifname and addr.interface_id is None)):
                        dbapi.address_update(addr.uuid, {'interface_id': interface.id})
                except Exception as ex:
                    print(f"Failed to link address {addr.name} to interface "
                          f"{interface.ifname}: {ex}")

    @puppet.puppet_context
    def _update_context(self):
        # interface is added as an operator by systemconfig.puppet_plugins
        self.context = \
            self.operator.interface._create_interface_context(self.host)  # pylint: disable=no-member

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


class InterfaceTestCase1(InterfaceTestCaseMixin, dbbase.BaseHostTestCase):

    def setUp(self):
        super(InterfaceTestCase1, self).setUp()
        self._setup_context()

    def _setup_configuration(self):
        self.host = self._create_test_host(constants.CONTROLLER)
        self.port, self.iface = self._create_ethernet_test(
            "mgmt0", constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_MGMT)
        self.mgmt_gateway_address = self.mgmt_subnet[1]
        self.oam_gateway_address = self.oam_subnet[1]

    def _update_context(self):
        super(InterfaceTestCase1, self)._update_context()

    def test_get_port_interface_id_index(self):
        index = self.operator.interface._get_port_interface_id_index(self.host)  # pylint: disable=no-member
        for port in self.ports:
            self.assertTrue(port['interface_id'] in index)
            self.assertEqual(index[port['interface_id']], port)

    def test_get_port_pciaddr_index(self):
        index = self.operator.interface._get_port_pciaddr_index(self.host)   # pylint: disable=no-member
        for port in self.ports:
            self.assertTrue(port['pciaddr'] in index)
            self.assertIn(port, index[port['pciaddr']])

    def test_get_network_type_index(self):
        index = self.operator.interface._get_network_type_index()  # pylint: disable=no-member
        for network in self._get_all_networks():
            self.assertTrue(network['type'] in index)
            self.assertEqual(index[network['type']], network)

    def test_get_address_interface_name_index(self):
        index = self.operator.interface._get_address_interface_name_index(self.host)  # pylint: disable=no-member
        for address in self.addresses:
            self.assertTrue(address['ifname'] in index)
            self.assertIn(address, index[address['ifname']])

    def test_get_routes_interface_name_index(self):
        index = self.operator.interface._get_routes_interface_name_index(self.host)  # pylint: disable=no-member
        for route in self.routes:
            self.assertTrue(route['ifname'] in index)
            self.assertIn(route, index[route['ifname']])

    def test_get_interface_mtu(self):
        value = interface.get_interface_mtu(self.context, self.iface)
        self.assertEqual(value, self.iface['imtu'])

    def test_get_interface_port(self):
        value = interface.get_interface_port(self.context, self.iface)
        self.assertEqual(value, self.port)

    def test_get_interface_port_name(self):
        value = interface.get_interface_port_name(self.context, self.iface)
        self.assertEqual(value, self.port['name'])

    def test_get_interface_os_ifname_ethernet(self):
        value = interface.get_interface_os_ifname(self.context, self.iface)
        self.assertEqual(value, self.port['name'])

    def test_get_interface_os_ifname_bond(self):
        self.iface['iftype'] = constants.INTERFACE_TYPE_AE
        value = interface.get_interface_os_ifname(self.context, self.iface)
        self.assertEqual(value, self.iface['ifname'])

    def _get_route_config(self, name='default', ensure='present',
                          gateway='1.2.3.1', interface='eth0',
                          netmask='0.0.0.0', network='default',
                          metric=1):
        config = f"{network} {netmask} {gateway} {interface} metric {metric}\n"
        return config

    def test_get_route_config_non_default(self):
        route = {'network': '1.2.3.0',
                 'prefix': 24,
                 'gateway': '1.2.3.1',
                 'metric': 20}
        config = interface.get_route_config(route, "eth0")
        expected = self._get_route_config(
            name='1.2.3.0/24', network='1.2.3.0',
            netmask='255.255.255.0', metric=20)
        self.assertEqual(expected, config)

    def test_get_route_config_default(self):
        route = {'network': '0.0.0.0',
                 'prefix': 0,
                 'gateway': '1.2.3.1',
                 'metric': 1}
        config = interface.get_route_config(route, "eth0")
        expected = self._get_route_config()
        self.assertEqual(expected, config)

    def test_is_an_n3000_i40_device_false(self):
        self.assertFalse(
            interface.is_an_n3000_i40_device(self.context, self.iface))

    def test_find_sriov_interfaces_by_driver_none(self):
        ifaces = interface.find_sriov_interfaces_by_driver(
            self.context, constants.DRIVER_MLX_CX4)
        self.assertTrue(not ifaces)


class InterfaceTestCase2(InterfaceTestCaseMixin, dbbase.BaseHostTestCase):

    def setUp(self):
        super(InterfaceTestCase2, self).setUp()
        self._setup_context()

    def _setup_configuration(self):
        pass

    def _update_context(self):
        # skip automatic context update, context updates will be invoked individually
        # in each test function, via the self._do_update_context() method
        pass

    def _do_update_context(self):
        super(InterfaceTestCase2, self)._update_context()

    def _create_host(self, personality, subfunction=None):
        self.host = self._create_test_host(personality, subfunction)

    def _create_host_and_interface(self, ifclass, networktype, **kwargs):
        self.host = self._create_test_host(
            kwargs.get('personality', constants.CONTROLLER),
            kwargs.get('subfunction', None))
        self.port, self.iface = self._create_ethernet_test(
            kwargs.get('name', 'mgmt0'), ifclass, networktype, **kwargs)

    def _set_address_mode(self, iface, ipv4_mode=constants.IPV4_DISABLED,
                          ipv6_mode=constants.IPV6_DISABLED):
        self.dbapi.address_mode_update(iface.id,
                                       {'family': constants.IPV4_FAMILY, 'mode': ipv4_mode})
        self.dbapi.address_mode_update(iface.id,
                                       {'family': constants.IPV6_FAMILY, 'mode': ipv6_mode})
        iface.ipv4_mode = ipv4_mode
        iface.ipv6_mode = ipv6_mode

    def test_is_platform_network_type_true(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT)
        self._do_update_context()
        result = interface.is_platform_network_type(self.iface)
        self.assertTrue(result)

    def test_is_platform_network_type_false(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_DATA,
                constants.NETWORK_TYPE_DATA)
        self._do_update_context()
        result = interface.is_platform_network_type(self.iface)
        self.assertFalse(result)

    def test_is_worker_subfunction_true(self):
        self._create_host(constants.WORKER)
        self._do_update_context()
        self.assertTrue(interface.is_worker_subfunction(self.context))

    def test_is_worker_subfunction_true_cpe(self):
        self._create_host(constants.CONTROLLER, constants.WORKER)
        self._do_update_context()
        self.assertTrue(interface.is_worker_subfunction(self.context))

    def test_is_worker_subfunction_false(self):
        self._create_host(constants.STORAGE)
        self._do_update_context()
        self.assertFalse(interface.is_worker_subfunction(self.context))

    def test_is_worker_subfunction_false_cpe(self):
        self._create_host(constants.CONTROLLER)
        self._do_update_context()
        self.assertFalse(interface.is_worker_subfunction(self.context))

    def test_is_pci_interface_true(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PCI_SRIOV,
                constants.NETWORK_TYPE_PCI_SRIOV)
        self._do_update_context()
        self.assertTrue(interface.is_pci_interface(self.iface))

    def test_is_pci_interface_false(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_DATA,
                constants.NETWORK_TYPE_DATA)
        self._do_update_context()
        self.assertFalse(interface.is_pci_interface(self.iface))

    def test_get_lower_interface_vlan(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT)
        vlan = self._create_vlan_test(
            "cluster-host", constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_CLUSTER_HOST, 1, self.iface)
        self._do_update_context()
        value = interface.get_lower_interface(self.context, vlan)
        self.assertEqual(value, self.iface)

    def test_get_lower_interface_vf(self):
        self._create_host_and_interface(
            constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV,
            name='sriov1', sriov_numvfs=2)
        vf = self._create_vf_test("vf1", 1, None, lower_iface=self.iface)
        self._do_update_context()
        value = interface.get_lower_interface(self.context, vf)
        self.assertEqual(value, self.iface)

    def test_get_interface_os_ifname_vlan_over_ethernet(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT)
        vlan1 = self._create_vlan_test(
            "cluster-host", constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_CLUSTER_HOST, 1, self.iface)
        vlan2 = self._create_vlan_test(
            "testvlan", constants.INTERFACE_CLASS_NONE,
            constants.NETWORK_TYPE_CLUSTER_HOST, 1, self.iface)
        vlan3 = self._create_vlan_test(
            "vlan999", constants.INTERFACE_CLASS_NONE,
            constants.NETWORK_TYPE_CLUSTER_HOST, 1, self.iface)
        vlan4 = self._create_vlan_test(
            "testvlan.999", constants.INTERFACE_CLASS_NONE,
            constants.NETWORK_TYPE_CLUSTER_HOST, 1, self.iface)
        self._do_update_context()
        self.assertEqual(interface.get_interface_os_ifname(self.context, vlan1),
                         "vlan1")
        self.assertEqual(interface.get_interface_os_ifname(self.context, vlan2),
                         "testvlan")
        self.assertEqual(interface.get_interface_os_ifname(self.context, vlan3),
                         "vlan#999")
        self.assertEqual(interface.get_interface_os_ifname(self.context, vlan4),
                         "testvlan#999")

    def test_get_interface_os_ifname_vlan_over_bond(self):
        self._create_host(constants.CONTROLLER)
        bond = self._create_bond_test("none")
        vlan = self._create_vlan_test(
            "cluster-host", constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_CLUSTER_HOST, 1, bond)
        self._do_update_context()
        value = interface.get_interface_os_ifname(self.context, vlan)
        self.assertEqual(value, "vlan1")

    def test_get_gateway_address_oam(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_OAM)
        network, address = self._create_address_for_interface(self.iface)
        self._do_update_context()
        gateway = interface.get_gateway_address(self.context, address)
        expected = str(self.oam_subnet[1])
        self.assertEqual(gateway, expected)

    def test_get_gateway_address_mgmt(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT)
        network, address = self._create_address_for_interface(self.iface)
        self._do_update_context()
        gateway = interface.get_gateway_address(self.context, address)
        expected = str(self.mgmt_subnet[1])
        self.assertEqual(gateway, expected)

    def test_get_interface_address_method_for_none(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_NONE,
                constants.NETWORK_TYPE_NONE)
        self._do_update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_data(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_DATA,
                constants.NETWORK_TYPE_DATA)
        _, address_ipv4 = self._create_address_for_interface(
            self.iface, family=constants.IPV4_FAMILY)
        _, address_ipv6 = self._create_address_for_interface(
            self.iface, family=constants.IPV6_FAMILY)
        self._do_update_context()

        self.iface['ipv4_mode'] = constants.IPV4_DISABLED
        self.iface['ipv6_mode'] = constants.IPV6_DISABLED
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

        self.iface['ipv4_mode'] = constants.IPV4_STATIC
        self.iface['ipv6_mode'] = constants.IPV6_DISABLED
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

        self.iface['ipv4_mode'] = constants.IPV4_DISABLED
        self.iface['ipv6_mode'] = constants.IPV6_STATIC
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

        self.iface['ipv4_mode'] = constants.IPV4_STATIC
        self.iface['ipv6_mode'] = constants.IPV6_STATIC
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

        self.iface['ipv4_mode'] = constants.IPV4_DISABLED
        self.iface['ipv6_mode'] = constants.IPV6_DISABLED
        method = interface.get_interface_address_method(
            self.context, self.iface, None, address_ipv4)
        self.assertEqual(method, 'manual')

        self.iface['ipv4_mode'] = constants.IPV4_STATIC
        self.iface['ipv6_mode'] = constants.IPV6_DISABLED
        method = interface.get_interface_address_method(
            self.context, self.iface, None, address_ipv4)
        self.assertEqual(method, 'static')

        self.iface['ipv4_mode'] = constants.IPV4_DISABLED
        self.iface['ipv6_mode'] = constants.IPV6_STATIC
        method = interface.get_interface_address_method(
            self.context, self.iface, None, address_ipv4)
        self.assertEqual(method, 'manual')

        self.iface['ipv4_mode'] = constants.IPV4_STATIC
        self.iface['ipv6_mode'] = constants.IPV6_STATIC
        method = interface.get_interface_address_method(
            self.context, self.iface, None, address_ipv4)
        self.assertEqual(method, 'static')

        self.iface['ipv4_mode'] = constants.IPV4_DISABLED
        self.iface['ipv6_mode'] = constants.IPV6_DISABLED
        method = interface.get_interface_address_method(
            self.context, self.iface, None, address_ipv6)
        self.assertEqual(method, 'manual')

        self.iface['ipv4_mode'] = constants.IPV4_STATIC
        self.iface['ipv6_mode'] = constants.IPV6_DISABLED
        method = interface.get_interface_address_method(
            self.context, self.iface, None, address_ipv6)
        self.assertEqual(method, 'manual')

        self.iface['ipv4_mode'] = constants.IPV4_DISABLED
        self.iface['ipv6_mode'] = constants.IPV6_STATIC
        method = interface.get_interface_address_method(
            self.context, self.iface, None, address_ipv6)
        self.assertEqual(method, 'static')

        self.iface['ipv4_mode'] = constants.IPV4_STATIC
        self.iface['ipv6_mode'] = constants.IPV6_STATIC
        method = interface.get_interface_address_method(
            self.context, self.iface, None, address_ipv6)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_pci_sriov(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PCI_SRIOV,
                constants.NETWORK_TYPE_PCI_SRIOV)
        self._do_update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_pci_pthru(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                constants.NETWORK_TYPE_PCI_PASSTHROUGH)
        self._do_update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_pxeboot_worker(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_PXEBOOT,
                personality=constants.WORKER)
        self._do_update_context()
        network = self._find_network_by_type(constants.NETWORK_TYPE_PXEBOOT)
        method = interface.get_interface_address_method(
            self.context, self.iface, network)
        self.assertEqual(method, 'dhcp')

    def test_get_interface_address_method_for_pxeboot_storage(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_PXEBOOT,
                personality=constants.STORAGE)
        self._do_update_context()
        network = self._find_network_by_type(constants.NETWORK_TYPE_PXEBOOT)
        method = interface.get_interface_address_method(
            self.context, self.iface, network)
        self.assertEqual(method, 'dhcp')

    def test_get_interface_address_method_for_pxeboot_controller(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_PXEBOOT)
        self._do_update_context()
        network = self._find_network_by_type(constants.NETWORK_TYPE_PXEBOOT)
        method = interface.get_interface_address_method(
            self.context, self.iface, network)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_mgmt_worker(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT,
                personality=constants.WORKER)
        self._do_update_context()
        network = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        method = interface.get_interface_address_method(
            self.context, self.iface, network)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_mgmt_storage(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT,
                personality=constants.STORAGE)
        self._do_update_context()
        network = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        method = interface.get_interface_address_method(
            self.context, self.iface, network)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_mgmt_controller(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT)
        self._do_update_context()
        network = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        method = interface.get_interface_address_method(
            self.context, self.iface, network)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_cluster_host_worker(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT,
                personality=constants.WORKER)
        self._do_update_context()
        network = self._find_network_by_type(constants.NETWORK_TYPE_CLUSTER_HOST)
        method = interface.get_interface_address_method(
            self.context, self.iface, network)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_cluster_host_storage(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_CLUSTER_HOST,
                personality=constants.STORAGE)
        self._do_update_context()
        network = self._find_network_by_type(constants.NETWORK_TYPE_CLUSTER_HOST)
        method = interface.get_interface_address_method(
            self.context, self.iface, network)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_cluster_host_controller(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_CLUSTER_HOST)
        self._do_update_context()
        network = self._find_network_by_type(constants.NETWORK_TYPE_CLUSTER_HOST)
        method = interface.get_interface_address_method(
            self.context, self.iface, network)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_oam_controller(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_OAM)
        self._do_update_context()
        network = self._find_network_by_type(constants.NETWORK_TYPE_OAM)
        method = interface.get_interface_address_method(
            self.context, self.iface, network)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_platform_ipv4(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_NONE)
        network, address = self._create_address_for_interface(self.iface)
        self._set_address_mode(self.iface, ipv4_mode=constants.IPV4_STATIC)
        self._do_update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface, network, address)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_platform_ipv6(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_NONE)
        network, address = self._create_address_for_interface(
            self.iface, family=constants.IPV6_FAMILY)
        self._set_address_mode(self.iface, ipv6_mode=constants.IPV6_STATIC)
        self._do_update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface, network, address)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_platform_base(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST])
        self._do_update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_platform_invalid(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_OAM,
                personality=constants.WORKER)
        self._set_address_mode(self.iface, ipv4_mode=constants.IPV4_STATIC)
        self._do_update_context()
        network = self._find_network_by_type(constants.NETWORK_TYPE_OAM)
        method = interface.get_interface_address_method(
            self.context, self.iface, network)
        self.assertEqual(method, 'dhcp')

    def test_get_interface_traffic_classifier_for_mgmt(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT)
        self._do_update_context()
        classifier = interface.get_interface_traffic_classifier(
            self.context, self.iface)
        expected = ('%s %s %s %s > /dev/null' %
                    (constants.TRAFFIC_CONTROL_SCRIPT,
                     self.port['name'], constants.NETWORK_TYPE_MGMT,
                     constants.LINK_SPEED_10G))
        self.assertEqual(classifier, expected)

    def test_get_interface_traffic_classifier_for_cluster_host(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_CLUSTER_HOST)
        self._do_update_context()
        classifier = interface.get_interface_traffic_classifier(
            self.context, self.iface)
        self.assertIsNone(classifier)

    def test_get_interface_traffic_classifier_for_oam(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_OAM)
        self._do_update_context()
        classifier = interface.get_interface_traffic_classifier(
            self.context, self.iface)
        self.assertIsNone(classifier)

    def test_get_interface_traffic_classifier_for_none(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_NONE,
                constants.NETWORK_TYPE_NONE)
        self._do_update_context()
        classifier = interface.get_interface_traffic_classifier(
            self.context, self.iface)
        self.assertIsNone(classifier)

    def test_get_sriov_interface_device_id(self):
        self._create_host_and_interface(
            constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV,
            name='sriov1', sriov_numvfs=2)
        self._do_update_context()
        value = interface.get_sriov_interface_device_id(self.context, self.iface)
        self.assertEqual(value, '1572')

    def test_get_sriov_interface_port(self):
        self._create_host_and_interface(
            constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV,
            name='sriov1', sriov_numvfs=2)
        vf = self._create_vf_test("vf1", 1, None, lower_iface=self.iface)
        self._do_update_context()
        value = interface.get_sriov_interface_port(self.context, vf)
        self.assertEqual(value, self.port)

    def test_get_sriov_interface_port_invalid(self):
        self._create_host_and_interface(
            constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
            constants.NETWORK_TYPE_PCI_PASSTHROUGH,
            name='pthru')
        self._do_update_context()
        self.assertRaises(AssertionError,
                          interface.get_sriov_interface_port,
                          self.context,
                          self.iface)

    def test_get_sriov_interface_vf_addrs(self):
        vf_addr1 = "0000:81:00.0"
        vf_addr2 = "0000:81:01.0"
        vf_addr_list = [vf_addr1, vf_addr2]
        self._create_host_and_interface(
            constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV,
            name='sriov1', sriov_numvfs=2)
        vf1 = self._create_vf_test("vf1", 1, None, lower_iface=self.iface)
        self._do_update_context()
        addrs1 = interface.get_sriov_interface_vf_addrs(
            self.context, self.iface, vf_addr_list)
        self.assertEqual(len(addrs1), 1)
        addrs2 = interface.get_sriov_interface_vf_addrs(
            self.context, vf1, vf_addr_list)
        self.assertEqual(len(addrs2), 1)

    def test_get_sriov_interface_vf_addrs_multiple_children(self):
        vf_addr1 = "0000:81:00.0"
        vf_addr2 = "0000:81:01.0"
        vf_addr3 = "0000:81:02.0"
        vf_addr_list = [vf_addr1, vf_addr2, vf_addr3]
        self._create_host_and_interface(
            constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV,
            name='sriov1', sriov_numvfs=3)
        vf1 = self._create_vf_test("vf1", 1, None, lower_iface=self.iface)
        vf2 = self._create_vf_test("vf2", 1, None, lower_iface=self.iface)
        self._do_update_context()
        addrs1 = interface.get_sriov_interface_vf_addrs(
            self.context, vf1, vf_addr_list)
        self.assertEqual(len(addrs1), 1)
        addrs2 = interface.get_sriov_interface_vf_addrs(
            self.context, vf2, vf_addr_list)
        self.assertEqual(len(addrs2), 1)
        addrs3 = interface.get_sriov_interface_vf_addrs(
            self.context, self.iface, vf_addr_list)
        self.assertEqual(len(addrs3), 1)

    def test_get_sriov_interface_vf_addrs_multiple_parents(self):
        vf_addr1 = "0000:81:00.0"
        vf_addr2 = "0000:81:01.0"
        vf_addr3 = "0000:81:02.0"
        vf_addr_list = [vf_addr1, vf_addr2, vf_addr3]
        self._create_host_and_interface(
            constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV,
            name='sriov1', sriov_numvfs=3)
        vf1 = self._create_vf_test("vf1", 2, None, lower_iface=self.iface)
        vf2 = self._create_vf_test("vf2", 1, None, lower_iface=vf1)
        self._do_update_context()
        addrs1 = interface.get_sriov_interface_vf_addrs(
            self.context, vf1, vf_addr_list)
        self.assertEqual(len(addrs1), 1)
        addrs2 = interface.get_sriov_interface_vf_addrs(
            self.context, vf2, vf_addr_list)
        self.assertEqual(len(addrs2), 1)
        addrs3 = interface.get_sriov_interface_vf_addrs(
            self.context, self.iface, vf_addr_list)
        self.assertEqual(len(addrs3), 1)

    def test_get_bridge_interface_name_none_dpdk_supported(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_DATA,
                constants.NETWORK_TYPE_DATA,
                dpdksupport=True)
        self._do_update_context()
        ifname = interface.get_bridge_interface_name(self.context, self.iface)
        self.assertIsNone(ifname)

    def test_get_bridge_interface_name_none_not_data(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT)
        self._do_update_context()
        ifname = interface.get_bridge_interface_name(self.context, self.iface)
        self.assertIsNone(ifname)

    def test_get_bridge_interface_name(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_DATA,
                constants.NETWORK_TYPE_DATA,
                dpdksupport=False)
        self._do_update_context()
        ifname = interface.get_bridge_interface_name(self.context, self.iface)
        self.assertEqual(ifname, 'br-' + self.port['name'])

    def test_needs_interface_config_kernel_mgmt(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_kernel_cluster_host(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_CLUSTER_HOST)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_kernel_oam(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_OAM)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_data(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_DATA,
                constants.NETWORK_TYPE_DATA,
                dpdksupport=True)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_data_slow(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_DATA,
                constants.NETWORK_TYPE_DATA,
                dpdksupport=False)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_data_mlx5(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_DATA,
                constants.NETWORK_TYPE_DATA,
                driver=constants.DRIVER_MLX_CX4)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_data_slow_worker(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_DATA,
                constants.NETWORK_TYPE_DATA,
                personality=constants.WORKER,
                dpdksupport=False)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_data_mlx5_worker(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_DATA,
                constants.NETWORK_TYPE_DATA,
                personality=constants.WORKER,
                driver=constants.DRIVER_MLX_CX4)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_sriov_worker(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PCI_SRIOV,
                constants.NETWORK_TYPE_PCI_SRIOV,
                personality=constants.WORKER)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_pthru_worker(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                personality=constants.WORKER)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_data_cpe_worker(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_DATA,
                constants.NETWORK_TYPE_DATA,
                personality=constants.CONTROLLER,
                subfunction=constants.WORKER,
                dpdksupport=True)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_data_slow_cpe_worker(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_DATA,
                constants.NETWORK_TYPE_DATA,
                personality=constants.CONTROLLER,
                subfunction=constants.WORKER,
                dpdksupport=False)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_data_mlx5_cpe_worker(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_DATA,
                constants.NETWORK_TYPE_DATA,
                personality=constants.CONTROLLER,
                subfunction=constants.WORKER,
                driver=constants.DRIVER_MLX_CX4)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_sriov_cpe(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PCI_SRIOV,
                constants.NETWORK_TYPE_PCI_SRIOV)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_sriov_cpe_worker(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PCI_SRIOV,
                constants.NETWORK_TYPE_PCI_SRIOV,
                personality=constants.CONTROLLER,
                subfunction=constants.WORKER)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_pthru_cpe_worker(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                personality=constants.CONTROLLER,
                subfunction=constants.WORKER)
        self._do_update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def _get_network_config_ifupdown(self, ifname='eth0', ensure='present',
                            family='inet', method='dhcp',
                            hotplug='false', onboot='true',
                            ipaddress=None, netmask=None,
                            options=None):
        config = {'ifname': ifname,
                  'ensure': ensure,
                  'family': family,
                  'method': method,
                  'hotplug': hotplug,
                  'onboot': onboot}
        if ipaddress:
            config['ipaddress'] = ipaddress
        if netmask:
            config['netmask'] = netmask
        config['options'] = options or {}
        return config

    def _get_static_network_config_ifupdown(self, **kwargs):
        ifname = kwargs.pop('ifname', 'eth0')
        method = kwargs.pop('method', 'static')
        ipaddress = kwargs.pop('ipaddress', '192.168.1.2')
        netmask = kwargs.pop('netmask', '255.255.255.0')
        return self._get_network_config_ifupdown(
            ifname=ifname, method=method,
            ipaddress=ipaddress, netmask=netmask, **kwargs)

    def _get_sriov_config(self, ifname='default',
                          vf_driver=constants.SRIOV_DRIVER_TYPE_VFIO,
                          num_vfs=2, pf_addr=None, device_id='1572',
                          port_name="eth0", up_requirement=False,
                          vf_config=None):
        if vf_config is None:
            vf_config = {}
        config = {'ifname': ifname,
                  'addr': pf_addr if pf_addr else self.port['pciaddr'],
                  'device_id': device_id,
                  'num_vfs': num_vfs,
                  'port_name': port_name,
                  'up_requirement': up_requirement,
                  'vf_config': vf_config}

        return config

    def _get_fpga_config(self, portname='eth1', device_id='0d58', vlans=None):
        config = {
            'ifname': portname,
            'device_id': device_id,
            'used_by': vlans
        }

        return config

    def _get_loopback_config(self):
        network_config = self._get_network_config_ifupdown(
            ifname=interface.LOOPBACK_IFNAME, method=interface.LOOPBACK_METHOD)
        return interface.format_network_config(network_config)

    def _get_ipv6_conf_iface_options(self, os_ifname):
        autoconf_off = 'echo 0 > /proc/sys/net/ipv6/conf/{}/autoconf'.format(os_ifname)
        accept_ra_off = 'echo 0 > /proc/sys/net/ipv6/conf/{}/accept_ra'.format(os_ifname)
        accept_redir_off = 'echo 0 > /proc/sys/net/ipv6/conf/{}/accept_redirects'.format(os_ifname)
        keep_addr_on_down = 'echo 1 > /proc/sys/net/ipv6/conf/{}/keep_addr_on_down'.format(os_ifname)
        ipv6_conf_iface = '{}; {}; {}; {}'.format(autoconf_off, accept_ra_off, accept_redir_off,
                                                  keep_addr_on_down)
        return ipv6_conf_iface

    def _get_postup_mtu(self, os_ifname, mtu):
        set_mtu = '/usr/sbin/ip link set dev {} mtu {}'.format(os_ifname, mtu)
        postup_mtu = '{};'.format(set_mtu)
        return postup_mtu

    def test_generate_loopback_config(self):
        config = {
            interface.NETWORK_CONFIG_RESOURCE: {},
        }
        interface.generate_loopback_config(config)
        expected = self._get_loopback_config()
        result = config[interface.NETWORK_CONFIG_RESOURCE].get(
            interface.LOOPBACK_IFNAME)
        self.assertEqual(result, expected)

    def test_get_controller_ethernet_config_oam_ifupdown(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_OAM)
        network, address = self._create_address_for_interface(self.iface)
        self._do_update_context()
        configs = interface.get_interface_network_configs(
            self.context, self.iface, network)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(self.port['name'])
        options = {'stx-description': 'ifname:mgmt0,net:oam',
                   'post-up': '{}'.format(ipv6_conf_iface_opt),
                   'mtu': '1500',
                   'gateway': '10.10.10.1'}
        expected = self._get_static_network_config_ifupdown(
            ipaddress='10.10.10.10',
            ifname=f"{self.port['name']}:{network.id}-{address.id}", options=options)
        self.assertEqual(expected, configs[0])

    def test_get_controller_ethernet_config_mgmt_ifupdown(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT)
        network, address = self._create_address_for_interface(self.iface)
        self._do_update_context()
        configs = interface.get_interface_network_configs(
            self.context, self.iface, network)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(self.port['name'])
        options = {'post-up': '%s' % ipv6_conf_iface_opt,
                   'mtu': '1500',
                   'stx-description': 'ifname:mgmt0,net:mgmt',
                   'gateway': '192.168.204.1'}
        expected = self._get_static_network_config_ifupdown(
            ipaddress='192.168.204.10',
            ifname=f"{self.port['name']}:{network.id}-{address.id}", options=options)
        self.assertEqual(expected, configs[0])

    def test_get_controller_ethernet_config_cluster_host_ifupdown(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_CLUSTER_HOST)
        network, address = self._create_address_for_interface(self.iface)
        self._do_update_context()
        configs = interface.get_interface_network_configs(
            self.context, self.iface, network)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(self.port['name'])
        options = {'stx-description': 'ifname:mgmt0,net:cluster-host',
                   'post-up': '{}'.format(ipv6_conf_iface_opt),
                   'mtu': '1500'}
        expected = self._get_static_network_config_ifupdown(
            ipaddress='192.168.206.10',
            ifname=f"{self.port['name']}:{network.id}-{address.id}", options=options)
        self.assertEqual(expected, configs[0])

    def test_get_controller_ethernet_config_slave_ifupdown(self):
        self._create_host(constants.CONTROLLER)
        bond = self._create_bond_test("bond0")
        self._do_update_context()
        iface = self.context['interfaces'][bond['uses'][0]]
        port = self.context['ports'][iface['id']]
        configs = interface.get_interface_network_configs(self.context, iface)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(port['name'])
        options = {'allow-bond0': port['name'],
                   'bond-master': 'bond0',
                   'stx-description': 'ifname:eth0,net:None',
                   'pre-up': '/usr/sbin/ip link set dev {} promisc on; {}'.format(port['name'],
                                                                             ipv6_conf_iface_opt),
                   'mtu': '1500'}
        expected = self._get_network_config_ifupdown(
            ifname=port['name'], method='manual', options=options)
        self.assertEqual(expected, configs[0])

    def test_get_controller_ethernet_config_slave_sriov_bond(self):
        self._create_host(constants.CONTROLLER)
        port1, iface1 = self._create_ethernet_test(
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            sriov_numvfs=16)
        port2, iface2 = self._create_ethernet_test(
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            sriov_numvfs=16)
        self._create_bond_test("bond0",
                               ifclass=constants.INTERFACE_CLASS_PLATFORM,
                               iface1=iface1,
                               iface2=iface2,
                               aemode='active_standby',
                               primary_reselect=constants.PRIMARY_RESELECT_ALWAYS)
        self._do_update_context()

        iface = iface1
        port = port1
        configs = interface.get_interface_network_configs(self.context, iface)
        numvfs_path = '/sys/class/net/{}/device/sriov_numvfs'.format(port['name'])
        numvfs_cmd = 'echo 0 > {0}; echo 16 > {0}'.format(numvfs_path)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(port['name'])
        options = {'allow-bond0': port['name'],
                   'bond-master': 'bond0',
                   'stx-description': 'ifname:{},net:None'.format(iface.ifname),
                   'pre-up': '/usr/sbin/ip link set dev {} promisc on; {}; {}'.format(
                       port['name'], numvfs_cmd, ipv6_conf_iface_opt),
                   'mtu': '1500'}
        expected = self._get_network_config_ifupdown(ifname=port['name'], method='manual',
                                                     options=options)
        self.assertEqual(expected, configs[0])

        iface = iface2
        port = port2
        configs = interface.get_interface_network_configs(self.context, iface)
        numvfs_path = '/sys/class/net/{}/device/sriov_numvfs'.format(port['name'])
        numvfs_cmd = 'echo 0 > {0}; echo 16 > {0}'.format(numvfs_path)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(port['name'])
        options = {'allow-bond0': port['name'],
                   'bond-master': 'bond0',
                   'stx-description': 'ifname:{},net:None'.format(iface.ifname),
                   'pre-up': '/usr/sbin/ip link set dev {} promisc on; {}; {}'.format(
                       port['name'], numvfs_cmd, ipv6_conf_iface_opt),
                   'mtu': '1500'}
        expected = self._get_network_config_ifupdown(ifname=port['name'], method='manual',
                                                     options=options)
        self.assertEqual(expected, configs[0])

    def test_get_controller_bond_config_duplex_ifupdown(self):
        self._create_host(constants.CONTROLLER)
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)
        bond = self._create_bond_test(
            "bond0", ifclass=constants.INTERFACE_CLASS_PLATFORM,
            networktype=constants.NETWORK_TYPE_MGMT)
        network, address = self._create_address_for_interface(bond)
        self._do_update_context()
        configs = interface.get_interface_network_configs(self.context, bond, network)
        options = {'bond-lacp-rate': 'fast',
                   'bond-miimon': '100',
                   'bond-mode': '802.3ad',
                   'bond-slaves': 'eth0 eth1 ',
                   'bond-xmit-hash-policy': 'layer2',
                   'stx-description': 'ifname:bond0,net:mgmt',
                   'gateway': '192.168.204.1',
                   'hwaddress': '02:11:22:33:44:12',
                   'mtu': '1500',
                   'post-up': 'echo 0 > /proc/sys/net/ipv6/conf/bond0/autoconf; echo '
                              '0 > /proc/sys/net/ipv6/conf/bond0/accept_ra; echo 0 > '
                              '/proc/sys/net/ipv6/conf/bond0/accept_redirects; echo 1'
                              ' > /proc/sys/net/ipv6/conf/bond0/keep_addr_on_down',
                   'up': 'end=$((SECONDS+10)); while { [ ! -d '
                   '/proc/sys/net/ipv6/conf/$IFACE ] || [ ! -d '
                   '/proc/sys/net/ipv4/conf/$IFACE ]; } && [ $SECONDS -lt $end '
                   ']; do sleep 1; done'}
        expected = self._get_static_network_config_ifupdown(
            ipaddress='192.168.204.10',
            ifname=f"{bond['ifname']}:{network.id}-{address.id}", options=options)
        self.assertEqual(expected, configs[0])

    def test_get_controller_bond_config_duplex_direct_ifupdown(self):
        self._create_host(constants.CONTROLLER)
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX_DIRECT
        self.dbapi.isystem_update(self.system.uuid, system_dict)
        bond = self._create_bond_test(
            "bond0", ifclass=constants.INTERFACE_CLASS_PLATFORM,
            networktype=constants.NETWORK_TYPE_MGMT)
        network, address = self._create_address_for_interface(bond)
        self._do_update_context()
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)

        configs = interface.get_interface_network_configs(self.context, bond)
        options = {'bond-lacp-rate': 'fast',
                   'bond-miimon': '100',
                   'bond-mode': '802.3ad',
                   'bond-slaves': 'eth0 eth1 ',
                   'bond-xmit-hash-policy': 'layer2',
                   'stx-description': 'ifname:bond0,net:None',
                   'hwaddress': '02:11:22:33:44:12',
                   'mtu': '1500',
                   'post-up': '/usr/local/bin/tc_setup.sh bond0 mgmt 10000 > /dev/null; '
                              'echo 0 > /proc/sys/net/ipv6/conf/bond0/autoconf; echo '
                              '0 > /proc/sys/net/ipv6/conf/bond0/accept_ra; echo 0 > '
                              '/proc/sys/net/ipv6/conf/bond0/accept_redirects; echo 1'
                              ' > /proc/sys/net/ipv6/conf/bond0/keep_addr_on_down',
                   'pre-up': '/sbin/modprobe bonding; grep bond0 '
                             '/sys/class/net/bonding_masters || echo +bond0 > '
                             '/sys/class/net/bonding_masters; sysctl -wq '
                             'net.ipv6.conf.bond0.accept_dad=0',
                   'up': 'end=$((SECONDS+10)); while { [ ! -d '
                   '/proc/sys/net/ipv6/conf/$IFACE ] || [ ! -d '
                   '/proc/sys/net/ipv4/conf/$IFACE ]; } && [ $SECONDS -lt $end '
                   ']; do sleep 1; done'}
        expected = self._get_network_config_ifupdown(
            method='manual', ifname=f"{bond['ifname']}", options=options)
        self.assertEqual(expected, configs[0])

        configs = interface.get_interface_network_configs(self.context, bond, network)
        options = {'bond-lacp-rate': 'fast',
                   'bond-miimon': '100',
                   'bond-mode': '802.3ad',
                   'bond-slaves': 'eth0 eth1 ',
                   'bond-xmit-hash-policy': 'layer2',
                   'stx-description': 'ifname:bond0,net:mgmt',
                   'gateway': '192.168.204.1',
                   'hwaddress': '02:11:22:33:44:12',
                   'mtu': '1500',
                   'post-up': 'echo 0 > /proc/sys/net/ipv6/conf/bond0/autoconf; echo '
                              '0 > /proc/sys/net/ipv6/conf/bond0/accept_ra; echo 0 > '
                              '/proc/sys/net/ipv6/conf/bond0/accept_redirects; echo 1'
                              ' > /proc/sys/net/ipv6/conf/bond0/keep_addr_on_down',
                   'up': 'end=$((SECONDS+10)); while { [ ! -d '
                   '/proc/sys/net/ipv6/conf/$IFACE ] || [ ! -d '
                   '/proc/sys/net/ipv4/conf/$IFACE ]; } && [ $SECONDS -lt $end '
                   ']; do sleep 1; done'}
        expected = self._get_static_network_config_ifupdown(
            ipaddress='192.168.204.10',
            ifname=f"{bond['ifname']}:{network.id}-{address.id}", options=options)
        self.assertEqual(expected, configs[0])

    def test_get_controller_bond_config_balanced_ifupdown(self):
        self._create_host(constants.CONTROLLER)
        bond = self._create_bond_test("bond0")
        self._do_update_context()
        configs = interface.get_interface_network_configs(self.context, bond)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(bond['ifname'])
        options = {'bond-miimon': '100',
                  'bond-slaves': 'eth0 eth1 ',
                  'bond-mode': 'balance-xor',
                  'bond-xmit-hash-policy': 'layer2',
                  'stx-description': 'ifname:bond0,net:None',
                  'hwaddress': bond['imac'],
                  'mtu': '1500',
                  'post-up': '{}'.format(ipv6_conf_iface_opt),
                  'up': 'end=$((SECONDS+10)); while { [ ! -d '
                   '/proc/sys/net/ipv6/conf/$IFACE ] || [ ! -d '
                   '/proc/sys/net/ipv4/conf/$IFACE ]; } && [ $SECONDS -lt $end '
                   ']; do sleep 1; done'}
        expected = self._get_network_config_ifupdown(
            ifname=bond['ifname'], method='manual', options=options)
        self.assertEqual(expected, configs[0])

    def test_get_controller_bond_config_8023ad_ifupdown(self):
        self._create_host(constants.CONTROLLER)
        bond = self._create_bond_test("bond0", aemode='802.3ad')
        self._do_update_context()
        configs = interface.get_interface_network_configs(self.context, bond)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(bond['ifname'])
        options = {'bond-lacp-rate': 'fast',
                   'bond-miimon': '100',
                   'bond-mode': '802.3ad',
                   'bond-slaves': 'eth0 eth1 ',
                   'bond-xmit-hash-policy': 'layer2',
                   'stx-description': 'ifname:bond0,net:None',
                   'hwaddress': bond['imac'],
                   'mtu': '1500',
                   'post-up': '{}'.format(ipv6_conf_iface_opt),
                   'up': 'end=$((SECONDS+10)); while { [ ! -d '
                   '/proc/sys/net/ipv6/conf/$IFACE ] || [ ! -d '
                   '/proc/sys/net/ipv4/conf/$IFACE ]; } && [ $SECONDS -lt $end '
                   ']; do sleep 1; done'}
        expected = self._get_network_config_ifupdown(
            ifname=bond['ifname'], method='manual', options=options)
        self.assertEqual(expected, configs[0])

    def test_get_controller_bond_config_active_standby_ifupdown(self):
        self._create_host(constants.CONTROLLER)
        bond = self._create_bond_test(
            "bond0",
            aemode='active_standby',
            primary_reselect=constants.PRIMARY_RESELECT_ALWAYS)
        self._do_update_context()
        configs = interface.get_interface_network_configs(self.context, bond)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(bond['ifname'])
        options = {'bond-miimon': '100',
                   'bond-mode': 'active-backup',
                   'bond-slaves': 'eth0 eth1 ',
                   'bond-primary': 'eth0',
                   'bond-primary-reselect': 'always',
                   'stx-description': 'ifname:bond0,net:None',
                   'hwaddress': bond['imac'],
                   'mtu': '1500',
                   'post-up': '{}'.format(ipv6_conf_iface_opt),
                   'up': 'end=$((SECONDS+10)); while { [ ! -d '
                   '/proc/sys/net/ipv6/conf/$IFACE ] || [ ! -d '
                   '/proc/sys/net/ipv4/conf/$IFACE ]; } && [ $SECONDS -lt $end '
                   ']; do sleep 1; done'}
        expected = self._get_network_config_ifupdown(
            ifname=bond['ifname'], method='manual', options=options)
        self.assertEqual(expected, configs[0])

    def test_get_controller_bond_config_active_standby_primary_reselect_ifupdown(self):
        self._create_host(constants.CONTROLLER)
        bond = self._create_bond_test(
            "bond0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_MGMT,
            aemode='active_standby',
            primary_reselect=constants.PRIMARY_RESELECT_BETTER)
        self._do_update_context()
        configs = interface.get_interface_network_configs(self.context, bond)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(bond['ifname'])
        options = {'bond-miimon': '100',
                   'bond-mode': 'active-backup',
                   'bond-slaves': 'eth0 eth1 ',
                   'bond-primary': 'eth0',
                   'bond-primary-reselect': 'better',
                   'stx-description': 'ifname:bond0,net:None',
                   'hwaddress': bond['imac'],
                   'mtu': '1500',
                   'post-up': '/usr/local/bin/tc_setup.sh bond0 mgmt 10000 > /dev/null; ' +
                              '{}'.format(ipv6_conf_iface_opt),
                   'up': 'end=$((SECONDS+10)); while { [ ! -d '
                   '/proc/sys/net/ipv6/conf/$IFACE ] || [ ! -d '
                   '/proc/sys/net/ipv4/conf/$IFACE ]; } && [ $SECONDS -lt $end '
                   ']; do sleep 1; done'}
        expected = self._get_network_config_ifupdown(
            ifname=bond['ifname'], method='manual', options=options)
        self.assertEqual(expected, configs[0])

    def test_get_controller_vlan_config_ifupdown(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT)
        vlan = self._create_vlan_test("vlan1", None, None, 1, self.iface)
        self._do_update_context()
        configs = interface.get_interface_network_configs(self.context, vlan)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options("vlan#1")
        mtu = '1500'
        set_mtu = self._get_postup_mtu("vlan#1", mtu)
        options = {'stx-description': 'ifname:vlan1,net:None',
                   'mtu': mtu,
                   'post-down': 'ip link del vlan#1',
                   'pre-up': '/sbin/modprobe -q 8021q; ip link add link '
                             '{} name vlan#1 type vlan id 1'.format(
                                 self.port['name']),
                   'post-up': '{} {}'.format(set_mtu, ipv6_conf_iface_opt),
                   'vlan-raw-device': '{}'.format(self.port['name'])}
        expected = self._get_network_config_ifupdown(
            ifname="vlan#1", method='manual', options=options)
        self.assertEqual(expected, configs[0])

    def test_get_controller_vlan_config_ifname_with_dot(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT)
        vlan = self._create_vlan_test("vlan.dot", None, None, 1, self.iface)
        self._do_update_context()
        configs = interface.get_interface_network_configs(self.context, vlan)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options("vlan.dot")
        mtu = '1500'
        set_mtu = self._get_postup_mtu("vlan.dot", mtu)
        options = {'stx-description': 'ifname:vlan.dot,net:None',
                   'mtu': mtu,
                   'post-down': 'ip link del vlan.dot',
                   'pre-up': '/sbin/modprobe -q 8021q; ip link add link '
                             '{} name vlan.dot type vlan id 1'.format(
                                 self.port['name']),
                   'post-up': '{} {}'.format(set_mtu, ipv6_conf_iface_opt),
                   'vlan-raw-device': '{}'.format(self.port['name'])}
        expected = self._get_network_config_ifupdown(
            ifname="vlan.dot", method='manual', options=options)
        self.assertEqual(expected, configs[0])

    def test_get_controller_vlan_config_duplex_direct_ifupdown(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_NONE,
                constants.NETWORK_TYPE_NONE)
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX_DIRECT
        self.dbapi.isystem_update(self.system.uuid, system_dict)
        vlan = self._create_vlan_test(
            "vlan100", constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_MGMT, 100, self.iface)
        network, address = self._create_address_for_interface(vlan)
        self._do_update_context()

        configs = interface.get_interface_network_configs(self.context, vlan)
        options = {'stx-description': 'ifname:vlan100,net:None',
                   'mtu': '1500',
                   'post-down': 'ip link del vlan100',
                   'post-up': '/usr/local/bin/tc_setup.sh vlan100 mgmt 10000 > /dev/null; '
                              '/usr/sbin/ip link set dev vlan100 mtu 1500; echo 0 > '
                              '/proc/sys/net/ipv6/conf/vlan100/autoconf; echo 0 '
                              '> /proc/sys/net/ipv6/conf/vlan100/accept_ra; echo 0 > '
                              '/proc/sys/net/ipv6/conf/vlan100/accept_redirects; echo 1'
                              ' > /proc/sys/net/ipv6/conf/vlan100/keep_addr_on_down',
                   'pre-up': '/sbin/modprobe -q 8021q; ip link add link '
                             '{} name vlan100 type vlan id 100; '.format(
                                 self.port['name']) +
                             'sysctl -wq net.ipv6.conf.vlan100.accept_dad=0',
                   'vlan-raw-device': '{}'.format(self.port['name'])}
        expected = self._get_network_config_ifupdown(
            method='manual', ifname="vlan100", options=options)
        self.assertEqual(expected, configs[0])

        configs = interface.get_interface_network_configs(self.context, vlan, network)
        options = {'stx-description': 'ifname:vlan100,net:mgmt',
                   'gateway': '192.168.204.1',
                   'mtu': '1500',
                   'post-up': '/usr/sbin/ip link set dev vlan100 mtu 1500; echo 0 > '
                              '/proc/sys/net/ipv6/conf/vlan100/autoconf; echo 0 '
                              '> /proc/sys/net/ipv6/conf/vlan100/accept_ra; echo 0 > '
                              '/proc/sys/net/ipv6/conf/vlan100/accept_redirects; echo'
                              ' 1 > /proc/sys/net/ipv6/conf/vlan100/keep_addr_on_down',
                   'pre-up': '/sbin/modprobe -q 8021q',
                   'vlan-raw-device': '{}'.format(self.port['name'])}
        expected = self._get_static_network_config_ifupdown(
            ipaddress='192.168.204.10',
            ifname=f"vlan100:{network.id}-{address.id}", options=options)
        self.assertEqual(expected, configs[0])

    def test_is_disable_dad_required(self):
        self._create_host_and_interface(constants.INTERFACE_CLASS_NONE, constants.NETWORK_TYPE_NONE)
        bond = self._create_bond_test("bond0", constants.INTERFACE_CLASS_PLATFORM)
        vlan = self._create_vlan_test("vlan100", constants.INTERFACE_CLASS_PLATFORM,
                                      constants.NETWORK_TYPE_MGMT, 100, self.iface)
        mgmt_network = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        clhost_network = self._find_network_by_type(constants.NETWORK_TYPE_CLUSTER_HOST)

        # Ethernet
        self.iface.networktypelist = [constants.NETWORK_TYPE_MGMT]
        self.assertTrue(interface.is_disable_dad_required(self.iface, None))
        self.assertFalse(interface.is_disable_dad_required(self.iface, mgmt_network))

        self.iface.networktypelist = [constants.NETWORK_TYPE_CLUSTER_HOST]
        self.assertTrue(interface.is_disable_dad_required(self.iface, None))
        self.assertFalse(interface.is_disable_dad_required(self.iface, clhost_network))

        self.iface.networktypelist = [constants.NETWORK_TYPE_MGMT,
                                      constants.NETWORK_TYPE_CLUSTER_HOST]
        self.assertTrue(interface.is_disable_dad_required(self.iface, None))
        self.assertFalse(interface.is_disable_dad_required(self.iface, mgmt_network))
        self.assertFalse(interface.is_disable_dad_required(self.iface, clhost_network))

        # Bond
        bond.networktypelist = [constants.NETWORK_TYPE_MGMT]
        self.assertTrue(interface.is_disable_dad_required(bond, None))
        self.assertFalse(interface.is_disable_dad_required(bond, mgmt_network))

        bond.networktypelist = [constants.NETWORK_TYPE_CLUSTER_HOST]
        self.assertTrue(interface.is_disable_dad_required(bond, None))
        self.assertFalse(interface.is_disable_dad_required(bond, clhost_network))

        bond.networktypelist = [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST]
        self.assertTrue(interface.is_disable_dad_required(bond, None))
        self.assertFalse(interface.is_disable_dad_required(bond, mgmt_network))
        self.assertFalse(interface.is_disable_dad_required(bond, clhost_network))

        # VLAN
        vlan.networktypelist = [constants.NETWORK_TYPE_MGMT]
        self.assertTrue(interface.is_disable_dad_required(vlan, None))
        self.assertFalse(interface.is_disable_dad_required(vlan, mgmt_network))

        vlan.networktypelist = [constants.NETWORK_TYPE_CLUSTER_HOST]
        self.assertTrue(interface.is_disable_dad_required(vlan, None))
        self.assertFalse(interface.is_disable_dad_required(vlan, clhost_network))

        vlan.networktypelist = [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST]
        self.assertTrue(interface.is_disable_dad_required(vlan, None))
        self.assertFalse(interface.is_disable_dad_required(vlan, mgmt_network))
        self.assertFalse(interface.is_disable_dad_required(vlan, clhost_network))

    def test_get_controller_ethernet_config_duplex_direct_mgmt_only(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT)
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX_DIRECT
        self.dbapi.isystem_update(self.system.uuid, system_dict)
        network, address = self._create_address_for_interface(self.iface)
        self._do_update_context()

        configs = interface.get_interface_network_configs(
            self.context, self.iface)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(self.port['name'])
        options = {'post-up': '/usr/local/bin/tc_setup.sh eth0 mgmt 10000 > /dev/null; ' +
                              '{}'.format(ipv6_conf_iface_opt),
                   'pre-up': 'sysctl -wq net.ipv6.conf.{}.accept_dad=0'.format(self.port['name']),
                   'mtu': '1500',
                   'stx-description': 'ifname:mgmt0,net:None'}
        expected = self._get_network_config_ifupdown(
            method='manual', ifname=f"{self.port['name']}", options=options)
        self.assertEqual(expected, configs[0])

        configs = interface.get_interface_network_configs(
            self.context, self.iface, network)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(self.port['name'])
        options = {'post-up': '%s' % ipv6_conf_iface_opt,
                   'mtu': '1500',
                   'stx-description': 'ifname:mgmt0,net:mgmt',
                   'gateway': '192.168.204.1'}
        expected = self._get_static_network_config_ifupdown(
            ipaddress='192.168.204.10',
            ifname=f"{self.port['name']}:{network.id}-{address.id}", options=options)
        self.assertEqual(expected, configs[0])

    def test_get_controller_ethernet_config_duplex_direct_mgmt_plus_cluster_host(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST])
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX_DIRECT
        self.dbapi.isystem_update(self.system.uuid, system_dict)
        mgmt_network, mgmt_address = self._create_address_for_interface(self.iface,
                constants.NETWORK_TYPE_MGMT)
        clhost_network, clhost_address = self._create_address_for_interface(self.iface,
                constants.NETWORK_TYPE_CLUSTER_HOST)
        self._do_update_context()

        configs = interface.get_interface_network_configs(
            self.context, self.iface)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(self.port['name'])
        options = {'post-up': '/usr/local/bin/tc_setup.sh eth0 mgmt 10000 > /dev/null; ' +
                              '{}'.format(ipv6_conf_iface_opt),
                   'pre-up': 'sysctl -wq net.ipv6.conf.{}.accept_dad=0'.format(self.port['name']),
                   'mtu': '1500',
                   'stx-description': 'ifname:mgmt0,net:None'}
        expected = self._get_network_config_ifupdown(
            method='manual', ifname=f"{self.port['name']}", options=options)
        self.assertEqual(expected, configs[0])

        configs = interface.get_interface_network_configs(
            self.context, self.iface, mgmt_network)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(self.port['name'])
        options = {'post-up': '%s' % ipv6_conf_iface_opt,
                   'mtu': '1500',
                   'stx-description': 'ifname:mgmt0,net:mgmt',
                   'gateway': '192.168.204.1'}
        expected = self._get_static_network_config_ifupdown(
            ipaddress='192.168.204.10',
            ifname=f"{self.port['name']}:{mgmt_network.id}-{mgmt_address.id}", options=options)
        self.assertEqual(expected, configs[0])

        configs = interface.get_interface_network_configs(
            self.context, self.iface, clhost_network)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(self.port['name'])
        options = {'post-up': '%s' % ipv6_conf_iface_opt,
                   'mtu': '1500',
                   'stx-description': 'ifname:mgmt0,net:cluster-host'}
        expected = self._get_static_network_config_ifupdown(
            ipaddress='192.168.206.10',
            ifname=f"{self.port['name']}:{clhost_network.id}-{clhost_address.id}", options=options)
        self.assertEqual(expected, configs[0])

    def test_get_controller_vlan_config_over_bond_ifupdown(self):
        self._create_host(constants.CONTROLLER)
        bond = self._create_bond_test("bond0")
        vlan = self._create_vlan_test("vlan1", None, None, 1, bond)
        self._do_update_context()
        configs = interface.get_interface_network_configs(self.context, vlan)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options("vlan#1")
        mtu = '1500'
        set_mtu = self._get_postup_mtu("vlan#1", mtu)
        options = {'stx-description': 'ifname:vlan1,net:None',
                   'post-down': 'ip link del vlan#1',
                   'mtu': mtu,
                   'pre-up': '/sbin/modprobe -q 8021q; ip link add link '
                             '{} name vlan#1 type vlan id 1'.format(
                                 bond['ifname']),
                   'post-up': '{} {}'.format(set_mtu, ipv6_conf_iface_opt),
                   'vlan-raw-device': '{}'.format(bond['ifname'])}
        expected = self._get_network_config_ifupdown(
            ifname="vlan#1", method='manual', options=options)
        self.assertEqual(expected, configs[0])

    def test_get_worker_ethernet_config_mgmt_ifupdown(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_MGMT,
                personality=constants.WORKER)
        network, address = self._create_address_for_interface(self.iface)
        self._do_update_context()
        configs = interface.get_interface_network_configs(
            self.context, self.iface, network)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(self.port['name'])
        options = {'stx-description': 'ifname:mgmt0,net:mgmt',
                   'mtu': '1500',
                   'gateway': '192.168.204.2',
                   'post-up': '{}'.format(ipv6_conf_iface_opt)}
        expected = self._get_static_network_config_ifupdown(
            ipaddress='192.168.204.10',
            ifname=f"{self.port['name']}:{network.id}-{address.id}", options=options)
        self.assertEqual(expected, configs[0])

    def test_get_worker_ethernet_config_cluster_host_ifupdown(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PLATFORM,
                constants.NETWORK_TYPE_CLUSTER_HOST,
                personality=constants.WORKER)
        network, address = self._create_address_for_interface(self.iface)
        self._do_update_context()
        configs = interface.get_interface_network_configs(
            self.context, self.iface, network)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(self.port['name'])
        options = {'stx-description': 'ifname:mgmt0,net:cluster-host',
                   'mtu': '1500',
                   'post-up': '{}'.format(ipv6_conf_iface_opt)}
        expected = self._get_static_network_config_ifupdown(
            ipaddress='192.168.206.10',
            ifname=f"{self.port['name']}:{network.id}-{address.id}", options=options)
        self.assertEqual(expected, configs[0])

    def test_get_worker_ethernet_config_pci_sriov_ifupdown(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PCI_SRIOV,
                constants.NETWORK_TYPE_PCI_SRIOV,
                personality=constants.WORKER)
        self._do_update_context()
        configs = interface.get_interface_network_configs(
            self.context, self.iface)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(self.port['name'])
        options = {'stx-description': 'ifname:mgmt0,net:None',
                   'mtu': '1500',
                   'pre-up': 'echo 0 > /sys/class/net/{}/device/sriov_numvfs;'
                             ' echo 0 > /sys/class/net/{}/device/sriov_numvfs'.format(
                                 self.port['name'], self.port['name']),
                   'post-up': '{}'.format(ipv6_conf_iface_opt)}
        expected = self._get_network_config_ifupdown(
            ifname=self.port['name'], method='manual', options=options)
        self.assertEqual(expected, configs[0])

    def test_get_worker_ethernet_config_pci_pthru_ifupdown(self):
        self._create_host_and_interface(
                constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                personality=constants.WORKER)
        self._do_update_context()
        configs = interface.get_interface_network_configs(
            self.context, self.iface)
        ipv6_conf_iface_opt = self._get_ipv6_conf_iface_options(self.port['name'])
        options = {'stx-description': 'ifname:mgmt0,net:None',
                   'mtu': '1500',
                   'pre-up':
                      'if [ -f  /sys/class/net/{}/device/sriov_numvfs ];'
                        ' then echo 0 > /sys/class/net/{}/device/sriov_numvfs; fi'.format(
                            self.port['name'], self.port['name']),
                   'post-up': '{}'.format(ipv6_conf_iface_opt)}
        expected = self._get_network_config_ifupdown(
            ifname=self.port['name'], method='manual', options=options)
        self.assertEqual(expected, configs[0])

    def test_get_worker_ethernet_config_pci_sriov_vf(self):
        self._create_host_and_interface(
            constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV,
            name='sriov1', sriov_numvfs=2)
        vf = self._create_vf_test("vf", 1, None, lower_iface=self.iface)
        self._do_update_context()
        configs = interface.get_interface_network_configs(self.context, vf)
        expected = []
        self.assertEqual(expected, configs)

    def _create_sriov_vf_config(self, iface_vf_driver, port_vf_driver,
                                vf_addr_list, num_vfs, max_tx_rate=None):
        self._create_host_and_interface(
            constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV,
            name='sriov1',
            iface_sriov_vf_driver=iface_vf_driver,
            sriov_numvfs=num_vfs,
            max_tx_rate=max_tx_rate,
            port_sriov_vf_driver=port_vf_driver,
            sriov_vfs_pci_address=vf_addr_list)
        self._do_update_context()

        config = interface.get_sriov_config(self.context, self.iface)
        return config

    def test_get_sriov_config_netdevice(self):
        vf_addr1 = "0000:81:00.0"
        vf_addr2 = "0000:81:01.0"
        device_id = '1572'
        port_name = 'eth0'
        vf_addr_list = "{},{}".format(vf_addr1, vf_addr2)
        num_vfs = 2

        config = self._create_sriov_vf_config(
            constants.SRIOV_DRIVER_TYPE_NETDEVICE, 'i40evf', vf_addr_list,
            num_vfs)
        expected_vf_config = {
            '0000:81:00.0': {'addr': '0000:81:00.0', 'driver': 'i40evf'},
            '0000:81:01.0': {'addr': '0000:81:01.0', 'driver': 'i40evf'}
        }
        expected = self._get_sriov_config(
            ifname=self.iface['ifname'],
            vf_driver='i40evf',
            num_vfs=num_vfs,
            device_id=device_id,
            port_name=port_name,
            vf_config=expected_vf_config,)
        self.assertEqual(expected, config)

    def test_get_sriov_config_vfio(self):
        vf_addr1 = "0000:81:00.0"
        vf_addr2 = "0000:81:01.0"
        device_id = '1572'
        port_name = 'eth0'
        vf_addr_list = "{},{}".format(vf_addr1, vf_addr2)
        num_vfs = 4

        config = self._create_sriov_vf_config(
            constants.SRIOV_DRIVER_TYPE_VFIO, 'i40evf', vf_addr_list,
            num_vfs)
        expected_vf_config = {
            '0000:81:00.0': {'addr': '0000:81:00.0', 'driver': 'vfio-pci'},
            '0000:81:01.0': {'addr': '0000:81:01.0', 'driver': 'vfio-pci'}
        }
        expected = self._get_sriov_config(
            ifname=self.iface['ifname'],
            vf_driver='vfio-pci',
            num_vfs=num_vfs,
            device_id=device_id,
            port_name=port_name,
            vf_config=expected_vf_config)
        self.assertEqual(expected, config)

    def test_get_sriov_config_default(self):
        vf_addr1 = "0000:81:00.0"
        vf_addr2 = "0000:81:01.0"
        device_id = '1572'
        port_name = 'eth0'
        vf_addr_list = "{},{}".format(vf_addr1, vf_addr2)
        num_vfs = 1

        config = self._create_sriov_vf_config(
            None, 'i40evf', vf_addr_list, num_vfs)
        expected_vf_config = {
            '0000:81:00.0': {'addr': '0000:81:00.0', 'driver': None},
            '0000:81:01.0': {'addr': '0000:81:01.0', 'driver': None}
        }
        expected = self._get_sriov_config(
            ifname=self.iface['ifname'],
            vf_driver=None,
            device_id=device_id,
            port_name=port_name,
            num_vfs=num_vfs,
            vf_config=expected_vf_config)
        self.assertEqual(expected, config)

    def test_get_sriov_config_iftype_vf(self):
        self._create_host_and_interface(
            constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV,
            name='sriov1',
            sriov_numvfs=4,
            iface_sriov_vf_driver=None,
            port_sriov_vf_driver="iavf",
            sriov_vfs_pci_address="0000:b1:02.0,0000:b1:02.1,0000:b1:02.2,0000:b1:02.3")
        self._create_vf_test("vf1", 1, 'vfio', lower_iface=self.iface)
        self._do_update_context()

        config = interface.get_sriov_config(self.context, self.iface)

        expected_vf_config = {
            '0000:b1:02.0': {'addr': '0000:b1:02.0', 'driver': None},
            '0000:b1:02.1': {'addr': '0000:b1:02.1', 'driver': None},
            '0000:b1:02.2': {'addr': '0000:b1:02.2', 'driver': None},
            '0000:b1:02.3': {'addr': '0000:b1:02.3', 'driver': 'vfio-pci'}
        }
        expected = self._get_sriov_config(
            self.iface['ifname'], None,
            num_vfs=4, pf_addr=self.port['pciaddr'],
            port_name="eth0",
            vf_config=expected_vf_config)
        self.assertEqual(expected, config)

    def test_get_sriov_config_iftype_vf_nested(self):
        self._create_host_and_interface(
            constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV,
            name='sriov1',
            sriov_numvfs=4,
            iface_sriov_vf_driver=None,
            port_sriov_vf_driver="iavf",
            sriov_vfs_pci_address="0000:b1:02.0,0000:b1:02.1,0000:b1:02.2,0000:b1:02.3")
        vf1 = self._create_vf_test("vf1", 2, 'vfio', lower_iface=self.iface)
        self._create_vf_test("vf2", 1, 'netdevice', lower_iface=vf1)
        self._do_update_context()

        config = interface.get_sriov_config(self.context, self.iface)

        expected_vf_config = {
            '0000:b1:02.0': {'addr': '0000:b1:02.0', 'driver': None},
            '0000:b1:02.1': {'addr': '0000:b1:02.1', 'driver': None},
            '0000:b1:02.2': {'addr': '0000:b1:02.2', 'driver': 'vfio-pci'},
            '0000:b1:02.3': {'addr': '0000:b1:02.3', 'driver': 'iavf'}
        }
        expected = self._get_sriov_config(
            self.iface['ifname'], None,
            num_vfs=4, pf_addr=self.port['pciaddr'],
            port_name="eth0",
            vf_config=expected_vf_config)
        self.assertEqual(expected, config)

    def test_get_sriov_config_iftype_vf_sibling(self):
        self._create_host_and_interface(
            constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV,
            name='sriov1',
            sriov_numvfs=4,
            iface_sriov_vf_driver=None,
            port_sriov_vf_driver="iavf",
            sriov_vfs_pci_address="0000:b1:02.0,0000:b1:02.1,0000:b1:02.2,0000:b1:02.3")
        self._create_vf_test("vf1", 2, 'vfio', lower_iface=self.iface)
        self._create_vf_test("vf2", 1, 'netdevice', lower_iface=self.iface)
        self._do_update_context()

        config = interface.get_sriov_config(self.context, self.iface)

        expected_vf_config = {
            '0000:b1:02.0': {'addr': '0000:b1:02.0', 'driver': None},
            '0000:b1:02.1': {'addr': '0000:b1:02.1', 'driver': 'iavf'},
            '0000:b1:02.2': {'addr': '0000:b1:02.2', 'driver': 'vfio-pci'},
            '0000:b1:02.3': {'addr': '0000:b1:02.3', 'driver': 'vfio-pci'}
        }
        expected = self._get_sriov_config(
            self.iface['ifname'], None,
            num_vfs=4, pf_addr=self.port['pciaddr'],
            port_name="eth0",
            vf_config=expected_vf_config)
        self.assertEqual(expected, config)

    @mock.patch.object(utils, 'get_sriov_vf_index')
    def test_get_sriov_config_with_ratelimit(self, mock_get_sriov_vf_index):
        vf_addr1 = "0000:81:00.0"
        vf_addr2 = "0000:81:01.0"
        device_id = '1572'
        port_name = 'eth0'
        vf_addr_list = "{},{}".format(vf_addr1, vf_addr2)
        num_vfs = 4
        max_tx_rate = 1000

        mock_get_sriov_vf_index.side_effect = [0, 1]
        config = self._create_sriov_vf_config(
            constants.SRIOV_DRIVER_TYPE_VFIO, 'i40evf', vf_addr_list,
            num_vfs, max_tx_rate)
        expected_vf_config = {
            '0000:81:00.0': {'addr': '0000:81:00.0', 'driver': 'vfio-pci', 'max_tx_rate': 1000,
                             'vfnumber': 0},
            '0000:81:01.0': {'addr': '0000:81:01.0', 'driver': 'vfio-pci', 'max_tx_rate': 1000,
                             'vfnumber': 1}
        }
        expected = self._get_sriov_config(
            ifname=self.iface['ifname'],
            vf_driver='vfio-pci',
            num_vfs=num_vfs,
            device_id=device_id,
            port_name=port_name,
            vf_config=expected_vf_config)
        self.assertEqual(expected, config)

    def test_get_sriov_config_vf_sibling_with_ratelimit(self):
        self._create_host_and_interface(
            constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV,
            name='sriov1',
            sriov_numvfs=4,
            iface_sriov_vf_driver=None,
            port_sriov_vf_driver="iavf",
            sriov_vfs_pci_address="0000:b1:02.0,0000:b1:02.1,0000:b1:02.2,0000:b1:02.3")
        self._create_vf_test("vf1", 2, 'vfio', lower_iface=self.iface)
        self._create_vf_test("vf2", 1, 'netdevice', lower_iface=self.iface, max_tx_rate=1000)
        self._do_update_context()

        config = interface.get_sriov_config(self.context, self.iface)

        expected_vf_config = {
            '0000:b1:02.0': {'addr': '0000:b1:02.0', 'driver': None},
            '0000:b1:02.1': {'addr': '0000:b1:02.1', 'driver': 'iavf', 'max_tx_rate': 1000,
                             'vfnumber': 1},
            '0000:b1:02.2': {'addr': '0000:b1:02.2', 'driver': 'vfio-pci'},
            '0000:b1:02.3': {'addr': '0000:b1:02.3', 'driver': 'vfio-pci'}
        }
        expected = self._get_sriov_config(
            self.iface['ifname'], None,
            num_vfs=4, pf_addr=self.port['pciaddr'],
            port_name="eth0",
            vf_config=expected_vf_config)
        self.assertEqual(expected, config)

    def test_get_fpga_config(self):
        self._create_host_and_interface(
            constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV,
            name='n3000',
            sriov_numvfs=4,
            iface_sriov_vf_driver=None,
            port_sriov_vf_driver="iavf",
            sriov_vfs_pci_address="0000:b1:02.0,0000:b1:02.1,0000:b1:02.2,0000:b1:02.3",
            pdevice="Ethernet Controller [0d58]")
        self._create_vf_test("vf1", 2, 'vfio', lower_iface=self.iface)
        self._create_vlan_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_OAM, 1, lower_iface=self.iface)
        self._do_update_context()

        config = interface.get_fpga_config(self.context, self.iface)

        # Since the interface's fpga config is used to determine whether
        # any upper vlan interfaces need to be brought up after an
        # n3000 device is reset, we ensure that no virtual (VF)
        # type interfaces are in the dict.
        expected = self._get_fpga_config(
            portname='eth0', device_id='0d58', vlans=["vlan1"])
        self.assertEqual(expected, config)

    def test_is_an_n3000_i40_device_true(self):
        self._create_host_and_interface(
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_MGMT,
            pdevice="Ethernet Controller [0d58]")
        self._do_update_context()
        self.assertTrue(
            interface.is_an_n3000_i40_device(self.context, self.iface))

    def test_find_sriov_interfaces_by_driver_one(self):
        self._create_host(constants.CONTROLLER)

        expected = ['sriov_cx4_0']
        vf_num = 2

        for ifname in expected:
            self._create_sriov_cx4_if_test(ifname, vf_num)
        self._do_update_context()

        ifaces = interface.find_sriov_interfaces_by_driver(
            self.context, constants.DRIVER_MLX_CX4)

        results = [iface['ifname'] for iface in ifaces]
        self.assertEqual(sorted(results), sorted(expected))

    def test_find_sriov_interfaces_by_driver_two(self):
        self._create_host(constants.CONTROLLER)

        expected = ['sriov_cx4_0', 'sriov_cx4_1']
        vf_num = 2

        for ifname in expected:
            self._create_sriov_cx4_if_test(ifname, vf_num)
        self._do_update_context()

        ifaces = interface.find_sriov_interfaces_by_driver(
            self.context, constants.DRIVER_MLX_CX4)

        results = [iface['ifname'] for iface in ifaces]
        self.assertEqual(sorted(results), sorted(expected))

    def _create_sriov_cx4_if_test(self, name, vf_num, **kwargs):
        port, iface = self._create_ethernet_test(
            name, constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV,
            driver=constants.DRIVER_MLX_CX4, sriov_numvfs=vf_num, **kwargs)
        return port, iface


class InterfaceHostTestCase(InterfaceTestCaseMixin, dbbase.BaseHostTestCase):

    def setUp(self):
        super(InterfaceHostTestCase, self).setUp()
        self._setup_context()
        self.expected_platform_interfaces = []
        self.expected_data_interfaces = []
        self.expected_pci_interfaces = []
        self.expected_slow_interfaces = []
        self.expected_bridged_interfaces = []
        self.expected_slave_interfaces = []
        self.expected_mlx_interfaces = []
        self.expected_bmc_interface = None
        self._assign_addresses_to_pool()
        self.exp_yaml_config = {}

    def _setup_configuration(self):
        # Personality is set to worker to avoid issues due to missing OAM
        # interface in this empty/dummy configuration
        self.host = self._create_test_host(constants.WORKER)

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.
        self.host.save(self.admin_context)
        super(InterfaceHostTestCase, self)._update_context()

    def _create_hieradata_directory(self):
        hiera_path = os.path.join(os.environ['VIRTUAL_ENV'], 'hieradata')
        if not os.path.exists(hiera_path):
            os.mkdir(hiera_path, 0o755)
        return hiera_path

    def _get_config_filename(self, hiera_directory):
        class_name = self.__class__.__name__
        return os.path.join(hiera_directory, class_name) + ".yaml"

    def test_generate_interface_config_ifupdown(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        print(config_filename)
        with open(config_filename, 'w') as config_file:
            config = self.operator.interface.get_host_config(self.host)  # pylint: disable=no-member
            self.assertIsNotNone(config)
            yaml.dump(config, config_file, default_flow_style=False)

    def test_interface_config_yaml_data_validation(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        print(config_filename)
        with open(config_filename, 'w') as config_file:
            config = self.operator.interface.get_host_config(self.host)  # pylint: disable=no-member
            self.assertIsNotNone(config)
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertTrue('platform::network::interfaces::network_config' in hiera_data.keys())
        print(f"self.exp_yaml_config={self.exp_yaml_config}")

        if len(self.exp_yaml_config):
            intf_cfg = hiera_data['platform::network::interfaces::network_config']
            for exp_intf in self.exp_yaml_config:
                self.assertTrue(exp_intf in intf_cfg.keys())
                if exp_intf != 'lo':
                    self.assertEqual(self.exp_yaml_config[exp_intf]['family'],
                                    intf_cfg[exp_intf]['family'])
                    self.assertEqual(self.exp_yaml_config[exp_intf]['method'],
                                    intf_cfg[exp_intf]['method'])
                    self.assertEqual(self.exp_yaml_config[exp_intf]['stx-description'],
                                    intf_cfg[exp_intf]['options']['stx-description'])
                    if 'bond-primary' in intf_cfg[exp_intf]['options'].keys():
                        self.assertEqual(self.exp_yaml_config[exp_intf]['bond-primary'],
                                        intf_cfg[exp_intf]['options']['bond-primary'])
                    if 'bond-slaves' in intf_cfg[exp_intf]['options'].keys():
                        self.assertEqual(self.exp_yaml_config[exp_intf]['bond-slaves'],
                                        intf_cfg[exp_intf]['options']['bond-slaves'])
                if self.exp_yaml_config[exp_intf]['tc']:
                    self.assertTrue('tc_setup.sh' in intf_cfg[exp_intf]['options']['post-up'])
                else:
                    if 'post-up' in intf_cfg[exp_intf]['options'].keys():
                        self.assertFalse('tc_setup.sh' in intf_cfg[exp_intf]['options']['post-up'])

    def test_create_interface_context(self):
        context = self.operator.interface._create_interface_context(self.host)  # pylint: disable=no-member
        self.assertIn('personality', context)
        self.assertIn('subfunctions', context)
        self.assertIn('devices', context)
        self.assertIn('ports', context)
        self.assertIn('interfaces', context)
        self.assertIn('addresses', context)
        self.assertIn('routes', context)

    def test_is_platform_interface(self):
        if not self.expected_platform_interfaces:
            self.assertTrue(True)
            return
        for iface in self.interfaces:
            expected = bool(iface['ifname'] in self.expected_platform_interfaces)
            if interface.is_platform_interface(self.context,
                                               iface) != expected:
                print("iface %s is %sa kernel interface" % (
                    iface['ifname'], ('not ' if expected else '')))

                self.assertFalse(True)

    def test_is_data_interface(self):
        if not self.expected_data_interfaces:
            self.assertTrue(True)
            return
        for iface in self.interfaces:
            expected = bool(iface['ifname'] in self.expected_data_interfaces)
            if interface.is_data_interface(self.context, iface) != expected:
                print("iface %s is %sa data interface" % (
                    iface['ifname'], ('not ' if expected else '')))
                self.assertFalse(True)

    def test_is_pci_interface(self):
        if not self.expected_pci_interfaces:
            self.assertTrue(True)
            return
        for iface in self.interfaces:
            expected = bool(iface['ifname'] in self.expected_pci_interfaces)
            if interface.is_pci_interface(iface) != expected:
                print("iface %s is %sa pci interface" % (
                    iface['ifname'], ('not ' if expected else '')))
                self.assertFalse(True)

    def test_is_a_mellanox_device(self):
        if not self.expected_mlx_interfaces:
            self.assertTrue(True)
            return
        for iface in self.interfaces:
            if (iface['iftype'] not in
                    [constants.INTERFACE_TYPE_ETHERNET, constants.INTERFACE_TYPE_VF]):
                continue
            expected = bool(iface['ifname'] in self.expected_mlx_interfaces)
            if interface.is_a_mellanox_device(self.context,
                                              iface) != expected:
                print("iface %s is %sa mellanox device" % (
                    iface['ifname'], ('not ' if expected else '')))
                self.assertFalse(True)

    def test_is_dpdk_compatible_false(self):
        if not self.expected_slow_interfaces:
            self.assertTrue(True)
            return
        for iface in self.interfaces:
            expected = bool(iface['ifname'] in self.expected_slow_interfaces)
            if interface.is_dpdk_compatible(self.context, iface) == expected:
                print("iface %s is %sdpdk compatible" % (
                    iface['ifname'], ('not ' if not expected else '')))
                self.assertFalse(True)

    def test_is_bridged_interface(self):
        if not self.expected_bridged_interfaces:
            self.assertTrue(True)
            return
        for iface in self.interfaces:
            expected = bool(
                iface['ifname'] in self.expected_bridged_interfaces)
            if interface.is_bridged_interface(self.context,
                                              iface) != expected:
                print("iface %s is %sa bridged interface" % (
                    iface['ifname'], ('not ' if expected else '')))
                self.assertFalse(True)

    def test_is_slave_interface(self):
        if not self.expected_slave_interfaces:
            self.assertTrue(True)
            return
        for iface in self.interfaces:
            expected = bool(iface['ifname'] in self.expected_slave_interfaces)
            if interface.is_slave_interface(self.context, iface) != expected:
                print("iface %s is %sa slave interface" % (
                    iface['ifname'], ('not ' if expected else '')))
                self.assertFalse(True)

    def test_needs_interface_config(self):
        expected_configured = (self.expected_platform_interfaces +
                               [self.expected_bmc_interface])
        if interface.is_worker_subfunction(self.context):
            expected_configured += (self.expected_pci_interfaces +
                                    self.expected_slow_interfaces +
                                    self.expected_mlx_interfaces)
        if (expected_configured == [None]):
            self.assertTrue(True)
            return
        for iface in self.interfaces:
            expected = bool(iface['ifname'] in expected_configured)
            actual = interface.needs_interface_config(self.context, iface)
            if expected != actual:
                print("iface %s is %sconfigured" % (
                    iface['ifname'], ('not ' if expected else '')))
                self.assertFalse(True)


class InterfaceControllerEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # ethernet interfaces.
        self.host = self._create_test_host(constants.CONTROLLER)
        self._create_ethernet_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_OAM,
                                   hostname=self.host.hostname)
        self._create_ethernet_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_MGMT,
                                   hostname=self.host.hostname)
        self._create_ethernet_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_CLUSTER_HOST,
                                   hostname=self.host.hostname)
        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceControllerEthernet, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['oam', 'mgmt', 'cluster-host']
        self.exp_yaml_config = {
            "eth0": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:oam,net:{None}',
                     'tc': False},
            "eth0:3-11": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:oam,net:{constants.NETWORK_TYPE_OAM}',
                     'tc': False},
            "eth1": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:mgmt,net:{None}', 'tc': True},
            "eth1:2": {'family': 'inet', 'method': 'static',
                       'stx-description': f'ifname:mgmt,net:{constants.NETWORK_TYPE_PXEBOOT}',
                       'tc': False},
            "eth1:2-7": {'family': 'inet', 'method': 'static',
                       'stx-description': f'ifname:mgmt,net:{constants.NETWORK_TYPE_MGMT}',
                       'tc': False},
            "eth2": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:cluster-host,net:{None}',
                     'tc': False},
            "eth2:4-15": {'family': 'inet', 'method': 'static',
                     'stx-description': 'ifname:cluster-host,'
                                   f'net:{constants.NETWORK_TYPE_CLUSTER_HOST}',
                     'tc': False},
            "lo": {'family': 'inet', 'method': 'loopback', 'stx-description': '',
                   'tc': False},
        }


class InterfaceControllerEthernetCfg2(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # ethernet interfaces. In this case the management is assigned
        # to management and cluster-host networks

        self.host = self._create_test_host(constants.CONTROLLER)

        self._create_ethernet_test('oam0', constants.INTERFACE_CLASS_PLATFORM,
                                    constants.NETWORK_TYPE_OAM,
                                    hostname=self.host.hostname)

        self._create_ethernet_test('mgmt0', constants.INTERFACE_CLASS_PLATFORM,
                                    [constants.NETWORK_TYPE_MGMT,
                                     constants.NETWORK_TYPE_CLUSTER_HOST],
                                    hostname=self.host.hostname)

        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceControllerEthernetCfg2, self).setUp()
        self.expected_bmc_interface = 'mgmt0'
        self.expected_platform_interfaces = ['oam0', 'mgmt0']
        self.exp_yaml_config = {
            "eth0": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:oam0,net:{None}',
                     'tc': False},
            "eth0:3-11": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:oam0,net:{constants.NETWORK_TYPE_OAM}',
                     'tc': False},
            "eth1": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:mgmt0,net:{None}', 'tc': True},
            "eth1:2": {'family': 'inet', 'method': 'static',
                       'stx-description': f'ifname:mgmt0,net:{constants.NETWORK_TYPE_PXEBOOT}',
                       'tc': False},
            "eth1:2-7": {'family': 'inet', 'method': 'static',
                       'stx-description': f'ifname:mgmt0,net:{constants.NETWORK_TYPE_MGMT}',
                       'tc': False},
            "eth1:4-15": {'family': 'inet', 'method': 'static',
                       'stx-description': 'ifname:mgmt0,'
                                     f'net:{constants.NETWORK_TYPE_CLUSTER_HOST}',
                       'tc': False},
            "lo": {'family': 'inet', 'method': 'loopback', 'stx-description': '',
                   'tc': False},
        }


class InterfaceControllerEthernetCfg3(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # ethernet interfaces. In this case the management is assigned
        # to management, pxeboot and cluster-host networks

        self.host = self._create_test_host(constants.CONTROLLER)

        self._create_ethernet_test('oam0', constants.INTERFACE_CLASS_PLATFORM,
                                    constants.NETWORK_TYPE_OAM,
                                    hostname=self.host.hostname)

        self._create_ethernet_test('mgmt0', constants.INTERFACE_CLASS_PLATFORM,
                                    [constants.NETWORK_TYPE_MGMT,
                                     constants.NETWORK_TYPE_CLUSTER_HOST,
                                     constants.NETWORK_TYPE_PXEBOOT],
                                    hostname=self.host.hostname)

        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceControllerEthernetCfg3, self).setUp()
        self.expected_bmc_interface = 'mgmt0'
        self.expected_platform_interfaces = ['oam0', 'mgmt0']
        self.exp_yaml_config = {
            "eth0": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:oam0,net:{None}',
                     'tc': False},
            "eth0:3-11": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:oam0,net:{constants.NETWORK_TYPE_OAM}',
                     'tc': False},
            "eth1": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:mgmt0,net:{None}', 'tc': True},
            "eth1:2": {'family': 'inet', 'method': 'static',
                       'stx-description': f'ifname:mgmt0,net:{constants.NETWORK_TYPE_PXEBOOT}',
                       'tc': False},
            "eth1:2-7": {'family': 'inet', 'method': 'static',
                       'stx-description': f'ifname:mgmt0,net:{constants.NETWORK_TYPE_MGMT}',
                       'tc': False},
            "eth1:4-15": {'family': 'inet', 'method': 'static',
                       'stx-description': 'ifname:mgmt0,'
                                     f'net:{constants.NETWORK_TYPE_CLUSTER_HOST}',
                       'tc': False},
            "lo": {'family': 'inet', 'method': 'loopback', 'stx-description': '',
                   'tc': False},
        }


class InterfaceControllerBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # aggregated ethernet interfaces.
        self.host = self._create_test_host(constants.CONTROLLER)

        self._create_bond_test('oam0', constants.INTERFACE_CLASS_PLATFORM,
                                constants.NETWORK_TYPE_OAM,
                                hostname=self.host.hostname)

        self._create_bond_test('mgmt0', constants.INTERFACE_CLASS_PLATFORM,
                                constants.NETWORK_TYPE_MGMT,
                                hostname=self.host.hostname)

        self._create_bond_test('cluster-host0', constants.INTERFACE_CLASS_PLATFORM,
                                constants.NETWORK_TYPE_CLUSTER_HOST,
                                hostname=self.host.hostname)

    def setUp(self):
        super(InterfaceControllerBond, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['eth0', 'eth1', 'oam0',
                                             'eth3', 'eth4', 'mgmt0',
                                             'eth6', 'eth7', 'cluster-host0']
        self.expected_slave_interfaces = ['eth0', 'eth1',
                                          'eth3', 'eth4',
                                          'eth6', 'eth7']
        # the slave interfaces do not match the linux name created by the test database
        # port:eth0 => ifname:eth0, port:eth1 => ifname:eth1
        # port:eth2 => ifname:eth3, port:eth3 => ifname:eth4 (differ)
        # port:eth4 => ifname:eth6, port:eth5 => ifname:eth7 (differ)
        self.exp_yaml_config = {
            "eth0": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth0,net:{None}', 'tc': False},
            "eth1": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth1,net:{None}', 'tc': False},
            "eth2": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth3,net:{None}', 'tc': False},
            "eth3": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth4,net:{None}', 'tc': False},
            "eth4": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth6,net:{None}', 'tc': False},
            "eth5": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth7,net:{None}', 'tc': False},
            "oam0": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:oam0,net:{None}',
                     'bond-slaves': 'eth0 eth1 ', 'tc': False},
            "oam0:3-11": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:oam0,net:{constants.NETWORK_TYPE_OAM}',
                     'bond-slaves': 'eth0 eth1 ', 'tc': False},
            "mgmt0": {'family': 'inet', 'method': 'manual',
                      'stx-description': f'ifname:mgmt0,net:{None}',
                      'bond-slaves': 'eth2 eth3 ', 'tc': True},
            "mgmt0:2": {'family': 'inet', 'method': 'static',
                      'stx-description': f'ifname:mgmt0,net:{constants.NETWORK_TYPE_PXEBOOT}',
                      'bond-slaves': 'eth2 eth3 ', 'tc': False},
            "mgmt0:2-7": {'family': 'inet', 'method': 'static',
                      'stx-description': f'ifname:mgmt0,net:{constants.NETWORK_TYPE_MGMT}',
                      'bond-slaves': 'eth2 eth3 ', 'tc': False},
            "cluster-host0": {'family': 'inet', 'method': 'manual',
                              'stx-description': f'ifname:cluster-host0,net:{None}',
                              'bond-slaves': 'eth4 eth5 ', 'tc': False},
            "cluster-host0:4-15": {'family': 'inet', 'method': 'static',
                              'stx-description': 'ifname:cluster-host0,'
                                     f'net:{constants.NETWORK_TYPE_CLUSTER_HOST}',
                              'bond-slaves': 'eth4 eth5 ', 'tc': False},
            "lo": {'family': 'inet', 'method': 'loopback', 'stx-description': '',
                   'tc': False},
        }


class InterfaceControllerBondCfg2(InterfaceHostTestCase):
    def _setup_configuration(self):
        self.host = self._create_test_host(constants.CONTROLLER)

        port1, iface1 = self._create_ethernet_test(ifname='bondbase0')
        port2, iface2 = self._create_ethernet_test(ifname='bondbase1')

        self._create_bond_test('oam0', constants.INTERFACE_CLASS_PLATFORM,
                                constants.NETWORK_TYPE_OAM,
                                hostname=self.host.hostname, iface1=iface1,
                                iface2=iface2, aemode='active-backup')

        self._create_bond_test('mgmt0', constants.INTERFACE_CLASS_PLATFORM,
                                constants.NETWORK_TYPE_MGMT,
                                hostname=self.host.hostname, iface1=iface1,
                                iface2=iface2, aemode='active-backup')

        self._create_bond_test('cluster-host0', constants.INTERFACE_CLASS_PLATFORM,
                                constants.NETWORK_TYPE_CLUSTER_HOST,
                                hostname=self.host.hostname)

    def setUp(self):
        super(InterfaceControllerBondCfg2, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['eth0', 'eth1', 'oam0',
                                             'mgmt0', 'eth4', 'eth5',
                                             'cluster-host0', 'bondbase0',
                                             'bondbase1']
        self.expected_slave_interfaces = ['eth4', 'eth5',
                                          'bondbase0',
                                          'bondbase1']
        # the slave interfaces do not match the linux name created by the test database
        # port:eth0 => ifname:bondbase0, port:eth1 => ifname:bondbase1
        # port:eth2 => ifname:eth4, port:eth3 => ifname:eth5 (differ)
        self.exp_yaml_config = {
            "eth0": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:bondbase0,net:{None}', 'tc': False},
            "eth1": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:bondbase1,net:{None}', 'tc': False},
            "eth2": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth4,net:{None}', 'tc': False},
            "eth3": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth5,net:{None}', 'tc': False},
            "oam0": {'family': 'inet', 'method': 'manual',
                     'bond-mode': 'active-backup', 'bond-primary': 'eth0',
                     'bond-slaves': 'eth0 eth1 ',
                     'stx-description': f'ifname:oam0,net:{None}',
                     'tc': False},
            "oam0:3-11": {'family': 'inet', 'method': 'static', 'bond-primary': 'eth0',
                          'bond-slaves': 'eth0 eth1 ',
                          'stx-description': f'ifname:oam0,net:{constants.NETWORK_TYPE_OAM}',
                          'tc': False},
            "mgmt0": {'family': 'inet', 'method': 'manual', 'bond-primary': 'eth0',
                      'bond-slaves': 'eth0 eth1 ',
                      'stx-description': f'ifname:mgmt0,net:{None}', 'tc': True},
            "mgmt0:2": {'family': 'inet', 'method': 'static', 'bond-primary': 'eth0',
                        'bond-slaves': 'eth0 eth1 ',
                        'stx-description': f'ifname:mgmt0,net:{constants.NETWORK_TYPE_PXEBOOT}',
                        'tc': False},
            "mgmt0:2-7": {'family': 'inet', 'method': 'static', 'bond-primary': 'eth0',
                          'bond-slaves': 'eth0 eth1 ',
                          'stx-description': f'ifname:mgmt0,net:{constants.NETWORK_TYPE_MGMT}',
                          'tc': False},
            "cluster-host0": {'family': 'inet', 'method': 'manual', 'bond-primary': 'eth2',
                              'bond-slaves': 'eth2 eth3 ',
                              'stx-description': f'ifname:cluster-host0,net:{None}',
                              'tc': False},
            "cluster-host0:4-15": {'family': 'inet', 'method': 'static', 'bond-primary': 'eth2',
                                   'bond-slaves': 'eth2 eth3 ',
                                   'stx-description': 'ifname:cluster-host0,'
                                   f'net:{constants.NETWORK_TYPE_CLUSTER_HOST}',
                                   'tc': False},
            "lo": {'family': 'inet', 'method': 'loopback', 'stx-description': '',
                   'tc': False},
        }


class InterfaceControllerVlanOverBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # vlan interfaces over aggregated ethernet interfaces
        self.host = self._create_test_host(constants.CONTROLLER)
        bond = self._create_bond_test('pxeboot0', constants.INTERFACE_CLASS_PLATFORM,
                                      constants.NETWORK_TYPE_PXEBOOT,
                                      hostname=self.host.hostname)

        self._create_vlan_test('oam0', constants.INTERFACE_CLASS_PLATFORM,
                                constants.NETWORK_TYPE_OAM, 1, bond,
                                hostname=self.host.hostname)

        self._create_vlan_test('mgmt0',
                                constants.INTERFACE_CLASS_PLATFORM,
                                constants.NETWORK_TYPE_MGMT, 2, bond,
                                hostname=self.host.hostname)

        self._create_vlan_test('cluster-host0', constants.INTERFACE_CLASS_PLATFORM,
                                constants.NETWORK_TYPE_CLUSTER_HOST, 3, bond,
                                hostname=self.host.hostname)

        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceControllerVlanOverBond, self).setUp()
        self.expected_bmc_interface = 'pxeboot'
        self.expected_platform_interfaces = ['eth0', 'eth1', 'pxeboot0',
                                             'oam0', 'mgmt0', 'cluster-host0']
        self.expected_slave_interfaces = ['eth0', 'eth1']
        self.exp_yaml_config = {
            "eth0": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth0,net:{None}', 'tc': False},
            "eth1": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth1,net:{None}', 'tc': False},
            "pxeboot0": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:pxeboot0,net:{None}',
                     'bond-slaves': 'eth0 eth1 ', 'tc': False},
            "pxeboot0:2": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:pxeboot0,net:{constants.NETWORK_TYPE_PXEBOOT}',
                     'bond-slaves': 'eth0 eth1 ', 'tc': False},
            "vlan1": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:oam0,net:{None}',
                     'tc': False},
            "vlan1:3-11": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:oam0,net:{constants.NETWORK_TYPE_OAM}',
                     'tc': False},
            "vlan2": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:mgmt0,net:{None}',
                     'tc': True},
            "vlan2:2-7": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:mgmt0,net:{constants.NETWORK_TYPE_MGMT}',
                     'tc': False},
            "vlan3": {'family': 'inet', 'method': 'manual',
                      'stx-description': f'ifname:cluster-host0,net:{None}',
                      'tc': False},
            "vlan3:4-15": {'family': 'inet', 'method': 'static',
                              'stx-description': 'ifname:cluster-host0,'
                                     f'net:{constants.NETWORK_TYPE_CLUSTER_HOST}',
                                     'tc': False},
            "lo": {'family': 'inet', 'method': 'loopback', 'stx-description': '',
                   'tc': False},
        }


class InterfaceControllerVlanOverEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # vlan interfaces over ethernet interfaces
        self.host = self._create_test_host(constants.CONTROLLER)

        port, iface = self._create_ethernet_test(
            'pxeboot', constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT, hostname=self.host.hostname)

        self._create_vlan_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_OAM, 1, iface,
                               hostname=self.host.hostname)

        self._create_vlan_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_MGMT, 2, iface,
                               hostname=self.host.hostname)

        self._create_vlan_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_CLUSTER_HOST, 3, iface,
                               hostname=self.host.hostname)

        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceControllerVlanOverEthernet, self).setUp()
        self.expected_bmc_interface = 'pxeboot'
        self.expected_platform_interfaces = ['eth0', 'pxeboot', 'oam',
                                             'mgmt', 'cluster-host']


class InterfaceComputeEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # worker and all interfaces are ethernet interfaces. Do not explicit
        # attach the PXEboot network
        self.host = self._create_test_host(constants.WORKER)
        _, if_mgmt = self._create_ethernet_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_MGMT,
                                   hostname=self.host.hostname)
        _, if_clhost = self._create_ethernet_test('cluster-host',
                                   constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_CLUSTER_HOST,
                                   hostname=self.host.hostname)
        self._create_ethernet_test('data', constants.INTERFACE_CLASS_DATA,
                                   hostname=self.host.hostname)
        self._create_ethernet_test('sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
                                   constants.NETWORK_TYPE_PCI_SRIOV,
                                   hostname=self.host.hostname)
        self._create_ethernet_test('pthru', constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                                   hostname=self.host.hostname)
        self._create_ethernet_test('slow', constants.INTERFACE_CLASS_DATA,
                                   constants.NETWORK_TYPE_DATA,
                                   dpdksupport=False,
                                   hostname=self.host.hostname)
        self._create_ethernet_test('mlx5', constants.INTERFACE_CLASS_DATA,
                                   constants.NETWORK_TYPE_DATA,
                                   driver=constants.DRIVER_MLX_CX4,
                                   hostname=self.host.hostname)
        self._create_ethernet_test('none')

        self._create_address_for_interface(if_mgmt)
        self._create_address_for_interface(if_clhost)

    def setUp(self):
        super(InterfaceComputeEthernet, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['mgmt', 'cluster-host']
        self.expected_data_interfaces = ['slow', 'data', 'mlx5']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.expected_slow_interfaces = ['slow']
        self.expected_bridged_interfaces = ['slow']
        self.expected_slave_interfaces = []
        self.expected_mlx_interfaces = ['mlx5']
        self.exp_yaml_config = {
            "eth0": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:mgmt,net:{None}', 'tc': True},
            "eth0:2": {'family': 'inet', 'method': 'dhcp',
                     'stx-description': f'ifname:mgmt,net:{constants.NETWORK_TYPE_PXEBOOT}',
                     'tc': False},
            "eth0:2-37": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:mgmt,net:{constants.NETWORK_TYPE_MGMT}',
                     'tc': False},
            "eth1": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:cluster-host,'
                     f'net:{None}', 'tc': False},
            "eth1:4-38": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:cluster-host,'
                     f'net:{constants.NETWORK_TYPE_CLUSTER_HOST}', 'tc': False},
            "eth3": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:sriov,net:{None}', 'tc': False},
            "eth4": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:pthru,net:{None}', 'tc': False},
            "eth5": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:slow,net:{None}', 'tc': False},
            "eth6": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:mlx5,net:{None}', 'tc': False},
            "lo": {'family': 'inet', 'method': 'loopback', 'stx-description': '',
                   'tc': False},
        }


class InterfaceComputeEthernetCfg2(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # worker and all interfaces are ethernet interfaces.
        # Explicitly assign PXEboot network with the management network
        self.host = self._create_test_host(constants.WORKER)
        _, if_mgmt = self._create_ethernet_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                                    [constants.NETWORK_TYPE_MGMT,
                                     constants.NETWORK_TYPE_PXEBOOT],
                                    hostname=self.host.hostname)
        _, if_clhost = self._create_ethernet_test('cluster-host',
                                    constants.INTERFACE_CLASS_PLATFORM,
                                    constants.NETWORK_TYPE_CLUSTER_HOST,
                                    hostname=self.host.hostname)
        self._create_ethernet_test('data', constants.INTERFACE_CLASS_DATA,
                                    hostname=self.host.hostname)
        self._create_ethernet_test('sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
                                    constants.NETWORK_TYPE_PCI_SRIOV,
                                    hostname=self.host.hostname)
        self._create_ethernet_test('pthru', constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                    constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                                    hostname=self.host.hostname)
        self._create_ethernet_test('slow', constants.INTERFACE_CLASS_DATA,
                                    constants.NETWORK_TYPE_DATA,
                                    dpdksupport=False,
                                    hostname=self.host.hostname)
        self._create_ethernet_test('mlx5', constants.INTERFACE_CLASS_DATA,
                                    constants.NETWORK_TYPE_DATA,
                                    driver=constants.DRIVER_MLX_CX4,
                                    hostname=self.host.hostname)
        self._create_ethernet_test('none')

        self._create_address_for_interface(if_mgmt)
        self._create_address_for_interface(if_clhost)

    def setUp(self):
        super(InterfaceComputeEthernetCfg2, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['mgmt', 'cluster-host']
        self.expected_data_interfaces = ['slow', 'data', 'mlx5']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.expected_slow_interfaces = ['slow']
        self.expected_bridged_interfaces = ['slow']
        self.expected_slave_interfaces = []
        self.expected_mlx_interfaces = ['mlx5']
        self.exp_yaml_config = {
            "eth0": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:mgmt,net:{None}', 'tc': True},
            "eth0:2": {'family': 'inet', 'method': 'dhcp',
                     'stx-description': f'ifname:mgmt,net:{constants.NETWORK_TYPE_PXEBOOT}',
                     'tc': False},
            "eth0:2-37": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:mgmt,net:{constants.NETWORK_TYPE_MGMT}',
                     'tc': False},
            "eth1": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:cluster-host,'
                     f'net:{None}', 'tc': False},
            "eth1:4-38": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:cluster-host,'
                     f'net:{constants.NETWORK_TYPE_CLUSTER_HOST}', 'tc': False},
            "eth3": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:sriov,net:{None}', 'tc': False},
            "eth4": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:pthru,net:{None}', 'tc': False},
            "eth5": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:slow,net:{None}', 'tc': False},
            "eth6": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:mlx5,net:{None}', 'tc': False},
            "lo": {'family': 'inet', 'method': 'loopback', 'stx-description': '',
                   'tc': False},
        }


class InterfaceComputeEthernetCfg3(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # worker and all interfaces are ethernet interfaces.
        # explicitly assign pxeboot network with the cluster-host network
        self.host = self._create_test_host(constants.WORKER)
        _, if_mgmt = self._create_ethernet_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                                    [constants.NETWORK_TYPE_MGMT],
                                    hostname=self.host.hostname)
        _, if_clhost = self._create_ethernet_test('cluster-host',
                                    constants.INTERFACE_CLASS_PLATFORM,
                                    [constants.NETWORK_TYPE_CLUSTER_HOST,
                                     constants.NETWORK_TYPE_PXEBOOT],
                                    hostname=self.host.hostname)
        self._create_ethernet_test('data', constants.INTERFACE_CLASS_DATA,
                                    hostname=self.host.hostname)
        self._create_ethernet_test('sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
                                    constants.NETWORK_TYPE_PCI_SRIOV,
                                    hostname=self.host.hostname)
        self._create_ethernet_test('pthru', constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                    constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                                    hostname=self.host.hostname)
        self._create_ethernet_test('slow', constants.INTERFACE_CLASS_DATA,
                                    constants.NETWORK_TYPE_DATA,
                                    dpdksupport=False,
                                    hostname=self.host.hostname)
        self._create_ethernet_test('mlx5', constants.INTERFACE_CLASS_DATA,
                                    constants.NETWORK_TYPE_DATA,
                                    driver=constants.DRIVER_MLX_CX4,
                                    hostname=self.host.hostname)
        self._create_ethernet_test('none')

        self._create_address_for_interface(if_mgmt)
        self._create_address_for_interface(if_clhost)

    def setUp(self):
        super(InterfaceComputeEthernetCfg3, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['mgmt', 'cluster-host']
        self.expected_data_interfaces = ['slow', 'data', 'mlx5']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.expected_slow_interfaces = ['slow']
        self.expected_bridged_interfaces = ['slow']
        self.expected_slave_interfaces = []
        self.expected_mlx_interfaces = ['mlx5']
        self.exp_yaml_config = {
            "eth0": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:mgmt,net:{None}',
                     'tc': True},
            "eth0:2-37": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:mgmt,net:{constants.NETWORK_TYPE_MGMT}',
                     'tc': False},
            "eth1": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:cluster-host,net:{None}', 'tc': False},
            "eth1:2": {'family': 'inet', 'method': 'dhcp',
                     'stx-description': f'ifname:cluster-host,net:{constants.NETWORK_TYPE_PXEBOOT}',
                     'tc': False},
            "eth1:4-38": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:cluster-host,'
                     f'net:{constants.NETWORK_TYPE_CLUSTER_HOST}', 'tc': False},
            "eth3": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:sriov,net:{None}', 'tc': False},
            "eth4": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:pthru,net:{None}', 'tc': False},
            "eth5": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:slow,net:{None}', 'tc': False},
            "eth6": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:mlx5,net:{None}', 'tc': False},
            "lo": {'family': 'inet', 'method': 'loopback', 'stx-description': '',
                   'tc': False},
        }


class InterfaceComputeVlanOverEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # worker and all interfaces are vlan interfaces over ethernet
        # interfaces.
        self.host = self._create_test_host(constants.WORKER)
        port, iface = self._create_ethernet_test(
            'pxeboot', constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_MGMT, 2, iface)
        self._create_vlan_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_CLUSTER_HOST, 3)
        # since the system vswitch_type is ovs-dpdk, it will not generate config for 'data'
        self._create_vlan_test('data', constants.INTERFACE_CLASS_DATA,
                               constants.NETWORK_TYPE_DATA, 5)
        self._create_ethernet_test('sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru', constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceComputeVlanOverEthernet, self).setUp()
        self.expected_bmc_interface = 'pxeboot'
        self.expected_platform_interfaces = ['pxeboot', 'mgmt',
                                             'eth2', 'cluster-host']
        self.expected_data_interfaces = ['eth4', 'data']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.exp_yaml_config = {
            "eth0": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:pxeboot,net:{None}',
                     'tc': False},
            "eth0:2": {'family': 'inet', 'method': 'dhcp',
                     'stx-description': f'ifname:pxeboot,net:{constants.NETWORK_TYPE_PXEBOOT}',
                     'tc': False},
            "eth1": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth2,net:{None}', 'tc': False},
            "vlan2": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:mgmt,net:{None}',
                     'tc': True},
            "vlan2:2-0": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:mgmt,net:{constants.NETWORK_TYPE_MGMT}',
                     'tc': False},
            "vlan3": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:cluster-host,net:{None}',
                     'tc': False},
            "vlan3:4-0": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:cluster-host,'
                                    f'net:{constants.NETWORK_TYPE_CLUSTER_HOST}',
                                    'tc': False},
            "eth3": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:sriov,net:{None}', 'tc': False},
            "eth4": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:pthru,net:{None}', 'tc': False},
            "lo": {'family': 'inet', 'method': 'loopback', 'stx-description': '',
                   'tc': False},
        }


class InterfaceComputeVlanOverEthernetCfg2(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # worker and all interfaces are vlan interfaces over ethernet
        # interfaces, mgmt interface handles mgmt and cluster-hos networks
        self.host = self._create_test_host(constants.WORKER)

        system_dict = self.system.as_dict()
        system_dict['capabilities']['vswitch_type'] = constants.VSWITCH_TYPE_NONE
        dbutils.update_test_isystem(system_dict)

        port, iface = self._create_ethernet_test(
            'pxeboot', constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT)
        if_mgmt = self._create_vlan_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                               [constants.NETWORK_TYPE_MGMT,
                                constants.NETWORK_TYPE_CLUSTER_HOST],
                               2, iface)
        self._create_vlan_test('data', constants.INTERFACE_CLASS_DATA,
                               constants.NETWORK_TYPE_DATA, 5)
        self._create_ethernet_test('sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru', constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

        self._create_address_for_interface(if_mgmt, constants.NETWORK_TYPE_MGMT)
        self._create_address_for_interface(if_mgmt, constants.NETWORK_TYPE_CLUSTER_HOST)

    def setUp(self):
        super(InterfaceComputeVlanOverEthernetCfg2, self).setUp()
        self.exp_yaml_config = {
            "data": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:data,net:{None}', 'tc': False},
            "eth0": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:pxeboot,net:{None}',
                     'tc': False},
            "eth0:2": {'family': 'inet', 'method': 'dhcp',
                     'stx-description': f'ifname:pxeboot,net:{constants.NETWORK_TYPE_PXEBOOT}',
                     'tc': False},
            "eth1": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth2,net:{None}', 'tc': False},
            "vlan2": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:mgmt,net:{None}', 'tc': True},
            "vlan2:2-37": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:mgmt,net:{constants.NETWORK_TYPE_MGMT}',
                     'tc': False},
            "vlan2:4-38": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:mgmt,'
                                    f'net:{constants.NETWORK_TYPE_CLUSTER_HOST}',
                     'tc': False},
            "eth2": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:sriov,net:{None}', 'tc': False},
            "eth3": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:pthru,net:{None}', 'tc': False},
            "lo": {'family': 'inet', 'method': 'loopback', 'stx-description': '',
                   'tc': False},
        }


class InterfaceComputeVfOverSriov(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # worker and all interfaces are ethernet interfaces, aside from
        # a VF interface over SR-IOV
        self.host = self._create_test_host(constants.WORKER)
        self._create_ethernet_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_MGMT)
        self._create_ethernet_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_CLUSTER_HOST)
        self._create_ethernet_test('data', constants.INTERFACE_CLASS_DATA)
        port, iface = self._create_ethernet_test(
            'sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=2,
            sriov_vf_driver=None)
        self._create_vf_test("vf", 1, None, lower_iface=iface)
        self._create_ethernet_test('pthru', constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

        # Mellanox devices should be identified correctly whether they are
        # the SR-IOV interface or a VF interface on top of another.
        # Driver can also be a string of different comma separated driver
        # names, this also tests for that
        port, iface = self._create_ethernet_test(
            'mlx5', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=2,
            driver=('%s,%s' % (constants.DRIVER_MLX_CX4, constants.DRIVER_MLX_CX4)))
        self._create_vf_test('vf_mlx5', 1, None, lower_iface=iface)

    def setUp(self):
        super(InterfaceComputeVfOverSriov, self).setUp()
        self.expected_bmc_interface = 'pxeboot'
        self.expected_platform_interfaces = ['pxeboot', 'mgmt',
                                             'eth2', 'cluster-host']
        self.expected_data_interfaces = ['eth4', 'data']
        self.expected_pci_interfaces = ['sriov', 'pthru', 'vf', 'mlx5', 'vf_mlx5']
        self.expected_mlx_interfaces = ['mlx5', 'vf_mlx5']


class InterfaceComputeBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # worker and all interfaces are aggregated ethernet interfaces.
        self.host = self._create_test_host(constants.WORKER)
        if_mgmt = self._create_bond_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_MGMT)
        if_clhost = self._create_bond_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_CLUSTER_HOST)
        self._create_bond_test('data', constants.INTERFACE_CLASS_DATA,
                               constants.NETWORK_TYPE_DATA)
        self._create_ethernet_test('sriov',
                                   constants.INTERFACE_CLASS_PCI_SRIOV,
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

        self._create_address_for_interface(if_mgmt)
        self._create_address_for_interface(if_clhost)

    def setUp(self):
        super(InterfaceComputeBond, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['eth0', 'eth1', 'mgmt',
                                             'eth3', 'eth4', 'cluster-host']
        self.expected_data_interfaces = ['eth6', 'eth7', 'data',
                                         'eth12', 'eth13', 'ex']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.expected_slave_interfaces = ['eth0', 'eth1', 'eth3', 'eth4',
                                          'eth6', 'eth7', 'eth9', 'eth10',
                                          'eth12', 'eth13']
        self.exp_yaml_config = {
            "eth0": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth0,net:{None}', 'tc': False},
            "eth1": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth1,net:{None}', 'tc': False},
            "mgmt": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:mgmt,net:{None}',
                     'bond-slaves': 'eth0 eth1 ', 'tc': True},
            "mgmt:2": {'family': 'inet', 'method': 'dhcp',
                     'stx-description': f'ifname:mgmt,net:{constants.NETWORK_TYPE_PXEBOOT}',
                     'bond-slaves': 'eth0 eth1 ', 'tc': False},
            "mgmt:2-37": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:mgmt,net:{constants.NETWORK_TYPE_MGMT}',
                     'bond-slaves': 'eth0 eth1 ', 'tc': False},
            "eth2": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth3,net:{None}', 'tc': False},
            "eth3": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth4,net:{None}', 'tc': False},
            "cluster-host": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:cluster-host,net:{None}',
                     'bond-slaves': 'eth2 eth3 ', 'tc': False},
            "cluster-host:4-38": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:cluster-host,'
                     f'net:{constants.NETWORK_TYPE_CLUSTER_HOST}',
                     'bond-slaves': 'eth2 eth3 ', 'tc': False},
            "eth6": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:sriov,net:{None}', 'tc': False},
            "eth7": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:pthru,net:{None}', 'tc': False},
            "lo": {'family': 'inet', 'method': 'loopback', 'stx-description': '',
                   'tc': False},
        }


class InterfaceComputeVlanOverBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # worker and all interfaces are vlan interfaces over ethernet
        # interfaces.
        self.host = self._create_test_host(constants.WORKER)
        bond = self._create_bond_test('pxeboot',
                                      constants.INTERFACE_CLASS_PLATFORM,
                                      constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_OAM, 1, bond)
        self._create_vlan_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_MGMT, 2, bond)
        self._create_vlan_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_CLUSTER_HOST, 3, bond)
        bond2 = self._create_bond_test('bond2')
        self._create_vlan_test('data', constants.INTERFACE_CLASS_DATA,
                               constants.NETWORK_TYPE_DATA, 5, bond2)
        self._create_ethernet_test('sriov',
                                   constants.INTERFACE_CLASS_PCI_SRIOV,
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceComputeVlanOverBond, self).setUp()
        self.expected_platform_interfaces = ['eth0', 'eth1', 'pxeboot',
                                             'oam', 'mgmt', 'cluster-host']
        self.expected_data_interfaces = ['eth6', 'eth7', 'bond2', 'data',
                                         'eth14', 'eth15']
        self.expected_slave_interfaces = ['eth0', 'eth1',
                                          'eth6', 'eth7',
                                          'eth10', 'eth11']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.exp_yaml_config = {
            "eth0": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth0,net:{None}', 'tc': False},
            "eth1": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:eth1,net:{None}', 'tc': False},
            "pxeboot": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:pxeboot,net:{None}',
                     'bond-slaves': 'eth0 eth1 ', 'tc': False},
            "pxeboot:2": {'family': 'inet', 'method': 'dhcp',
                     'stx-description': f'ifname:pxeboot,net:{constants.NETWORK_TYPE_PXEBOOT}',
                     'bond-slaves': 'eth0 eth1 ', 'tc': False},
            "vlan1": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:oam,net:{None}',
                     'tc': False},
            "vlan1:3-0": {'family': 'inet', 'method': 'dhcp',
                     'stx-description': f'ifname:oam,net:{constants.NETWORK_TYPE_OAM}',
                     'tc': False},
            "vlan2": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:mgmt,net:{None}',
                     'tc': True},
            "vlan2:2-0": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:mgmt,net:{constants.NETWORK_TYPE_MGMT}',
                     'tc': False},
            "vlan3": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:cluster-host,net:{None}',
                                    'tc': False},
            "vlan3:4-0": {'family': 'inet', 'method': 'static',
                     'stx-description': f'ifname:cluster-host,'
                                    f'net:{constants.NETWORK_TYPE_CLUSTER_HOST}',
                                    'tc': False},
            "eth4": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:sriov,net:{None}', 'tc': False},
            "eth5": {'family': 'inet', 'method': 'manual',
                     'stx-description': f'ifname:pthru,net:{None}', 'tc': False},
            "lo": {'family': 'inet', 'method': 'loopback', 'stx-description': '',
                   'tc': False},
        }


class InterfaceCpeEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a controller subfunction and all interfaces are
        # ethernet interfaces.
        self.host = self._create_test_host(constants.CONTROLLER)
        self._create_ethernet_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_OAM)
        self._create_ethernet_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_MGMT)
        self._create_ethernet_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_CLUSTER_HOST)
        self._create_ethernet_test('data', constants.INTERFACE_CLASS_DATA,
                                   constants.NETWORK_TYPE_DATA)
        self._create_ethernet_test('sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru', constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)
        port, iface = (
            self._create_ethernet_test('slow', constants.INTERFACE_CLASS_DATA,
                                       constants.NETWORK_TYPE_DATA,
                                       dpdksupport=False))
        port, iface = (
            self._create_ethernet_test('mlx5', constants.INTERFACE_CLASS_DATA,
                                       constants.NETWORK_TYPE_DATA,
                                       driver=constants.DRIVER_MLX_CX4))
        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceCpeEthernet, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['oam', 'mgmt', 'cluster-host']
        self.expected_data_interfaces = ['slow', 'data', 'mlx5']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.expected_slow_interfaces = ['slow']
        self.expected_bridged_interfaces = ['slow']
        self.expected_slave_interfaces = []
        self.expected_mlx_interfaces = ['mlx5']


class InterfaceCpeVlanOverEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a controller subfunction and all interfaces are
        # vlan interfaces over ethernet interfaces.
        self.host = self._create_test_host(constants.CONTROLLER)
        port, iface = self._create_ethernet_test(
            'pxeboot', constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_OAM, 1, iface)
        self._create_vlan_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_MGMT, 2, iface)
        self._create_vlan_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_CLUSTER_HOST, 3)
        self._create_vlan_test('data', constants.INTERFACE_CLASS_DATA,
                               constants.NETWORK_TYPE_DATA, 5)
        self._create_ethernet_test('sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru', constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceCpeVlanOverEthernet, self).setUp()
        self.expected_bmc_interface = 'pxeboot'
        self.expected_platform_interfaces = ['pxeboot', 'mgmt', 'oam',
                                             'eth3', 'cluster-host']
        self.expected_data_interfaces = ['eth5', 'data']
        self.expected_pci_interfaces = ['sriov', 'pthru']


class InterfaceCpeBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a controller subfunction and all interfaces are
        # aggregated ethernet interfaces.
        self.host = self._create_test_host(constants.CONTROLLER)
        self._create_bond_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_OAM)
        self._create_bond_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_MGMT)
        self._create_bond_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_CLUSTER_HOST)
        self._create_bond_test('data', constants.INTERFACE_CLASS_DATA,
                               constants.NETWORK_TYPE_DATA)
        self._create_ethernet_test('sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru', constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceCpeBond, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['eth0', 'eth1', 'oam',
                                             'eth3', 'eth4', 'mgmt',
                                             'eth6', 'eth7', 'cluster-host']
        self.expected_data_interfaces = ['eth9', 'eth10', 'data']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.expected_slave_interfaces = ['eth0', 'eth1', 'eth3', 'eth4',
                                          'eth6', 'eth7', 'eth9', 'eth10',
                                          'eth12', 'eth13']


class InterfaceCpeVlanOverBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a controller subfunction and all interfaces are
        # vlan interfaces over aggregated ethernet interfaces.
        self.host = self._create_test_host(constants.CONTROLLER)
        bond = self._create_bond_test('pxeboot', constants.INTERFACE_CLASS_PLATFORM,
                                      constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_OAM, 1, bond)
        self._create_vlan_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_MGMT, 2, bond)
        self._create_vlan_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_CLUSTER_HOST, 3, bond)
        bond2 = self._create_bond_test('bond4')
        self._create_vlan_test('data', constants.INTERFACE_CLASS_DATA,
                               constants.NETWORK_TYPE_DATA, 5,
                               bond2)
        self._create_ethernet_test('sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru', constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceCpeVlanOverBond, self).setUp()
        self.expected_platform_interfaces = ['eth0', 'eth1', 'pxeboot',
                                             'oam', 'mgmt', 'cluster-host']
        self.expected_data_interfaces = ['eth6', 'eth7', 'bond4', 'data']
        self.expected_slave_interfaces = ['eth0', 'eth1',
                                          'eth6', 'eth7']
        self.expected_pci_interfaces = ['sriov', 'pthru']


class InterfaceCpeComputeEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a worker subfunction and all interfaces are
        # ethernet interfaces.
        self.host = self._create_test_host(constants.CONTROLLER, constants.WORKER)
        self._create_ethernet_test('data', constants.INTERFACE_CLASS_DATA,
                                   constants.NETWORK_TYPE_DATA)
        self._create_ethernet_test('sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru', constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)
        self._create_ethernet_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_OAM)
        self._create_ethernet_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_MGMT)
        self._create_ethernet_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_CLUSTER_HOST)
        port, iface = (
            self._create_ethernet_test('slow', constants.INTERFACE_CLASS_DATA,
                                       constants.NETWORK_TYPE_DATA,
                                       dpdksupport=False))
        port, iface = (
            self._create_ethernet_test('mlx5', constants.INTERFACE_CLASS_DATA,
                                       constants.NETWORK_TYPE_DATA,
                                       driver=constants.DRIVER_MLX_CX4))
        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceCpeComputeEthernet, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['oam', 'mgmt', 'cluster-host']
        self.expected_data_interfaces = ['slow', 'data', 'mlx5']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.expected_slow_interfaces = ['slow']
        self.expected_bridged_interfaces = ['slow']
        self.expected_slave_interfaces = []
        self.expected_mlx_interfaces = ['mlx5']


class InterfaceCpeComputeVlanOverEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a worker subfunction and all interfaces are
        # vlan interfaces over ethernet interfaces.
        self.host = self._create_test_host(constants.CONTROLLER, constants.WORKER)
        port, iface = self._create_ethernet_test(
            'pxeboot', constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_OAM, 1, iface)
        self._create_vlan_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_MGMT, 2, iface)
        self._create_vlan_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_CLUSTER_HOST, 3)
        self._create_vlan_test('data', constants.INTERFACE_CLASS_DATA,
                               constants.NETWORK_TYPE_DATA, 5)
        self._create_ethernet_test('sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru', constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceCpeComputeVlanOverEthernet, self).setUp()
        self.expected_bmc_interface = 'pxeboot'
        self.expected_platform_interfaces = ['pxeboot', 'oam', 'mgmt',
                                             'eth3', 'cluster-host']
        self.expected_data_interfaces = ['eth5', 'data']
        self.expected_pci_interfaces = ['sriov', 'pthru']


class InterfaceCpeComputeBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a worker subfunction and all interfaces are
        # aggregated ethernet interfaces.
        self.host = self._create_test_host(constants.CONTROLLER, constants.WORKER)
        self._create_bond_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_OAM)
        self._create_bond_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_MGMT)
        self._create_bond_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_CLUSTER_HOST)
        self._create_bond_test('data', constants.INTERFACE_CLASS_DATA,
                               constants.NETWORK_TYPE_DATA)
        self._create_ethernet_test('sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru', constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceCpeComputeBond, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['eth0', 'eth1', 'oam',
                                             'eth3', 'eth4', 'mgmt',
                                             'eth6', 'eth7', 'cluster-host']
        self.expected_data_interfaces = ['eth9', 'eth10', 'data']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.expected_slave_interfaces = ['eth0', 'eth1', 'eth3', 'eth4',
                                          'eth6', 'eth7', 'eth9', 'eth10',
                                          'eth12', 'eth13']


class InterfaceCpeComputeVlanOverBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a worker subfunction and all interfaces are
        # vlan interfaces over aggregated ethernet interfaces.
        self.host = self._create_test_host(constants.CONTROLLER, constants.WORKER)
        bond = self._create_bond_test('pxeboot',
                                      constants.INTERFACE_CLASS_PLATFORM,
                                      constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_OAM, 1, bond)
        self._create_vlan_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_MGMT, 2, bond)
        self._create_vlan_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_CLUSTER_HOST, 3, bond)
        bond2 = self._create_bond_test('bond2')
        self._create_vlan_test('data', constants.INTERFACE_CLASS_DATA,
                               constants.NETWORK_TYPE_DATA, 5,
                               bond2)
        self._create_ethernet_test('sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru', constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceCpeComputeVlanOverBond, self).setUp()
        self.expected_platform_interfaces = ['eth0', 'eth1', 'pxeboot',
                                             'oam', 'mgmt', 'cluster-host']
        self.expected_data_interfaces = ['eth6', 'eth7', 'bond2', 'data']
        self.expected_slave_interfaces = ['eth0', 'eth1',
                                          'eth6', 'eth7']
        self.expected_pci_interfaces = ['sriov', 'pthru']


# Mnemonics for building expected interface configs
NET = 'net'                 # Expected network type, constants.NETWORK_TYPE_<type> or None
FAMILY = 'family'           # Expected family, INET or INET6
INET = 'inet'               # Value 'inet' for expected FAMILY
INET6 = 'inet6'             # Value 'inet6' for expected FAMILY
METHOD = 'method'           # Expected method, STATIC or MANUAL
STATIC = 'static'           # Value 'static' for expected METHOD
MANUAL = 'manual'           # Value 'manual' for expected METHOD
DHCP = 'dhcp'               # Value 'dhcp' for expected METHOD
OPTIONS = 'options'         # Expected options, dictionary
GATEWAY = 'gateway'         # Option 'gateway', True if gateway address must be present
ALLOW = 'allow'             # Option 'allow-<master>' for bond slaves, True if must be present
UP = 'up'                   # Option 'up' operation, should be a list of command mnemonics
PRE_UP = 'pre-up'           # Option 'pre-up' operation, should be a list of command mnemonics
POST_UP = 'post-up'         # Option 'post-up' operation, should be a list of command mnemonics
DOWN = 'down'               # Option 'down' operation, should be a list of command mnemonics
PRE_DOWN = 'pre-down'       # Option 'pre-down' operation, should be a list of command mnemonics
POST_DOWN = 'post-down'     # Option 'post-down' operation, should be a list of command mnemonics
IPV6_CFG = 'ipv6-cfg'       # Operation command to set IPv6 conf params like autoconf and accept_ra
SET_MTU = 'set-mtu'         # Operation command to set MTU
SET_TC = 'set-tc'           # Operation command to configure traffic classifier
VLAN_MOD = 'vlan-mod'       # Operation command to add vlan kernel module
VLAN_ADD = 'vlan-add'       # Operation command to create vlan
VLAN_DEL = 'vlan-del'       # Operation command to remove vlan
PROMISC_ON = 'prmsc-on'     # Operation command to enable promiscuous mode
UNDEPR = 'undepr'           # Operation command to undeprecate IPv6 address
SRIOV = 'sriov'             # Operation command to setup sriov
PTHROUGH = 'pthrough'       # Operation command to setup pass-through
BOND_CHECK = 'bond-check'   # Operation command to check bond interface directory
BOND_SETUP = 'bond-stp'     # Operation command to setup bond
DIS_DAD = 'disable-dad'     # Operation command to disable DAD
MODES = 'modes'             # List of modes where this configuration is expected, all if unspecified
SS_IPV4 = 'ss-ipv4'         # Configuration is expected for Single Stack IPv4 mode
SS_IPV6 = 'ss-ipv6'         # Configuration is expected for Single Stack IPv6 mode
DS_IPV4 = 'ds-ipv4'         # Configuration is expected for Dual Stack / Primary IPv4 mode
DS_IPV6 = 'ds-ipv6'         # Configuration is expected for Dual Stack / Primary IPv6 mode
OPERATIONS = [UP, PRE_UP, POST_UP, DOWN, PRE_DOWN, POST_DOWN]


class InterfaceConfigTestMixin(InterfaceTestCaseMixin):
    def setUp(self):
        super(InterfaceConfigTestMixin, self).setUp()
        self._setup_context()

    def _setup_configuration(self):
        self.interface_index = {}
        self.new_address_index = {}

    def _update_context(self):
        # skip automatic context update
        pass

    def _do_update_context(self):
        super(InterfaceConfigTestMixin, self)._update_context()

    debuglevel = int(os.environ.get('TOX_DEBUG_LEVEL', '0'))

    def _include_interface(self, iface, info):
        iface_dict = {
            'interface': iface,
            'info': info,
            'networks': {
                None: {
                    'network': None,
                    'addresses': {
                        constants.IPV4_FAMILY: [],
                        constants.IPV6_FAMILY: [],
                    }
                }
            },
            'gateways': {}
        }
        self.interface_index[iface.ifname] = iface_dict
        return iface_dict

    def _include_network(self, iface, network):
        self.interface_index[iface.ifname]['networks'][network.id] = {
            'network': network,
            'addresses': {
                constants.IPV4_FAMILY: [],
                constants.IPV6_FAMILY: [],
            }
        }

    def _include_address(self, iface, network, address):
        network_id = network.id if network else None
        (self.interface_index[iface.ifname]['networks'][network_id]['addresses']
            [address.family]).append(address)

    def _include_gateway(self, iface, address, gateway):
        self.interface_index[iface.ifname]['gateways'][address.id] = gateway

    def _get_new_address(self, addrpool, family=None):
        id = addrpool.id if addrpool else -int(family)
        entry = self.new_address_index.get(id, None)
        if not entry:
            if addrpool:
                ipnetwork = netaddr.IPNetwork(addrpool.network + '/' + str(addrpool.prefix))
            else:
                if family == constants.IPV6_FAMILY:
                    ipnetwork = netaddr.IPNetwork('fda0::/64')
                else:
                    ipnetwork = netaddr.IPNetwork('192.168.100.0/24')
            entry = {'ipnetwork': ipnetwork, 'offset': 10}
            self.new_address_index[id] = entry
        offset = entry['offset']
        entry['offset'] += 1
        return str(entry['ipnetwork'][offset]), entry['ipnetwork'].prefixlen

    def _get_new_pool_address(self, addrpool):
        return self._get_new_address(addrpool)

    def _get_new_detached_address(self, family):
        return self._get_new_address(None, family)

    def _setup_detached_address(self, iface, family):
        pool = None
        if family == constants.IPV4_FAMILY and iface.ipv4_mode == constants.IPV4_POOL:
            pool = self.dbapi.address_pool_get(iface.ipv4_pool)
        elif family == constants.IPV6_FAMILY and iface.ipv4_mode == constants.IPV6_POOL:
            pool = self.dbapi.address_pool_get(iface.ipv6_pool)

        values = {'family': family, 'interface_id': iface.id}

        if pool:
            values['name'] = f"{iface.ifname}-pool-ipv{family}"
            values['address_pool_id'] = pool.id
            addr, prefixlen = self._get_new_pool_address(pool)
        else:
            values['name'] = f"{iface.ifname}-detached-ipv{family}"
            addr, prefixlen = self._get_new_detached_address(family)

        values['address'] = addr
        values['prefix'] = prefixlen
        address = self._create_test_address(**values)

        if (family == constants.IPV4_FAMILY and iface.ipv4_mode in
                {constants.IPV4_STATIC, constants.IPV4_POOL} or
                family == constants.IPV6_FAMILY and iface.ipv6_mode in
                {constants.IPV6_STATIC, constants.IPV6_POOL}):
            self._include_address(iface, None, address)

    def _setup_detached_addresses(self, iface):
        iface_info = self.interface_index[iface.ifname]['info']
        for _ in range(iface_info['ipv4_addresses']):
            self._setup_detached_address(iface, constants.IPV4_FAMILY)
        for _ in range(iface_info['ipv6_addresses']):
            self._setup_detached_address(iface, constants.IPV6_FAMILY)

    def _assign_address_to_interface(self, iface, address):
        dbapi = db_api.get_instance()
        dbapi.address_update(address.uuid, {'interface_id': iface.id})
        address.interface_id = iface.id
        address.ifname = iface.ifname

    def _get_controller_pool_address(self, iface, addrpool):
        self.assertIsNotNone(addrpool.controller0_address_id)
        address = self._find_address_by_id(addrpool.controller0_address_id)
        self._assign_address_to_interface(iface, address)
        return address

    def _create_non_controller_pool_address(self, iface, network, addrpool):
        addr, prefixlen = self._get_new_pool_address(addrpool)
        return self._create_test_address(
                name=utils.format_address_name(self.host.hostname, network.type),
                family=addrpool.family,
                prefix=prefixlen,
                address=addr,
                interface_id=iface.id,
                address_pool_id=addrpool.id)

    def _setup_gateway(self, iface, network, addrpool, address):
        if (network and network.type == constants.NETWORK_TYPE_MGMT and
                self.host.personality in [constants.WORKER, constants.STORAGE]):
            gateway_address = addrpool.floating_address
        else:
            gateway_address = addrpool.gateway_address
        self._include_gateway(iface, address, gateway_address)

    def _setup_pool_address(self, iface, network, addrpool):
        if self.host.personality == constants.CONTROLLER:
            address = self._get_controller_pool_address(iface, addrpool)
        else:
            address = self._create_non_controller_pool_address(iface, network, addrpool)
        self._include_address(iface, network, address)
        self._setup_gateway(iface, network, addrpool, address)

    def _setup_network_and_addresses(self, iface, networktype):
        network = self._find_network_by_type(networktype)
        self._include_network(iface, network)
        if self.host.personality != constants.CONTROLLER:
            if networktype not in [constants.NETWORK_TYPE_MGMT,
                                   constants.NETWORK_TYPE_CLUSTER_HOST,
                                   constants.NETWORK_TYPE_STORAGE,
                                   constants.NETWORK_TYPE_ADMIN]:
                return
        addrpools = self._find_network_address_pools(network.id)
        for addrpool in addrpools:
            self._setup_pool_address(iface, network, addrpool)

    def _setup_networks_and_addresses(self, iface):
        for networktype in iface.networktypelist:
            self._setup_network_and_addresses(iface, networktype)

    def _setup_addresses(self, iface):
        if iface.ifclass == constants.INTERFACE_CLASS_DATA:
            self._setup_detached_addresses(iface)
        elif iface.ifclass == constants.INTERFACE_CLASS_PLATFORM:
            if iface.networktypelist:
                self._setup_networks_and_addresses(iface)
            else:
                self._setup_detached_addresses(iface)

    def _setup_interface(self, iface, interface_info):
        self._include_interface(iface, interface_info)
        self._setup_addresses(iface)

    def _build_interface_info(self, **kwargs):
        return {'kernel_name': kwargs.get('kernel_name', None),
                'upper_device': kwargs.get('upper_device', None),
                'bond_slaves': kwargs.get('bond_slaves', None),
                'bond_primary': kwargs.get('bond_primary', None),
                'dpdksupport': kwargs.get('dpdksupport', True),
                'driver': kwargs.get('driver', None),
                'ipv4_addresses': kwargs.get('ipv4_addresses', 0),
                'ipv6_addresses': kwargs.get('ipv6_addresses', 0)}

    def _setup_bond_slave(self, port, iface, master_info):

        interface_info = self._build_interface_info(
            kernel_name=port.name,
            upper_device=master_info['kernel_name'],
            is_slave=True)

        self._setup_interface(iface, interface_info)

    def _get_address_netmask(self, address):
        network = netaddr.IPNetwork(address.address + '/' + str(address.prefix))
        if network.version == constants.IPV6_FAMILY:
            return str(network.prefixlen)
        else:
            return str(network.netmask)

    def _get_stx_description(self, iface, network):
        networktext = network.type if network else 'None'
        return f"ifname:{iface.ifname},net:{networktext}"

    def _get_traffic_classifier_cmd(self, iface, kernel_name):
        if constants.NETWORK_TYPE_MGMT in iface.networktypelist:
            cmd = '%s %s %s %s > /dev/null' % (constants.TRAFFIC_CONTROL_SCRIPT,
                                               kernel_name,
                                               constants.NETWORK_TYPE_MGMT,
                                               constants.LINK_SPEED_10G)
            return [cmd]
        return []

    def _get_cmd_ipv6_conf_iface_options(self, os_ifname):
        return ['echo 0 > /proc/sys/net/ipv6/conf/{}/autoconf'.format(os_ifname),
                'echo 0 > /proc/sys/net/ipv6/conf/{}/accept_ra'.format(os_ifname),
                'echo 0 > /proc/sys/net/ipv6/conf/{}/accept_redirects'.format(os_ifname),
                'echo 1 > /proc/sys/net/ipv6/conf/{}/keep_addr_on_down'.format(os_ifname)]

    def _get_cmd_postup_mtu(self, os_ifname, mtu):
        return ['/usr/sbin/ip link set dev {} mtu {}'.format(os_ifname, mtu)]

    def _get_cmd_vlan_kernel_module(self):
        return ['/sbin/modprobe -q 8021q']

    def _get_cmd_vlan_creation(self, raw_device, kernel_name, vlan_id):
        return ['ip link add link {} name {} type vlan id {}'.format(
            raw_device, kernel_name, vlan_id)]

    def _get_cmd_vlan_removal(self, kernel_name):
        return ['ip link del {}'.format(kernel_name)]

    def _get_promisc_cmd(self, kernel_name):
        return ['/usr/sbin/ip link set dev {} promisc on'.format(kernel_name)]

    def _get_undeprecate_cmd(self, kernel_name, address):
        return ['ip -6 addr replace {}/{} dev {} preferred_lft forever'.format(
            address.address, address.prefix, kernel_name)]

    def _get_sriov_numvfs_path(self, port):
        return '/sys/class/net/{}/device/sriov_numvfs'.format(port)

    def _get_sriov_numvfs_cmd(self, port, numvfs):
        sriovfs_path = self._get_sriov_numvfs_path(port)
        return ['echo 0 > {}'.format(sriovfs_path),
                'echo {} > {}'.format(numvfs, sriovfs_path)]

    def _get_pci_passthrough_numvfs_cmd(self, port):
        sriovfs_path = self._get_sriov_numvfs_path(port)
        return ['if [ -f  {0} ]; then echo 0 > {0}; fi'.format(sriovfs_path)]

    def _get_bond_check_cmd(self):
        cmd = (
            "end=$((SECONDS+10)); "
            "while { [ ! -d /proc/sys/net/ipv6/conf/$IFACE ] || "
            "[ ! -d /proc/sys/net/ipv4/conf/$IFACE ]; } && "
            "[ $SECONDS -lt $end ]; do "
            "sleep 1; "
            "done"
        )
        return [cmd]

    def _get_bonding_setup_cmd(self, kernel_name):
        return ['/sbin/modprobe bonding',
                'grep %s /sys/class/net/bonding_masters || '
                'echo +%s > /sys/class/net/bonding_masters' % (kernel_name, kernel_name)]

    def _get_disable_dad_cmd(self, kernel_name):
        return ["sysctl -wq net.ipv6.conf.%s.accept_dad=0" % kernel_name]

    def _get_operations(self, iface_dict, commands, address):
        iface = iface_dict['interface']
        kernel_name = iface_dict['info']['kernel_name']
        operation_list = []
        for command in commands:
            if command == IPV6_CFG:
                operation_list.extend(self._get_cmd_ipv6_conf_iface_options(kernel_name))
            elif command == SET_MTU:
                operation_list.extend(self._get_cmd_postup_mtu(kernel_name, iface.imtu))
            elif command == SET_TC:
                operation_list.extend(self._get_traffic_classifier_cmd(iface, kernel_name))
            elif command == VLAN_MOD:
                operation_list.extend(self._get_cmd_vlan_kernel_module())
            elif command == VLAN_ADD:
                operation_list.extend(self._get_cmd_vlan_creation(
                    iface_dict['info']['upper_device'], kernel_name, iface.vlan_id))
            elif command == VLAN_DEL:
                operation_list.extend(self._get_cmd_vlan_removal(kernel_name))
            elif command == PROMISC_ON:
                operation_list.extend(self._get_promisc_cmd(kernel_name))
            elif command == UNDEPR:
                operation_list.extend(self._get_undeprecate_cmd(kernel_name, address))
            elif command == SRIOV:
                operation_list.extend(self._get_sriov_numvfs_cmd(kernel_name, iface.sriov_numvfs))
            elif command == PTHROUGH:
                operation_list.extend(self._get_pci_passthrough_numvfs_cmd(kernel_name))
            elif command == BOND_CHECK:
                operation_list.extend(self._get_bond_check_cmd())
            elif command == BOND_SETUP:
                operation_list.extend(self._get_bonding_setup_cmd(kernel_name))
            elif command == DIS_DAD:
                operation_list.extend(self._get_disable_dad_cmd(kernel_name))
        return '; '.join(operation_list)

    def _get_ifcfg_options(self, iface_dict, network, address, exp_cfg):
        iface = iface_dict['interface']
        exp_options = exp_cfg[OPTIONS]

        options = {'mtu': str(iface_dict['interface'].imtu),
                   'stx-description': self._get_stx_description(iface, network)}

        if exp_options.pop('vlan-raw-device', False):
            self.assertEqual(iface.iftype, constants.INTERFACE_TYPE_VLAN,
                             f"Interface {iface.ifname} is not VLAN")
            options['vlan-raw-device'] = iface_dict['info']['upper_device']

        if exp_options.pop('hwaddress', False):
            options['hwaddress'] = iface.imac.rstrip()
        if exp_options.pop('bond-primary', False):
            options['bond-primary'] = iface_dict['info']['bond_primary']
        if exp_options.pop('bond-slaves', False):
            options['bond-slaves'] = iface_dict['info']['bond_slaves']
        if exp_options.pop('bond-master', False):
            options['bond-master'] = iface_dict['info']['upper_device']
        if exp_options.pop(ALLOW, False):
            key = 'allow-{}'.format(iface_dict['info']['upper_device'])
            options[key] = iface_dict['info']['kernel_name']

        for oper in OPERATIONS:
            oper_list = exp_options.pop(oper, None)
            if oper_list:
                options[oper] = self._get_operations(iface_dict, oper_list, address)

        options.update(exp_options)

        return options

    def _get_expected_interface_config(self, iface_dict, network, address, exp_cfg, base):
        iface = iface_dict['interface']

        has_gateway = exp_cfg[OPTIONS].pop(GATEWAY, False)

        config = {
            'ensure': 'present',
            'onboot': 'true',
            'hotplug': 'false',
            'family': exp_cfg[FAMILY],
            'method': exp_cfg[METHOD],
            'options': self._get_ifcfg_options(iface_dict, network, address, exp_cfg)}

        if exp_cfg[METHOD] == STATIC:
            self.assertIsNotNone(address,
                    f"Address expected for interface {iface.ifname} / "
                    f"network {network.type if network else None}, but not present")
            config['ipaddress'] = address.address
            config['netmask'] = self._get_address_netmask(address)
            if has_gateway:
                gateway = iface_dict['gateways'].get(address.id, None)
                self.assertIsNotNone(gateway,
                        f"Gateway expected for interface {iface.ifname} / "
                        f"network {network.type if network else None} / "
                        f"address {address.address} but not present")
                config['options']['gateway'] = gateway

        kernelname = iface_dict['info']['kernel_name']
        if base:
            ifname = kernelname
        else:
            if network and network.type == constants.NETWORK_TYPE_PXEBOOT:
                ifname = f"{kernelname}:2"
            else:
                ifname = f"{kernelname}:{network.id if network else 0}-{address.id if address else 0}"

        return {ifname: config}

    def _get_address(self, iface_dict, network, family, index):
        network_id = network.id if network else None
        self.assertIn(network_id, iface_dict['networks'],
                f"Network '{network.type if network else None}' is not associated"
                f"with interface '{iface_dict['interface'].ifname}'")
        addr_list = iface_dict['networks'][network_id]['addresses'][family]
        self.assertGreater(len(addr_list), index,
                f"There are only {len(addr_list)} IPv{family} addresses associated with interface "
                f"{iface_dict['interface'].ifname} for network {network.type if network else None},"
                f" index {index + 1} is out of bounds")
        return addr_list[index]

    def _is_config_included(self, exp_cfg):
        modes = exp_cfg.pop(MODES, None)
        if not modes:
            return True
        return self.system_mode in modes

    def _get_expected_interface_configs(self, ifname, expected_iface_configs):
        self.assertIn(ifname, self.interface_index, f"Interface {ifname} was not created")
        iface_dict = self.interface_index[ifname]
        address_index = defaultdict(lambda: defaultdict(int))
        base = True
        interface_configs = {}
        for exp_cfg in expected_iface_configs:
            if not self._is_config_included(exp_cfg):
                continue
            network = self._find_network_by_type(exp_cfg[NET])
            network_id = network.id if network else None
            if network_id not in iface_dict['networks']:
                if (network.type == constants.NETWORK_TYPE_PXEBOOT and
                        constants.NETWORK_TYPE_MGMT in iface_dict['interface'].networktypelist):
                    self._setup_network_and_addresses(iface_dict['interface'], network.type)
            address = None
            if exp_cfg[METHOD] == STATIC:
                if exp_cfg[FAMILY] == INET6:
                    family = constants.IPV6_FAMILY
                else:
                    family = constants.IPV4_FAMILY
                address = self._get_address(iface_dict, network, family,
                                            address_index[network_id][family])
                address_index[network_id][family] += 1
            config = self._get_expected_interface_config(iface_dict, network,
                                                         address, exp_cfg, base)
            interface_configs.update(config)
            base = False
        return interface_configs

    def _add_loopback_config(self, interface_configs):
        interface_configs['lo'] = {'ensure': 'present',
                                   'family': 'inet',
                                   'hotplug': 'false',
                                   'method': 'loopback',
                                   'onboot': 'true',
                                   'options': {}}

    def _get_expected_config(self, expected_configs):
        interface_configs = {}
        for ifname, expected_iface_configs in expected_configs.items():
            configs = self._get_expected_interface_configs(ifname, expected_iface_configs)
            interface_configs.update(configs)
        self._add_loopback_config(interface_configs)
        return interface_configs

    def _get_generated_config(self):
        hiera_data = self.operator.interface.get_host_config(self.host)
        self.assertIn('platform::network::interfaces::network_config', hiera_data)
        return hiera_data['platform::network::interfaces::network_config']

    def _remove_non_serializable_elements(self, object_vars):
        object_vars.pop('_changed_fields', None)
        object_vars.pop('_created_at', None)
        object_vars.pop('_updated_at', None)
        return object_vars

    # Prints interface index contents for debug purposes
    def _print_interface_index(self):
        printable_interface_index = {}
        for interface_dict in self.interface_index.values():
            interface = interface_dict['interface']
            printable_network_dict = {}
            for network_dict in interface_dict['networks'].values():
                network = network_dict['network']
                printable_address_index = defaultdict(list)
                for family, addresses in network_dict['addresses'].items():
                    for address in addresses:
                        printable_address_index[family].append(
                                self._remove_non_serializable_elements(vars(address)))
                printable_network_dict[network.id if network else 0] = {
                    'network': (self._remove_non_serializable_elements(vars(network)) if network
                                else None),
                    'addresses': printable_address_index}
            printable_interface_index[interface.ifname] = {
                'interface': self._remove_non_serializable_elements(vars(interface)),
                'info': interface_dict['info'],
                'networks': printable_network_dict}
        print(json.dumps(printable_interface_index, sort_keys=True, indent=4))

    def _create_host(self, personality=constants.CONTROLLER, subfunction=None):
        self.host = self._create_test_host(personality, subfunction)

    def _add_ethernet(self, ifname=None, ifclass=None, networktype=None, **kwargs):
        port, iface = self._create_ethernet_test(ifname, ifclass, networktype, **kwargs)

        driver = kwargs.get('driver', 'ixgbe')

        interface_info = self._build_interface_info(
            kernel_name=port.name,
            dpdksupport=kwargs.get('dpdksupport', True),
            driver=driver,
            ipv4_addresses=kwargs.get('ipv4_addresses', 0),
            ipv6_addresses=kwargs.get('ipv6_addresses', 0))

        self._setup_interface(iface, interface_info)

        return iface

    def _add_bond(self, ifname=None, ifclass=None, networktype=None, **kwargs):
        port1, slave1 = self._create_ethernet_test()
        port2, slave2 = self._create_ethernet_test()

        iface = self._create_bond_test(ifname, ifclass, networktype,
                                       iface1=slave1, iface2=slave2, **kwargs)

        interface_info = self._build_interface_info(
            kernel_name=iface.ifname,
            bond_slaves='{} {} '.format(port1.name, port2.name),
            bond_primary=port1.name,
            ipv4_addresses=kwargs.get('ipv4_addresses', 0),
            ipv6_addresses=kwargs.get('ipv6_addresses', 0))

        self._setup_interface(iface, interface_info)

        self._setup_bond_slave(port1, slave1, interface_info)
        self._setup_bond_slave(port2, slave2, interface_info)

        return iface

    def _add_vlan(self, lower_iface, vlan_id, ifname=None, ifclass=None,
                  networktype=None, **kwargs):
        iface = self._create_vlan_test(ifname, ifclass, networktype, vlan_id, lower_iface, **kwargs)

        lower_iface_dict = self.interface_index[lower_iface.ifname]
        lower_iface_info = lower_iface_dict['info']

        interface_info = self._build_interface_info(
            kernel_name=interface.get_vlan_os_ifname(iface),
            upper_device=lower_iface_info['kernel_name'],
            ipv4_addresses=kwargs.get('ipv4_addresses', 0),
            ipv6_addresses=kwargs.get('ipv6_addresses', 0))

        self._setup_interface(iface, interface_info)

        return iface

    def _validate_config(self, expected):
        self._do_update_context()
        expected_config = self._get_expected_config(expected)
        if self.debuglevel >= 2:
            self._print_interface_index()
        generated_config = self._get_generated_config()
        self.assertEqual(expected_config, generated_config)
        if self.debuglevel >= 1:
            print(json.dumps(generated_config, sort_keys=True, indent=4))

    def test_controller_ethernet_oam(self):
        self._create_host(constants.CONTROLLER)
        self._add_ethernet('oam0', constants.INTERFACE_CLASS_PLATFORM, constants.NETWORK_TYPE_OAM)
        expected = {
            'oam0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [SET_TC, IPV6_CFG]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_OAM, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6],
                    NET: constants.NETWORK_TYPE_OAM, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [SET_TC, IPV6_CFG, UNDEPR]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_OAM, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG, UNDEPR]}}],
        }
        self._validate_config(expected)

    def test_controller_ethernet_separate_nets_pxeboot_unassigned(self):
        self._create_host(constants.CONTROLLER)
        self._add_ethernet('mgmt0', constants.INTERFACE_CLASS_PLATFORM, constants.NETWORK_TYPE_MGMT)
        self._add_ethernet('clhost0', constants.INTERFACE_CLASS_PLATFORM,
                           constants.NETWORK_TYPE_CLUSTER_HOST)
        self._add_ethernet('none')
        expected = {
            'mgmt0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [SET_TC, IPV6_CFG]}},
                {NET: constants.NETWORK_TYPE_PXEBOOT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG, UNDEPR]}}],
            'clhost0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV4],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG, UNDEPR]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG, UNDEPR]}}],
        }
        self._validate_config(expected)

    def test_controller_ethernet_joined_nets_pxeboot_unassigned(self):
        self._create_host(constants.CONTROLLER)
        self._add_ethernet('mgmt0', constants.INTERFACE_CLASS_PLATFORM,
                           [constants.NETWORK_TYPE_MGMT,
                            constants.NETWORK_TYPE_CLUSTER_HOST])
        self._add_ethernet('none')
        expected = {
            'mgmt0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [SET_TC, IPV6_CFG]}},
                {NET: constants.NETWORK_TYPE_PXEBOOT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG, UNDEPR]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}}],
        }
        self._validate_config(expected)

    def test_controller_ethernet_joined_nets_pxeboot_assigned(self):
        self._create_host(constants.CONTROLLER)
        self._add_ethernet('mgmt0', constants.INTERFACE_CLASS_PLATFORM,
                           [constants.NETWORK_TYPE_MGMT,
                            constants.NETWORK_TYPE_CLUSTER_HOST,
                            constants.NETWORK_TYPE_PXEBOOT])
        self._add_ethernet('none')
        expected = {
            'mgmt0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [SET_TC, IPV6_CFG]}},
                {NET: constants.NETWORK_TYPE_PXEBOOT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG, UNDEPR]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}}],
        }
        self._validate_config(expected)

    def test_controller_ethernet_separate_nets_pxeboot_assigned(self):
        self._create_host(constants.CONTROLLER)
        self._add_ethernet('pxe0', constants.INTERFACE_CLASS_PLATFORM,
                           constants.NETWORK_TYPE_PXEBOOT)
        self._add_ethernet('mgmt0', constants.INTERFACE_CLASS_PLATFORM,
                           [constants.NETWORK_TYPE_MGMT,
                            constants.NETWORK_TYPE_CLUSTER_HOST])
        self._add_ethernet('none')
        expected = {
            'pxe0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {NET: constants.NETWORK_TYPE_PXEBOOT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}}],
            'mgmt0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [SET_TC, IPV6_CFG]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG, UNDEPR]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}}],
        }
        self._validate_config(expected)

    def test_controller_vlan_over_bond(self):
        self._create_host(constants.CONTROLLER)
        pxe0 = self._add_bond('pxe0', constants.INTERFACE_CLASS_PLATFORM,
                              constants.NETWORK_TYPE_PXEBOOT)
        self._add_vlan(pxe0, 100, 'mgmt0', constants.INTERFACE_CLASS_PLATFORM,
                       constants.NETWORK_TYPE_MGMT)
        self._add_vlan(pxe0, 200, 'clhost0', constants.INTERFACE_CLASS_PLATFORM,
                       constants.NETWORK_TYPE_CLUSTER_HOST)
        expected = {
            'pxe0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {'bond-lacp-rate': 'fast', 'bond-miimon': '100',
                              'bond-mode': '802.3ad', 'bond-slaves': True,
                              'bond-xmit-hash-policy': 'layer2', 'hwaddress': True,
                              POST_UP: [SET_TC, IPV6_CFG], UP: [BOND_CHECK]}},
                {NET: constants.NETWORK_TYPE_PXEBOOT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {'bond-lacp-rate': 'fast', 'bond-miimon': '100',
                              'bond-mode': '802.3ad', 'bond-slaves': True,
                              'bond-xmit-hash-policy': 'layer2', 'hwaddress': True,
                              POST_UP: [SET_TC, IPV6_CFG], UP: [BOND_CHECK]}}],
            'eth0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {ALLOW: True, 'bond-master': True, PRE_UP: [PROMISC_ON, IPV6_CFG]}}],
            'eth1': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {ALLOW: True, 'bond-master': True, PRE_UP: [PROMISC_ON, IPV6_CFG]}}],
            'mgmt0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_TC, SET_MTU, IPV6_CFG]}},
                {MODES: [SS_IPV4],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, 'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, 'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG]}},
                {MODES: [SS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, 'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG, UNDEPR]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, 'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG, UNDEPR]}}],
            'clhost0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG]}},
                {MODES: [SS_IPV4],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG]}},
                {MODES: [SS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG, UNDEPR]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG, UNDEPR]}}],
        }
        self._validate_config(expected)

    def test_controller_shared_vlan_over_pxeboot(self):
        self._create_host(constants.CONTROLLER)
        pxe0 = self._add_bond('pxe0', constants.INTERFACE_CLASS_PLATFORM,
                              constants.NETWORK_TYPE_PXEBOOT)
        self._add_vlan(pxe0, 200, 'mgmt0', constants.INTERFACE_CLASS_PLATFORM,
                       [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST])
        expected = {
            'pxe0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {'bond-lacp-rate': 'fast', 'bond-miimon': '100',
                              'bond-mode': '802.3ad', 'bond-slaves': True,
                              'bond-xmit-hash-policy': 'layer2', 'hwaddress': True,
                              POST_UP: [SET_TC, IPV6_CFG], UP: [BOND_CHECK]}},
                {NET: constants.NETWORK_TYPE_PXEBOOT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {'bond-lacp-rate': 'fast', 'bond-miimon': '100',
                              'bond-mode': '802.3ad', 'bond-slaves': True,
                              'bond-xmit-hash-policy': 'layer2', 'hwaddress': True,
                              POST_UP: [SET_TC, IPV6_CFG], UP: [BOND_CHECK]}}],
            'eth0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {ALLOW: True, 'bond-master': True, PRE_UP: [PROMISC_ON, IPV6_CFG]}}],
            'eth1': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {ALLOW: True, 'bond-master': True, PRE_UP: [PROMISC_ON, IPV6_CFG]}}],
            'mgmt0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_TC, SET_MTU, IPV6_CFG]}},
                {MODES: [SS_IPV4],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, 'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, 'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG]}},
                {MODES: [SS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, 'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG, UNDEPR]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, 'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG, UNDEPR]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {'vlan-raw-device': True, PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG]}}],
        }
        self._validate_config(expected)

    def test_controller_duplex_direct_ethernet(self):
        self._create_host(constants.CONTROLLER)
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX_DIRECT
        self.dbapi.isystem_update(self.system.uuid, system_dict)
        self._add_ethernet('mgmt0', constants.INTERFACE_CLASS_PLATFORM,
                           constants.NETWORK_TYPE_MGMT)
        self._add_ethernet('clhost0', constants.INTERFACE_CLASS_PLATFORM,
                           constants.NETWORK_TYPE_CLUSTER_HOST)
        expected = {
            'mgmt0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {PRE_UP: [DIS_DAD], POST_UP: [SET_TC, IPV6_CFG]}},
                {NET: constants.NETWORK_TYPE_PXEBOOT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG, UNDEPR]}}],
            'clhost0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {PRE_UP: [DIS_DAD], POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV4],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [SET_TC, IPV6_CFG, UNDEPR]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG, UNDEPR]}}],
        }
        self._validate_config(expected)

    def test_controller_duplex_direct_vlan_over_bond(self):
        self._create_host(constants.CONTROLLER)
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX_DIRECT
        self.dbapi.isystem_update(self.system.uuid, system_dict)
        pxe0 = self._add_ethernet('pxe0', constants.INTERFACE_CLASS_PLATFORM,
                                  constants.NETWORK_TYPE_PXEBOOT)
        self._add_bond('mgmt0', constants.INTERFACE_CLASS_PLATFORM,
                       constants.NETWORK_TYPE_MGMT)
        self._add_vlan(pxe0, 200, 'clhost0', constants.INTERFACE_CLASS_PLATFORM,
                       constants.NETWORK_TYPE_CLUSTER_HOST)
        expected = {
            'pxe0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {NET: constants.NETWORK_TYPE_PXEBOOT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}}],
            'mgmt0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {'bond-lacp-rate': 'fast', 'bond-miimon': '100',
                              'bond-mode': '802.3ad', 'bond-slaves': True,
                              'bond-xmit-hash-policy': 'layer2', 'hwaddress': True,
                              PRE_UP: [BOND_SETUP, DIS_DAD], POST_UP: [SET_TC, IPV6_CFG],
                              UP: [BOND_CHECK]}},
                {MODES: [SS_IPV4],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, 'bond-lacp-rate': 'fast', 'bond-miimon': '100',
                              'bond-mode': '802.3ad', 'bond-slaves': True,
                              'bond-xmit-hash-policy': 'layer2', 'hwaddress': True,
                              POST_UP: [IPV6_CFG],
                              UP: [BOND_CHECK]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, 'bond-lacp-rate': 'fast', 'bond-miimon': '100',
                              'bond-mode': '802.3ad', 'bond-slaves': True,
                              'bond-xmit-hash-policy': 'layer2', 'hwaddress': True,
                              POST_UP: [IPV6_CFG], UP: [BOND_CHECK]}},
                {MODES: [SS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, 'bond-lacp-rate': 'fast', 'bond-miimon': '100',
                              'bond-mode': '802.3ad', 'bond-slaves': True,
                              'bond-xmit-hash-policy': 'layer2', 'hwaddress': True,
                              POST_UP: [IPV6_CFG, UNDEPR],
                              UP: [BOND_CHECK]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, 'bond-lacp-rate': 'fast', 'bond-miimon': '100',
                              'bond-mode': '802.3ad', 'bond-slaves': True,
                              'bond-xmit-hash-policy': 'layer2', 'hwaddress': True,
                              POST_UP: [IPV6_CFG, UNDEPR],
                              UP: [BOND_CHECK]}}],
            'eth1': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {ALLOW: True, 'bond-master': True, PRE_UP: [PROMISC_ON, IPV6_CFG]}}],
            'eth2': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {ALLOW: True, 'bond-master': True, PRE_UP: [PROMISC_ON, IPV6_CFG]}}],
            'clhost0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {'vlan-raw-device': True,
                              PRE_UP: [VLAN_MOD, VLAN_ADD, DIS_DAD], POST_UP: [SET_MTU, IPV6_CFG],
                              POST_DOWN: [VLAN_DEL]}},
                {MODES: [SS_IPV4],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {'vlan-raw-device': True,
                              PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {'vlan-raw-device': True,
                              PRE_UP: [VLAN_MOD], POST_UP: [SET_MTU, IPV6_CFG]}},
                {MODES: [SS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {'vlan-raw-device': True,
                              PRE_UP: [VLAN_MOD],
                              POST_UP: [SET_MTU, IPV6_CFG, UNDEPR]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {'vlan-raw-device': True,
                              PRE_UP: [VLAN_MOD], POST_UP: [SET_MTU, IPV6_CFG, UNDEPR]}}],
        }
        self._validate_config(expected)

    def test_worker_ethernet_pxe_unassigned(self):
        self._create_host(constants.WORKER)
        self._add_ethernet('mgmt0', constants.INTERFACE_CLASS_PLATFORM,
                           constants.NETWORK_TYPE_MGMT)
        self._add_ethernet('clhost0', constants.INTERFACE_CLASS_PLATFORM,
                           constants.NETWORK_TYPE_CLUSTER_HOST)
        self._add_ethernet('none')
        expected = {
            'mgmt0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [SET_TC, IPV6_CFG]}},
                {NET: constants.NETWORK_TYPE_PXEBOOT, FAMILY: INET, METHOD: DHCP,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG, UNDEPR]}}],
            'clhost0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [SET_TC, IPV6_CFG]}},
                {MODES: [SS_IPV4],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [SET_TC, IPV6_CFG, UNDEPR]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG, UNDEPR]}}],
        }
        self._validate_config(expected)

    def test_worker_ethernet_pxe_with_mgmt(self):
        self._create_host(constants.WORKER)
        self._add_ethernet('mgmt0', constants.INTERFACE_CLASS_PLATFORM,
                           [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_PXEBOOT])
        self._add_ethernet('clhost0', constants.INTERFACE_CLASS_PLATFORM,
                           constants.NETWORK_TYPE_CLUSTER_HOST)
        self._add_ethernet('none')
        expected = {
            'mgmt0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [SET_TC, IPV6_CFG]}},
                {NET: constants.NETWORK_TYPE_PXEBOOT, FAMILY: INET, METHOD: DHCP,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG, UNDEPR]}}],
            'clhost0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV4],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG, UNDEPR]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG, UNDEPR]}}],
        }
        self._validate_config(expected)

    def test_worker_ethernet_pxe_with_cluster_host(self):
        self._create_host(constants.WORKER)
        self._add_ethernet('mgmt0', constants.INTERFACE_CLASS_PLATFORM, constants.NETWORK_TYPE_MGMT)
        self._add_ethernet('clhost0', constants.INTERFACE_CLASS_PLATFORM,
                           [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_PXEBOOT])
        self._add_ethernet('none')
        expected = {
            'mgmt0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [SET_TC, IPV6_CFG]}},
                {MODES: [SS_IPV4],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG, UNDEPR]}},
                {MODES: [DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_MGMT, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {GATEWAY: True, POST_UP: [IPV6_CFG, UNDEPR]}}],
            'clhost0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {NET: constants.NETWORK_TYPE_PXEBOOT, FAMILY: INET, METHOD: DHCP,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: constants.NETWORK_TYPE_CLUSTER_HOST, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG, UNDEPR]}}],
        }
        self._validate_config(expected)

    def test_worker_sriov_and_pci_passthrough(self):
        self._create_host(constants.WORKER)
        self._add_ethernet('sriov0', constants.INTERFACE_CLASS_PCI_SRIOV,
                           constants.NETWORK_TYPE_PCI_SRIOV)
        self._add_ethernet('pthru0', constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                           constants.NETWORK_TYPE_PCI_PASSTHROUGH)
        expected = {
            'sriov0': [
                {NET: constants.NETWORK_TYPE_PCI_SRIOV, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {PRE_UP: [SRIOV], POST_UP: [IPV6_CFG]}}],
            'pthru0': [
                {NET: constants.NETWORK_TYPE_PCI_PASSTHROUGH, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {PRE_UP: [PTHROUGH], POST_UP: [IPV6_CFG]}}],
        }
        self._validate_config(expected)

    def test_worker_data_over_ethernet(self):
        self._create_host(constants.WORKER)
        self._add_ethernet('data0', constants.INTERFACE_CLASS_DATA, constants.NETWORK_TYPE_DATA)
        self._add_ethernet('slow0', constants.INTERFACE_CLASS_DATA, constants.NETWORK_TYPE_DATA,
                           dpdksupport=False)
        self._add_ethernet('mlx0', constants.INTERFACE_CLASS_DATA, constants.NETWORK_TYPE_DATA,
                           driver=constants.DRIVER_MLX_CX4)
        expected = {
            'slow0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [IPV6_CFG]}}],
            'mlx0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [IPV6_CFG]}}],
        }
        self._validate_config(expected)

    def _get_static_address_args(self, static_enabled, addr_count):
        families = [self.primary_address_family]
        if self.secondary_address_family:
            families.append(self.secondary_address_family)
        kwargs = {}
        if constants.IPV4_FAMILY in families:
            if static_enabled:
                kwargs['ipv4_mode'] = constants.IPV4_STATIC
            kwargs['ipv4_addresses'] = addr_count
        if constants.IPV6_FAMILY in families:
            if static_enabled:
                kwargs['ipv6_mode'] = constants.IPV6_STATIC
            kwargs['ipv6_addresses'] = addr_count
        return kwargs

    def _get_pool_address_args(self, pools, addr_count):
        kwargs = {}
        if constants.IPV4_FAMILY in pools:
            kwargs['ipv4_mode'] = constants.IPV4_POOL
            kwargs['ipv4_pool'] = pools[constants.IPV4_FAMILY].uuid
            kwargs['ipv4_addresses'] = addr_count
        if constants.IPV6_FAMILY in pools:
            kwargs['ipv6_mode'] = constants.IPV6_POOL
            kwargs['ipv6_pool'] = pools[constants.IPV6_FAMILY].uuid
            kwargs['ipv6_addresses'] = addr_count
        return kwargs

    def test_worker_data_over_ethernet_static_addresses(self):
        self._create_host(constants.WORKER)
        system_dict = self.system.as_dict()
        system_dict['capabilities']['vswitch_type'] = constants.VSWITCH_TYPE_NONE
        self.dbapi.isystem_update(self.system.uuid, system_dict)
        self._add_ethernet('data0', constants.INTERFACE_CLASS_DATA, constants.NETWORK_TYPE_DATA)
        self._add_ethernet('data1', constants.INTERFACE_CLASS_DATA, constants.NETWORK_TYPE_DATA,
                           **self._get_static_address_args(False, 1))
        self._add_ethernet('data2', constants.INTERFACE_CLASS_DATA, constants.NETWORK_TYPE_DATA,
                           **self._get_static_address_args(True, 0))
        self._add_ethernet('data3', constants.INTERFACE_CLASS_DATA, constants.NETWORK_TYPE_DATA,
                           **self._get_static_address_args(True, 1))
        self._add_ethernet('data4', constants.INTERFACE_CLASS_DATA, constants.NETWORK_TYPE_DATA,
                           **self._get_static_address_args(True, 2))
        expected = {
            'data0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [IPV6_CFG]}}],
            'data1': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [IPV6_CFG]}}],
            'data2': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [IPV6_CFG]}}],
            'data3': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: None, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: None, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}}],
            'data4': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: None, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: None, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: None, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: None, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}}],
        }
        self._validate_config(expected)

    def test_address_mode_pool(self):
        families = [self.primary_address_family]
        if self.secondary_address_family:
            families.append(self.secondary_address_family)

        pools = {}
        for family in families:
            if family == constants.IPV4_FAMILY:
                subnet = netaddr.IPNetwork('192.167.101.0/24')
            else:
                subnet = netaddr.IPNetwork('af00::/64')
            test_pool = dbutils.create_test_address_pool(
                name=f"test-ipv{family}", network=str(subnet.network),
                family=family, prefix=subnet.prefixlen,
                ranges=[[str(subnet[1]), str(subnet[-2])]])
            pools[family] = test_pool

        self._create_host(constants.CONTROLLER)
        self._add_ethernet('platform0', constants.INTERFACE_CLASS_PLATFORM,
                           **self._get_pool_address_args(pools, 1))
        expected = {
            'platform0': [
                {NET: None, FAMILY: INET, METHOD: MANUAL,
                    OPTIONS: {POST_UP: [SET_TC, IPV6_CFG]}},
                {MODES: [SS_IPV4, DS_IPV4, DS_IPV6],
                    NET: None, FAMILY: INET, METHOD: STATIC,
                    OPTIONS: {POST_UP: [IPV6_CFG]}},
                {MODES: [SS_IPV6, DS_IPV4, DS_IPV6],
                    NET: None, FAMILY: INET6, METHOD: STATIC,
                    OPTIONS: {POST_UP: [SET_TC, IPV6_CFG]}}],
        }
        self._validate_config(expected)

    def test_get_interface_data_for_rate_limit(self):
        self._create_host(constants.CONTROLLER)
        oam_kwargs = {'max_tx_rate': 30, 'max_rx_rate': 30}
        port, _ = self._create_ethernet_test('oam0', constants.INTERFACE_CLASS_PLATFORM,
                                        constants.NETWORK_TYPE_OAM, **oam_kwargs)

        # creating a pxeboot interface, mgmt interface will be created on top of it.
        # Rate limit will not be configured for pxeboot as it has only internal traffic.
        iface_pxeboot_kwargs = {'max_tx_rate': 30, 'max_rx_rate': 30}
        iface_pxeboot = self._add_bond('pxeboot', constants.INTERFACE_CLASS_PLATFORM,
                            constants.NETWORK_TYPE_PXEBOOT, **iface_pxeboot_kwargs)

        iface_mgmt_kwargs = {'max_tx_rate': None, 'max_rx_rate': 0}
        mgmt_vlan_id = 100
        self._add_vlan(iface_pxeboot, mgmt_vlan_id, 'mgmt0',
                            constants.INTERFACE_CLASS_PLATFORM, constants.NETWORK_TYPE_MGMT,
                            **iface_mgmt_kwargs)

        dbapi = db_api.get_instance()
        config = {
            interface.RATE_LIMIT_CONFIG_RESOURCE: {},
        }
        system_dict = self.system.as_dict()
        mode = system_dict['system_mode']
        address_pool = 'ipv4' if mode == SS_IPV4 else 'ipv6' if mode == SS_IPV6 else 'dual'
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        system_dict['distributed_cloud_role'] = constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD
        self.dbapi.isystem_update(self.system.uuid, system_dict)
        self._do_update_context()

        expected_output = {
            'vlan' + str(mgmt_vlan_id): {
                'accept_subnet': ['mgmt'],
                'max_tx_rate': None,
                'max_rx_rate': 0,
                'address_pool': address_pool
            },
            port['name']: {
                'max_tx_rate': 30,
                'max_rx_rate': 30,
                'address_pool': address_pool
            },
        }
        interface.generate_data_iface_rate_limit(self.context, config, dbapi)
        rate_limit_config = config[interface.RATE_LIMIT_CONFIG_RESOURCE]
        self.assertEqual(rate_limit_config, expected_output)


class InterfaceConfigTestIPv4(InterfaceConfigTestMixin,
                              dbbase.BaseHostTestCase):
    system_mode = SS_IPV4


class InterfaceConfigTestIPv6(InterfaceConfigTestMixin,
                              dbbase.BaseIPv6Mixin,
                              dbbase.BaseHostTestCase):
    system_mode = SS_IPV6


class InterfaceConfigTestDualStackPrimaryIPv4(InterfaceConfigTestMixin,
                                              dbbase.BaseDualStackPrimaryIPv4Mixin,
                                              dbbase.BaseHostTestCase):
    system_mode = DS_IPV4


class InterfaceConfigTestDualStackPrimaryIPv6(InterfaceConfigTestMixin,
                                              dbbase.BaseDualStackPrimaryIPv6Mixin,
                                              dbbase.BaseHostTestCase):
    system_mode = DS_IPV6
