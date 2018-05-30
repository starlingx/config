# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import print_function

import netaddr
import os
import uuid
import yaml

from sysinv.common import constants
from sysinv.common import utils
from sysinv.puppet import interface
from sysinv.puppet import puppet
from sysinv.objects import base as objbase

from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


NETWORKTYPES_WITH_V4_ADDRESSES = [constants.NETWORK_TYPE_MGMT,
                                  constants.NETWORK_TYPE_DATA_VRS,
                                  constants.NETWORK_TYPE_OAM,
                                  constants.NETWORK_TYPE_PXEBOOT]

NETWORKTYPES_WITH_V6_ADDRESSES = [constants.NETWORK_TYPE_INFRA,
                                  constants.NETWORK_TYPE_DATA]

NETWORKTYPES_WITH_V4_ROUTES = [constants.NETWORK_TYPE_DATA_VRS]

NETWORKTYPES_WITH_V6_ROUTES = [constants.NETWORK_TYPE_DATA]


class BaseTestCase(dbbase.DbTestCase):

    def setUp(self):
        super(BaseTestCase, self).setUp()
        self.operator = puppet.PuppetOperator(self.dbapi)
        self.oam_gateway_address = netaddr.IPNetwork('10.10.10.1/24')
        self.mgmt_gateway_address = netaddr.IPNetwork('192.168.204.1/24')
        self.ports = []
        self.interfaces = []
        self.addresses = []
        self.routes = []
        self.networks = []

    def assertIn(self, needle, haystack, message=''):
        """Custom assertIn that handles object comparison"""
        if isinstance(needle, objbase.SysinvObject):
            # compare objects based on unique DB identifier
            needle = needle.id
            haystack = [o.id for o in haystack]
        super(BaseTestCase, self).assertIn(needle, haystack, message)

    def assertEqual(self, expected, observed, message=''):
        """Custom assertEqual that handles object comparison"""
        if (isinstance(expected, objbase.SysinvObject) and
                isinstance(observed, objbase.SysinvObject)):
            expected = expected.id
            observed = observed.id
        super(BaseTestCase, self).assertEqual(expected, observed, message)

    def _setup_address_and_routes(self, iface):
        networktype = utils.get_primary_network_type(iface)
        if networktype in NETWORKTYPES_WITH_V4_ADDRESSES:
            address = {'interface_id': iface['id'],
                       'family': 4,
                       'prefix': 24,
                       'address': '192.168.1.2'}
            self.addresses.append(dbutils.create_test_address(**address))
        elif networktype in NETWORKTYPES_WITH_V6_ADDRESSES:
            address = {'interface_id': iface['id'],
                       'family': 6,
                       'prefix': 64,
                       'address': '2001:1::2'}
            self.addresses.append(dbutils.create_test_address(**address))
        if networktype in NETWORKTYPES_WITH_V4_ROUTES:
            route = {'interface_id': iface['id'],
                     'family': 4,
                     'prefix': 24,
                     'network': '192.168.1.0',
                     'gateway': '192.168.1.1',
                     'metric': '1'}
            self.routes.append(dbutils.create_test_route(**route))
            route = {'interface_id': iface['id'],
                     'family': 4,
                     'prefix': 0,
                     'network': '0.0.0.0',
                     'gateway': '192.168.1.1',
                     'metric': '1'}
            self.routes.append(dbutils.create_test_route(**route))
        if networktype in NETWORKTYPES_WITH_V6_ROUTES:
            route = {'interface_id': iface['id'],
                     'family': 6,
                     'prefix': 64,
                     'network': '2001:1::',
                     'gateway': '2001:1::1',
                     'metric': '1'}
            self.routes.append(dbutils.create_test_route(**route))
            route = {'interface_id': iface['id'],
                     'family': 6,
                     'prefix': 0,
                     'network': '::',
                     'gateway': '2001:1::1',
                     'metric': '1'}
            self.routes.append(dbutils.create_test_route(**route))

    def _create_ethernet_test(self, ifname=None, networktype=None, **kwargs):
        if isinstance(networktype, list):
            networktype = ','.join(networktype)
        interface_id = len(self.interfaces)
        if not ifname:
            ifname = (networktype or 'eth') + str(interface_id)
        interface = {'id': interface_id,
                     'uuid': str(uuid.uuid4()),
                     'forihostid': self.host.id,
                     'ifname': ifname,
                     'iftype': constants.INTERFACE_TYPE_ETHERNET,
                     'imac': '02:11:22:33:44:' + str(10 + interface_id),
                     'uses': [],
                     'used_by': [],
                     'networktype': networktype,
                     'imtu': 1500,
                     'sriov_numvfs': kwargs.get('sriov_numvfs', 0)}
        db_interface = dbutils.create_test_interface(**interface)
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
                'pciaddr': kwargs.get('pciaddr',
                                      '0000:00:00.' + str(port_id + 1)),
                'dev_id': kwargs.get('dev_id', 0)}
        db_port = dbutils.create_test_ethernet_port(**port)
        self.ports.append(db_port)
        self._setup_address_and_routes(db_interface)
        return db_port, db_interface

    def _create_vlan_test(self, ifname, networktype, vlan_id,
                          lower_iface=None):
        if isinstance(networktype, list):
            networktype = ','.join(networktype)
        if not lower_iface:
            lower_port, lower_iface = self._create_ethernet_test()
        if not ifname:
            ifname = 'vlan' + str(vlan_id)
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
                     'networktype': networktype,
                     'imtu': 1500}
        lower_iface['used_by'].append(interface['ifname'])
        db_interface = dbutils.create_test_interface(**interface)
        self.interfaces.append(db_interface)
        self._setup_address_and_routes(db_interface)
        return db_interface

    def _create_bond_test(self, ifname, networktype=None):
        if isinstance(networktype, list):
            networktype = ','.join(networktype)
        port1, iface1 = self._create_ethernet_test()
        port2, iface2 = self._create_ethernet_test()
        interface_id = len(self.interfaces)
        if not ifname:
            ifname = 'bond' + str(interface_id)
        interface = {'id': interface_id,
                     'uuid': str(uuid.uuid4()),
                     'forihostid': self.host.id,
                     'ifname': ifname,
                     'iftype': constants.INTERFACE_TYPE_AE,
                     'imac': '02:11:22:33:44:' + str(10 + interface_id),
                     'uses': [iface1['ifname'], iface2['ifname']],
                     'used_by': [],
                     'networktype': networktype,
                     'imtu': 1500,
                     'txhashpolicy': 'layer2'}

        lacp_types = [constants.NETWORK_TYPE_MGMT,
                      constants.NETWORK_TYPE_PXEBOOT]
        if networktype in lacp_types:
            interface['aemode'] = '802.3ad'
        else:
            interface['aemode'] = 'balanced'

        iface1['used_by'].append(interface['ifname'])
        iface2['used_by'].append(interface['ifname'])
        db_interface = dbutils.create_test_interface(**interface)
        self.interfaces.append(db_interface)
        self._setup_address_and_routes(db_interface)
        return db_interface

    def _create_test_networks(self):
        mgmt_pool = dbutils.create_test_address_pool(
            network='192.168.204.0',
            name='management',
            ranges=[['192.168.204.2', '192.168.204.254']],
            prefix=24)

        pxeboot_pool = dbutils.create_test_address_pool(
            network='192.168.202.0',
            name='pxeboot',
            ranges=[['192.168.202.2', '192.168.202.254']],
            prefix=24)

        bm_pool = dbutils.create_test_address_pool(
            network='192.168.203.0',
            name='board-management',
            ranges=[['192.168.203.2', '192.168.203.254']],
            prefix=24)

        infra_pool = dbutils.create_test_address_pool(
            network='192.168.205.0',
            name='infrastructure',
            ranges=[['192.168.205.2', '192.168.205.254']],
            prefix=24)

        oam_pool = dbutils.create_test_address_pool(
            network='10.10.10.0',
            name='oam',
            ranges=[['10.10.10.2', '10.10.10.254']],
            prefix=24)

        self.networks.append(dbutils.create_test_network(
            type=constants.NETWORK_TYPE_MGMT,
            link_capacity=constants.LINK_SPEED_1G,
            vlan_id=2,
            address_pool_id=mgmt_pool.id))

        self.networks.append(dbutils.create_test_network(
            type=constants.NETWORK_TYPE_PXEBOOT,
            link_capacity=constants.LINK_SPEED_1G,
            vlan_id=None,
            address_pool_id=pxeboot_pool.id))

        self.networks.append(dbutils.create_test_network(
            type=constants.NETWORK_TYPE_BM,
            link_capacity=constants.LINK_SPEED_1G,
            vlan_id=78,
            address_pool_id=bm_pool.id))

        self.networks.append(dbutils.create_test_network(
            type=constants.NETWORK_TYPE_INFRA,
            link_capacity=constants.LINK_SPEED_10G,
            vlan_id=3,
            address_pool_id=infra_pool.id))

        self.networks.append(dbutils.create_test_network(
            type=constants.NETWORK_TYPE_OAM,
            link_capacity=constants.LINK_SPEED_1G,
            vlan_id=None,
            address_pool_id=oam_pool.id))

    def _create_test_host_ips(self):
        name = utils.format_address_name(constants.CONTROLLER_0_HOSTNAME,
                                         constants.NETWORK_TYPE_OAM)
        address = {
            'name': name,
            'family': 4,
            'prefix': 24,
            'address': '10.10.10.3'
        }
        dbutils.create_test_address(**address)

        name = utils.format_address_name(constants.CONTROLLER_1_HOSTNAME,
                                         constants.NETWORK_TYPE_OAM)
        address = {
            'name': name,
            'family': 4,
            'prefix': 24,
            'address': '10.10.10.4'
        }
        dbutils.create_test_address(**address)

        name = utils.format_address_name(constants.CONTROLLER_0_HOSTNAME,
                                         constants.NETWORK_TYPE_PXEBOOT)
        address = {
            'name': name,
            'family': 4,
            'prefix': 24,
            'address': '192.168.202.3'
        }
        dbutils.create_test_address(**address)

        name = utils.format_address_name(constants.CONTROLLER_1_HOSTNAME,
                                         constants.NETWORK_TYPE_PXEBOOT)
        address = {
            'name': name,
            'family': 4,
            'prefix': 24,
            'address': '192.168.202.4'
        }
        dbutils.create_test_address(**address)

        name = utils.format_address_name(constants.CONTROLLER_0_HOSTNAME,
                                         constants.NETWORK_TYPE_BM)
        address = {
            'name': name,
            'family': 4,
            'prefix': 24,
            'address': '192.168.203.3'
        }
        dbutils.create_test_address(**address)

        name = utils.format_address_name(constants.CONTROLLER_1_HOSTNAME,
                                         constants.NETWORK_TYPE_BM)
        address = {
            'name': name,
            'family': 4,
            'prefix': 24,
            'address': '192.168.203.4'
        }
        dbutils.create_test_address(**address)

    def _create_test_floating_ips(self):
        name = utils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                         constants.NETWORK_TYPE_MGMT)
        address = {
            'name': name,
            'family': 4,
            'prefix': 24,
            'address': '192.168.1.2'
        }
        dbutils.create_test_address(**address)

        name = utils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                         constants.NETWORK_TYPE_OAM)
        address = {
            'name': name,
            'family': 4,
            'prefix': 24,
            'address': '10.10.10.2'
        }
        dbutils.create_test_address(**address)

    def _create_test_gateways(self):
        name = utils.format_address_name(constants.CONTROLLER_GATEWAY,
                                         constants.NETWORK_TYPE_MGMT)
        ipaddr = self.mgmt_gateway_address
        address = {
            'name': name,
            'family': ipaddr.version,
            'prefix': ipaddr.prefixlen,
            'address': str(ipaddr.ip)
        }
        dbutils.create_test_address(**address)

        name = utils.format_address_name(constants.CONTROLLER_GATEWAY,
                                         constants.NETWORK_TYPE_OAM)
        ipaddr = self.oam_gateway_address
        address = {
            'name': name,
            'family': ipaddr.version,
            'prefix': ipaddr.prefixlen,
            'address': str(ipaddr.ip)
        }
        dbutils.create_test_address(**address)

    def _create_test_system(self, system_type=None, system_mode=None):
        system = {
            'system_type': system_type,
            'system_mode': system_mode,
        }
        self.system = dbutils.create_test_isystem(**system)
        self.load = dbutils.create_test_load()

    def _create_test_common(self, system_type=None, system_mode=None):
        self._create_test_system()
        self._create_test_networks()
        self._create_test_gateways()
        self._create_test_floating_ips()
        self._create_test_host_ips()

    def _create_test_host(self, personality, subfunction=None):
        subfunctions = [personality]
        if subfunction:
            subfunctions.append(subfunction)

        host = {'personality': personality,
                'hostname': '%s-0' % personality,
                'forisystemid': self.system.id,
                'subfunctions': ",".join(subfunctions)}

        self.host = dbutils.create_test_ihost(**host)
        return host

    @puppet.puppet_context
    def _update_context(self):
        self.context = self.operator.interface._create_interface_context(self.host)

    def _setup_context(self):
        self._setup_configuration()
        self._update_context()


class InterfaceTestCase(BaseTestCase):
    def _setup_configuration(self):
        # Create a single port/interface for basic function testing
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER)
        self.port, self.iface = self._create_ethernet_test(
            "mgmt0", constants.NETWORK_TYPE_MGMT)

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.
        self.host.save(self.admin_context)
        self.port.save(self.admin_context)
        self.iface.save(self.admin_context)
        super(InterfaceTestCase, self)._update_context()

    def setUp(self):
        super(InterfaceTestCase, self).setUp()
        self._setup_context()

    def test_is_platform_network_type_true(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        result = interface.is_platform_network_type(self.iface)
        self.assertTrue(result)

    def test_is_platform_network_type_false(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        result = interface.is_platform_network_type(self.iface)
        self.assertFalse(result)

    def test_get_port_interface_id_index(self):
        index = self.operator.interface._get_port_interface_id_index(self.host)
        for port in self.ports:
            self.assertTrue(port['interface_id'] in index)
            self.assertEqual(index[port['interface_id']], port)

    def test_get_port_pciaddr_index(self):
        index = self.operator.interface._get_port_pciaddr_index(self.host)
        for port in self.ports:
            self.assertTrue(port['pciaddr'] in index)
            self.assertIn(port, index[port['pciaddr']])

    def test_get_interface_name_index(self):
        index = self.operator.interface._get_interface_name_index(self.host)
        for iface in self.interfaces:
            self.assertTrue(iface['ifname'] in index)
            self.assertEqual(index[iface['ifname']], iface)

    def test_get_network_type_index(self):
        index = self.operator.interface._get_network_type_index()
        for network in self.networks:
            self.assertTrue(network['type'] in index)
            self.assertEqual(index[network['type']], network)

    def test_get_address_interface_name_index(self):
        index = self.operator.interface._get_address_interface_name_index(self.host)
        for address in self.addresses:
            self.assertTrue(address['ifname'] in index)
            self.assertIn(address, index[address['ifname']])

    def test_get_routes_interface_name_index(self):
        index = self.operator.interface._get_routes_interface_name_index(self.host)
        for route in self.routes:
            self.assertTrue(route['ifname'] in index)
            self.assertIn(route, index[route['ifname']])

    def test_get_gateway_index(self):
        index = self.operator.interface._get_gateway_index()
        self.assertEqual(len(index), 2)
        self.assertEqual(index[constants.NETWORK_TYPE_MGMT],
                         str(self.mgmt_gateway_address.ip))
        self.assertEqual(index[constants.NETWORK_TYPE_OAM],
                         str(self.oam_gateway_address.ip))

    def test_is_compute_subfunction_true(self):
        self.host['personality'] = constants.COMPUTE
        self.host['subfunctions'] = constants.COMPUTE
        self._update_context()
        self.assertTrue(interface.is_compute_subfunction(self.context))

    def test_is_compute_subfunction_true_cpe(self):
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.COMPUTE
        self._update_context()
        self.assertTrue(interface.is_compute_subfunction(self.context))

    def test_is_compute_subfunction_false(self):
        self.host['personality'] = constants.STORAGE
        self.host['subfunctions'] = constants.STORAGE
        self._update_context()
        self.assertFalse(interface.is_compute_subfunction(self.context))

    def test_is_compute_subfunction_false_cpe(self):
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.CONTROLLER
        self._update_context()
        self.assertFalse(interface.is_compute_subfunction(self.context))

    def test_is_pci_interface_true(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_SRIOV
        self.assertTrue(interface.is_pci_interface(self.iface))

    def test_is_pci_interface_false(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.assertFalse(interface.is_pci_interface(self.iface))

    def test_get_interface_mtu(self):
        value = interface.get_interface_mtu(self.context, self.iface)
        self.assertEqual(value, self.iface['imtu'])

    def test_get_interface_port(self):
        value = interface.get_interface_port(self.context, self.iface)
        self.assertEqual(value, self.port)

    def test_get_interface_port_name(self):
        value = interface.get_interface_port_name(self.context, self.iface)
        self.assertEqual(value, self.port['name'])

    def test_get_lower_interface(self):
        vlan = self._create_vlan_test(
            "infra", constants.NETWORK_TYPE_INFRA, 1, self.iface)
        self._update_context()
        value = interface.get_lower_interface(self.context, vlan)
        self.assertEqual(value, self.iface)

    def test_get_interface_os_ifname_ethernet(self):
        value = interface.get_interface_os_ifname(self.context, self.iface)
        self.assertEqual(value, self.port['name'])

    def test_get_interface_os_ifname_bond(self):
        self.iface['iftype'] = constants.INTERFACE_TYPE_AE
        value = interface.get_interface_os_ifname(self.context, self.iface)
        self.assertEqual(value, self.iface['ifname'])

    def test_get_interface_os_ifname_vlan_over_ethernet(self):
        vlan = self._create_vlan_test(
            "infra", constants.NETWORK_TYPE_INFRA, 1, self.iface)
        self._update_context()
        value = interface.get_interface_os_ifname(self.context, vlan)
        self.assertEqual(value, self.port['name'] + ".1")

    def test_get_interface_os_ifname_vlan_over_bond(self):
        bond = self._create_bond_test("none")
        vlan = self._create_vlan_test(
            "infra", constants.NETWORK_TYPE_INFRA, 1, bond)
        self._update_context()
        value = interface.get_interface_os_ifname(self.context, vlan)
        self.assertEqual(value, bond['ifname'] + ".1")

    def test_get_interface_primary_address(self):
        address = interface.get_interface_primary_address(
            self.context, self.iface)
        self.assertIsNotNone(address)
        self.assertEqual(address['address'], '192.168.1.2')
        self.assertEqual(address['prefix'], 24)
        self.assertEqual(address['netmask'], '255.255.255.0')

    def test_get_interface_primary_address_none(self):
        self.context['addresses'] = {}
        address = interface.get_interface_primary_address(
            self.context, self.iface)
        self.assertIsNone(address)

    def test_get_interface_address_family_ipv4(self):
        family = interface.get_interface_address_family(
            self.context, self.iface)
        self.assertEqual(family, 'inet')

    def test_get_interface_address_family_ipv6(self):
        address = interface.get_interface_primary_address(
            self.context, self.iface)
        address['address'] = '2001::1'
        address['prefix'] = 64
        address['family'] = 6
        family = interface.get_interface_address_family(
            self.context, self.iface)
        self.assertEqual(family, 'inet6')

    def test_get_interface_address_family_none(self):
        self.context['addresses'] = {}
        family = interface.get_interface_address_family(
            self.context, self.iface)
        self.assertEqual(family, 'inet')

    def test_get_interface_gateway_address_oam(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_OAM
        gateway = interface.get_interface_gateway_address(
            self.context, self.iface)
        expected = str(self.oam_gateway_address.ip)
        self.assertEqual(gateway, expected)

    def test_get_interface_gateway_address_mgmt(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        gateway = interface.get_interface_gateway_address(
            self.context, self.iface)
        expected = str(self.mgmt_gateway_address.ip)
        self.assertEqual(gateway, expected)

    def test_get_interface_gateway_address_none(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        gateway = interface.get_interface_gateway_address(
            self.context, self.iface)
        self.assertIsNone(gateway)

    def test_get_interface_address_method_for_none(self):
        self.iface['networktype'] = None
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_data(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_data_vrs(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA_VRS
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_pci_sriov(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_SRIOV
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_pci_pthru(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_PASSTHROUGH
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_pxeboot_compute(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_PXEBOOT
        self.host['personality'] = constants.COMPUTE
        self._update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_pxeboot_storage(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_PXEBOOT
        self.host['personality'] = constants.STORAGE
        self._update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_pxeboot_controller(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_PXEBOOT
        self.host['personality'] = constants.CONTROLLER
        self._update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_mgmt_compute(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        self.host['personality'] = constants.COMPUTE
        self._update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'dhcp')

    def test_get_interface_address_method_for_mgmt_storage(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        self.host['personality'] = constants.STORAGE
        self._update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'dhcp')

    def test_get_interface_address_method_for_mgmt_controller(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        self.host['personality'] = constants.CONTROLLER
        self._update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_infra_compute(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_INFRA
        self.host['personality'] = constants.COMPUTE
        self._update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'dhcp')

    def test_get_interface_address_method_for_infra_storage(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_INFRA
        self.host['personality'] = constants.STORAGE
        self._update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'dhcp')

    def test_get_interface_address_method_for_infra_controller(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_INFRA
        self.host['personality'] = constants.CONTROLLER
        self._update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_oam_controller(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_OAM
        self.host['personality'] = constants.CONTROLLER
        self._update_context()
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'static')

    def test_get_interface_traffic_classifier_for_mgmt(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        classifier = interface.get_interface_traffic_classifier(
            self.context, self.iface)
        print(self.context)
        expected = ('/usr/local/bin/cgcs_tc_setup.sh %s %s %s > /dev/null' %
                    (self.port['name'], constants.NETWORK_TYPE_MGMT,
                     constants.LINK_SPEED_1G))
        self.assertEqual(classifier, expected)

    def test_get_interface_traffic_classifier_for_infra(self):
        self.iface['ifname'] = 'infra0'
        self.iface['networktype'] = constants.NETWORK_TYPE_INFRA
        classifier = interface.get_interface_traffic_classifier(
            self.context, self.iface)
        expected = ('/usr/local/bin/cgcs_tc_setup.sh %s %s %s > /dev/null' %
                    (self.port['name'], constants.NETWORK_TYPE_INFRA,
                     constants.LINK_SPEED_10G))
        self.assertEqual(classifier, expected)

    def test_get_interface_traffic_classifier_for_oam(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_OAM
        classifier = interface.get_interface_traffic_classifier(
            self.context, self.iface)
        self.assertIsNone(classifier)

    def test_get_interface_traffic_classifier_for_none(self):
        self.iface['networktype'] = None
        classifier = interface.get_interface_traffic_classifier(
            self.context, self.iface)
        self.assertIsNone(classifier)

    def test_get_bridge_interface_name_none_dpdk_supported(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.port['dpdksupport'] = True
        self._update_context()
        ifname = interface.get_bridge_interface_name(self.context, self.iface)
        self.assertIsNone(ifname)

    def test_get_bridge_interface_name_none_not_data(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        ifname = interface.get_bridge_interface_name(self.context, self.iface)
        self.assertIsNone(ifname)

    def test_get_bridge_interface_name(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.port['dpdksupport'] = False
        self._update_context()
        ifname = interface.get_bridge_interface_name(self.context, self.iface)
        self.assertEqual(ifname, 'br-' + self.port['name'])

    def test_needs_interface_config_kernel_mgmt(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        self.host['personality'] = constants.CONTROLLER
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_kernel_infra(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_INFRA
        self.host['personality'] = constants.CONTROLLER
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_kernel_oam(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_OAM
        self.host['personality'] = constants.CONTROLLER
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_kernel_vrs(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA_VRS
        self.host['personality'] = constants.CONTROLLER
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_data(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.CONTROLLER
        self.port['dpdksupport'] = True
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_data_slow(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.CONTROLLER
        self.port['dpdksupport'] = False
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_data_mlx4(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.CONTROLLER
        self.port['driver'] = interface.DRIVER_MLX_CX3
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_data_mlx5(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.CONTROLLER
        self.port['driver'] = interface.DRIVER_MLX_CX4
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_data_slow_compute(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.COMPUTE
        self.port['dpdksupport'] = False
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_data_mlx4_compute(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.COMPUTE
        self.port['driver'] = interface.DRIVER_MLX_CX3
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_data_mlx5_compute(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.COMPUTE
        self.port['driver'] = interface.DRIVER_MLX_CX4
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_sriov_compute(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_SRIOV
        self.host['personality'] = constants.COMPUTE
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_pthru_compute(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_PASSTHROUGH
        self.host['personality'] = constants.COMPUTE
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_data_cpe_compute(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.COMPUTE
        self.port['dpdksupport'] = True
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_data_slow_cpe_compute(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.COMPUTE
        self.port['dpdksupport'] = False
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_data_mlx4_cpe_compute(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.COMPUTE
        self.port['driver'] = interface.DRIVER_MLX_CX3
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_data_mlx5_cpe_compute(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.COMPUTE
        self.port['driver'] = interface.DRIVER_MLX_CX4
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_sriov_cpe(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_SRIOV
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.CONTROLLER
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_sriov_cpe_compute(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_SRIOV
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.COMPUTE
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_pthru_cpe_compute(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_PASSTHROUGH
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.COMPUTE
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def _get_network_config(self, ifname='eth0', ensure='present',
                            family='inet', method='dhcp',
                            hotplug='false', onboot='true',
                            mtu=None, options=None, **kwargs):
        config = {'ifname': ifname,
                  'ensure': ensure,
                  'family': family,
                  'method': method,
                  'hotplug': hotplug,
                  'onboot': onboot}
        if mtu:
            config['mtu'] = str(mtu)
        config['options'] = options or {}
        config.update(**kwargs)
        return config

    def _get_static_network_config(self, **kwargs):
        ifname = kwargs.pop('ifname', 'eth0')
        method = kwargs.pop('method', 'static')
        ipaddress = kwargs.pop('ipaddress', '192.168.1.2')
        netmask = kwargs.pop('netmask', '255.255.255.0')
        return self._get_network_config(
            ifname=ifname, method=method,
            ipaddress=ipaddress, netmask=netmask, **kwargs)

    def _get_route_config(self, name='default', ensure='present',
                          gateway='1.2.3.1', interface='eth0',
                          netmask='0.0.0.0', network='default',
                          metric=1):
        config = {'name': name,
                  'ensure': ensure,
                  'gateway': gateway,
                  'interface': interface,
                  'netmask': netmask,
                  'network': network,
                  'options': 'metric ' + str(metric)}
        return config

    def _get_loopback_config(self):
        network_config = self._get_network_config(
            ifname=interface.LOOPBACK_IFNAME, method=interface.LOOPBACK_METHOD)
        return interface.format_network_config(network_config)

    def test_generate_loopback_config(self):
        config = {
            interface.NETWORK_CONFIG_RESOURCE: {},
        }
        interface.generate_loopback_config(config)
        expected = self._get_loopback_config()
        result = config[interface.NETWORK_CONFIG_RESOURCE].get(
            interface.LOOPBACK_IFNAME)
        self.assertEqual(result, expected)

    def test_get_controller_ethernet_config_oam(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_OAM
        self._update_context()
        config = interface.get_interface_network_config(
            self.context, self.iface)
        options = {'LINKDELAY': '20'}
        expected = self._get_static_network_config(
            ifname=self.port['name'], mtu=1500, gateway='10.10.10.1',
            options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_ethernet_config_mgmt(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        self._update_context()
        config = interface.get_interface_network_config(
            self.context, self.iface)
        options = {'LINKDELAY': '20',
                   'post_up':
                       '/usr/local/bin/cgcs_tc_setup.sh %s %s %s > /dev/null' %
                       (self.port['name'], constants.NETWORK_TYPE_MGMT,
                        constants.LINK_SPEED_1G)}
        expected = self._get_static_network_config(
            ifname=self.port['name'], mtu=1500, gateway='192.168.204.1',
            options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_ethernet_config_infra(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_INFRA
        self._update_context()
        config = interface.get_interface_network_config(
            self.context, self.iface)
        options = {'LINKDELAY': '20',
                   'post_up':
                       '/usr/local/bin/cgcs_tc_setup.sh %s %s %s > /dev/null' %
                       (self.port['name'], constants.NETWORK_TYPE_INFRA,
                        constants.LINK_SPEED_10G)}
        expected = self._get_static_network_config(
            ifname=self.port['name'], mtu=1500,
            options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_ethernet_config_slave(self):
        bond = self._create_bond_test("bond0")
        self._update_context()
        iface = self.context['interfaces'][bond['uses'][0]]
        port = self.context['ports'][iface['id']]
        config = interface.get_interface_network_config(self.context, iface)
        options = {'SLAVE': 'yes',
                   'PROMISC': 'yes',
                   'MASTER': 'bond0',
                   'LINKDELAY': '20'}
        expected = self._get_network_config(
            ifname=port['name'], mtu=1500, method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_config_balanced(self):
        bond = self._create_bond_test("bond0")
        self._update_context()
        config = interface.get_interface_network_config(self.context, bond)
        options = {'up': 'sleep 10',
                   'MACADDR': bond['imac'],
                   'BONDING_OPTS':
                       'mode=balance-xor xmit_hash_policy=layer2 miimon=100'}
        expected = self._get_network_config(
            ifname=bond['ifname'], mtu=1500, method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_config_8023ad(self):
        bond = self._create_bond_test("bond0")
        bond['aemode'] = '802.3ad'
        self._update_context()
        config = interface.get_interface_network_config(self.context, bond)
        options = {'up': 'sleep 10',
                   'MACADDR': bond['imac'],
                   'BONDING_OPTS':
                       'mode=802.3ad lacp_rate=fast '
                       'xmit_hash_policy=layer2 miimon=100'}
        expected = self._get_network_config(
            ifname=bond['ifname'], mtu=1500, method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_config_active_standby(self):
        bond = self._create_bond_test("bond0")
        bond['aemode'] = 'active_standby'
        self._update_context()
        config = interface.get_interface_network_config(self.context, bond)
        options = {'up': 'sleep 10',
                   'MACADDR': bond['imac'],
                   'BONDING_OPTS': 'mode=active-backup miimon=100'}
        expected = self._get_network_config(
            ifname=bond['ifname'], mtu=1500, method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_vlan_config(self):
        vlan = self._create_vlan_test("vlan1", None, 1, self.iface)
        self._update_context()
        config = interface.get_interface_network_config(self.context, vlan)
        options = {'VLAN': 'yes',
                   'pre_up': '/sbin/modprobe -q 8021q'}
        expected = self._get_network_config(
            ifname=self.port['name'] + ".1", mtu=1500, method='manual',
            options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_vlan_config_over_bond(self):
        bond = self._create_bond_test("bond0")
        vlan = self._create_vlan_test("vlan1", None, 1, bond)
        self._update_context()
        config = interface.get_interface_network_config(self.context, vlan)
        options = {'VLAN': 'yes',
                   'pre_up': '/sbin/modprobe -q 8021q'}
        expected = self._get_network_config(
            ifname=bond['ifname'] + ".1", mtu=1500, method='manual',
            options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_compute_ethernet_config_mgmt(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        self.host['personality'] = constants.COMPUTE
        self._update_context()
        config = interface.get_interface_network_config(
            self.context, self.iface)
        options = {'LINKDELAY': '20',
                   'post_up':
                       '/usr/local/bin/cgcs_tc_setup.sh %s %s %s > /dev/null' %
                       (self.port['name'], constants.NETWORK_TYPE_MGMT,
                        constants.LINK_SPEED_1G)}
        expected = self._get_network_config(
            ifname=self.port['name'], mtu=1500, options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_compute_ethernet_config_infra(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_INFRA
        self.host['personality'] = constants.COMPUTE
        self._update_context()
        config = interface.get_interface_network_config(
            self.context, self.iface)
        options = {'LINKDELAY': '20',
                   'post_up':
                       '/usr/local/bin/cgcs_tc_setup.sh %s %s %s > /dev/null' %
                       (self.port['name'], constants.NETWORK_TYPE_INFRA,
                        constants.LINK_SPEED_10G)}
        expected = self._get_network_config(
            ifname=self.port['name'], mtu=1500, options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_compute_ethernet_config_pci_sriov(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_SRIOV
        self.host['personality'] = constants.COMPUTE
        self._update_context()
        config = interface.get_interface_network_config(
            self.context, self.iface)
        options = {'LINKDELAY': '20',
                   'pre_up':
                       'echo 0 > /sys/class/net/eth0/device/sriov_numvfs; '
                       'echo 0 > /sys/class/net/eth0/device/sriov_numvfs'}
        expected = self._get_network_config(
            ifname=self.port['name'], method='manual',
            mtu=1500, options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_compute_ethernet_config_pci_pthru(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_PASSTHROUGH
        self.host['personality'] = constants.COMPUTE
        self._update_context()
        config = interface.get_interface_network_config(
            self.context, self.iface)
        options = {'LINKDELAY': '20',
                   'pre_up':
                       'if [ -f  /sys/class/net/eth0/device/sriov_numvfs ]; then'
                       ' echo 0 > /sys/class/net/eth0/device/sriov_numvfs; fi'}
        expected = self._get_network_config(
            ifname=self.port['name'], mtu=1500, method='manual',
            options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_compute_ethernet_config_data_vrs(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA_VRS
        self.host['personality'] = constants.COMPUTE
        self._update_context()
        config = interface.get_interface_network_config(
            self.context, self.iface)
        options = {'LINKDELAY': '20'}
        expected = self._get_static_network_config(
            ifname=self.port['name'], mtu=1500, options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_compute_ethernet_config_data_slow(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.port['dpdksupport'] = False
        self.host['personality'] = constants.COMPUTE
        self._update_context()
        config = interface.get_interface_network_config(
            self.context, self.iface)
        options = {'BRIDGE': 'br-' + self.port['name'],
                   'LINKDELAY': '20'}
        expected = self._get_network_config(
            ifname=self.port['name'], mtu=1500, method='manual',
            options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_compute_ethernet_config_data_slow_as_bond_slave(self):
        bond = self._create_bond_test("data1", constants.NETWORK_TYPE_DATA)
        self.host['personality'] = constants.COMPUTE
        self._update_context()
        lower_ifname = bond['uses'][0]
        lower_iface = self.context['interfaces'][lower_ifname]
        lower_port = interface.get_interface_port(self.context, lower_iface)
        lower_port['dpdksupport'] = False
        lower_port.save(self.admin_context)
        self._update_context()
        config = interface.get_interface_network_config(
            self.context, lower_iface)
        options = {'BRIDGE': 'br-' + lower_port['name'],
                   'LINKDELAY': '20'}
        expected = self._get_network_config(
            ifname=lower_port['name'], mtu=1500, method='manual',
            options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_compute_ethernet_config_data_slow_bridge(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.port['dpdksupport'] = False
        self.host['personality'] = constants.COMPUTE
        self._update_context()
        avp_config, bridge_config = interface.get_bridged_network_config(
            self.context, self.iface)
        # Check the AVP config
        options = {'BRIDGE': 'br-' + self.port['name'],
                   'LINKDELAY': '20'}
        expected = self._get_network_config(
            ifname=self.port['name'] + '-avp', mtu=1500, method='manual',
            options=options)
        print(expected)
        self.assertEqual(avp_config, expected)
        # Check the expected bridge config
        options = {'TYPE': 'Bridge'}
        expected = self._get_network_config(
            ifname='br-' + self.port['name'], method='manual', options=options)
        print(expected)
        self.assertEqual(expected, bridge_config)

    def test_get_route_config(self):
        route = {'network': '1.2.3.0',
                 'prefix': 24,
                 'gateway': '1.2.3.1',
                 'metric': 20}
        config = interface.get_route_config(route, "eth0")
        expected = self._get_route_config(
            name='1.2.3.0/24', network='1.2.3.0',
            netmask='255.255.255.0', metric=20)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_route_config_default(self):
        route = {'network': '0.0.0.0',
                 'prefix': 0,
                 'gateway': '1.2.3.1',
                 'metric': 1}
        config = interface.get_route_config(route, "eth0")
        expected = self._get_route_config()
        print(expected)
        self.assertEqual(expected, config)

    def test_is_a_mellanox_cx3_device_false(self):
        self.assertFalse(
            interface.is_a_mellanox_cx3_device(self.context, self.iface))

    def test_is_a_mellanox_cx3_device_true(self):
        self.port['driver'] = interface.DRIVER_MLX_CX3
        self._update_context()
        self.assertTrue(
            interface.is_a_mellanox_cx3_device(self.context, self.iface))

    def test_find_sriov_interfaces_by_driver_none(self):
        ifaces = interface.find_sriov_interfaces_by_driver(
            self.context, interface.DRIVER_MLX_CX3)
        self.assertTrue(not ifaces)

    def test_find_sriov_interfaces_by_driver_one(self):
        expected = ['sriov_cx3_0']
        vf_num = 2

        for ifname in expected:
            self._create_sriov_cx3_if_test(ifname, vf_num)
        self._update_context()

        ifaces = interface.find_sriov_interfaces_by_driver(
            self.context, interface.DRIVER_MLX_CX3)

        results = [iface['ifname'] for iface in ifaces]
        self.assertEqual(sorted(results), sorted(expected))

    def test_find_sriov_interfaces_by_driver_two(self):
        expected = ['sriov_cx3_0', 'sriov_cx3_1']
        vf_num = 2

        for ifname in expected:
            self._create_sriov_cx3_if_test(ifname, vf_num)
        self._update_context()

        ifaces = interface.find_sriov_interfaces_by_driver(
            self.context, interface.DRIVER_MLX_CX3)

        results = [iface['ifname'] for iface in ifaces]
        self.assertEqual(sorted(results), sorted(expected))

    def test_build_mlx4_num_vfs_options_none(self):
        expected = ""

        num_vfs_options = interface.build_mlx4_num_vfs_options(self.context)

        self.assertEqual(num_vfs_options, expected)

    def test_build_mlx4_num_vfs_options_one(self):
        ifname = 'sriov_cx3_0'
        vf_num = 2

        port, iface = self._create_sriov_cx3_if_test(ifname, vf_num)
        self._update_context()
        expected = "%s-%d;0;0" % (port['pciaddr'], vf_num)

        num_vfs_options = interface.build_mlx4_num_vfs_options(self.context)

        self.assertEqual(num_vfs_options, expected)

    def test_build_mlx4_num_vfs_options_two(self):
        ifname0, ifname1 = 'sriov_cx3_0', 'sriov_cx3_1'
        vf_num = 2

        port0, iface0 = self._create_sriov_cx3_if_test(ifname0, vf_num)
        port1, iface1 = self._create_sriov_cx3_if_test(ifname1, vf_num)
        self._update_context()
        expected = [
            "%s-%d;0;0,%s-%d;0;0" % (port0['pciaddr'], vf_num,
                                     port1['pciaddr'], vf_num),
            "%s-%d;0;0,%s-%d;0;0" % (port1['pciaddr'], vf_num,
                                     port0['pciaddr'], vf_num),
        ]
        num_vfs_options = interface.build_mlx4_num_vfs_options(self.context)

        self.assertIn(num_vfs_options, expected)

    def test_build_mlx4_num_vfs_options_dup(self):
        ifname0, ifname1 = 'sriov_cx3_0', 'sriov_cx3_1'
        vf_num = 2

        port0, iface0 = self._create_sriov_cx3_if_test(ifname0, vf_num)
        port1, iface1 = self._create_sriov_cx3_if_test(
            ifname1, vf_num, pciaddr=port0['pciaddr'],dev_id=1)
        self._update_context()

        expected = "%s-%d;0;0" % (port0['pciaddr'], vf_num)
        num_vfs_options = interface.build_mlx4_num_vfs_options(self.context)

        self.assertEqual(num_vfs_options, expected)

    def _create_sriov_cx3_if_test(self, name, vf_num, **kwargs):
        port, iface = self._create_ethernet_test(
            name, constants.NETWORK_TYPE_PCI_SRIOV,
            driver=interface.DRIVER_MLX_CX3, sriov_numvfs=vf_num, **kwargs)
        return port, iface


class InterfaceVswitchTestCase(BaseTestCase):
    def _setup_configuration(self):
        # Create a single port/interface for basic function testing
        self._create_test_common()
        self._create_test_host(constants.COMPUTE)
        self.port, self.iface = (
            self._create_ethernet_test('data0',
                                       constants.NETWORK_TYPE_DATA))

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.
        self.host.save(self.admin_context)
        self.port.save(self.admin_context)
        self.iface.save(self.admin_context)
        super(InterfaceVswitchTestCase, self)._update_context()

    def setUp(self):
        super(InterfaceVswitchTestCase, self).setUp()
        self._setup_context()

    def test_needs_vswitch_config_false_on_controller(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.CONTROLLER
        self._update_context()
        needed = interface.needs_vswitch_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_vswitch_config_true_on_compute(self):
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        needed = interface.needs_vswitch_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_vswitch_config_false_for_platform(self):
        vlan = self._create_vlan_test('infra0',
                                      constants.NETWORK_TYPE_INFRA, 1)
        self.host['personality'] = constants.COMPUTE
        self._update_context()
        needed = interface.needs_vswitch_config(self.context, vlan)
        self.assertFalse(needed)

    def test_get_vswitch_ethernet_command(self):
        cmd = interface.get_vswitch_ethernet_command(self.context, self.iface)
        expected = ("ethernet add %(port_uuid)s %(iface_uuid)s %(mtu)s\n" %
                    {'port_uuid': self.port['uuid'],
                     'iface_uuid': self.iface['uuid'],
                     'mtu': self.iface['imtu']})
        self.assertEqual(expected, cmd)

    def test_get_vswitch_ethernet_command_slow_data(self):
        self.port['dpdksupport'] = False
        self._update_context()
        cmd = interface.get_vswitch_ethernet_command(self.context, self.iface)
        expected = (
            "port add avp-provider %(uuid)s %(mac)s 0 %(mtu)s %(ifname)s\n" %
            {'uuid': self.iface['uuid'],
             'mtu': self.iface['imtu'],
             'mac': interface._set_local_admin_bit(self.iface['imac']),
             'ifname': self.port['name'] + '-avp'})
        self.assertEqual(expected, cmd)

    def test_get_vswitch_vlan_command(self):
        vlan = self._create_vlan_test(
            'data1', constants.NETWORK_TYPE_DATA, 1, self.iface)
        self._update_context()
        cmd = interface.get_vswitch_vlan_command(self.context, vlan)
        expected = ("vlan add %(lower_uuid)s %(vlan_id)s %(uuid)s %(mtu)s\n" %
                    {'lower_uuid': self.iface['uuid'],
                     'vlan_id': vlan['vlan_id'],
                     'uuid': vlan['uuid'],
                     'mtu': vlan['imtu']})
        self.assertEqual(expected, cmd)

    def test_get_vswitch_vlan_command_for_platform(self):
        vlan = self._create_vlan_test(
            'infra', constants.NETWORK_TYPE_INFRA, 1, self.iface)
        self._update_context()
        cmd = interface.get_vswitch_vlan_command(self.context, vlan)
        expected = (
            "vlan add %(lower_uuid)s %(vlan_id)s %(uuid)s %(mtu)s host\n" %
            {'lower_uuid': self.iface['uuid'],
             'vlan_id': vlan['vlan_id'],
             'uuid': vlan['uuid'],
             'mtu': vlan['imtu']})
        self.assertEqual(expected, cmd)

    def test_get_vswitch_address_command(self):
        address = self.context['addresses'].get(self.iface['ifname'])[0]
        cmd = interface.get_vswitch_address_command(self.iface, address)
        expected = (
            "interface add addr %(iface_uuid)s %(address)s/%(prefix)s\n" %
            {'iface_uuid': self.iface['uuid'],
             'address': address['address'],
             'prefix': address['prefix']})
        self.assertEqual(expected, cmd)

    def test_get_vswitch_route_command(self):
        route = self.context['routes'].get(self.iface['ifname'])[0]
        cmd = interface.get_vswitch_route_command(self.iface, route)
        expected = (
            "route append %(network)s/%(prefix)s %(iface_uuid)s %(gateway)s "
            "%(metric)s\n" %
            {'iface_uuid': self.iface['uuid'],
             'network': route['network'],
             'gateway': route['gateway'],
             'prefix': route['prefix'],
             'metric': route['metric']})
        self.assertEqual(expected, cmd)

    def test_get_vswitch_bond_options_balanced(self):
        bond = self._create_bond_test('data1', constants.NETWORK_TYPE_DATA)
        self._update_context()
        bond['aemode'] = 'balanced'
        options = interface.get_vswitch_bond_options(bond)
        expected = {'distribution': 'hash-mac',
                    'protection': 'loadbalance',
                    'monitor': 'link-state'}
        self.assertEqual(options, expected)

    def test_get_vswitch_bond_options_8023ad(self):
        bond = self._create_bond_test('data1', constants.NETWORK_TYPE_DATA)
        self._update_context()
        bond['aemode'] = '802.3ad'
        options = interface.get_vswitch_bond_options(bond)
        expected = {'distribution': 'hash-mac',
                    'protection': '802.3ad',
                    'monitor': 'link-state'}
        self.assertEqual(options, expected)

    def test_get_vswitch_bond_options_active_backup(self):
        bond = self._create_bond_test('data1', constants.NETWORK_TYPE_DATA)
        self._update_context()
        bond['aemode'] = 'active_backup'
        options = interface.get_vswitch_bond_options(bond)
        expected = {'distribution': 'none',
                    'protection': 'failover',
                    'monitor': 'link-state'}
        self.assertEqual(options, expected)

    def test_get_vswitch_bond_commands(self):
        bond = self._create_bond_test('data1', constants.NETWORK_TYPE_DATA)
        self._update_context()
        bond['aemode'] = '802.3ad'
        options = interface.get_vswitch_bond_options(bond)
        attributes = {'uuid': bond['uuid'],
                      'mtu': bond['imtu']}
        attributes.update(options)
        for index, lower_ifname in enumerate(bond['uses']):
            lower_iface = self.context['interfaces'][lower_ifname]
            attributes['member%s_uuid' % index] = lower_iface['uuid']
        expected = (
            "ae add %(uuid)s %(mtu)s %(protection)s %(distribution)s %(monitor)s\n"
            "ae attach member %(uuid)s %(member0_uuid)s\n"
            "ae attach member %(uuid)s %(member1_uuid)s\n" %
            attributes)
        cmds = interface.get_vswitch_bond_commands(self.context, bond)
        self.assertEqual(cmds, expected)


class InterfaceHostTestCase(BaseTestCase):
    def _setup_configuration(self):
        # Personality is set to compute to avoid issues due to missing OAM
        # interface in this empty/dummy configuration
        self._create_test_common()
        self._create_test_host(constants.COMPUTE)

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.
        self.host.save(self.admin_context)
        super(InterfaceHostTestCase, self)._update_context()

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

    def _create_hieradata_directory(self):
        hiera_path = os.path.join(os.environ['VIRTUAL_ENV'], 'hieradata')
        if not os.path.exists(hiera_path):
            os.mkdir(hiera_path, 0o755)
        return hiera_path

    def _get_config_filename(self, hiera_directory):
        class_name = self.__class__.__name__
        return os.path.join(hiera_directory, class_name) + ".yaml"

    def _create_vswitch_directory(self):
        vswitch_path = os.path.join(os.environ['VIRTUAL_ENV'], 'vswitch')
        if not os.path.exists(vswitch_path):
            os.mkdir(vswitch_path, 0o755)
        return vswitch_path

    def _get_vswitch_filename(self, vswitch_directory):
        class_name = self.__class__.__name__
        return os.path.join(vswitch_directory, class_name) + ".cmds"

    def test_generate_interface_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        vswitch_directory = self._create_vswitch_directory()
        vswitch_filename = self._get_vswitch_filename(vswitch_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.interface.get_host_config(self.host)
            self.assertIsNotNone(config)
            yaml.dump(config, config_file, default_flow_style=False)
        with open(vswitch_filename, 'w') as commands:
            commands.write(config['cgcs_vswitch::vswitch_commands'])

    def test_create_interface_context(self):
        context = self.operator.interface._create_interface_context(self.host)
        self.assertIn('personality', context)
        self.assertIn('subfunctions', context)
        self.assertIn('devices', context)
        self.assertIn('ports', context)
        self.assertIn('interfaces', context)
        self.assertIn('addresses', context)
        self.assertIn('routes', context)
        self.assertIn('gateways', context)

    def test_find_bmc_lower_interface(self):
        if self.expected_bmc_interface:
            lower_iface = interface._find_bmc_lower_interface(self.context)
            lower_ifname = lower_iface['ifname']
            self.assertEqual(lower_ifname, self.expected_bmc_interface)

    def test_is_platform_interface(self):
        for iface in self.interfaces:
            expected = bool(
                iface['ifname'] in self.expected_platform_interfaces)
            if interface.is_platform_interface(self.context,
                                               iface) != expected:
                print("iface %s is %sa kernel interface" % (
                    iface['ifname'], ('not ' if expected else '')))

                self.assertFalse(True)

    def test_is_data_interface(self):
        for iface in self.interfaces:
            expected = bool(iface['ifname'] in self.expected_data_interfaces)
            if interface.is_data_interface(self.context, iface) != expected:
                print("iface %s is %sa vswitch interface" % (
                    iface['ifname'], ('not ' if expected else '')))
                self.assertFalse(True)

    def test_is_pci_interface(self):
        for iface in self.interfaces:
            expected = bool(iface['ifname'] in self.expected_pci_interfaces)
            if interface.is_pci_interface(iface) != expected:
                print("iface %s is %sa pci interface" % (
                    iface['ifname'], ('not ' if expected else '')))
                self.assertFalse(True)

    def test_is_a_mellanox_device(self):
        for iface in self.interfaces:
            if iface['iftype'] != constants.INTERFACE_TYPE_ETHERNET:
                continue
            expected = bool(iface['ifname'] in self.expected_mlx_interfaces)
            if interface.is_a_mellanox_device(self.context,
                                              iface) != expected:
                print("iface %s is %sa mellanox device" % (
                    iface['ifname'], ('not ' if expected else '')))
                self.assertFalse(True)

    def test_is_dpdk_compatible_false(self):
        for iface in self.interfaces:
            expected = bool(iface['ifname'] in self.expected_slow_interfaces)
            if interface.is_dpdk_compatible(self.context, iface) == expected:
                print("iface %s is %sdpdk compatible" % (
                    iface['ifname'], ('not ' if not expected else '')))
                self.assertFalse(True)

    def test_is_bridged_interface(self):
        for iface in self.interfaces:
            expected = bool(
                iface['ifname'] in self.expected_bridged_interfaces)
            if interface.is_bridged_interface(self.context,
                                              iface) != expected:
                print("iface %s is %sa bridged interface" % (
                    iface['ifname'], ('not ' if expected else '')))
                self.assertFalse(True)

    def test_is_slave_interface(self):
        for iface in self.interfaces:
            expected = bool(iface['ifname'] in self.expected_slave_interfaces)
            if interface.is_slave_interface(self.context, iface) != expected:
                print("iface %s is %sa slave interface" % (
                    iface['ifname'], ('not ' if expected else '')))
                self.assertFalse(True)

    def test_needs_interface_config(self):
        expected_configured = (self.expected_platform_interfaces +
                               [self.expected_bmc_interface])
        if interface.is_compute_subfunction(self.context):
            expected_configured += (self.expected_pci_interfaces +
                                    self.expected_slow_interfaces +
                                    self.expected_mlx_interfaces)
        for iface in self.interfaces:
            expected = bool(iface['ifname'] in expected_configured)
            actual = interface.needs_interface_config(self.context, iface)
            if expected != actual:
                print("iface %s is %sconfigured" % (
                    iface['ifname'], ('not ' if expected else '')))
                self.assertFalse(True)

    def test_needs_vswitch_config(self):
        expected_configured = []
        if interface.is_compute_subfunction(self.context):
            expected_configured += (self.expected_data_interfaces +
                                    self.expected_slow_interfaces)
        for iface in self.interfaces:
            expected = bool(iface['ifname'] in expected_configured)
            actual = interface.needs_vswitch_config(self.context, iface)
            if expected != actual:
                print("iface %s is %sconfigured" % (
                    iface['ifname'], ('not ' if expected else '')))
                self.assertFalse(True)


class InterfaceControllerEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # ethernet interfaces.
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER)
        self._create_ethernet_test('oam', constants.NETWORK_TYPE_OAM)
        self._create_ethernet_test('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_ethernet_test('infra', constants.NETWORK_TYPE_INFRA)
        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceControllerEthernet, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['oam', 'mgmt', 'infra']


class InterfaceControllerBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # aggregated ethernet interfaces.
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER)
        self._create_bond_test('oam', constants.NETWORK_TYPE_OAM)
        self._create_bond_test('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_bond_test('infra', constants.NETWORK_TYPE_INFRA)

    def setUp(self):
        super(InterfaceControllerBond, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['eth0', 'eth1', 'oam',
                                             'eth3', 'eth4', 'mgmt',
                                             'eth6', 'eth7', 'infra']
        self.expected_slave_interfaces = ['eth0', 'eth1',
                                          'eth3', 'eth4',
                                          'eth6', 'eth7']


class InterfaceControllerVlanOverBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # vlan interfaces over aggregated ethernet interfaces
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER)
        bond = self._create_bond_test('pxeboot',
                                      constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('oam', constants.NETWORK_TYPE_OAM, 1, bond)
        self._create_vlan_test('mgmt', constants.NETWORK_TYPE_MGMT, 2, bond)
        self._create_vlan_test('infra', constants.NETWORK_TYPE_INFRA, 3,
                               bond)
        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceControllerVlanOverBond, self).setUp()
        self.expected_bmc_interface = 'pxeboot'
        self.expected_platform_interfaces = ['eth0', 'eth1', 'pxeboot',
                                             'oam', 'mgmt', 'infra']
        self.expected_slave_interfaces = ['eth0', 'eth1']


class InterfaceControllerVlanOverEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # vlan interfaces over ethernet interfaces
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER)
        port, iface = self._create_ethernet_test(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('oam', constants.NETWORK_TYPE_OAM, 1, iface)
        self._create_vlan_test('mgmt', constants.NETWORK_TYPE_MGMT, 2,
                               iface)
        self._create_vlan_test('infra', constants.NETWORK_TYPE_INFRA, 3,
                               iface)
        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceControllerVlanOverEthernet, self).setUp()
        self.expected_bmc_interface = 'pxeboot'
        self.expected_platform_interfaces = ['eth0', 'pxeboot', 'oam',
                                             'mgmt', 'infra']


class InterfaceComputeEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # compute and all interfaces are ethernet interfaces.
        self._create_test_common()
        self._create_test_host(constants.COMPUTE)
        self._create_ethernet_test('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_ethernet_test('infra', constants.NETWORK_TYPE_INFRA)
        self._create_ethernet_test('vrs', constants.NETWORK_TYPE_DATA_VRS)
        self._create_ethernet_test('data', constants.NETWORK_TYPE_DATA)
        self._create_ethernet_test('sriov',
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)
        port, iface = (
            self._create_ethernet_test('slow', constants.NETWORK_TYPE_DATA,
                                       dpdksupport=False))
        port, iface = (
            self._create_ethernet_test('mlx4', constants.NETWORK_TYPE_DATA,
                                       driver=interface.DRIVER_MLX_CX3))
        port, iface = (
            self._create_ethernet_test('mlx5', constants.NETWORK_TYPE_DATA,
                                       driver=interface.DRIVER_MLX_CX4))
        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceComputeEthernet, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['mgmt', 'infra', 'vrs']
        self.expected_data_interfaces = ['slow', 'data', 'mlx4', 'mlx5']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.expected_slow_interfaces = ['slow']
        self.expected_bridged_interfaces = ['slow']
        self.expected_slave_interfaces = []
        self.expected_mlx_interfaces = ['mlx4', 'mlx5']


class InterfaceComputeVlanOverEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # compute and all interfaces are vlan interfaces over ethernet
        # interfaces.
        self._create_test_common()
        self._create_test_host(constants.COMPUTE)
        port, iface = self._create_ethernet_test(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('mgmt', constants.NETWORK_TYPE_MGMT, 2,
                               iface)
        self._create_vlan_test('infra', constants.NETWORK_TYPE_INFRA, 3)
        self._create_vlan_test('vrs', constants.NETWORK_TYPE_DATA_VRS, 4)
        self._create_vlan_test('data', constants.NETWORK_TYPE_DATA, 5)
        self._create_ethernet_test('sriov',
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceComputeVlanOverEthernet, self).setUp()
        self.expected_bmc_interface = 'pxeboot'
        self.expected_platform_interfaces = ['pxeboot', 'mgmt',
                                             'eth2', 'infra',
                                             'eth4', 'vrs']
        self.expected_data_interfaces = ['eth6', 'data']
        self.expected_pci_interfaces = ['sriov', 'pthru']


class InterfaceComputeBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        self._create_test_common()
        # compute and all interfaces are aggregated ethernet interfaces.
        self._create_test_host(constants.COMPUTE)
        self._create_bond_test('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_bond_test('infra', constants.NETWORK_TYPE_INFRA)
        self._create_bond_test('vrs', constants.NETWORK_TYPE_DATA_VRS)
        self._create_bond_test('data', constants.NETWORK_TYPE_DATA)
        self._create_ethernet_test('sriov',
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceComputeBond, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['eth0', 'eth1', 'mgmt',
                                             'eth3', 'eth4', 'infra',
                                             'eth6', 'eth7', 'vrs']
        self.expected_data_interfaces = ['eth9', 'eth10', 'data',
                                         'eth12', 'eth13', 'ex']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.expected_slave_interfaces = ['eth0', 'eth1', 'eth3', 'eth4',
                                          'eth6', 'eth7', 'eth9', 'eth10',
                                          'eth12', 'eth13']


class InterfaceComputeVlanOverBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # compute and all interfaces are vlan interfaces over ethernet
        # interfaces.
        self._create_test_common()
        self._create_test_host(constants.COMPUTE)
        bond = self._create_bond_test('pxeboot',
                                      constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('oam', constants.NETWORK_TYPE_OAM, 1, bond)
        self._create_vlan_test('mgmt', constants.NETWORK_TYPE_MGMT, 2, bond)
        self._create_vlan_test('infra', constants.NETWORK_TYPE_INFRA, 3,
                               bond)
        bond1 = self._create_bond_test('bond1')
        self._create_vlan_test('vrs', constants.NETWORK_TYPE_DATA_VRS, 4,
                               bond1)
        bond2 = self._create_bond_test('bond2')
        self._create_vlan_test('data', constants.NETWORK_TYPE_DATA, 5,
                               bond2)
        self._create_ethernet_test('sriov',
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceComputeVlanOverBond, self).setUp()
        self.expected_platform_interfaces = ['eth0', 'eth1', 'pxeboot',
                                             'oam', 'mgmt', 'infra',
                                             'eth6', 'eth7', 'bond1', 'vrs']
        self.expected_data_interfaces = ['eth10', 'eth11', 'bond2', 'data',
                                         'eth14', 'eth15']
        self.expected_slave_interfaces = ['eth0', 'eth1',
                                          'eth6', 'eth7',
                                          'eth10', 'eth11']
        self.expected_pci_interfaces = ['sriov', 'pthru']


class InterfaceComputeVlanOverDataEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # compute and all interfaces are vlan interfaces over data ethernet
        # interfaces.
        self._create_test_common()
        self._create_test_host(constants.COMPUTE)
        port, iface = (
            self._create_ethernet_test(
                'data',
                [constants.NETWORK_TYPE_PXEBOOT, constants.NETWORK_TYPE_DATA]))
        self._create_ethernet_test('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_ethernet_test('infra', constants.NETWORK_TYPE_INFRA)
        self._create_vlan_test('vrs', constants.NETWORK_TYPE_DATA_VRS, 4,
                               iface)
        self._create_vlan_test('data2', constants.NETWORK_TYPE_DATA, 5,
                               iface)
        self._create_ethernet_test('sriov',
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceComputeVlanOverDataEthernet, self).setUp()
        self.expected_platform_interfaces = ['data', 'mgmt',
                                             'eth2', 'infra',
                                             'vrs']
        self.expected_data_interfaces = ['data', 'data2']
        self.expected_pci_interfaces = ['sriov', 'pthru']


class InterfaceCpeEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a controller subfunction and all interfaces are
        # ethernet interfaces.
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER)
        self._create_ethernet_test('oam', constants.NETWORK_TYPE_OAM)
        self._create_ethernet_test('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_ethernet_test('infra', constants.NETWORK_TYPE_INFRA)
        self._create_ethernet_test('vrs', constants.NETWORK_TYPE_DATA_VRS)
        self._create_ethernet_test('data', constants.NETWORK_TYPE_DATA)
        self._create_ethernet_test('sriov',
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)
        port, iface = (
            self._create_ethernet_test('slow', constants.NETWORK_TYPE_DATA,
                                       dpdksupport=False))
        port, iface = (
            self._create_ethernet_test('mlx4', constants.NETWORK_TYPE_DATA,
                                       driver=interface.DRIVER_MLX_CX3))
        port, iface = (
            self._create_ethernet_test('mlx5', constants.NETWORK_TYPE_DATA,
                                       driver=interface.DRIVER_MLX_CX4))
        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceCpeEthernet, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['oam', 'mgmt', 'infra', 'vrs']
        self.expected_data_interfaces = ['slow', 'data', 'mlx4', 'mlx5']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.expected_slow_interfaces = ['slow']
        self.expected_bridged_interfaces = ['slow']
        self.expected_slave_interfaces = []
        self.expected_mlx_interfaces = ['mlx4', 'mlx5']


class InterfaceCpeVlanOverEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a controller subfunction and all interfaces are
        # vlan interfaces over ethernet interfaces.
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER)
        port, iface = self._create_ethernet_test(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('oam', constants.NETWORK_TYPE_OAM, 1, iface)
        self._create_vlan_test('mgmt', constants.NETWORK_TYPE_MGMT, 2,
                               iface)
        self._create_vlan_test('infra', constants.NETWORK_TYPE_INFRA, 3)
        self._create_vlan_test('vrs', constants.NETWORK_TYPE_DATA_VRS, 4)
        self._create_vlan_test('data', constants.NETWORK_TYPE_DATA, 5)
        self._create_ethernet_test('sriov',
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceCpeVlanOverEthernet, self).setUp()
        self.expected_bmc_interface = 'pxeboot'
        self.expected_platform_interfaces = ['pxeboot', 'mgmt', 'oam',
                                             'eth3', 'infra',
                                             'eth5', 'vrs']
        self.expected_data_interfaces = ['eth7', 'data']
        self.expected_pci_interfaces = ['sriov', 'pthru']


class InterfaceCpeBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a controller subfunction and all interfaces are
        # aggregated ethernet interfaces.
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER)
        self._create_bond_test('oam', constants.NETWORK_TYPE_OAM)
        self._create_bond_test('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_bond_test('infra', constants.NETWORK_TYPE_INFRA)
        self._create_bond_test('vrs', constants.NETWORK_TYPE_DATA_VRS)
        self._create_bond_test('data', constants.NETWORK_TYPE_DATA)
        self._create_ethernet_test('sriov',
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceCpeBond, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['eth0', 'eth1', 'oam',
                                             'eth3', 'eth4', 'mgmt',
                                             'eth6', 'eth7', 'infra',
                                             'eth9', 'eth10', 'vrs']
        self.expected_data_interfaces = ['eth12', 'eth13', 'data']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.expected_slave_interfaces = ['eth0', 'eth1', 'eth3', 'eth4',
                                          'eth6', 'eth7', 'eth9', 'eth10',
                                          'eth12', 'eth13']


class InterfaceCpeVlanOverBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a controller subfunction and all interfaces are
        # vlan interfaces over aggregated ethernet interfaces.
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER)
        bond = self._create_bond_test('pxeboot',
                                      constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('oam', constants.NETWORK_TYPE_OAM, 1, bond)
        self._create_vlan_test('mgmt', constants.NETWORK_TYPE_MGMT, 2, bond)
        self._create_vlan_test('infra', constants.NETWORK_TYPE_INFRA, 3,
                               bond)
        bond1 = self._create_bond_test('bond3')
        self._create_vlan_test('vrs', constants.NETWORK_TYPE_DATA_VRS, 4,
                               bond1)
        bond2 = self._create_bond_test('bond4')
        self._create_vlan_test('data', constants.NETWORK_TYPE_DATA, 5,
                               bond2)
        self._create_ethernet_test('sriov',
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceCpeVlanOverBond, self).setUp()
        self.expected_platform_interfaces = ['eth0', 'eth1', 'pxeboot',
                                             'oam', 'mgmt', 'infra',
                                             'eth6', 'eth7', 'bond3', 'vrs']
        self.expected_data_interfaces = ['eth10', 'eth11', 'bond4', 'data']
        self.expected_slave_interfaces = ['eth0', 'eth1',
                                          'eth6', 'eth7',
                                          'eth10', 'eth11']
        self.expected_pci_interfaces = ['sriov', 'pthru']


class InterfaceCpeVlanOverDataEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a controller subfunction and all interfaces are
        # vlan interfaces over data ethernet interfaces.
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER)
        port, iface = (
            self._create_ethernet_test(
                'data',
                [constants.NETWORK_TYPE_PXEBOOT, constants.NETWORK_TYPE_DATA]))
        self._create_vlan_test('oam', constants.NETWORK_TYPE_OAM, 1, iface)
        self._create_vlan_test('mgmt', constants.NETWORK_TYPE_MGMT, 2,
                               iface)
        self._create_vlan_test('infra', constants.NETWORK_TYPE_INFRA, 3,
                               iface)
        self._create_vlan_test('vrs', constants.NETWORK_TYPE_DATA_VRS, 4,
                               iface)
        self._create_vlan_test('data2', constants.NETWORK_TYPE_DATA, 5,
                               iface)
        self._create_ethernet_test('sriov',
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceCpeVlanOverDataEthernet, self).setUp()
        self.expected_platform_interfaces = ['data', 'oam', 'mgmt',
                                             'infra', 'vrs']
        self.expected_data_interfaces = ['data', 'data2']
        self.expected_pci_interfaces = ['sriov', 'pthru']


class InterfaceCpeComputeEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a compute subfunction and all interfaces are
        # ethernet interfaces.
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER, constants.COMPUTE)
        self._create_ethernet_test('oam', constants.NETWORK_TYPE_OAM)
        self._create_ethernet_test('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_ethernet_test('infra', constants.NETWORK_TYPE_INFRA)
        self._create_ethernet_test('vrs', constants.NETWORK_TYPE_DATA_VRS)
        self._create_ethernet_test('data', constants.NETWORK_TYPE_DATA)
        self._create_ethernet_test('sriov',
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)
        port, iface = (
            self._create_ethernet_test('slow', constants.NETWORK_TYPE_DATA,
                                       dpdksupport=False))
        port, iface = (
            self._create_ethernet_test('mlx4', constants.NETWORK_TYPE_DATA,
                                       driver=interface.DRIVER_MLX_CX3))
        port, iface = (
            self._create_ethernet_test('mlx5', constants.NETWORK_TYPE_DATA,
                                       driver=interface.DRIVER_MLX_CX4))
        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceCpeComputeEthernet, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['oam', 'mgmt', 'infra', 'vrs']
        self.expected_data_interfaces = ['slow', 'data', 'mlx4', 'mlx5']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.expected_slow_interfaces = ['slow']
        self.expected_bridged_interfaces = ['slow']
        self.expected_slave_interfaces = []
        self.expected_mlx_interfaces = ['mlx4', 'mlx5']


class InterfaceCpeComputeVlanOverEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a compute subfunction and all interfaces are
        # vlan interfaces over ethernet interfaces.
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER, constants.COMPUTE)
        port, iface = self._create_ethernet_test(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('oam', constants.NETWORK_TYPE_OAM, 1, iface)
        self._create_vlan_test('mgmt', constants.NETWORK_TYPE_MGMT, 2,
                               iface)
        self._create_vlan_test('infra', constants.NETWORK_TYPE_INFRA, 3)
        self._create_vlan_test('vrs', constants.NETWORK_TYPE_DATA_VRS, 4)
        self._create_vlan_test('data', constants.NETWORK_TYPE_DATA, 5)
        self._create_ethernet_test('sriov',
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceCpeComputeVlanOverEthernet, self).setUp()
        self.expected_bmc_interface = 'pxeboot'
        self.expected_platform_interfaces = ['pxeboot', 'oam', 'mgmt',
                                             'eth3', 'infra',
                                             'eth5', 'vrs']
        self.expected_data_interfaces = ['eth7', 'data']
        self.expected_pci_interfaces = ['sriov', 'pthru']


class InterfaceCpeComputeBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a compute subfunction and all interfaces are
        # aggregated ethernet interfaces.
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER, constants.COMPUTE)
        self._create_bond_test('oam', constants.NETWORK_TYPE_OAM)
        self._create_bond_test('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_bond_test('infra', constants.NETWORK_TYPE_INFRA)
        self._create_bond_test('vrs', constants.NETWORK_TYPE_DATA_VRS)
        self._create_bond_test('data', constants.NETWORK_TYPE_DATA)
        self._create_ethernet_test('sriov',
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceCpeComputeBond, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['eth0', 'eth1', 'oam',
                                             'eth3', 'eth4', 'mgmt',
                                             'eth6', 'eth7', 'infra',
                                             'eth9', 'eth10', 'vrs']
        self.expected_data_interfaces = ['eth12', 'eth13', 'data']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.expected_slave_interfaces = ['eth0', 'eth1', 'eth3', 'eth4',
                                          'eth6', 'eth7', 'eth9', 'eth10',
                                          'eth12', 'eth13']


class InterfaceCpeComputeVlanOverBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a compute subfunction and all interfaces are
        # vlan interfaces over aggregated ethernet interfaces.
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER, constants.COMPUTE)
        bond = self._create_bond_test('pxeboot',
                                      constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('oam', constants.NETWORK_TYPE_OAM, 1, bond)
        self._create_vlan_test('mgmt', constants.NETWORK_TYPE_MGMT, 2, bond)
        self._create_vlan_test('infra', constants.NETWORK_TYPE_INFRA, 3,
                               bond)
        bond1 = self._create_bond_test('bond1')
        self._create_vlan_test('vrs', constants.NETWORK_TYPE_DATA_VRS, 4,
                               bond1)
        bond2 = self._create_bond_test('bond2')
        self._create_vlan_test('data', constants.NETWORK_TYPE_DATA, 5,
                               bond2)
        self._create_ethernet_test('sriov',
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceCpeComputeVlanOverBond, self).setUp()
        self.expected_platform_interfaces = ['eth0', 'eth1', 'pxeboot',
                                             'oam', 'mgmt', 'infra',
                                             'eth6', 'eth7', 'bond1', 'vrs']
        self.expected_data_interfaces = ['eth10', 'eth11', 'bond2', 'data']
        self.expected_slave_interfaces = ['eth0', 'eth1',
                                          'eth6', 'eth7',
                                          'eth10', 'eth11']
        self.expected_pci_interfaces = ['sriov', 'pthru']


class InterfaceCpeComputeVlanOverDataEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a compute subfunction and all interfaces are
        # vlan interfaces over data ethernet interfaces.
        self._create_test_common()
        self._create_test_host(constants.CONTROLLER, constants.COMPUTE)
        port, iface = (
            self._create_ethernet_test(
                'data',
                [constants.NETWORK_TYPE_PXEBOOT, constants.NETWORK_TYPE_DATA]))
        self._create_ethernet_test('oam', constants.NETWORK_TYPE_OAM)
        self._create_ethernet_test('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_ethernet_test('infra', constants.NETWORK_TYPE_INFRA)
        self._create_vlan_test('vrs', constants.NETWORK_TYPE_DATA_VRS, 4,
                               iface)
        self._create_vlan_test('data2', constants.NETWORK_TYPE_DATA, 5,
                               iface)
        self._create_ethernet_test('sriov',
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

    def setUp(self):
        super(InterfaceCpeComputeVlanOverDataEthernet, self).setUp()
        self.expected_platform_interfaces = ['data', 'oam', 'mgmt',
                                             'infra', 'vrs']
        self.expected_data_interfaces = ['data', 'data2']
        self.expected_pci_interfaces = ['sriov', 'pthru']
