# Copyright (c) 2017-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import print_function

import os
import uuid
import yaml
import mock

from sysinv.common import utils
from sysinv.common import constants
from sysinv.puppet import interface
from sysinv.puppet import puppet
from sysinv.objects import base as objbase

from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
from sysinv.tests.puppet import base


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

    def _setup_address_and_routes(self, iface):
        if not iface['ifclass'] or iface['ifclass'] == constants.INTERFACE_CLASS_NONE:
            return None
        if iface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM:
            address = {'interface_id': iface['id'],
                       'family': 4,
                       'prefix': 24,
                       'address': '192.168.1.2'}
            self.addresses.append(dbutils.create_test_address(**address))
        elif iface['ifclass'] == constants.INTERFACE_CLASS_DATA:
            address = {'interface_id': iface['id'],
                       'family': 6,
                       'prefix': 64,
                       'address': '2001:1::2'}
            self.addresses.append(dbutils.create_test_address(**address))
        if iface['ifclass'] == constants.INTERFACE_CLASS_DATA:
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
        if iface['ifclass'] == constants.INTERFACE_CLASS_DATA:
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

    def _find_network_by_type(self, networktype):
        for network in self.networks:
            if network['type'] == networktype:
                return network

    def _find_address_pool_by_uuid(self, pool_uuid):
        for pool in self.address_pools:
            if pool['uuid'] == pool_uuid:
                return pool

    def _get_network_ids_by_type(self, networktype):
        if isinstance(networktype, list):
            networktypelist = networktype
        elif networktype:
            networktypelist = [networktype]
        else:
            networktypelist = []
        networks = []
        for network_type in networktypelist:
            network = self._find_network_by_type(networktype)
            networks.append(str(network['id']))
        return networks

    def _update_interface_address_pool(self, iface, networktype):
        network = self._find_network_by_type(networktype)
        pool = self._find_address_pool_by_uuid(network['pool_uuid'])
        addresses = self.context['addresses'].get(iface['ifname'], [])
        for address in addresses:
            address['pool_uuid'] = pool['uuid']

    def _create_ethernet_test(self, ifname=None, ifclass=None,
                              networktype=None, **kwargs):
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
                     'sriov_vf_driver': kwargs.get('iface_sriov_vf_driver', None)}
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
        self._setup_address_and_routes(db_interface)
        return db_port, db_interface

    def _create_vlan_test(self, ifname, ifclass, networktype, vlan_id,
                          lower_iface=None):
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
                     'imtu': 1500}
        lower_iface['used_by'].append(interface['ifname'])
        db_interface = dbutils.create_test_interface(**interface)
        self.interfaces.append(db_interface)
        self._setup_address_and_routes(db_interface)
        return db_interface

    def _create_bond_test(self, ifname, ifclass=None, networktype=None):
        port1, iface1 = self._create_ethernet_test()
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
        self._setup_address_and_routes(db_interface)
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


class InterfaceTestCase(InterfaceTestCaseMixin, dbbase.BaseHostTestCase):

    def setUp(self):
        super(InterfaceTestCase, self).setUp()
        self._setup_context()
        p = mock.patch('sysinv.puppet.interface.is_syscfg_network')
        self.mock_puppet_interface_sysconfig = p.start()
        self.mock_puppet_interface_sysconfig.return_value = True
        self.addCleanup(p.stop)

    def _setup_configuration(self):
        # Create a single port/interface for basic function testing
        self.host = self._create_test_host(constants.CONTROLLER)
        self.port, self.iface = self._create_ethernet_test(
            "mgmt0", constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_MGMT)
        self.mgmt_gateway_address = self.mgmt_subnet[1]
        self.oam_gateway_address = self.oam_subnet[1]

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.
        self.host.save(self.admin_context)
        self.port.save(self.admin_context)
        self.iface.save(self.admin_context)
        super(InterfaceTestCase, self)._update_context()

    def test_is_platform_network_type_true(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_MGMT)
        result = interface.is_platform_network_type(self.iface)
        self.assertTrue(result)

    def test_is_platform_network_type_false(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        result = interface.is_platform_network_type(self.iface)
        self.assertFalse(result)

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

    def test_get_interface_name_index(self):
        index = self.operator.interface._get_interface_name_index(self.interfaces)  # pylint: disable=no-member
        for iface in self.interfaces:
            self.assertTrue(iface['ifname'] in index)
            self.assertEqual(index[iface['ifname']], iface)

    def test_get_network_type_index(self):
        index = self.operator.interface._get_network_type_index()  # pylint: disable=no-member
        for network in self.networks:
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

    def test_get_gateway_index(self):
        index = self.operator.interface._get_gateway_index()  # pylint: disable=no-member
        self.assertEqual(len(index), 2)
        self.assertEqual(index[constants.NETWORK_TYPE_MGMT],
                         str(self.mgmt_gateway_address))
        self.assertEqual(index[constants.NETWORK_TYPE_OAM],
                         str(self.oam_gateway_address))

    def test_is_worker_subfunction_true(self):
        self.host['personality'] = constants.WORKER
        self.host['subfunctions'] = constants.WORKER
        self._update_context()
        self.assertTrue(interface.is_worker_subfunction(self.context))

    def test_is_worker_subfunction_true_cpe(self):
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.WORKER
        self._update_context()
        self.assertTrue(interface.is_worker_subfunction(self.context))

    def test_is_worker_subfunction_false(self):
        self.host['personality'] = constants.STORAGE
        self.host['subfunctions'] = constants.STORAGE
        self._update_context()
        self.assertFalse(interface.is_worker_subfunction(self.context))

    def test_is_worker_subfunction_false_cpe(self):
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.CONTROLLER
        self._update_context()
        self.assertFalse(interface.is_worker_subfunction(self.context))

    def test_is_pci_interface_true(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PCI_SRIOV
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_SRIOV
        self.assertTrue(interface.is_pci_interface(self.iface))

    def test_is_pci_interface_false(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
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

    def test_get_lower_interface_vlan(self):
        vlan = self._create_vlan_test(
            "cluster-host", constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_CLUSTER_HOST, 1, self.iface)
        self._update_context()
        value = interface.get_lower_interface(self.context, vlan)
        self.assertEqual(value, self.iface)

    def test_get_lower_interface_vf(self):
        port, iface = self._create_ethernet_test(
            'sriov1', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=2,
            sriov_vf_driver=None)
        vf = self._create_vf_test("vf1", 1, None, lower_iface=iface)
        self._update_context()
        value = interface.get_lower_interface(self.context, vf)
        self.assertEqual(value, iface)

    def test_get_interface_os_ifname_ethernet(self):
        value = interface.get_interface_os_ifname(self.context, self.iface)
        self.assertEqual(value, self.port['name'])

    def test_get_interface_os_ifname_bond(self):
        self.iface['iftype'] = constants.INTERFACE_TYPE_AE
        value = interface.get_interface_os_ifname(self.context, self.iface)
        self.assertEqual(value, self.iface['ifname'])

    def test_get_interface_os_ifname_vlan_over_ethernet(self):
        vlan = self._create_vlan_test(
            "cluster-host", constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_CLUSTER_HOST, 1, self.iface)
        self._update_context()
        value = interface.get_interface_os_ifname(self.context, vlan)
        self.assertEqual(value, "vlan1")

    def test_get_interface_os_ifname_vlan_over_bond(self):
        bond = self._create_bond_test("none")
        vlan = self._create_vlan_test(
            "cluster-host", constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_CLUSTER_HOST, 1, bond)
        self._update_context()
        value = interface.get_interface_os_ifname(self.context, vlan)
        self.assertEqual(value, "vlan1")

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
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_OAM
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_OAM)
        gateway = interface.get_interface_gateway_address(
            self.context, constants.NETWORK_TYPE_OAM)
        expected = str(self.oam_gateway_address)
        self.assertEqual(gateway, expected)

    def test_get_interface_gateway_address_mgmt(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_MGMT)
        gateway = interface.get_interface_gateway_address(
            self.context, constants.NETWORK_TYPE_MGMT)
        expected = str(self.mgmt_gateway_address)
        self.assertEqual(gateway, expected)

    def test_get_interface_gateway_address_none(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        gateway = interface.get_interface_gateway_address(
            self.context, constants.NETWORK_TYPE_DATA)
        self.assertIsNone(gateway)

    def test_get_interface_address_method_for_none(self):
        self.iface['ifclass'] = None
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_data(self):
        # test for CentOS
        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')
        # test for Debian
        self.mock_puppet_interface_sysconfig.return_value = False
        self.iface['ipv4_mode'] = constants.IPV4_DISABLED
        self.iface['ipv6_mode'] = constants.IPV6_DISABLED
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')
        self.iface['ipv4_mode'] = constants.IPV4_STATIC
        self.iface['ipv6_mode'] = constants.IPV6_DISABLED
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'static')
        self.iface['ipv4_mode'] = constants.IPV4_DISABLED
        self.iface['ipv6_mode'] = constants.IPV6_STATIC
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'static')
        self.iface['ipv4_mode'] = constants.IPV4_STATIC
        self.iface['ipv6_mode'] = constants.IPV6_STATIC
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_pci_sriov(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PCI_SRIOV
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_SRIOV
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_pci_pthru(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PCI_PASSTHROUGH
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_PASSTHROUGH
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_pxeboot_worker(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_PXEBOOT
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_PXEBOOT)
        self.host['personality'] = constants.WORKER
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_PXEBOOT)
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_PXEBOOT)
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'manual')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_pxeboot_storage(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_PXEBOOT
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_PXEBOOT)
        self.host['personality'] = constants.STORAGE
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_PXEBOOT)
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_PXEBOOT)
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'manual')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_pxeboot_controller(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_PXEBOOT
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_PXEBOOT)
        self.host['personality'] = constants.CONTROLLER
        self._update_context()
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_PXEBOOT)
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'static')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_mgmt_worker(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_MGMT)
        self.host['personality'] = constants.WORKER
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_MGMT)
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_MGMT)
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'dhcp')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'dhcp')

    def test_get_interface_address_method_for_mgmt_storage(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_MGMT)
        self.host['personality'] = constants.STORAGE
        self._update_context()
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_MGMT)
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'dhcp')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'dhcp')

    def test_get_interface_address_method_for_mgmt_controller(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_MGMT)
        self.host['personality'] = constants.CONTROLLER
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_MGMT)
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_MGMT)
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'static')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_cluster_host_worker(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_CLUSTER_HOST
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        self.host['personality'] = constants.WORKER
        self._update_context()
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'static')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_cluster_host_storage(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_CLUSTER_HOST
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        self.host['personality'] = constants.STORAGE
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_CLUSTER_HOST)
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'static')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_cluster_host_controller(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_CLUSTER_HOST
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        self.host['personality'] = constants.CONTROLLER
        self._update_context()
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'static')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_oam_controller(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_OAM
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_OAM)
        self.host['personality'] = constants.CONTROLLER
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_OAM)
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_OAM)
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'static')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'static')

    def test_get_interface_address_method_for_platform_ipv4(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['ipv4_mode'] = constants.IPV4_STATIC
        self.iface['networktype'] = constants.NETWORK_TYPE_NONE
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'static')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'static')

        self.iface['networktypelist'] = [constants.NETWORK_TYPE_MGMT,
                                         constants.NETWORK_TYPE_CLUSTER_HOST]
        # test for CentOS
        self.mock_puppet_interface_sysconfig.return_value = True
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'static')

        # test for Debian
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_platform_ipv6(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['ipv6_mode'] = constants.IPV6_STATIC
        self.iface['networktype'] = constants.NETWORK_TYPE_NONE
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'static')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'static')

        self.iface['networktypelist'] = [constants.NETWORK_TYPE_MGMT,
                                         constants.NETWORK_TYPE_CLUSTER_HOST]
        # test for CentOS
        self.mock_puppet_interface_sysconfig.return_value = True
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'static')

        # test for Debian
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface)
        self.assertEqual(method, 'manual')

    def test_get_interface_address_method_for_platform_invalid(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['ipv4_mode'] = constants.IPV4_STATIC
        self.iface['networktype'] = constants.NETWORK_TYPE_OAM
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_OAM)
        self.host['personality'] = constants.WORKER
        self._update_context()
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_OAM)
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'dhcp')
        self.mock_puppet_interface_sysconfig.return_value = False
        method = interface.get_interface_address_method(
            self.context, self.iface, network.id)
        self.assertEqual(method, 'dhcp')

    def test_get_interface_traffic_classifier_for_mgmt(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktypelist'] = [constants.NETWORK_TYPE_MGMT]
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_MGMT)
        classifier = interface.get_interface_traffic_classifier(
            self.context, self.iface)
        print(self.context)
        expected = ('%s %s %s %s > /dev/null' %
                    (constants.TRAFFIC_CONTROL_SCRIPT,
                     self.port['name'], constants.NETWORK_TYPE_MGMT,
                     constants.LINK_SPEED_10G))
        self.assertEqual(classifier, expected)

    def test_get_interface_traffic_classifier_for_cluster_host(self):
        self.iface['ifname'] = 'cluster_host0'
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktypelist'] = [constants.NETWORK_TYPE_CLUSTER_HOST]
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        classifier = interface.get_interface_traffic_classifier(
            self.context, self.iface)
        self.assertIsNone(classifier)

    def test_get_interface_traffic_classifier_for_oam(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktypelist'] = [constants.NETWORK_TYPE_OAM]
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_OAM)
        classifier = interface.get_interface_traffic_classifier(
            self.context, self.iface)
        self.assertIsNone(classifier)

    def test_get_interface_traffic_classifier_for_none(self):
        classifier = interface.get_interface_traffic_classifier(
            self.context, self.iface)
        self.assertIsNone(classifier)

    def test_get_sriov_interface_device_id(self):
        port, iface = self._create_ethernet_test(
            'sriov1', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=2,
            sriov_vf_driver=None)
        self._update_context()
        value = interface.get_sriov_interface_device_id(self.context, iface)
        self.assertEqual(value, '1572')

    def test_get_sriov_interface_port(self):
        port, iface = self._create_ethernet_test(
            'sriov1', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=2,
            sriov_vf_driver=None)
        vf = self._create_vf_test("vf1", 1, None, lower_iface=iface)
        self._update_context()
        value = interface.get_sriov_interface_port(self.context, vf)
        self.assertEqual(value, port)

    def test_get_sriov_interface_port_invalid(self):
        port, iface = self._create_ethernet_test('pthru',
            constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
            constants.NETWORK_TYPE_PCI_PASSTHROUGH)
        self._update_context()
        self.assertRaises(AssertionError,
                          interface.get_sriov_interface_port,
                          self.context,
                          iface)

    def test_get_sriov_interface_vf_addrs(self):
        vf_addr1 = "0000:81:00.0"
        vf_addr2 = "0000:81:01.0"
        vf_addr_list = [vf_addr1, vf_addr2]
        port, iface = self._create_ethernet_test(
            'sriov1', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=2,
            sriov_vf_driver=None)
        vf1 = self._create_vf_test("vf1", 1, None, lower_iface=iface)
        self._update_context()
        addrs1 = interface.get_sriov_interface_vf_addrs(
            self.context, iface, vf_addr_list)
        self.assertEqual(len(addrs1), 1)
        addrs2 = interface.get_sriov_interface_vf_addrs(
            self.context, vf1, vf_addr_list)
        self.assertEqual(len(addrs2), 1)

    def test_get_sriov_interface_vf_addrs_multiple_children(self):
        vf_addr1 = "0000:81:00.0"
        vf_addr2 = "0000:81:01.0"
        vf_addr3 = "0000:81:02.0"
        vf_addr_list = [vf_addr1, vf_addr2, vf_addr3]
        port, iface = self._create_ethernet_test(
            'sriov1', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=3,
            sriov_vf_driver=None)
        vf1 = self._create_vf_test("vf1", 1, None, lower_iface=iface)
        vf2 = self._create_vf_test("vf2", 1, None, lower_iface=iface)
        self._update_context()
        addrs1 = interface.get_sriov_interface_vf_addrs(
            self.context, vf1, vf_addr_list)
        self.assertEqual(len(addrs1), 1)
        addrs2 = interface.get_sriov_interface_vf_addrs(
            self.context, vf2, vf_addr_list)
        self.assertEqual(len(addrs2), 1)
        addrs3 = interface.get_sriov_interface_vf_addrs(
            self.context, iface, vf_addr_list)
        self.assertEqual(len(addrs3), 1)

    def test_get_sriov_interface_vf_addrs_multiple_parents(self):
        vf_addr1 = "0000:81:00.0"
        vf_addr2 = "0000:81:01.0"
        vf_addr3 = "0000:81:02.0"
        vf_addr_list = [vf_addr1, vf_addr2, vf_addr3]
        port, iface = self._create_ethernet_test(
            'sriov1', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=3,
            sriov_vf_driver=None)
        vf1 = self._create_vf_test("vf1", 2, None, lower_iface=iface)
        vf2 = self._create_vf_test("vf2", 1, None, lower_iface=vf1)
        self._update_context()
        addrs1 = interface.get_sriov_interface_vf_addrs(
            self.context, vf1, vf_addr_list)
        self.assertEqual(len(addrs1), 1)
        addrs2 = interface.get_sriov_interface_vf_addrs(
            self.context, vf2, vf_addr_list)
        self.assertEqual(len(addrs2), 1)
        addrs3 = interface.get_sriov_interface_vf_addrs(
            self.context, iface, vf_addr_list)
        self.assertEqual(len(addrs3), 1)

    def test_get_bridge_interface_name_none_dpdk_supported(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.port['dpdksupport'] = True
        self._update_context()
        ifname = interface.get_bridge_interface_name(self.context, self.iface)
        self.assertIsNone(ifname)

    def test_get_bridge_interface_name_none_not_data(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_MGMT)
        ifname = interface.get_bridge_interface_name(self.context, self.iface)
        self.assertIsNone(ifname)

    def test_get_bridge_interface_name(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.port['dpdksupport'] = False
        self._update_context()
        ifname = interface.get_bridge_interface_name(self.context, self.iface)
        self.assertEqual(ifname, 'br-' + self.port['name'])

    def test_needs_interface_config_kernel_mgmt(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_MGMT
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_MGMT)
        self.host['personality'] = constants.CONTROLLER
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_kernel_cluster_host(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_CLUSTER_HOST
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        self.host['personality'] = constants.CONTROLLER
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_kernel_oam(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_OAM
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_OAM)
        self.host['personality'] = constants.CONTROLLER
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_data(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.CONTROLLER
        self.port['dpdksupport'] = True
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_data_slow(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.CONTROLLER
        self.port['dpdksupport'] = False
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_data_mlx5(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.CONTROLLER
        self.port['driver'] = constants.DRIVER_MLX_CX4
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_data_slow_worker(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.WORKER
        self.port['dpdksupport'] = False
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_data_mlx5_worker(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.WORKER
        self.port['driver'] = constants.DRIVER_MLX_CX4
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_sriov_worker(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PCI_SRIOV
        self.iface['iftype'] = constants.INTERFACE_TYPE_ETHERNET
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_SRIOV
        self.host['personality'] = constants.WORKER
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_pthru_worker(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PCI_PASSTHROUGH
        self.iface['iftype'] = constants.INTERFACE_TYPE_ETHERNET
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_PASSTHROUGH
        self.host['personality'] = constants.WORKER
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_data_cpe_worker(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.WORKER
        self.port['dpdksupport'] = True
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_data_slow_cpe_worker(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.WORKER
        self.port['dpdksupport'] = False
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_data_mlx5_cpe_worker(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.WORKER
        self.port['driver'] = constants.DRIVER_MLX_CX4
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_sriov_cpe(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PCI_SRIOV
        self.iface['iftype'] = constants.INTERFACE_TYPE_ETHERNET
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_SRIOV
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.CONTROLLER
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertFalse(needed)

    def test_needs_interface_config_sriov_cpe_worker(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PCI_SRIOV
        self.iface['iftype'] = constants.INTERFACE_TYPE_ETHERNET
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_SRIOV
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.WORKER
        self._update_context()
        needed = interface.needs_interface_config(self.context, self.iface)
        self.assertTrue(needed)

    def test_needs_interface_config_pthru_cpe_worker(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PCI_PASSTHROUGH
        self.iface['iftype'] = constants.INTERFACE_TYPE_ETHERNET
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_PASSTHROUGH
        self.host['personality'] = constants.CONTROLLER
        self.host['subfunctions'] = constants.WORKER
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
        network_config = self._get_network_config(
            ifname=interface.LOOPBACK_IFNAME, method=interface.LOOPBACK_METHOD)
        return interface.format_network_config(network_config)

    def _get_ipv6_autoconf_off(self, os_ifname):
        autoconf_off = 'echo 0 > /proc/sys/net/ipv6/conf/{}/autoconf'.format(os_ifname)
        accept_ra_off = 'echo 0 > /proc/sys/net/ipv6/conf/{}/accept_ra'.format(os_ifname)
        accept_redir_off = 'echo 0 > /proc/sys/net/ipv6/conf/{}/accept_redirects'.format(os_ifname)
        ipv6_autocnf_off = '{}; {}; {}'.format(autoconf_off, accept_ra_off, accept_redir_off)
        return ipv6_autocnf_off

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

    def test_get_controller_ethernet_config_oam(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_OAM
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_OAM)
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_OAM)
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_OAM)
        config = interface.get_interface_network_config(
            self.context, self.iface, network.id)
        options = {'IPV6_AUTOCONF': 'no',
                   'LINKDELAY': '20'}
        expected = self._get_static_network_config(
            ifname=self.port['name'], mtu=1500, gateway='10.10.10.1',
            options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_ethernet_config_oam_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_OAM
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_OAM)
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_OAM)
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_OAM)
        config = interface.get_interface_network_config(
            self.context, self.iface, network.id)
        ipv6_autocnf_off = self._get_ipv6_autoconf_off(self.port['name'])
        options = {'post-up': '{}'.format(ipv6_autocnf_off),
                   'mtu': '1500',
                   'gateway': '10.10.10.1'}
        expected = self._get_static_network_config_ifupdown(
            ifname=self.port['name'], options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_ethernet_config_mgmt(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktypelist'] = [constants.NETWORK_TYPE_MGMT]
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_MGMT)
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_MGMT)
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        config = interface.get_interface_network_config(
            self.context, self.iface, network.id)
        options = {'IPV6_AUTOCONF': 'no',
                   'LINKDELAY': '20',
                   'post_up':
                       '%s %s %s %s > /dev/null' %
                       (constants.TRAFFIC_CONTROL_SCRIPT,
                        self.port['name'], constants.NETWORK_TYPE_MGMT,
                        constants.LINK_SPEED_10G)}
        expected = self._get_static_network_config(
            ifname=self.port['name'], mtu=1500, gateway='192.168.204.1',
            options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_ethernet_config_mgmt_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktypelist'] = [constants.NETWORK_TYPE_MGMT]
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_MGMT)
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_MGMT)
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        config = interface.get_interface_network_config(
            self.context, self.iface, network.id)
        ipv6_autocnf_off = self._get_ipv6_autoconf_off(self.port['name'])
        options = {'post-up': '%s %s %s %s > /dev/null; %s' % (constants.TRAFFIC_CONTROL_SCRIPT,
                        self.port['name'], constants.NETWORK_TYPE_MGMT, constants.LINK_SPEED_10G,
                        ipv6_autocnf_off),
                   'mtu': '1500',
                   'gateway': '192.168.204.1'}
        expected = self._get_static_network_config_ifupdown(
            ifname=self.port['name'], options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_ethernet_config_cluster_host(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_CLUSTER_HOST
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_CLUSTER_HOST)
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        config = interface.get_interface_network_config(
            self.context, self.iface, network.id)
        options = {'IPV6_AUTOCONF': 'no',
                   'LINKDELAY': '20'}
        expected = self._get_static_network_config(
            ifname=self.port['name'], mtu=1500,
            options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_ethernet_config_cluster_host_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_CLUSTER_HOST
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_CLUSTER_HOST)
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        config = interface.get_interface_network_config(
            self.context, self.iface, network.id)
        ipv6_autocnf_off = self._get_ipv6_autoconf_off(self.port['name'])
        options = {'post-up': '{}'.format(ipv6_autocnf_off),
                   'mtu': '1500'}
        expected = self._get_static_network_config_ifupdown(
            ifname=self.port['name'], options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_ethernet_config_slave(self):
        bond = self._create_bond_test("bond0")
        self._update_context()
        iface = self.context['interfaces'][bond['uses'][0]]
        port = self.context['ports'][iface['id']]
        config = interface.get_interface_network_config(self.context, iface)
        options = {'IPV6_AUTOCONF': 'no',
                   'SLAVE': 'yes',
                   'PROMISC': 'yes',
                   'MASTER': 'bond0',
                   'LINKDELAY': '20'}
        expected = self._get_network_config(
            ifname=port['name'], mtu=1500, method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_ethernet_config_slave_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        bond = self._create_bond_test("bond0")
        self._update_context()
        iface = self.context['interfaces'][bond['uses'][0]]
        port = self.context['ports'][iface['id']]
        config = interface.get_interface_network_config(self.context, iface)
        ipv6_autocnf_off = self._get_ipv6_autoconf_off(port['name'])
        options = {'allow-bond0': port['name'],
                   'bond-master': 'bond0',
                   'pre-up': '/usr/sbin/ip link set dev {} promisc on; {}'.format(port['name'],
                                                                             ipv6_autocnf_off),
                   'mtu': '1500'}
        expected = self._get_network_config_ifupdown(
            ifname=port['name'], method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_network_config(self):
        bond = self._create_bond_test("bond0")
        self._update_context()
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        config = interface.get_bond_network_config(self.context, bond, {'options': {}}, network.id)
        expected = {'options':
                       {'BONDING_OPTS': 'mode=balance-xor xmit_hash_policy=layer2 miimon=100',
                        'MACADDR': bond['imac'],
                        'up': 'sleep 10'}}
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_config_duplex(self):
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)
        bond = self._create_bond_test(
            "bond0", ifclass=constants.INTERFACE_CLASS_PLATFORM,
            networktype=constants.NETWORK_TYPE_MGMT)
        self._update_context()
        self._update_interface_address_pool(
            bond, constants.NETWORK_TYPE_MGMT)
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        config = interface.get_interface_network_config(self.context, bond, network.id)
        options = {'IPV6_AUTOCONF': 'no',
                   'up': 'sleep 10',
                   'MACADDR': bond['imac'],
                   'BONDING_OPTS':
                       'mode=802.3ad lacp_rate=fast xmit_hash_policy=layer2 miimon=100'}
        expected = self._get_static_network_config(
            ifname=bond['ifname'], gateway='192.168.204.1', ipaddress='192.168.1.2',
            mtu=1500, options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_config_duplex_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX
        self.dbapi.isystem_update(self.system.uuid, system_dict)
        bond = self._create_bond_test(
            "bond0", ifclass=constants.INTERFACE_CLASS_PLATFORM,
            networktype=constants.NETWORK_TYPE_MGMT)
        self._update_context()
        self._update_interface_address_pool(
            bond, constants.NETWORK_TYPE_MGMT)
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        config = interface.get_interface_network_config(self.context, bond, network.id)
        options = {'bond-lacp-rate': 'fast',
                   'bond-miimon': '100',
                   'bond-mode': '802.3ad',
                   'bond-slaves': 'eth1 eth2 ',
                   'bond-xmit-hash-policy': 'layer2',
                   'gateway': '192.168.204.1',
                   'hwaddress': '02:11:22:33:44:13',
                   'mtu': '1500',
                   'post-up': 'echo 0 > /proc/sys/net/ipv6/conf/bond0/autoconf; echo '
                              '0 > /proc/sys/net/ipv6/conf/bond0/accept_ra; echo 0 > '
                              '/proc/sys/net/ipv6/conf/bond0/accept_redirects',
                   'up': 'sleep 10'}
        expected = self._get_static_network_config_ifupdown(
            ifname=bond['ifname'], options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_config_duplex_direct(self):
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX_DIRECT
        self.dbapi.isystem_update(self.system.uuid, system_dict)
        bond = self._create_bond_test(
            "bond0", ifclass=constants.INTERFACE_CLASS_PLATFORM,
            networktype=constants.NETWORK_TYPE_MGMT)
        self._update_context()
        self._update_interface_address_pool(
            bond, constants.NETWORK_TYPE_MGMT)
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        config = interface.get_interface_network_config(self.context, bond, network.id)
        options = {'IPV6_AUTOCONF': 'no',
                   'up': 'sleep 10',
                   'pre_up': '/sbin/modprobe bonding; grep bond0 '
                             '/sys/class/net/bonding_masters || echo +bond0 > '
                             '/sys/class/net/bonding_masters; sysctl -wq '
                             'net.ipv6.conf.bond0.accept_dad=0',
                   'MACADDR': bond['imac'],
                   'BONDING_OPTS':
                       'mode=802.3ad lacp_rate=fast xmit_hash_policy=layer2 miimon=100'}
        expected = self._get_static_network_config(
            ifname=bond['ifname'], gateway='192.168.204.1', ipaddress='192.168.1.2',
            mtu=1500, options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_config_duplex_direct_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        system_dict = self.system.as_dict()
        system_dict['system_mode'] = constants.SYSTEM_MODE_DUPLEX_DIRECT
        self.dbapi.isystem_update(self.system.uuid, system_dict)
        bond = self._create_bond_test(
            "bond0", ifclass=constants.INTERFACE_CLASS_PLATFORM,
            networktype=constants.NETWORK_TYPE_MGMT)
        self._update_context()
        self._update_interface_address_pool(
            bond, constants.NETWORK_TYPE_MGMT)
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        config = interface.get_interface_network_config(self.context, bond, network.id)
        options = {'bond-lacp-rate': 'fast',
                   'bond-miimon': '100',
                   'bond-mode': '802.3ad',
                   'bond-slaves': 'eth1 eth2 ',
                   'bond-xmit-hash-policy': 'layer2',
                   'gateway': '192.168.204.1',
                   'hwaddress': '02:11:22:33:44:13',
                   'mtu': '1500',
                   'post-up': 'echo 0 > /proc/sys/net/ipv6/conf/bond0/autoconf; echo '
                              '0 > /proc/sys/net/ipv6/conf/bond0/accept_ra; echo 0 > '
                              '/proc/sys/net/ipv6/conf/bond0/accept_redirects',
                   'pre-up': '/sbin/modprobe bonding; grep bond0 '
                             '/sys/class/net/bonding_masters || echo +bond0 > '
                             '/sys/class/net/bonding_masters; sysctl -wq '
                             'net.ipv6.conf.bond0.accept_dad=0',
                   'up': 'sleep 10'}
        expected = self._get_static_network_config_ifupdown(
            ifname=bond['ifname'], options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_config_balanced(self):
        bond = self._create_bond_test("bond0")
        self._update_context()
        config = interface.get_interface_network_config(self.context, bond)
        options = {'IPV6_AUTOCONF': 'no',
                   'up': 'sleep 10',
                   'MACADDR': bond['imac'],
                   'BONDING_OPTS':
                       'mode=balance-xor xmit_hash_policy=layer2 miimon=100'}
        expected = self._get_network_config(
            ifname=bond['ifname'], mtu=1500, method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_config_balanced_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        bond = self._create_bond_test("bond0")
        self._update_context()
        config = interface.get_interface_network_config(self.context, bond)
        ipv6_autocnf_off = self._get_ipv6_autoconf_off(bond['ifname'])
        options = {'bond-miimon': '100',
                  'bond-slaves': 'eth1 eth2 ',
                  'bond-mode': 'balance-xor',
                  'bond-xmit-hash-policy': 'layer2',
                  'hwaddress': bond['imac'],
                  'mtu': '1500',
                  'post-up': '{}'.format(ipv6_autocnf_off),
                  'up': 'sleep 10'}
        expected = self._get_network_config_ifupdown(
            ifname=bond['ifname'], method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_config_8023ad(self):
        bond = self._create_bond_test("bond0")
        bond['aemode'] = '802.3ad'
        self._update_context()
        config = interface.get_interface_network_config(self.context, bond)
        options = {'IPV6_AUTOCONF': 'no',
                   'up': 'sleep 10',
                   'MACADDR': bond['imac'],
                   'BONDING_OPTS':
                       'mode=802.3ad lacp_rate=fast '
                       'xmit_hash_policy=layer2 miimon=100'}
        expected = self._get_network_config(
            ifname=bond['ifname'], mtu=1500, method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_config_8023ad_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        bond = self._create_bond_test("bond0")
        bond['aemode'] = '802.3ad'
        self._update_context()
        config = interface.get_interface_network_config(self.context, bond)
        ipv6_autocnf_off = self._get_ipv6_autoconf_off(bond['ifname'])
        options = {'bond-lacp-rate': 'fast',
                   'bond-miimon': '100',
                   'bond-mode': '802.3ad',
                   'bond-slaves': 'eth1 eth2 ',
                   'bond-xmit-hash-policy': 'layer2',
                   'hwaddress': bond['imac'],
                   'mtu': '1500',
                   'post-up': '{}'.format(ipv6_autocnf_off),
                   'up': 'sleep 10'}
        expected = self._get_network_config_ifupdown(
            ifname=bond['ifname'], method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_config_active_standby(self):
        bond = self._create_bond_test("bond0")
        bond['aemode'] = 'active_standby'
        bond['primary_reselect'] = constants.PRIMARY_RESELECT_ALWAYS
        self._update_context()
        config = interface.get_interface_network_config(self.context, bond)
        options = {'IPV6_AUTOCONF': 'no',
                   'up': 'sleep 10',
                   'MACADDR': bond['imac'],
                   'BONDING_OPTS': 'mode=active-backup miimon=100 primary=eth1 primary_reselect=always'}
        expected = self._get_network_config(
            ifname=bond['ifname'], mtu=1500, method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_config_active_standby_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        bond = self._create_bond_test("bond0")
        bond['aemode'] = 'active_standby'
        bond['primary_reselect'] = constants.PRIMARY_RESELECT_ALWAYS
        self._update_context()
        config = interface.get_interface_network_config(self.context, bond)
        ipv6_autocnf_off = self._get_ipv6_autoconf_off(bond['ifname'])
        options = {'bond-miimon': '100',
                   'bond-mode': 'active-backup',
                   'bond-slaves': 'eth1 eth2 ',
                   'bond-primary': 'eth1',
                   'bond-primary-reselect': 'always',
                   'hwaddress': bond['imac'],
                   'mtu': '1500',
                   'post-up': '{}'.format(ipv6_autocnf_off),
                   'up': 'sleep 10'}
        expected = self._get_network_config_ifupdown(
            ifname=bond['ifname'], method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_config_active_standby_primary_reselect(self):
        bond = self._create_bond_test("bond0", constants.INTERFACE_CLASS_PLATFORM,
                                      constants.NETWORK_TYPE_MGMT)
        bond['aemode'] = 'active_standby'
        bond['primary_reselect'] = constants.PRIMARY_RESELECT_BETTER
        self._update_context()
        config = interface.get_interface_network_config(self.context, bond)
        options = {'IPV6_AUTOCONF': 'no',
                   'up': 'sleep 10',
                   'MACADDR': bond['imac'],
                   'BONDING_OPTS': 'mode=active-backup miimon=100 primary=eth1 primary_reselect=better'}
        expected = self._get_network_config(
            ifname=bond['ifname'], mtu=1500, method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_bond_config_active_standby_primary_reselect_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        bond = self._create_bond_test("bond0", constants.INTERFACE_CLASS_PLATFORM,
                                      constants.NETWORK_TYPE_MGMT)
        bond['aemode'] = 'active_standby'
        bond['primary_reselect'] = constants.PRIMARY_RESELECT_BETTER
        self._update_context()
        config = interface.get_interface_network_config(self.context, bond)
        ipv6_autocnf_off = self._get_ipv6_autoconf_off(bond['ifname'])
        options = {'bond-miimon': '100',
                   'bond-mode': 'active-backup',
                   'bond-slaves': 'eth1 eth2 ',
                   'bond-primary': 'eth1',
                   'bond-primary-reselect': 'better',
                   'hwaddress': bond['imac'],
                   'mtu': '1500',
                   'post-up': '{}'.format(ipv6_autocnf_off),
                   'up': 'sleep 10'}
        expected = self._get_network_config_ifupdown(
            ifname=bond['ifname'], method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_vlan_config(self):
        vlan = self._create_vlan_test("vlan1", None, None, 1, self.iface)
        self._update_context()
        config = interface.get_interface_network_config(self.context, vlan)
        options = {'IPV6_AUTOCONF': 'no',
                   'PHYSDEV': self.port['name'],
                   'VLAN': 'yes',
                   'pre_up': '/sbin/modprobe -q 8021q'}
        expected = self._get_network_config(
            ifname=self.port['name'] + ".1", mtu=1500, method='manual',
            options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_vlan_config_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        vlan = self._create_vlan_test("vlan1", None, None, 1, self.iface)
        self._update_context()
        config = interface.get_interface_network_config(self.context, vlan)
        vlan_ifname = self.port['name'] + ".1"
        ipv6_autocnf_off = self._get_ipv6_autoconf_off(vlan_ifname)
        mtu = '1500'
        set_mtu = self._get_postup_mtu(vlan_ifname, mtu)
        options = {'mtu': mtu,
                   'pre-up': '/sbin/modprobe -q 8021q',
                   'post-up': '{} {}'.format(set_mtu, ipv6_autocnf_off),
                   'vlan-raw-device': '{}'.format(self.port['name'])}
        expected = self._get_network_config_ifupdown(
            ifname=vlan_ifname, method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_vlan_config_over_bond(self):
        bond = self._create_bond_test("bond0")
        vlan = self._create_vlan_test("vlan1", None, None, 1, bond)
        self._update_context()
        config = interface.get_interface_network_config(self.context, vlan)
        options = {'IPV6_AUTOCONF': 'no',
                   'PHYSDEV': bond['ifname'],
                   'VLAN': 'yes',
                   'pre_up': '/sbin/modprobe -q 8021q'}
        expected = self._get_network_config(
            ifname=bond['ifname'] + ".1", mtu=1500, method='manual',
            options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_controller_vlan_config_over_bond_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        bond = self._create_bond_test("bond0")
        vlan = self._create_vlan_test("vlan1", None, None, 1, bond)
        self._update_context()
        config = interface.get_interface_network_config(self.context, vlan)
        vlan_ifname = bond['ifname'] + ".1"
        ipv6_autocnf_off = self._get_ipv6_autoconf_off(vlan_ifname)
        mtu = '1500'
        set_mtu = self._get_postup_mtu(vlan_ifname, mtu)
        options = {'mtu': mtu,
                   'pre-up': '/sbin/modprobe -q 8021q',
                   'post-up': '{} {}'.format(set_mtu, ipv6_autocnf_off),
                   'vlan-raw-device': '{}'.format(bond['ifname'])}
        expected = self._get_network_config_ifupdown(
            ifname=vlan_ifname, method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_worker_ethernet_config_mgmt(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktypelist'] = [constants.NETWORK_TYPE_MGMT]
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_MGMT)
        self.host['personality'] = constants.WORKER
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_MGMT)
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        config = interface.get_interface_network_config(
            self.context, self.iface, network.id)
        options = {'IPV6_AUTOCONF': 'no',
                   'LINKDELAY': '20',
                   'post_up':
                       '%s %s %s %s > /dev/null' %
                       (constants.TRAFFIC_CONTROL_SCRIPT,
                        self.port['name'], constants.NETWORK_TYPE_MGMT,
                        constants.LINK_SPEED_10G)}
        expected = self._get_network_config(
            ifname=self.port['name'], mtu=1500, options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_worker_ethernet_config_mgmt_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktypelist'] = [constants.NETWORK_TYPE_MGMT]
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_MGMT)
        self.host['personality'] = constants.WORKER
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_MGMT)
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        config = interface.get_interface_network_config(
            self.context, self.iface, network.id)
        ipv6_autocnf_off = self._get_ipv6_autoconf_off(self.port['name'])
        options = {'mtu': '1500',
                   'post-up': '/usr/local/bin/tc_setup.sh {} mgmt 10000 > '
                           '/dev/null; {}'.format(self.port['name'], ipv6_autocnf_off),
                   }
        expected = self._get_network_config_ifupdown(ifname=self.port['name'], options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_worker_ethernet_config_cluster_host(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_CLUSTER_HOST
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        self.host['personality'] = constants.WORKER
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_CLUSTER_HOST)
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        config = interface.get_interface_network_config(
            self.context, self.iface, network.id)
        options = {'IPV6_AUTOCONF': 'no',
                   'LINKDELAY': '20'}
        expected = self._get_static_network_config(
            ifname=self.port['name'], mtu=1500, options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_worker_ethernet_config_cluster_host_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PLATFORM
        self.iface['networktype'] = constants.NETWORK_TYPE_CLUSTER_HOST
        self.iface['networks'] = self._get_network_ids_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        self.host['personality'] = constants.WORKER
        self._update_context()
        self._update_interface_address_pool(
            self.iface, constants.NETWORK_TYPE_CLUSTER_HOST)
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        config = interface.get_interface_network_config(
            self.context, self.iface, network.id)
        ipv6_autocnf_off = self._get_ipv6_autoconf_off(self.port['name'])
        options = {'mtu': '1500',
                   'post-up': '{}'.format(ipv6_autocnf_off)}
        expected = self._get_static_network_config_ifupdown(
            ifname=self.port['name'], options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_worker_ethernet_config_pci_sriov(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PCI_SRIOV
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_SRIOV
        self.host['personality'] = constants.WORKER
        self._update_context()
        config = interface.get_interface_network_config(
            self.context, self.iface)
        options = {'IPV6_AUTOCONF': 'no',
                   'LINKDELAY': '20',
                   'pre_up':
                       'echo 0 > /sys/class/net/eth0/device/sriov_numvfs; '
                       'echo 0 > /sys/class/net/eth0/device/sriov_numvfs'}
        expected = self._get_network_config(
            ifname=self.port['name'], method='manual',
            mtu=1500, options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_worker_ethernet_config_pci_sriov_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PCI_SRIOV
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_SRIOV
        self.host['personality'] = constants.WORKER
        self._update_context()
        config = interface.get_interface_network_config(
            self.context, self.iface)
        ipv6_autocnf_off = self._get_ipv6_autoconf_off(self.port['name'])
        options = {'mtu': '1500',
                   'pre-up': 'echo 0 > /sys/class/net/{}/device/sriov_numvfs;'
                             ' echo 0 > /sys/class/net/{}/device/sriov_numvfs'.format(self.port['name'],
                                                                                 self.port['name']),
                   'post-up': '{}'.format(ipv6_autocnf_off)}
        expected = self._get_network_config_ifupdown(
            ifname=self.port['name'], method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_worker_ethernet_config_pci_pthru(self):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PCI_PASSTHROUGH
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_PASSTHROUGH
        self.host['personality'] = constants.WORKER
        self._update_context()
        config = interface.get_interface_network_config(
            self.context, self.iface)
        options = {'IPV6_AUTOCONF': 'no',
                   'LINKDELAY': '20',
                   'pre_up':
                       'if [ -f  /sys/class/net/eth0/device/sriov_numvfs ]; then'
                       ' echo 0 > /sys/class/net/eth0/device/sriov_numvfs; fi'}
        expected = self._get_network_config(
            ifname=self.port['name'], mtu=1500, method='manual',
            options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_worker_ethernet_config_pci_pthru_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PCI_PASSTHROUGH
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_PASSTHROUGH
        self.host['personality'] = constants.WORKER
        self._update_context()
        config = interface.get_interface_network_config(
            self.context, self.iface)
        ipv6_autocnf_off = self._get_ipv6_autoconf_off(self.port['name'])
        options = {'mtu': '1500',
                   'pre-up':
                      'if [ -f  /sys/class/net/{}/device/sriov_numvfs ];'
                        ' then echo 0 > /sys/class/net/{}/device/sriov_numvfs; fi'.format(
                            self.port['name'], self.port['name']),
                   'post-up': '{}'.format(ipv6_autocnf_off)}
        expected = self._get_network_config_ifupdown(
            ifname=self.port['name'], method='manual', options=options)
        print(expected)
        self.assertEqual(expected, config)

    def test_get_worker_ethernet_config_pci_sriov_vf(self):
        port, iface = self._create_ethernet_test(
            'sriov', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=2,
            sriov_vf_driver=None)
        vf = self._create_vf_test("vf", 1, None, lower_iface=iface)
        self._update_context()
        config = interface.get_interface_network_config(self.context, vf)
        expected = {}
        print(expected)
        self.assertEqual(expected, config)

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

    def _create_sriov_vf_config(self, iface_vf_driver, port_vf_driver,
                                vf_addr_list, num_vfs, max_tx_rate=None):
        self.iface['ifclass'] = constants.INTERFACE_CLASS_PCI_SRIOV
        self.iface['networktype'] = constants.NETWORK_TYPE_PCI_SRIOV
        self.iface['sriov_vf_driver'] = iface_vf_driver
        self.iface['sriov_numvfs'] = num_vfs
        self.iface['max_tx_rate'] = max_tx_rate
        self.port['sriov_vf_driver'] = port_vf_driver
        self.port['sriov_vfs_pci_address'] = vf_addr_list
        self._update_context()

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
        port, iface = self._create_ethernet_test(
            'sriov1', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=4,
            iface_sriov_vf_driver=None,
            port_sriov_vf_driver="iavf",
            sriov_vfs_pci_address="0000:b1:02.0,0000:b1:02.1,0000:b1:02.2,0000:b1:02.3")
        self._create_vf_test("vf1", 1, 'vfio', lower_iface=iface)
        self._update_context()

        config = interface.get_sriov_config(self.context, iface)

        expected_vf_config = {
            '0000:b1:02.0': {'addr': '0000:b1:02.0', 'driver': None},
            '0000:b1:02.1': {'addr': '0000:b1:02.1', 'driver': None},
            '0000:b1:02.2': {'addr': '0000:b1:02.2', 'driver': None},
            '0000:b1:02.3': {'addr': '0000:b1:02.3', 'driver': 'vfio-pci'}
        }
        expected = self._get_sriov_config(
            iface['ifname'], None,
            num_vfs=4, pf_addr=port['pciaddr'],
            port_name="eth1",
            vf_config=expected_vf_config)
        self.assertEqual(expected, config)

    def test_get_sriov_config_iftype_vf_nested(self):
        port, iface = self._create_ethernet_test(
            'sriov1', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=4,
            iface_sriov_vf_driver=None,
            port_sriov_vf_driver="iavf",
            sriov_vfs_pci_address="0000:b1:02.0,0000:b1:02.1,0000:b1:02.2,0000:b1:02.3")
        vf1 = self._create_vf_test("vf1", 2, 'vfio', lower_iface=iface)
        self._create_vf_test("vf2", 1, 'netdevice', lower_iface=vf1)
        self._update_context()

        config = interface.get_sriov_config(self.context, iface)

        expected_vf_config = {
            '0000:b1:02.0': {'addr': '0000:b1:02.0', 'driver': None},
            '0000:b1:02.1': {'addr': '0000:b1:02.1', 'driver': None},
            '0000:b1:02.2': {'addr': '0000:b1:02.2', 'driver': 'vfio-pci'},
            '0000:b1:02.3': {'addr': '0000:b1:02.3', 'driver': 'iavf'}
        }
        expected = self._get_sriov_config(
            iface['ifname'], None,
            num_vfs=4, pf_addr=port['pciaddr'],
            port_name="eth1",
            vf_config=expected_vf_config)
        self.assertEqual(expected, config)

    def test_get_sriov_config_iftype_vf_sibling(self):
        port, iface = self._create_ethernet_test(
            'sriov1', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=4,
            iface_sriov_vf_driver=None,
            port_sriov_vf_driver="iavf",
            sriov_vfs_pci_address="0000:b1:02.0,0000:b1:02.1,0000:b1:02.2,0000:b1:02.3")
        self._create_vf_test("vf1", 2, 'vfio', lower_iface=iface)
        self._create_vf_test("vf2", 1, 'netdevice', lower_iface=iface)
        self._update_context()

        config = interface.get_sriov_config(self.context, iface)

        expected_vf_config = {
            '0000:b1:02.0': {'addr': '0000:b1:02.0', 'driver': None},
            '0000:b1:02.1': {'addr': '0000:b1:02.1', 'driver': 'iavf'},
            '0000:b1:02.2': {'addr': '0000:b1:02.2', 'driver': 'vfio-pci'},
            '0000:b1:02.3': {'addr': '0000:b1:02.3', 'driver': 'vfio-pci'}
        }
        expected = self._get_sriov_config(
            iface['ifname'], None,
            num_vfs=4, pf_addr=port['pciaddr'],
            port_name="eth1",
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
            '0000:81:00.0': {'addr': '0000:81:00.0', 'driver': 'vfio-pci', 'max_tx_rate': 1000, 'vfnumber': 0},
            '0000:81:01.0': {'addr': '0000:81:01.0', 'driver': 'vfio-pci', 'max_tx_rate': 1000, 'vfnumber': 1}
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
        port, iface = self._create_ethernet_test(
            'sriov1', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=4,
            iface_sriov_vf_driver=None,
            port_sriov_vf_driver="iavf",
            sriov_vfs_pci_address="0000:b1:02.0,0000:b1:02.1,0000:b1:02.2,0000:b1:02.3")
        self._create_vf_test("vf1", 2, 'vfio', lower_iface=iface)
        self._create_vf_test("vf2", 1, 'netdevice', lower_iface=iface, max_tx_rate=1000)
        self._update_context()

        config = interface.get_sriov_config(self.context, iface)

        expected_vf_config = {
            '0000:b1:02.0': {'addr': '0000:b1:02.0', 'driver': None},
            '0000:b1:02.1': {'addr': '0000:b1:02.1', 'driver': 'iavf', 'max_tx_rate': 1000, 'vfnumber': 1},
            '0000:b1:02.2': {'addr': '0000:b1:02.2', 'driver': 'vfio-pci'},
            '0000:b1:02.3': {'addr': '0000:b1:02.3', 'driver': 'vfio-pci'}
        }
        expected = self._get_sriov_config(
            iface['ifname'], None,
            num_vfs=4, pf_addr=port['pciaddr'],
            port_name="eth1",
            vf_config=expected_vf_config)
        self.assertEqual(expected, config)

    def test_get_fpga_config(self):
        port, iface = self._create_ethernet_test(
            'n3000', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=4,
            iface_sriov_vf_driver=None,
            port_sriov_vf_driver="iavf",
            sriov_vfs_pci_address="0000:b1:02.0,0000:b1:02.1,0000:b1:02.2,0000:b1:02.3",
            pdevice="Ethernet Controller [0d58]")
        self._create_vf_test("vf1", 2, 'vfio', lower_iface=iface)
        self._create_vlan_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_OAM, 1, lower_iface=iface)
        self._update_context()

        config = interface.get_fpga_config(self.context, iface)

        # Since the interface's fpga config is used to determine whether
        # any upper vlan interfaces need to be brought up after an
        # n3000 device is reset, we ensure that no virtual (VF)
        # type interfaces are in the dict.
        # Note: the operating system name of a vlan will be
        # vlan<VID> regardless of the logical name.
        expected = self._get_fpga_config(
            portname='eth1', device_id='0d58', vlans=["vlan1"])
        self.assertEqual(expected, config)

    def test_is_an_n3000_i40_device_false(self):
        self.assertFalse(
            interface.is_an_n3000_i40_device(self.context, self.iface))

    def test_is_an_n3000_i40_device_true(self):
        self.port['pdevice'] = "Ethernet Controller [0d58]"
        self._update_context()
        self.assertTrue(
            interface.is_an_n3000_i40_device(self.context, self.iface))

    def test_find_sriov_interfaces_by_driver_none(self):
        ifaces = interface.find_sriov_interfaces_by_driver(
            self.context, constants.DRIVER_MLX_CX4)
        self.assertTrue(not ifaces)

    def test_find_sriov_interfaces_by_driver_one(self):
        expected = ['sriov_cx4_0']
        vf_num = 2

        for ifname in expected:
            self._create_sriov_cx4_if_test(ifname, vf_num)
        self._update_context()

        ifaces = interface.find_sriov_interfaces_by_driver(
            self.context, constants.DRIVER_MLX_CX4)

        results = [iface['ifname'] for iface in ifaces]
        self.assertEqual(sorted(results), sorted(expected))

    def test_find_sriov_interfaces_by_driver_two(self):
        expected = ['sriov_cx4_0', 'sriov_cx4_1']
        vf_num = 2

        for ifname in expected:
            self._create_sriov_cx4_if_test(ifname, vf_num)
        self._update_context()

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
        p = mock.patch('sysinv.puppet.interface.is_syscfg_network')
        self.mock_puppet_interface_sysconfig = p.start()
        self.mock_puppet_interface_sysconfig.return_value = True
        self.addCleanup(p.stop)

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

    def test_generate_interface_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.interface.get_host_config(self.host)  # pylint: disable=no-member
            self.assertIsNotNone(config)
            yaml.dump(config, config_file, default_flow_style=False)

    def test_generate_interface_config_ifupdown(self):
        self.mock_puppet_interface_sysconfig.return_value = False
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.interface.get_host_config(self.host)  # pylint: disable=no-member
            self.assertIsNotNone(config)
            yaml.dump(config, config_file, default_flow_style=False)

    def test_create_interface_context(self):
        context = self.operator.interface._create_interface_context(self.host)  # pylint: disable=no-member
        self.assertIn('personality', context)
        self.assertIn('subfunctions', context)
        self.assertIn('devices', context)
        self.assertIn('ports', context)
        self.assertIn('interfaces', context)
        self.assertIn('addresses', context)
        self.assertIn('routes', context)
        self.assertIn('gateways', context)

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
                print("iface %s is %sa data interface" % (
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
        if interface.is_worker_subfunction(self.context):
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


class InterfaceControllerEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # ethernet interfaces.
        self.host = self._create_test_host(constants.CONTROLLER)
        self._create_ethernet_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_OAM)
        self._create_ethernet_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_MGMT)
        self._create_ethernet_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_CLUSTER_HOST)
        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceControllerEthernet, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['oam', 'mgmt', 'cluster-host']


class InterfaceControllerBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # aggregated ethernet interfaces.
        self.host = self._create_test_host(constants.CONTROLLER)
        self._create_bond_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_OAM)
        self._create_bond_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_MGMT)
        self._create_bond_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_CLUSTER_HOST)

    def setUp(self):
        super(InterfaceControllerBond, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['eth0', 'eth1', 'oam',
                                             'eth3', 'eth4', 'mgmt',
                                             'eth6', 'eth7', 'cluster-host']
        self.expected_slave_interfaces = ['eth0', 'eth1',
                                          'eth3', 'eth4',
                                          'eth6', 'eth7']


class InterfaceControllerVlanOverBond(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # vlan interfaces over aggregated ethernet interfaces
        self.host = self._create_test_host(constants.CONTROLLER)
        bond = self._create_bond_test('pxeboot',
                                      constants.INTERFACE_CLASS_PLATFORM,
                                      constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_OAM, 1, bond)
        self._create_vlan_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_MGMT, 2, bond)
        self._create_vlan_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_CLUSTER_HOST, 3,
                               bond)
        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceControllerVlanOverBond, self).setUp()
        self.expected_bmc_interface = 'pxeboot'
        self.expected_platform_interfaces = ['eth0', 'eth1', 'pxeboot',
                                             'oam', 'mgmt', 'cluster-host']
        self.expected_slave_interfaces = ['eth0', 'eth1']


class InterfaceControllerVlanOverEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # vlan interfaces over ethernet interfaces
        self.host = self._create_test_host(constants.CONTROLLER)
        port, iface = self._create_ethernet_test(
            'pxeboot', constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan_test('oam', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_OAM, 1, iface)
        self._create_vlan_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_MGMT, 2, iface)
        self._create_vlan_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_CLUSTER_HOST, 3, iface)
        self._create_ethernet_test('none')

    def setUp(self):
        super(InterfaceControllerVlanOverEthernet, self).setUp()
        self.expected_bmc_interface = 'pxeboot'
        self.expected_platform_interfaces = ['eth0', 'pxeboot', 'oam',
                                             'mgmt', 'cluster-host']


class InterfaceComputeEthernet(InterfaceHostTestCase):
    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # worker and all interfaces are ethernet interfaces.
        self.host = self._create_test_host(constants.WORKER)
        self._create_ethernet_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_MGMT)
        self._create_ethernet_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                                   constants.NETWORK_TYPE_CLUSTER_HOST)
        self._create_ethernet_test('data', constants.INTERFACE_CLASS_DATA)
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
        super(InterfaceComputeEthernet, self).setUp()
        self.expected_bmc_interface = 'mgmt'
        self.expected_platform_interfaces = ['mgmt', 'cluster-host']
        self.expected_data_interfaces = ['slow', 'data', 'mlx5']
        self.expected_pci_interfaces = ['sriov', 'pthru']
        self.expected_slow_interfaces = ['slow']
        self.expected_bridged_interfaces = ['slow']
        self.expected_slave_interfaces = []
        self.expected_mlx_interfaces = ['mlx5']


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
        self._create_bond_test('mgmt', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_MGMT)
        self._create_bond_test('cluster-host', constants.INTERFACE_CLASS_PLATFORM,
                               constants.NETWORK_TYPE_CLUSTER_HOST)
        self._create_bond_test('data', constants.INTERFACE_CLASS_DATA,
                               constants.NETWORK_TYPE_DATA)
        self._create_ethernet_test('sriov',
                                   constants.INTERFACE_CLASS_PCI_SRIOV,
                                   constants.NETWORK_TYPE_PCI_SRIOV)
        self._create_ethernet_test('pthru',
                                   constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                   constants.NETWORK_TYPE_PCI_PASSTHROUGH)

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
