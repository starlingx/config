# Copyright (c) 2017-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid
import mock
import os
import yaml

from netaddr import IPAddress
from sysinv.tests.puppet import base
from sysinv.puppet import puppet
from sysinv.objects import base as objbase
from sysinv.tests.db import base as dbbase
from sysinv.common import constants
from sysinv.common import platform_firewall as firewall
from sysinv.tests.db import utils as dbutils
from sysinv.db import api as db_api
from sysinv.puppet import interface as puppet_intf


class PlatformFirewallTestCaseMixin(base.PuppetTestCaseMixin):
    """ This PlatformFirewallTestCaseMixin needs to be used with a subclass
        of BaseHostTestCase
    """

    def assertIn(self, needle, haystack, message=''):
        """Custom assertIn that handles object comparison"""
        if isinstance(needle, objbase.SysinvObject):
            # compare objects based on unique DB identifier
            needle = needle.id
            haystack = [o.id for o in haystack]
        super(PlatformFirewallTestCaseMixin, self).assertIn(needle, haystack, message)

    def assertEqual(self, expected, observed, message=''):
        """Custom assertEqual that handles object comparison"""
        if (isinstance(expected, objbase.SysinvObject) and
                isinstance(observed, objbase.SysinvObject)):
            expected = expected.id
            observed = observed.id
        super(PlatformFirewallTestCaseMixin, self).assertEqual(expected, observed, message)

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

    def _find_network_by_type(self, networktype):
        for network in self.networks:
            if network['type'] == networktype:
                return network

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

    def _create_loopback_test(self, ifname=None, ifclass=None,
                              networktype=None, **kwargs):
        interface_id = len(self.interfaces)
        if not ifname:
            ifname = "lo"
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
                     'iftype': constants.INTERFACE_TYPE_VIRTUAL,
                     'imac': '00:00:00:00:00:00',
                     'uses': [],
                     'used_by': [],
                     'ifclass': ifclass,
                     'networktype': networktype}
        db_interface = dbutils.create_test_interface(**interface)
        for network in networks:
            dbutils.create_test_interface_network_assign(db_interface['id'], network)
        self.interfaces.append(db_interface)

        return db_interface

    def _create_vlan_test(self, ifname, ifclass, networktype, vlan_id,
                          lower_iface=None):
        if not lower_iface:
            lower_port, lower_iface = self._create_ethernet_test()
        host_id = lower_iface.forihostid
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
                     'forihostid': host_id,
                     'ifname': ifname,
                     'iftype': constants.INTERFACE_TYPE_VLAN,
                     'vlan_id': vlan_id,
                     'imac': '02:11:22:33:44:' + str(10 + interface_id),
                     'uses': [lower_iface['ifname']],
                     'used_by': [],
                     'ifclass': ifclass,
                     'networktype': networktype,
                     'imtu': 1500}
        lower_iface['used_by'].append(interface['ifname'])
        db_interface = dbutils.create_test_interface(**interface)
        for network in networks:
            dbutils.create_test_interface_network_assign(db_interface['id'], network)
        self.interfaces.append(db_interface)
        return db_interface

    def _create_bond_test(self, ifname, ifclass=None, networktype=None, host_id=None):
        if not host_id:
            host_id = self.host.id
        port1, iface1 = self._create_ethernet_test(host_id=host_id)
        port2, iface2 = self._create_ethernet_test(host_id=host_id)
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
                     'forihostid': host_id,
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
        for network in networks:
            dbutils.create_test_interface_network_assign(db_interface['id'], network)
        self.interfaces.append(db_interface)
        return db_interface

    def _create_test_route(self, interface, network, prefix, gateway='192.168.0.1'):
        route_db = dbutils.create_test_route(
            interface_id=interface.id,
            family=4,
            network=network,
            prefix=prefix,
            gateway=gateway)
        self.routes.append(route_db)
        return route_db

    def _create_hieradata_directory(self):
        hiera_path = os.path.join(os.environ['VIRTUAL_ENV'], 'hieradata')
        if not os.path.exists(hiera_path):
            os.mkdir(hiera_path, 0o755)
        return hiera_path

    def _get_config_filename(self, hiera_directory):
        class_name = self.__class__.__name__
        return os.path.join(hiera_directory, class_name) + ".yaml"

    def _check_gnp_values(self, gnp, net_type, db_api, egress_size=3, ingress_size=3):

        network = self.context['networks'][net_type]
        addr_pool = db_api.address_pool_get(network.pool_uuid)

        ip_version = IPAddress(f"{addr_pool.network}").version
        nodetype_selector = f"has(nodetype) && nodetype == '{self.host.personality}'"
        iftype_selector = f"has(iftype) && iftype contains '{network.type}'"
        selector = f"{nodetype_selector} && {iftype_selector}"
        ICMP = "ICMP"
        if (ip_version == 6):
            ICMP = "ICMPv6"

        self.assertEqual(gnp["apiVersion"], "crd.projectcalico.org/v1")
        self.assertEqual(gnp["kind"], "GlobalNetworkPolicy")
        self.assertEqual(gnp['metadata']['name'],
                         f"{self.host.personality}-{net_type}-if-gnp")
        self.assertEqual(gnp['spec']['applyOnForward'], True)
        self.assertEqual(gnp['spec']['order'], 100)

        self.assertEqual(gnp['spec']['selector'], selector)
        self.assertEqual(gnp['spec']['types'], ["Ingress", "Egress"])
        self.assertEqual(len(gnp['spec']['egress']), egress_size)
        self.assertEqual(len(gnp['spec']['ingress']), ingress_size)

        # egress rules
        self.assertEqual(gnp['spec']['egress'][0]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['egress'][0]['metadata']['annotations']['name'],
                f"stx-egr-{self.host.personality}-{net_type}-tcp{ip_version}")
        self.assertEqual(gnp['spec']['egress'][0]['ipVersion'], ip_version)
        self.assertFalse('destination' in gnp['spec']['egress'][0].keys())
        self.assertFalse('source' in gnp['spec']['egress'][0].keys())

        self.assertEqual(gnp['spec']['egress'][1]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['egress'][1]['metadata']['annotations']['name'],
                f"stx-egr-{self.host.personality}-{net_type}-udp{ip_version}")
        self.assertEqual(gnp['spec']['egress'][1]['ipVersion'], ip_version)
        self.assertFalse('destination' in gnp['spec']['egress'][1].keys())
        self.assertFalse('source' in gnp['spec']['egress'][1].keys())

        self.assertEqual(gnp['spec']['egress'][2]['protocol'], ICMP)
        self.assertEqual(gnp['spec']['egress'][2]['metadata']['annotations']['name'],
                f"stx-egr-{self.host.personality}-{net_type}-{ICMP.lower()}{ip_version}")
        self.assertEqual(gnp['spec']['egress'][2]['ipVersion'], ip_version)
        self.assertFalse('destination' in gnp['spec']['egress'][2].keys())
        self.assertFalse('source' in gnp['spec']['egress'][2].keys())

        # ingress rules
        self.assertEqual(gnp['spec']['ingress'][0]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][0]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-{net_type}-tcp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][0]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][0]['source']['nets'][0],
                         f"{addr_pool.network}/{addr_pool.prefix}")

        self.assertEqual(gnp['spec']['ingress'][1]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][1]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-{net_type}-udp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][1]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][1]['source']['nets'][0],
                         f"{addr_pool.network}/{addr_pool.prefix}")

        self.assertEqual(gnp['spec']['ingress'][2]['protocol'], ICMP)
        self.assertEqual(gnp['spec']['ingress'][2]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-{net_type}-{ICMP.lower()}{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][2]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][2]['source']['nets'][0],
                         f"{addr_pool.network}/{addr_pool.prefix}")

        cpod_net = db_api.network_get_by_type(constants.NETWORK_TYPE_CLUSTER_POD)
        cpod_pool = db_api.address_pool_get(cpod_net.pool_uuid)

        if (ip_version == 4 and (net_type == constants.NETWORK_TYPE_PXEBOOT
                or net_type == constants.NETWORK_TYPE_MGMT
                or net_type == constants.NETWORK_TYPE_STORAGE)):
            self.assertEqual(gnp['spec']['ingress'][3]['metadata']['annotations']['name'],
                    f"stx-ingr-{self.host.personality}-dhcp-udp{ip_version}")
            self.assertEqual(gnp['spec']['ingress'][3]['protocol'], "UDP")
            self.assertEqual(gnp['spec']['ingress'][3]['ipVersion'], ip_version)
            self.assertEqual(gnp['spec']['ingress'][3]['destination']['ports'], [67])

        if (ip_version == 4 and (net_type == constants.NETWORK_TYPE_CLUSTER_HOST)):
            self.assertEqual(gnp['spec']['ingress'][0]['source']['nets'][1],
                             f"{cpod_pool.network}/{cpod_pool.prefix}")
            self.assertEqual(gnp['spec']['ingress'][1]['source']['nets'][1],
                             f"{cpod_pool.network}/{cpod_pool.prefix}")
            self.assertEqual(gnp['spec']['ingress'][2]['source']['nets'][1],
                             f"{cpod_pool.network}/{cpod_pool.prefix}")

            # check that SCTP rule was added for egress cluster-host in IPv6
            self.assertEqual(gnp['spec']['egress'][3]['protocol'], "SCTP")
            self.assertEqual(gnp['spec']['egress'][3]['metadata']['annotations']['name'],
                    f"stx-egr-{self.host.personality}-{net_type}-sctp{ip_version}")
            self.assertEqual(gnp['spec']['egress'][3]['ipVersion'], ip_version)
            self.assertFalse('destination' in gnp['spec']['egress'][3].keys())
            self.assertFalse('source' in gnp['spec']['egress'][3].keys())
            # check that SCTP rule was added for ingress cluster-host in IPv4
            self.assertEqual(gnp['spec']['ingress'][3]['protocol'], "SCTP")
            self.assertEqual(gnp['spec']['ingress'][3]['metadata']['annotations']['name'],
                    f"stx-ingr-{self.host.personality}-{net_type}-sctp{ip_version}")
            self.assertEqual(gnp['spec']['ingress'][3]['ipVersion'], ip_version)
            self.assertEqual(gnp['spec']['ingress'][3]['source']['nets'][0],
                            f"{addr_pool.network}/{addr_pool.prefix}")
            self.assertEqual(gnp['spec']['ingress'][3]['source']['nets'][1],
                             f"{cpod_pool.network}/{cpod_pool.prefix}")

            self.assertEqual(gnp['spec']['ingress'][4]['metadata']['annotations']['name'],
                    f"stx-ingr-{self.host.personality}-dhcp-udp{ip_version}")
            self.assertEqual(gnp['spec']['ingress'][4]['protocol'], "UDP")
            self.assertEqual(gnp['spec']['ingress'][4]['ipVersion'], ip_version)
            self.assertEqual(gnp['spec']['ingress'][4]['destination']['ports'], [67])

        if (ip_version == 6 and (net_type == constants.NETWORK_TYPE_CLUSTER_HOST)):
            self.assertEqual(gnp['spec']['ingress'][0]['source']['nets'][1],
                             f"{cpod_pool.network}/{cpod_pool.prefix}")
            self.assertEqual(gnp['spec']['ingress'][0]['source']['nets'][2], "fe80::/64")
            self.assertEqual(gnp['spec']['ingress'][1]['source']['nets'][1],
                             f"{cpod_pool.network}/{cpod_pool.prefix}")
            self.assertEqual(gnp['spec']['ingress'][1]['source']['nets'][2], "fe80::/64")
            self.assertEqual(gnp['spec']['ingress'][2]['source']['nets'][1],
                             f"{cpod_pool.network}/{cpod_pool.prefix}")
            self.assertEqual(gnp['spec']['ingress'][2]['source']['nets'][2], "fe80::/64")

            # check that SCTP rule was added for egress cluster-host in IPv6
            self.assertEqual(gnp['spec']['egress'][3]['protocol'], "SCTP")
            self.assertEqual(gnp['spec']['egress'][3]['metadata']['annotations']['name'],
                    f"stx-egr-{self.host.personality}-{net_type}-sctp{ip_version}")
            self.assertEqual(gnp['spec']['egress'][3]['ipVersion'], ip_version)
            self.assertFalse('destination' in gnp['spec']['egress'][3].keys())
            self.assertFalse('source' in gnp['spec']['egress'][3].keys())

            # check that SCTP rule was added for ingress cluster-host in IPv6
            self.assertEqual(gnp['spec']['ingress'][3]['protocol'], "SCTP")
            self.assertEqual(gnp['spec']['ingress'][3]['metadata']['annotations']['name'],
                    f"stx-ingr-{self.host.personality}-{net_type}-sctp{ip_version}")
            self.assertEqual(gnp['spec']['ingress'][3]['ipVersion'], ip_version)
            self.assertEqual(gnp['spec']['ingress'][3]['source']['nets'][0],
                            f"{addr_pool.network}/{addr_pool.prefix}")
            self.assertEqual(gnp['spec']['ingress'][3]['source']['nets'][1],
                             f"{cpod_pool.network}/{cpod_pool.prefix}")
            self.assertEqual(gnp['spec']['ingress'][3]['source']['nets'][2], "fe80::/64")

        if (ip_version == 6 and (net_type != constants.NETWORK_TYPE_CLUSTER_HOST)):
            self.assertEqual(gnp['spec']['ingress'][0]['source']['nets'][1], "fe80::/64")
            self.assertEqual(gnp['spec']['ingress'][1]['source']['nets'][1], "fe80::/64")
            self.assertEqual(gnp['spec']['ingress'][2]['source']['nets'][1], "fe80::/64")

    def _check_he_values(self, hep, intf, network_list):

        nodename = self.host.hostname
        ifname = intf.ifname
        os_ifname = puppet_intf.get_interface_os_ifname(self.context, intf)
        hep_name = f'{nodename}-{ifname}-if-hep'
        self.assertTrue(hep_name in hep.keys())
        network_list.sort()
        iftype = '.'.join(network_list)

        self.assertEqual(hep[hep_name]["apiVersion"], "crd.projectcalico.org/v1")
        self.assertEqual(hep[hep_name]["kind"], "HostEndpoint")
        self.assertEqual(hep[hep_name]['metadata']['labels']['iftype'], iftype)
        self.assertEqual(hep[hep_name]['metadata']['labels']['nodetype'], self.host.personality)
        self.assertEqual(hep[hep_name]['metadata']['labels']['ifname'], f"{nodename}.{ifname}")
        self.assertEqual(hep[hep_name]['metadata']['name'], f"{nodename}-{ifname}-if-hep")
        self.assertEqual(hep[hep_name]['spec']['interfaceName'], os_ifname)
        self.assertEqual(hep[hep_name]['spec']['node'], nodename)

    def _create_service_parameter_test_set(self):
        service_parameter_data = [
            {
                'service': constants.SERVICE_TYPE_HTTP,
                'section': constants.SERVICE_PARAM_SECTION_HTTP_CONFIG,
                'name': constants.SERVICE_PARAM_HTTP_PORT_HTTP,
                'value': str(constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
            },
            {
                'service': constants.SERVICE_TYPE_HTTP,
                'section': constants.SERVICE_PARAM_SECTION_HTTP_CONFIG,
                'name': constants.SERVICE_PARAM_HTTP_PORT_HTTPS,
                'value': str(constants.SERVICE_PARAM_HTTP_PORT_HTTPS_DEFAULT)
            },
            {
                'service': constants.SERVICE_TYPE_KUBERNETES,
                'section': constants.SERVICE_PARAM_SECTION_KUBERNETES_CERTIFICATES,
                'name': constants.SERVICE_PARAM_NAME_KUBERNETES_API_SAN_LIST,
                'value': 'localurl'
            },
            {
                'service': constants.SERVICE_TYPE_KUBERNETES,
                'section': constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
                'name': constants.SERVICE_PARAM_NAME_OIDC_USERNAME_CLAIM,
                'value': 'wad'
            },
            {
                'service': constants.SERVICE_TYPE_KUBERNETES,
                'section': constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
                'name': constants.SERVICE_PARAM_NAME_OIDC_ISSUER_URL,
                'value': 'https://10.10.10.3:30556/dex'
            },
            {
                'service': constants.SERVICE_TYPE_KUBERNETES,
                'section': constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
                'name': constants.SERVICE_PARAM_NAME_OIDC_CLIENT_ID,
                'value': 'wad'
            }
        ]

        for service in service_parameter_data:
            dbutils.create_test_service_parameter(**service)

    def _set_dc_role(self, dc_role):
        system = self.dbapi.isystem_get_one()
        self.dbapi.isystem_update(system.uuid, {'distributed_cloud_role': dc_role})


# Controller, non-DC
#   eth0:oam       [oam]
#   eth1:mgmt0     [mgmt]
#   eth2:cluster0  [cluster-host]
#   eth3:pxe0      [pxeboot]
class PlatformFirewallTestCaseControllerNonDc_Setup01(PlatformFirewallTestCaseMixin,
                                                      dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseControllerNonDc_Setup01, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(PlatformFirewallTestCaseControllerNonDc_Setup01, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.

        self.host.save(self.admin_context)
        super(PlatformFirewallTestCaseControllerNonDc_Setup01, self)._update_context()

    def _setup_configuration(self):
        # Create a single port/interface for basic function testing
        self.host = self._create_test_host(constants.CONTROLLER)

        port, iface = self._create_ethernet_test("oam0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_OAM)
        self.test_interfaces.update({constants.NETWORK_TYPE_OAM: iface})

        port, iface = self._create_ethernet_test("mgmt0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_MGMT)
        self.test_interfaces.update({constants.NETWORK_TYPE_MGMT: iface})

        port, iface = self._create_ethernet_test("cluster0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_CLUSTER_HOST)
        self.test_interfaces.update({constants.NETWORK_TYPE_CLUSTER_HOST: iface})

        port, iface = self._create_ethernet_test("pxe0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT)
        self.test_interfaces.update({constants.NETWORK_TYPE_PXEBOOT: iface})

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        # for now we do NOT handle OAM configuration
        self.assertFalse('platform::firewall::calico::oam::config' in hiera_data.keys())

        self.assertTrue('platform::firewall::calico::admin::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::cluster_host::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::mgmt::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::pxeboot::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::storage::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::hostendpoint::config' in hiera_data.keys())

        # these GNPs are empty (not used in the current test database)
        self.assertFalse(hiera_data['platform::firewall::calico::admin::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::storage::config'])

        # these GNPs are filled
        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=4, ingress_size=5)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 3)
        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                              [constants.NETWORK_TYPE_MGMT])
        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_CLUSTER_HOST],
                              [constants.NETWORK_TYPE_CLUSTER_HOST])
        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT],
                              [constants.NETWORK_TYPE_PXEBOOT])

        # for now we do NOT handle OAM configuration
        self.assertFalse(f"{self.host.hostname}-oam0-if-hep" in
                         hiera_data['platform::firewall::calico::hostendpoint::config'].keys())


# Controller, non-DC, IPv4
#   eth0:oam
#   eth1:mgmt.pxeboot.cluster-host
#   eth2:storage
class PlatformFirewallTestCaseControllerNonDc_Setup02(PlatformFirewallTestCaseMixin,
                                                      dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseControllerNonDc_Setup02, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(PlatformFirewallTestCaseControllerNonDc_Setup02, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()
        p = mock.patch('sysinv.puppet.platform_firewall._get_dc_role')
        self.mock_platform_firewall_get_dc_role = p.start()
        self.mock_platform_firewall_get_dc_role.return_value = None
        self.addCleanup(p.stop)

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.

        self.host.save(self.admin_context)
        super(PlatformFirewallTestCaseControllerNonDc_Setup02, self)._update_context()

    def _setup_configuration(self):
        # Create a single port/interface for basic function testing
        self.host = self._create_test_host(constants.CONTROLLER)

        port, iface = self._create_ethernet_test("oam0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_OAM)
        self.test_interfaces.update({constants.NETWORK_TYPE_OAM: iface})

        port, iface = self._create_ethernet_test(ifname="mgmt0",
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            networktype=[constants.NETWORK_TYPE_MGMT,
                         constants.NETWORK_TYPE_CLUSTER_HOST,
                         constants.NETWORK_TYPE_PXEBOOT])
        self.test_interfaces.update({constants.NETWORK_TYPE_MGMT: iface})

        port, iface = self._create_ethernet_test(ifname="stor0",
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            networktype=[constants.NETWORK_TYPE_STORAGE])
        self.test_interfaces.update({constants.NETWORK_TYPE_STORAGE: iface})

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        # for now we do NOT handle OAM configuration
        self.assertFalse('platform::firewall::calico::oam::config' in hiera_data.keys())

        self.assertTrue('platform::firewall::calico::admin::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::cluster_host::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::mgmt::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::pxeboot::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::storage::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::hostendpoint::config' in hiera_data.keys())

        # these GNPs are empty (not used in the current test database)
        self.assertFalse(hiera_data['platform::firewall::calico::admin::config'])

        # these GNPs are filled
        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=4, ingress_size=5)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=3, ingress_size=4)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 2)
        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                              [constants.NETWORK_TYPE_MGMT,
                               constants.NETWORK_TYPE_CLUSTER_HOST,
                               constants.NETWORK_TYPE_PXEBOOT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_STORAGE],
                              [constants.NETWORK_TYPE_STORAGE])

        # for now we do NOT handle OAM configuration
        self.assertFalse(f"{self.host.hostname}-oam0-if-hep" in
                         hiera_data['platform::firewall::calico::hostendpoint::config'].keys())


# Controller, non-DC
#   eth0:oam
#   lo:mgmt.cluster-host
class PlatformFirewallTestCaseControllerNonDc_Setup03(PlatformFirewallTestCaseMixin,
                                                      dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseControllerNonDc_Setup03, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(PlatformFirewallTestCaseControllerNonDc_Setup03, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()
        p = mock.patch('sysinv.puppet.platform_firewall._get_dc_role')
        self.mock_platform_firewall_get_dc_role = p.start()
        self.mock_platform_firewall_get_dc_role.return_value = None
        self.addCleanup(p.stop)

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.

        self.host.save(self.admin_context)
        super(PlatformFirewallTestCaseControllerNonDc_Setup03, self)._update_context()

    def _setup_configuration(self):
        # Create a single port/interface for basic function testing
        self.host = self._create_test_host(constants.CONTROLLER)

        port, iface = self._create_ethernet_test("oam0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_OAM)
        self.test_interfaces.update({constants.NETWORK_TYPE_OAM: iface})

        iface = self._create_loopback_test(ifname="lo",
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            networktype=[constants.NETWORK_TYPE_MGMT,
                         constants.NETWORK_TYPE_CLUSTER_HOST])
        self.test_interfaces.update({constants.NETWORK_TYPE_MGMT: iface})

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        # for now we do NOT handle OAM configuration
        self.assertFalse('platform::firewall::calico::oam::config' in hiera_data.keys())

        self.assertTrue('platform::firewall::calico::admin::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::cluster_host::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::mgmt::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::pxeboot::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::storage::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::hostendpoint::config' in hiera_data.keys())

        # do not install firewall if the network is assigned to the loopback
        self.assertFalse(hiera_data['platform::firewall::calico::admin::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::cluster_host::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::mgmt::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::pxeboot::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::storage::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::hostendpoint::config'])


# Controller, non-DC
#   eth0:              oam
#   eth1:              pxeboot
#   vlan100@eth1:      mgmt
#   bond0@[eth2,eth3]: cluster-host.storage
class PlatformFirewallTestCaseControllerNonDc_Setup04(PlatformFirewallTestCaseMixin,
                                                    dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseControllerNonDc_Setup04, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(PlatformFirewallTestCaseControllerNonDc_Setup04, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()
        p = mock.patch('sysinv.puppet.platform_firewall._get_dc_role')
        self.mock_platform_firewall_get_dc_role = p.start()
        self.mock_platform_firewall_get_dc_role.return_value = None
        self.addCleanup(p.stop)

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.

        self.host.save(self.admin_context)
        super(PlatformFirewallTestCaseControllerNonDc_Setup04, self)._update_context()

    def _setup_configuration(self):
        # Create a single port/interface for basic function testing
        self.host = self._create_test_host(constants.CONTROLLER)

        port, iface = self._create_ethernet_test("oam0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_OAM)
        self.test_interfaces.update({constants.NETWORK_TYPE_OAM: iface})

        port, iface = self._create_ethernet_test("pxe0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT)
        self.test_interfaces.update({constants.NETWORK_TYPE_PXEBOOT: iface})

        iface = self._create_vlan_test("mgmt0",
            constants.INTERFACE_CLASS_PLATFORM,
            [constants.NETWORK_TYPE_MGMT], 100,
            self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT])
        self.test_interfaces.update({constants.NETWORK_TYPE_MGMT: iface})

        iface = self._create_bond_test("cluster0",
            constants.INTERFACE_CLASS_PLATFORM,
            [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_STORAGE])
        self.test_interfaces.update({constants.NETWORK_TYPE_CLUSTER_HOST: iface})

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        # for now we do NOT handle OAM configuration
        self.assertFalse('platform::firewall::calico::oam::config' in hiera_data.keys())

        self.assertTrue('platform::firewall::calico::admin::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::cluster_host::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::mgmt::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::pxeboot::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::storage::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::hostendpoint::config' in hiera_data.keys())

        # do not install firewall if the network is assigned to the loopback
        self.assertFalse(hiera_data['platform::firewall::calico::admin::config'])

        # these GNPs are filled
        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=4, ingress_size=5)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=3, ingress_size=4)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 3)
        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT],
                              [constants.NETWORK_TYPE_PXEBOOT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                              [constants.NETWORK_TYPE_MGMT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_CLUSTER_HOST],
                              [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_STORAGE])


# Controller, non-DC
#   eth0:              oam
#   eth1:              mgmt.cluster-host
class PlatformFirewallTestCaseControllerNonDc_Setup05(PlatformFirewallTestCaseMixin,
                                                    dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseControllerNonDc_Setup05, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(PlatformFirewallTestCaseControllerNonDc_Setup05, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()
        p = mock.patch('sysinv.puppet.platform_firewall._get_dc_role')
        self.mock_platform_firewall_get_dc_role = p.start()
        self.mock_platform_firewall_get_dc_role.return_value = None
        self.addCleanup(p.stop)

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.

        self.host.save(self.admin_context)
        super(PlatformFirewallTestCaseControllerNonDc_Setup05, self)._update_context()

    def _setup_configuration(self):
        # Create a single port/interface for basic function testing
        self.host = self._create_test_host(constants.CONTROLLER)

        port, iface = self._create_ethernet_test("oam0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_OAM)
        self.test_interfaces.update({constants.NETWORK_TYPE_OAM: iface})

        port, iface = self._create_ethernet_test("mgmt0",
            constants.INTERFACE_CLASS_PLATFORM,
            [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST])
        self.test_interfaces.update({constants.NETWORK_TYPE_MGMT: iface})

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        # for now we do NOT handle OAM configuration
        self.assertFalse('platform::firewall::calico::oam::config' in hiera_data.keys())

        self.assertTrue('platform::firewall::calico::admin::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::cluster_host::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::mgmt::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::pxeboot::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::storage::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::hostendpoint::config' in hiera_data.keys())

        # do not install firewall if the network is assigned to the loopback
        self.assertFalse(hiera_data['platform::firewall::calico::admin::config'])

        # these GNPs are filled
        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=4, ingress_size=5)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertFalse(hiera_data['platform::firewall::calico::storage::config'])

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 1)

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                              [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST,
                               constants.NETWORK_TYPE_PXEBOOT])


# Controller, non-DC, IPv6
#   eth0:              oam
#   eth1:              pxeboot
#   vlan100@eth1:      mgmt
#   vlan101@eth1:      cluster-host
#   bond0@[eth2,eth3]: storage
class PlatformFirewallTestCaseControllerNonDc_Setup06(PlatformFirewallTestCaseMixin,
                                                    dbbase.BaseIPv6Mixin,
                                                    dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseControllerNonDc_Setup06, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(PlatformFirewallTestCaseControllerNonDc_Setup06, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()
        p = mock.patch('sysinv.puppet.platform_firewall._get_dc_role')
        self.mock_platform_firewall_get_dc_role = p.start()
        self.mock_platform_firewall_get_dc_role.return_value = None
        self.addCleanup(p.stop)

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.

        self.host.save(self.admin_context)
        super(PlatformFirewallTestCaseControllerNonDc_Setup06, self)._update_context()

    def _setup_configuration(self):
        # Create a single port/interface for basic function testing
        self.host = self._create_test_host(constants.CONTROLLER)

        port, iface = self._create_ethernet_test("oam0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_OAM)
        self.test_interfaces.update({constants.NETWORK_TYPE_OAM: iface})

        port, iface = self._create_ethernet_test("pxe0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT)
        self.test_interfaces.update({constants.NETWORK_TYPE_PXEBOOT: iface})

        iface = self._create_vlan_test("mgmt0",
            constants.INTERFACE_CLASS_PLATFORM,
            [constants.NETWORK_TYPE_MGMT], 100,
            self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT])
        self.test_interfaces.update({constants.NETWORK_TYPE_MGMT: iface})

        iface = self._create_vlan_test("cluster0",
            constants.INTERFACE_CLASS_PLATFORM,
            [constants.NETWORK_TYPE_CLUSTER_HOST], 101,
            self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT])
        self.test_interfaces.update({constants.NETWORK_TYPE_CLUSTER_HOST: iface})

        iface = self._create_bond_test("stor0",
            constants.INTERFACE_CLASS_PLATFORM,
            [constants.NETWORK_TYPE_STORAGE])
        self.test_interfaces.update({constants.NETWORK_TYPE_STORAGE: iface})

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        # for now we do NOT handle OAM configuration
        self.assertFalse('platform::firewall::calico::oam::config' in hiera_data.keys())

        self.assertTrue('platform::firewall::calico::admin::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::cluster_host::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::mgmt::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::pxeboot::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::storage::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::hostendpoint::config' in hiera_data.keys())

        # do not install firewall if the network is assigned to the loopback
        self.assertFalse(hiera_data['platform::firewall::calico::admin::config'])

        # these GNPs are filled
        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=3, ingress_size=3)

        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=4, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=3, ingress_size=3)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 4)
        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT],
                              [constants.NETWORK_TYPE_PXEBOOT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                              [constants.NETWORK_TYPE_MGMT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_CLUSTER_HOST],
                              [constants.NETWORK_TYPE_CLUSTER_HOST])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_STORAGE],
                              [constants.NETWORK_TYPE_STORAGE])


# Controller, DC, Subcloud
#   eth0:              oam
#   eth1:              pxeboot
#   vlan100@eth1:      mgmt
#   vlan101@eth1:      admin
#   bond0@[eth2,eth3]: cluster-host.storage
class PlatformFirewallTestCaseControllerDcSubcloud_Setup01(PlatformFirewallTestCaseMixin,
                                                           dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseControllerDcSubcloud_Setup01, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(PlatformFirewallTestCaseControllerDcSubcloud_Setup01, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.
        self.host.save(self.admin_context)
        super(PlatformFirewallTestCaseControllerDcSubcloud_Setup01, self)._update_context()

    def _setup_configuration(self):
        # Create a single port/interface for basic function testing
        self.host = self._create_test_host(constants.CONTROLLER)

        port, iface = self._create_ethernet_test("oam0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_OAM)
        self.test_interfaces.update({constants.NETWORK_TYPE_OAM: iface})

        port, iface = self._create_ethernet_test("pxe0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT)
        self.test_interfaces.update({constants.NETWORK_TYPE_PXEBOOT: iface})

        iface = self._create_vlan_test("mgmt0",
            constants.INTERFACE_CLASS_PLATFORM, [constants.NETWORK_TYPE_MGMT], 100,
            self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT])
        self.test_interfaces.update({constants.NETWORK_TYPE_MGMT: iface})

        iface = self._create_vlan_test("admin0",
            constants.INTERFACE_CLASS_PLATFORM, [constants.NETWORK_TYPE_ADMIN], 101,
            self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT])
        self.test_interfaces.update({constants.NETWORK_TYPE_ADMIN: iface})

        iface = self._create_bond_test("cluster0",
            constants.INTERFACE_CLASS_PLATFORM,
            [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_STORAGE])
        self.test_interfaces.update({constants.NETWORK_TYPE_CLUSTER_HOST: iface})

        self._create_service_parameter_test_set()
        self._set_dc_role(constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD)

        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                                '192.168.1.0', 26)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                                '192.168.1.64', 26)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_ADMIN],
                                '192.168.3.0', 24)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_ADMIN],
                                '192.168.4.0', 24)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_OAM],
                                '192.168.5.0', 24)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT],
                                '192.168.20.0', 24)

    def _check_gnp_admin_values(self, gnp, net_type, db_api, egress_size=3, ingress_size=3):

        network = self.context['networks'][net_type]
        addr_pool = db_api.address_pool_get(network.pool_uuid)

        ip_version = IPAddress(f"{addr_pool.network}").version
        nodetype_selector = f"has(nodetype) && nodetype == '{self.host.personality}'"
        iftype_selector = f"has(iftype) && iftype contains '{network.type}'"
        selector = f"{nodetype_selector} && {iftype_selector}"

        self.assertEqual(gnp["apiVersion"], "crd.projectcalico.org/v1")
        self.assertEqual(gnp["kind"], "GlobalNetworkPolicy")
        self.assertEqual(gnp['metadata']['name'],
                         f"{self.host.personality}-{net_type}-if-gnp")
        self.assertEqual(gnp['spec']['applyOnForward'], True)
        self.assertEqual(gnp['spec']['order'], 100)

        self.assertEqual(gnp['spec']['selector'], selector)
        self.assertEqual(gnp['spec']['types'], ["Ingress", "Egress"])
        self.assertEqual(len(gnp['spec']['egress']), egress_size)
        self.assertEqual(len(gnp['spec']['ingress']), ingress_size)

        # egress rules
        self.assertEqual(gnp['spec']['egress'][0]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['egress'][0]['metadata']['annotations']['name'],
                f"stx-egr-{self.host.personality}-{net_type}-tcp{ip_version}")
        self.assertEqual(gnp['spec']['egress'][0]['ipVersion'], ip_version)
        self.assertFalse('destination' in gnp['spec']['egress'][0].keys())
        self.assertFalse('source' in gnp['spec']['egress'][0].keys())

        self.assertEqual(gnp['spec']['egress'][1]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['egress'][1]['metadata']['annotations']['name'],
                f"stx-egr-{self.host.personality}-{net_type}-udp{ip_version}")
        self.assertEqual(gnp['spec']['egress'][1]['ipVersion'], ip_version)
        self.assertFalse('destination' in gnp['spec']['egress'][1].keys())
        self.assertFalse('source' in gnp['spec']['egress'][1].keys())

        self.assertEqual(gnp['spec']['egress'][2]['protocol'], "ICMP")
        self.assertEqual(gnp['spec']['egress'][2]['metadata']['annotations']['name'],
                f"stx-egr-{self.host.personality}-{net_type}-icmp{ip_version}")
        self.assertEqual(gnp['spec']['egress'][2]['ipVersion'], ip_version)
        self.assertFalse('destination' in gnp['spec']['egress'][2].keys())
        self.assertFalse('source' in gnp['spec']['egress'][2].keys())

        # ingress rules
        tcp_ports = list(firewall.SUBCLOUD["tcp"].keys())
        tcp_ports.append(constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
        tcp_ports.sort()
        udp_ports = list(firewall.SUBCLOUD["udp"].keys())
        udp_ports.sort()

        self.assertEqual(gnp['spec']['ingress'][0]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][0]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-subcloud-tcp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][0]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][0]['destination']['ports'], tcp_ports)
        # only the admin network routes will be added to the firewall
        self.assertEqual(gnp['spec']['ingress'][0]['source']['nets'][0], "192.168.3.0/24")
        self.assertEqual(gnp['spec']['ingress'][0]['source']['nets'][1], "192.168.4.0/24")

        self.assertEqual(gnp['spec']['ingress'][1]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][1]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-subcloud-udp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][1]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][1]['destination']['ports'], udp_ports)
        # only the admin network routes will be added to the firewall
        self.assertEqual(gnp['spec']['ingress'][1]['source']['nets'][0], "192.168.3.0/24")
        self.assertEqual(gnp['spec']['ingress'][1]['source']['nets'][1], "192.168.4.0/24")

        self.assertEqual(gnp['spec']['ingress'][2]['protocol'], "ICMP")
        self.assertEqual(gnp['spec']['ingress'][2]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-subcloud-icmp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][2]['ipVersion'], ip_version)
        # only the admin network routes will be added to the firewall
        self.assertEqual(gnp['spec']['ingress'][2]['source']['nets'][0], "192.168.3.0/24")
        self.assertEqual(gnp['spec']['ingress'][2]['source']['nets'][1], "192.168.4.0/24")

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertFalse('platform::firewall::calico::oam::config' in hiera_data.keys())

        self.assertTrue('platform::firewall::calico::admin::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::cluster_host::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::mgmt::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::pxeboot::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::storage::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::hostendpoint::config' in hiera_data.keys())

        # these GNPs are filled
        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=4, ingress_size=5)

        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::admin::config'])
        self._check_gnp_admin_values(hiera_data['platform::firewall::calico::admin::config'],
                               constants.NETWORK_TYPE_ADMIN, self.dbapi)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 4)

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                              [constants.NETWORK_TYPE_MGMT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_ADMIN],
                              [constants.NETWORK_TYPE_ADMIN])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_CLUSTER_HOST],
                              [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_STORAGE])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT],
                              [constants.NETWORK_TYPE_PXEBOOT])

        # for now we do NOT handle OAM configuration
        self.assertFalse(f"{self.host.hostname}-oam0-if-hep" in
                         hiera_data['platform::firewall::calico::hostendpoint::config'].keys())


# Controller, DC, SystemController
#   eth0:              oam
#   eth1:              pxeboot
#   vlan100@eth1:      mgmt
#   bond0@[eth2,eth3]: cluster-host.storage
class PlatformFirewallTestCaseControllerDcSysCtrl_Setup01(PlatformFirewallTestCaseMixin,
                                                          dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseControllerDcSysCtrl_Setup01, self).__init__(*args, **kwargs)
        self.test_interfaces = []
        self.hosts = []

    def setUp(self):
        super(PlatformFirewallTestCaseControllerDcSysCtrl_Setup01, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.
        for host in self.hosts:
            host.save(self.admin_context)
        super(PlatformFirewallTestCaseControllerDcSysCtrl_Setup01, self)._update_context()

    def _setup_controller(self, unit):
        host = self._create_test_host(constants.CONTROLLER, unit=unit)
        self.hosts.append(host)

        interfaces = dict()

        port, iface = self._create_ethernet_test("oam0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_OAM,
            host.id)
        interfaces.update({constants.NETWORK_TYPE_OAM: iface})

        port, iface = self._create_ethernet_test("pxe0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT,
            host.id)
        interfaces.update({constants.NETWORK_TYPE_PXEBOOT: iface})

        iface = self._create_vlan_test("mgmt0",
            constants.INTERFACE_CLASS_PLATFORM,
            [constants.NETWORK_TYPE_MGMT], 100,
            interfaces[constants.NETWORK_TYPE_PXEBOOT])
        interfaces.update({constants.NETWORK_TYPE_MGMT: iface})

        iface = self._create_bond_test("cluster0",
            constants.INTERFACE_CLASS_PLATFORM,
            [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_STORAGE],
            host.id)
        interfaces.update({constants.NETWORK_TYPE_CLUSTER_HOST: iface})

        self.test_interfaces.append(interfaces)

    def _setup_worker(self):
        host = self._create_test_host(constants.WORKER)
        self.hosts.append(host)

        interfaces = dict()

        port, iface = self._create_ethernet_test("mgmt0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_MGMT,
            host.id)
        interfaces.update({constants.NETWORK_TYPE_MGMT: iface})

        port, iface = self._create_ethernet_test("cluster0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_CLUSTER_HOST,
            host.id)
        interfaces.update({constants.NETWORK_TYPE_CLUSTER_HOST: iface})

        port, iface = self._create_ethernet_test("pxe0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT,
            host.id)
        interfaces.update({constants.NETWORK_TYPE_PXEBOOT: iface})

        self.test_interfaces.append(interfaces)

    def _setup_routes(self):
        # Controller-0

        # Common management route in controller-0 and controller-1
        self._create_test_route(self.test_interfaces[0][constants.NETWORK_TYPE_MGMT],
                                '192.168.1.0', 26)

        # Management route exclusive to controller-0
        self._create_test_route(self.test_interfaces[0][constants.NETWORK_TYPE_MGMT],
                                '192.168.1.64', 26)

        # Non-management routes
        self._create_test_route(self.test_interfaces[0][constants.NETWORK_TYPE_OAM],
                                '192.168.5.0', 24)
        self._create_test_route(self.test_interfaces[0][constants.NETWORK_TYPE_PXEBOOT],
                                '192.168.20.0', 24)

        # Controller-1

        # Common management route in controller-0 and controller-1
        self._create_test_route(self.test_interfaces[1][constants.NETWORK_TYPE_MGMT],
                                '192.168.1.0', 26)

        # Management route exclusive to controller-1
        self._create_test_route(self.test_interfaces[1][constants.NETWORK_TYPE_MGMT],
                                '192.168.1.128', 26)

        # Non-management routes
        self._create_test_route(self.test_interfaces[1][constants.NETWORK_TYPE_OAM],
                                '192.168.5.0', 24)
        self._create_test_route(self.test_interfaces[1][constants.NETWORK_TYPE_PXEBOOT],
                                '192.168.20.0', 24)

        # Worker
        self._create_test_route(self.test_interfaces[2][constants.NETWORK_TYPE_MGMT],
                                '192.168.1.192', 26)
        self._create_test_route(self.test_interfaces[2][constants.NETWORK_TYPE_CLUSTER_HOST],
                                '192.168.6.0', 24)
        self._create_test_route(self.test_interfaces[2][constants.NETWORK_TYPE_PXEBOOT],
                                '192.168.30.0', 24)

    def _setup_configuration(self):

        self._setup_controller(0)
        self._setup_controller(1)

        self._setup_worker()

        self.host = self.hosts[0]

        self._setup_routes()

        self._create_service_parameter_test_set()
        self._set_dc_role(constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER)

    def _check_gnp_values_mgmt_sysctrl(self, gnp):

        ip_version = gnp['spec']['ingress'][0]['ipVersion']

        subcloud_networks = ['192.168.1.0/26', '192.168.1.128/26', '192.168.1.64/26']

        # ingress rules
        self.assertEqual(gnp['spec']['ingress'][4]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][4]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-systemcontroller-tcp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][4]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][4]['source']['nets'], subcloud_networks)

        tcp_ports = list(firewall.SYSTEMCONTROLLER["tcp"].keys())
        tcp_ports.append(constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
        tcp_ports.sort()
        self.assertEqual(gnp['spec']['ingress'][4]['destination']['ports'], tcp_ports)

        self.assertEqual(gnp['spec']['ingress'][5]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][5]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-systemcontroller-udp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][5]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][5]['source']['nets'], subcloud_networks)

        udp_ports = list(firewall.SYSTEMCONTROLLER["udp"].keys())
        udp_ports.sort()
        self.assertEqual(gnp['spec']['ingress'][5]['destination']['ports'], udp_ports)

        self.assertEqual(gnp['spec']['ingress'][6]['protocol'], "ICMP")
        self.assertEqual(gnp['spec']['ingress'][6]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-systemcontroller-icmp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][6]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][6]['source']['nets'], subcloud_networks)

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertFalse('platform::firewall::calico::oam::config' in hiera_data.keys())

        self.assertTrue('platform::firewall::calico::admin::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::cluster_host::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::mgmt::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::pxeboot::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::storage::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::hostendpoint::config' in hiera_data.keys())

        # these GNPs are empty (not used in the current test database)
        self.assertFalse(hiera_data['platform::firewall::calico::admin::config'])

        # these GNPs are filled
        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=4, ingress_size=5)

        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=3, ingress_size=7)
        self._check_gnp_values_mgmt_sysctrl(hiera_data['platform::firewall::calico::mgmt::config'])

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=3, ingress_size=4)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 3)

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[0][constants.NETWORK_TYPE_MGMT],
                              [constants.NETWORK_TYPE_MGMT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[0][constants.NETWORK_TYPE_CLUSTER_HOST],
                              [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_STORAGE])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[0][constants.NETWORK_TYPE_PXEBOOT],
                              [constants.NETWORK_TYPE_PXEBOOT])

        # for now we do NOT handle OAM configuration
        self.assertFalse(f"{self.host.hostname}-oam0-if-hep" in
                         hiera_data['platform::firewall::calico::hostendpoint::config'].keys())


# AIO-DX, Controller, DC, Subcloud
#   eth0:              oam
#   eth1:              pxeboot
#   vlan100@eth1:      mgmt     (no admin network)
#   bond0@[eth2,eth3]: cluster-host.storage
class PlatformFirewallTestCaseControllerDcSubcloud_Setup02(PlatformFirewallTestCaseMixin,
                                                           dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseControllerDcSubcloud_Setup02, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(PlatformFirewallTestCaseControllerDcSubcloud_Setup02, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.
        self.host.save(self.admin_context)
        super(PlatformFirewallTestCaseControllerDcSubcloud_Setup02, self)._update_context()

    def _setup_configuration(self):
        # Create a single port/interface for basic function testing
        self.host = self._create_test_host(constants.CONTROLLER)

        port, iface = self._create_ethernet_test("oam0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_OAM)
        self.test_interfaces.update({constants.NETWORK_TYPE_OAM: iface})

        port, iface = self._create_ethernet_test("pxe0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT)
        self.test_interfaces.update({constants.NETWORK_TYPE_PXEBOOT: iface})

        iface = self._create_vlan_test("mgmt0",
            constants.INTERFACE_CLASS_PLATFORM,
            [constants.NETWORK_TYPE_MGMT], 100,
            self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT])
        self.test_interfaces.update({constants.NETWORK_TYPE_MGMT: iface})

        iface = self._create_bond_test("cluster0",
            constants.INTERFACE_CLASS_PLATFORM,
            [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_STORAGE])
        self.test_interfaces.update({constants.NETWORK_TYPE_CLUSTER_HOST: iface})

        self._create_service_parameter_test_set()
        self._set_dc_role(constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD)

        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                                '192.168.1.0', 26)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                                '192.168.1.64', 26)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_OAM],
                                '192.168.5.0', 24)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT],
                                '192.168.20.0', 24)

    def _check_gnp_values_mgmt_subcloud(self, gnp):

        ip_version = gnp['spec']['ingress'][0]['ipVersion']

        # ingress rules
        self.assertEqual(gnp['spec']['ingress'][4]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][4]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-subcloud-tcp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][4]['ipVersion'], ip_version)

        tcp_ports = list(firewall.SUBCLOUD["tcp"].keys())
        tcp_ports.append(constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
        tcp_ports.sort()
        self.assertEqual(gnp['spec']['ingress'][4]['destination']['ports'], tcp_ports)
        self.assertEqual(gnp['spec']['ingress'][4]['source']['nets'][0], "192.168.1.0/26")
        self.assertEqual(gnp['spec']['ingress'][4]['source']['nets'][1], "192.168.1.64/26")

        self.assertEqual(gnp['spec']['ingress'][5]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][5]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-subcloud-udp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][5]['ipVersion'], ip_version)

        udp_ports = list(firewall.SUBCLOUD["udp"].keys())
        udp_ports.sort()
        self.assertEqual(gnp['spec']['ingress'][5]['destination']['ports'], udp_ports)
        self.assertEqual(gnp['spec']['ingress'][5]['source']['nets'][0], "192.168.1.0/26")
        self.assertEqual(gnp['spec']['ingress'][5]['source']['nets'][1], "192.168.1.64/26")

        self.assertEqual(gnp['spec']['ingress'][6]['protocol'], "ICMP")
        self.assertEqual(gnp['spec']['ingress'][6]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-subcloud-icmp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][6]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][6]['source']['nets'][0], "192.168.1.0/26")
        self.assertEqual(gnp['spec']['ingress'][6]['source']['nets'][1], "192.168.1.64/26")

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertFalse('platform::firewall::calico::oam::config' in hiera_data.keys())

        self.assertTrue('platform::firewall::calico::admin::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::cluster_host::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::mgmt::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::pxeboot::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::storage::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::hostendpoint::config' in hiera_data.keys())

        # these GNPs are filled
        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=4, ingress_size=5)

        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=3, ingress_size=7)
        self._check_gnp_values_mgmt_subcloud(hiera_data['platform::firewall::calico::mgmt::config'])

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertFalse(hiera_data['platform::firewall::calico::admin::config'])

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 3)

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                              [constants.NETWORK_TYPE_MGMT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_CLUSTER_HOST],
                              [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_STORAGE])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT],
                              [constants.NETWORK_TYPE_PXEBOOT])

        # for now we do NOT handle OAM configuration
        self.assertFalse(f"{self.host.hostname}-oam0-if-hep" in
                         hiera_data['platform::firewall::calico::hostendpoint::config'].keys())


# Worker, non-DC
#   eth0:oam       [oam]
#   eth1:mgmt0     [mgmt]
#   eth2:cluster0  [cluster-host]
#   eth3:pxe0      [pxeboot]
class PlatformFirewallTestCaseWorkerNonDc_Setup01(PlatformFirewallTestCaseMixin,
                                                  dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseWorkerNonDc_Setup01, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(PlatformFirewallTestCaseWorkerNonDc_Setup01, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.

        self.host.save(self.admin_context)
        super(PlatformFirewallTestCaseWorkerNonDc_Setup01, self)._update_context()

    def _setup_configuration(self):
        # Create a single port/interface for basic function testing
        self.host = self._create_test_host(constants.WORKER)

        port, iface = self._create_ethernet_test("mgmt0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_MGMT)
        self.test_interfaces.update({constants.NETWORK_TYPE_MGMT: iface})

        port, iface = self._create_ethernet_test("cluster0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_CLUSTER_HOST)
        self.test_interfaces.update({constants.NETWORK_TYPE_CLUSTER_HOST: iface})

        port, iface = self._create_ethernet_test("pxe0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT)
        self.test_interfaces.update({constants.NETWORK_TYPE_PXEBOOT: iface})

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        # for now we do NOT handle OAM configuration
        self.assertFalse('platform::firewall::calico::oam::config' in hiera_data.keys())

        self.assertTrue('platform::firewall::calico::admin::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::cluster_host::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::mgmt::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::pxeboot::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::storage::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::hostendpoint::config' in hiera_data.keys())

        # these GNPs are empty (not used in the current test database)
        self.assertFalse(hiera_data['platform::firewall::calico::admin::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::storage::config'])

        # these GNPs are filled
        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=4, ingress_size=5)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 3)
        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                              [constants.NETWORK_TYPE_MGMT])
        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_CLUSTER_HOST],
                              [constants.NETWORK_TYPE_CLUSTER_HOST])
        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT],
                              [constants.NETWORK_TYPE_PXEBOOT])

        # for now we do NOT handle OAM configuration
        self.assertFalse(f"{self.host.hostname}-oam0-if-hep" in
                         hiera_data['platform::firewall::calico::hostendpoint::config'].keys())


# Storage, non-DC
#   eth0:oam       [oam]
#   eth1:mgmt0     [mgmt]
#   eth2:storage0  [storage]
#   eth3:pxe0      [pxeboot]
class PlatformFirewallTestCaseStorageNonDc_Setup01(PlatformFirewallTestCaseMixin,
                                                   dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseStorageNonDc_Setup01, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(PlatformFirewallTestCaseStorageNonDc_Setup01, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.

        self.host.save(self.admin_context)
        super(PlatformFirewallTestCaseStorageNonDc_Setup01, self)._update_context()

    def _setup_configuration(self):
        # Create a single port/interface for basic function testing
        self.host = self._create_test_host(constants.STORAGE)

        port, iface = self._create_ethernet_test("mgmt0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_MGMT)
        self.test_interfaces.update({constants.NETWORK_TYPE_MGMT: iface})

        port, iface = self._create_ethernet_test("stor0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_STORAGE)
        self.test_interfaces.update({constants.NETWORK_TYPE_STORAGE: iface})

        port, iface = self._create_ethernet_test("pxe0",
            constants.INTERFACE_CLASS_PLATFORM,
            constants.NETWORK_TYPE_PXEBOOT)
        self.test_interfaces.update({constants.NETWORK_TYPE_PXEBOOT: iface})

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        # for now we do NOT handle OAM configuration
        self.assertFalse('platform::firewall::calico::oam::config' in hiera_data.keys())

        self.assertTrue('platform::firewall::calico::admin::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::cluster_host::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::mgmt::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::pxeboot::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::storage::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::hostendpoint::config' in hiera_data.keys())

        # these GNPs are empty (not used in the current test database)
        # storage nodes do not run kubernetes
        self.assertFalse(hiera_data['platform::firewall::calico::admin::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::cluster_host::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::mgmt::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::storage::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::hostendpoint::config'])
