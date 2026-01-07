# Copyright (c) 2017-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid
import mock
import os
import yaml

from sysinv.tests.puppet import base
from sysinv.puppet import puppet
from sysinv.objects import base as objbase
from sysinv.tests.db import base as dbbase
from sysinv.common import constants
from sysinv.common import platform_firewall as firewall
from sysinv.common import utils as cutils
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

    def _create_test_route(self, interface, network, prefix, gateway='192.168.0.1', proto=4):
        route_db = dbutils.create_test_route(
            interface_id=interface.id,
            family=proto,
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

    def _check_egress_rules(self, filtered_rules, ip_version, net_type, ICMP):

        self.assertEqual(filtered_rules['egress'][0]['protocol'], "TCP")
        self.assertEqual(filtered_rules['egress'][0]['metadata']['annotations']['name'],
                f"stx-egr-{self.host.personality}-{net_type}-tcp{ip_version}")
        self.assertEqual(filtered_rules['egress'][0]['ipVersion'], ip_version)
        self.assertFalse('destination' in filtered_rules['egress'][0].keys())
        self.assertFalse('source' in filtered_rules['egress'][0].keys())

        self.assertEqual(filtered_rules['egress'][1]['protocol'], "UDP")
        self.assertEqual(filtered_rules['egress'][1]['metadata']['annotations']['name'],
                f"stx-egr-{self.host.personality}-{net_type}-udp{ip_version}")
        self.assertEqual(filtered_rules['egress'][1]['ipVersion'], ip_version)
        self.assertFalse('destination' in filtered_rules['egress'][1].keys())
        self.assertFalse('source' in filtered_rules['egress'][1].keys())

        self.assertEqual(filtered_rules['egress'][2]['protocol'], ICMP)
        self.assertEqual(filtered_rules['egress'][2]['metadata']['annotations']['name'],
                f"stx-egr-{self.host.personality}-{net_type}-{ICMP.lower()}{ip_version}")
        self.assertEqual(filtered_rules['egress'][2]['ipVersion'], ip_version)
        self.assertFalse('destination' in filtered_rules['egress'][2].keys())
        self.assertFalse('source' in filtered_rules['egress'][2].keys())

    def _check_tcp_port(self, gnp, port, present=True):
            if (present):
                self.assertIn(port, gnp['spec']['ingress'][0]['destination']['ports'])
            else:
                self.assertNotIn(port, gnp['spec']['ingress'][0]['destination']['ports'])

    def _check_gnp_values(self, gnp, net_type, db_api, egress_size=3, ingress_size=3):

        network = self.context['networks'][net_type]

        cpod_pool_index = {}
        if net_type == constants.NETWORK_TYPE_CLUSTER_HOST:
            cpod_net = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_CLUSTER_POD)
            if cpod_net:
                cpod_pools = self.dbapi.address_pools_get_by_network(cpod_net.id)
                for cpod_pool in cpod_pools:
                    cpod_pool_index[cpod_pool.family] = cpod_pool

        rule_index = {family: {'egress': [], 'ingress': []} for family in [4, 6]}
        for direction in ['egress', 'ingress']:
            for rule in gnp['spec'][direction]:
                rule_index[rule["ipVersion"]][direction].append(rule)

        self.assertEqual(gnp["apiVersion"], "crd.projectcalico.org/v1")
        self.assertEqual(gnp["kind"], "GlobalNetworkPolicy")
        self.assertEqual(gnp['metadata']['name'],
                         f"{self.host.personality}-{net_type}-if-gnp")
        self.assertEqual(gnp['spec']['applyOnForward'], False)
        self.assertEqual(gnp['spec']['order'], 100)

        self.assertEqual(gnp['spec']['types'], ["Ingress", "Egress"])
        self.assertEqual(len(gnp['spec']['egress']), egress_size)
        self.assertEqual(len(gnp['spec']['ingress']), ingress_size)

        nodetype_selector = f"has(nodetype) && nodetype == '{self.host.personality}'"
        iftype_selector = f"has(iftype) && iftype contains '{network.type}'"
        selector = f"{nodetype_selector} && {iftype_selector}"
        if (constants.NETWORK_TYPE_OAM == net_type):
            nodetype_selector = f"(has(nodetype) && nodetype == '{self.host.personality}')"
            notetype_selector = f"(has(notetype) && notetype == '{self.host.personality}')"
            selector = f"({nodetype_selector} || {notetype_selector}) && {iftype_selector}"

        self.assertEqual(gnp['spec']['selector'], selector)

        addr_pools = self.dbapi.address_pools_get_by_network(network.id)
        for addr_pool in addr_pools:
            ip_version = addr_pool.family

            filtered_rules = rule_index[ip_version]

            ICMP = "ICMP"
            if (ip_version == 6):
                ICMP = "ICMPv6"

            # egress rules
            self._check_egress_rules(filtered_rules, ip_version, net_type, ICMP)

            # ingress rules
            self.assertEqual(filtered_rules['ingress'][0]['protocol'], "TCP")
            self.assertEqual(filtered_rules['ingress'][0]['metadata']['annotations']['name'],
                    f"stx-ingr-{self.host.personality}-{net_type}-tcp{ip_version}")
            self.assertEqual(filtered_rules['ingress'][0]['ipVersion'], ip_version)

            self.assertEqual(filtered_rules['ingress'][1]['protocol'], "UDP")
            self.assertEqual(filtered_rules['ingress'][1]['metadata']['annotations']['name'],
                    f"stx-ingr-{self.host.personality}-{net_type}-udp{ip_version}")
            self.assertEqual(filtered_rules['ingress'][1]['ipVersion'], ip_version)

            self.assertEqual(filtered_rules['ingress'][2]['protocol'], ICMP)
            self.assertEqual(filtered_rules['ingress'][2]['metadata']['annotations']['name'],
                    f"stx-ingr-{self.host.personality}-{net_type}-{ICMP.lower()}{ip_version}")
            self.assertEqual(filtered_rules['ingress'][2]['ipVersion'], ip_version)

            if (net_type == constants.NETWORK_TYPE_OAM):
                tcp_ports = set(filtered_rules['ingress'][0]['destination']['ports'])
                udp_ports = set(filtered_rules['ingress'][1]['destination']['ports'])
                for port in firewall.OAM_COMMON["tcp"]:
                    # Not necessary to validate these ports as this is done separately
                    if (port == constants.PLATFORM_FIREWALL_HTTP_PORT or
                            port == constants.PLATFORM_CEPH_PARAMS_RGW_PORT):
                        continue
                    self.assertIn(port, tcp_ports)
                for port in firewall.OAM_COMMON["udp"]:
                    self.assertIn(port, udp_ports)

            else:
                self.assertEqual(filtered_rules['ingress'][0]['source']['nets'][0],
                                 f"{addr_pool.network}/{addr_pool.prefix}")
                self.assertEqual(filtered_rules['ingress'][1]['source']['nets'][0],
                                 f"{addr_pool.network}/{addr_pool.prefix}")
                self.assertEqual(filtered_rules['ingress'][2]['source']['nets'][0],
                                 f"{addr_pool.network}/{addr_pool.prefix}")

            if net_type == constants.NETWORK_TYPE_MGMT:
                self.assertEqual(filtered_rules['ingress'][3]['metadata']['annotations']['name'],
                        f"stx-ingr-{self.host.personality}-mgmt-esp{ip_version}")
                self.assertEqual(filtered_rules['ingress'][3]['protocol'], 50)
                self.assertEqual(filtered_rules['ingress'][3]['ipVersion'], ip_version)

            if (ip_version == 4 and (net_type == constants.NETWORK_TYPE_PXEBOOT
                    or net_type == constants.NETWORK_TYPE_STORAGE)):
                self.assertEqual(filtered_rules['ingress'][3]['metadata']['annotations']['name'],
                        f"stx-ingr-{self.host.personality}-dhcp-udp{ip_version}")
                self.assertEqual(filtered_rules['ingress'][3]['protocol'], "UDP")
                self.assertEqual(filtered_rules['ingress'][3]['ipVersion'], ip_version)
                self.assertEqual(filtered_rules['ingress'][3]['destination']['ports'], [67])

            if (ip_version == 4 and (net_type == constants.NETWORK_TYPE_CLUSTER_HOST)):
                cpod_pool = cpod_pool_index[ip_version]

                self.assertEqual(filtered_rules['ingress'][0]['source']['nets'][1],
                                 f"{cpod_pool.network}/{cpod_pool.prefix}")
                self.assertEqual(filtered_rules['ingress'][1]['source']['nets'][1],
                                 f"{cpod_pool.network}/{cpod_pool.prefix}")
                self.assertEqual(filtered_rules['ingress'][2]['source']['nets'][1],
                                 f"{cpod_pool.network}/{cpod_pool.prefix}")

                # check that ESP rule was added for egress cluster-host in IPv4
                self.assertEqual(filtered_rules['egress'][3]['protocol'], 50)
                self.assertEqual(filtered_rules['egress'][3]['metadata']['annotations']['name'],
                        f"stx-egr-{self.host.personality}-{net_type}-esp{ip_version}")
                self.assertEqual(filtered_rules['egress'][3]['ipVersion'], ip_version)
                self.assertFalse('destination' in filtered_rules['egress'][3].keys())
                self.assertFalse('source' in filtered_rules['egress'][3].keys())

                # check that ESP rule was added for ingress cluster-host in IPv4
                self.assertEqual(filtered_rules['ingress'][3]['protocol'], 50)
                self.assertEqual(filtered_rules['ingress'][3]['metadata']['annotations']['name'],
                        f"stx-ingr-{self.host.personality}-{net_type}-esp{ip_version}")
                self.assertEqual(filtered_rules['ingress'][3]['ipVersion'], ip_version)
                self.assertEqual(filtered_rules['ingress'][3]['source']['nets'][0],
                                 f"{addr_pool.network}/{addr_pool.prefix}")
                self.assertEqual(filtered_rules['ingress'][3]['source']['nets'][1],
                                 f"{cpod_pool.network}/{cpod_pool.prefix}")

                # check that SCTP rule was added for egress cluster-host in IPv4
                self.assertEqual(filtered_rules['egress'][4]['protocol'], "SCTP")
                self.assertEqual(filtered_rules['egress'][4]['metadata']['annotations']['name'],
                        f"stx-egr-{self.host.personality}-{net_type}-sctp{ip_version}")
                self.assertEqual(filtered_rules['egress'][4]['ipVersion'], ip_version)
                self.assertFalse('destination' in filtered_rules['egress'][4].keys())
                self.assertFalse('source' in filtered_rules['egress'][4].keys())

                # check that SCTP rule was added for ingress cluster-host in IPv4
                self.assertEqual(filtered_rules['ingress'][4]['protocol'], "SCTP")
                self.assertEqual(filtered_rules['ingress'][4]['metadata']['annotations']['name'],
                        f"stx-ingr-{self.host.personality}-{net_type}-sctp{ip_version}")
                self.assertEqual(filtered_rules['ingress'][4]['ipVersion'], ip_version)
                self.assertEqual(filtered_rules['ingress'][4]['source']['nets'][0],
                                 f"{addr_pool.network}/{addr_pool.prefix}")
                self.assertEqual(filtered_rules['ingress'][4]['source']['nets'][1],
                                 f"{cpod_pool.network}/{cpod_pool.prefix}")

                self.assertEqual(filtered_rules['ingress'][5]['metadata']['annotations']['name'],
                        f"stx-ingr-{self.host.personality}-dhcp-udp{ip_version}")
                self.assertEqual(filtered_rules['ingress'][5]['protocol'], "UDP")
                self.assertEqual(filtered_rules['ingress'][5]['ipVersion'], ip_version)
                self.assertEqual(filtered_rules['ingress'][5]['destination']['ports'], [67])

            if (ip_version == 6 and (net_type == constants.NETWORK_TYPE_CLUSTER_HOST)):
                cpod_pool = cpod_pool_index[ip_version]

                self.assertEqual(filtered_rules['ingress'][0]['source']['nets'][1],
                                 f"{cpod_pool.network}/{cpod_pool.prefix}")
                self.assertEqual(filtered_rules['ingress'][0]['source']['nets'][2], "fe80::/64")
                self.assertEqual(filtered_rules['ingress'][1]['source']['nets'][1],
                                 f"{cpod_pool.network}/{cpod_pool.prefix}")
                self.assertEqual(filtered_rules['ingress'][1]['source']['nets'][2], "fe80::/64")
                self.assertEqual(filtered_rules['ingress'][2]['source']['nets'][1],
                                 f"{cpod_pool.network}/{cpod_pool.prefix}")
                self.assertEqual(filtered_rules['ingress'][2]['source']['nets'][2], "fe80::/64")

                # check that ESP rule was added for egress cluster-host in IPv6
                self.assertEqual(filtered_rules['egress'][3]['protocol'], 50)
                self.assertEqual(filtered_rules['egress'][3]['metadata']['annotations']['name'],
                        f"stx-egr-{self.host.personality}-{net_type}-esp{ip_version}")
                self.assertEqual(filtered_rules['egress'][3]['ipVersion'], ip_version)
                self.assertFalse('destination' in filtered_rules['egress'][3].keys())
                self.assertFalse('source' in filtered_rules['egress'][3].keys())

                # check that ESP rule was added for ingress cluster-host in IPv6
                self.assertEqual(filtered_rules['ingress'][3]['protocol'], 50)
                self.assertEqual(filtered_rules['ingress'][3]['metadata']['annotations']['name'],
                        f"stx-ingr-{self.host.personality}-{net_type}-esp{ip_version}")
                self.assertEqual(filtered_rules['ingress'][3]['ipVersion'], ip_version)
                self.assertEqual(filtered_rules['ingress'][3]['source']['nets'][0],
                                 f"{addr_pool.network}/{addr_pool.prefix}")
                self.assertEqual(filtered_rules['ingress'][3]['source']['nets'][1],
                                 f"{cpod_pool.network}/{cpod_pool.prefix}")
                self.assertEqual(filtered_rules['ingress'][3]['source']['nets'][2], "fe80::/64")

                # check that SCTP rule was added for egress cluster-host in IPv6
                self.assertEqual(filtered_rules['egress'][4]['protocol'], "SCTP")
                self.assertEqual(filtered_rules['egress'][4]['metadata']['annotations']['name'],
                        f"stx-egr-{self.host.personality}-{net_type}-sctp{ip_version}")
                self.assertEqual(filtered_rules['egress'][4]['ipVersion'], ip_version)
                self.assertFalse('destination' in filtered_rules['egress'][4].keys())
                self.assertFalse('source' in filtered_rules['egress'][4].keys())

                # check that SCTP rule was added for ingress cluster-host in IPv6
                self.assertEqual(filtered_rules['ingress'][4]['protocol'], "SCTP")
                self.assertEqual(filtered_rules['ingress'][4]['metadata']['annotations']['name'],
                        f"stx-ingr-{self.host.personality}-{net_type}-sctp{ip_version}")
                self.assertEqual(filtered_rules['ingress'][4]['ipVersion'], ip_version)
                self.assertEqual(filtered_rules['ingress'][4]['source']['nets'][0],
                                 f"{addr_pool.network}/{addr_pool.prefix}")
                self.assertEqual(filtered_rules['ingress'][4]['source']['nets'][1],
                                 f"{cpod_pool.network}/{cpod_pool.prefix}")
                self.assertEqual(filtered_rules['ingress'][4]['source']['nets'][2], "fe80::/64")

            if (ip_version == 6 and (net_type != constants.NETWORK_TYPE_CLUSTER_HOST)
                    and (net_type != constants.NETWORK_TYPE_OAM)):
                self.assertEqual(filtered_rules['ingress'][0]['source']['nets'][1], "fe80::/64")
                self.assertEqual(filtered_rules['ingress'][1]['source']['nets'][1], "fe80::/64")
                self.assertEqual(filtered_rules['ingress'][2]['source']['nets'][1], "fe80::/64")

    def _check_he_values(self, hep, intf, network_list):

        nodename = self.host.hostname
        ifname = intf.ifname
        os_ifname = puppet_intf.get_interface_os_ifname(self.context, intf)
        network_list.sort()
        iftype = '.'.join(network_list)

        hep_name = f'{nodename}-{ifname}-if-hep'
        if constants.NETWORK_TYPE_OAM in iftype:
            # to keep compatible with current implementation
            hep_name = f'{nodename}-oam-if-hep'
        self.assertTrue(hep_name in hep.keys())

        self.assertEqual(hep[hep_name]["apiVersion"], "crd.projectcalico.org/v1")
        self.assertEqual(hep[hep_name]["kind"], "HostEndpoint")
        self.assertEqual(hep[hep_name]['metadata']['labels']['iftype'], iftype)
        self.assertEqual(hep[hep_name]['metadata']['labels']['nodetype'], self.host.personality)
        self.assertEqual(hep[hep_name]['metadata']['labels']['ifname'], f"{nodename}.{ifname}")
        self.assertEqual(hep[hep_name]['metadata']['name'], hep_name)
        self.assertEqual(hep[hep_name]['spec']['interfaceName'], os_ifname)
        self.assertEqual(hep[hep_name]['spec']['node'], nodename)

    def _check_oam_expected_IPs(self, db_api, hep):
        nodename = self.host.hostname
        hep_name = f'{nodename}-oam-if-hep'
        if cutils.is_aio_simplex_system(db_api):
            addr_name = cutils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                                   constants.NETWORK_TYPE_OAM)
        else:
            addr_name = cutils.format_address_name(nodename, constants.NETWORK_TYPE_OAM)
        addresses = self.dbapi.address_get_by_name(addr_name)
        address_texts = [str(address.address) for address in addresses]
        self.assertTrue(address_texts)
        self.assertEqual(hep[hep_name]["spec"]["expectedIPs"], address_texts)

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

    def _check_gnp_admin_values(self, gnp, net_type, db_api, egress_size=3, ingress_size=3):

        network = self.context['networks'][net_type]

        rule_index = {family: {'egress': [], 'ingress': []} for family in [4, 6]}
        for direction in ['egress', 'ingress']:
            for rule in gnp['spec'][direction]:
                rule_index[rule["ipVersion"]][direction].append(rule)

        nodetype_selector = f"has(nodetype) && nodetype == '{self.host.personality}'"
        iftype_selector = f"has(iftype) && iftype contains '{network.type}'"
        selector = f"{nodetype_selector} && {iftype_selector}"

        self.assertEqual(gnp["apiVersion"], "crd.projectcalico.org/v1")
        self.assertEqual(gnp["kind"], "GlobalNetworkPolicy")
        self.assertEqual(gnp['metadata']['name'], f"{self.host.personality}-{net_type}-if-gnp")
        self.assertEqual(gnp['spec']['applyOnForward'], False)
        self.assertEqual(gnp['spec']['order'], 100)

        self.assertEqual(gnp['spec']['selector'], selector)
        self.assertEqual(gnp['spec']['types'], ["Ingress", "Egress"])
        self.assertEqual(len(gnp['spec']['egress']), egress_size)
        self.assertEqual(len(gnp['spec']['ingress']), ingress_size)

        addr_pools = self.dbapi.address_pools_get_by_network(network.id)
        for addr_pool in addr_pools:
            ip_version = addr_pool.family

            filtered_rules = rule_index[ip_version]

            ICMP = "ICMP"
            if (ip_version == 6):
                ICMP = "ICMPv6"

            # egress rules
            idx = 0
            self.assertEqual(filtered_rules['egress'][idx]['protocol'], "TCP")
            self.assertEqual(filtered_rules['egress'][idx]['metadata']['annotations']['name'],
                    f"stx-egr-{self.host.personality}-{net_type}-tcp{ip_version}")
            self.assertEqual(filtered_rules['egress'][idx]['ipVersion'], ip_version)
            self.assertFalse('destination' in filtered_rules['egress'][idx].keys())
            self.assertFalse('source' in filtered_rules['egress'][idx].keys())

            idx += 1
            self.assertEqual(filtered_rules['egress'][idx]['protocol'], "UDP")
            self.assertEqual(filtered_rules['egress'][idx]['metadata']['annotations']['name'],
                    f"stx-egr-{self.host.personality}-{net_type}-udp{ip_version}")
            self.assertEqual(filtered_rules['egress'][idx]['ipVersion'], ip_version)
            self.assertFalse('destination' in filtered_rules['egress'][idx].keys())
            self.assertFalse('source' in filtered_rules['egress'][idx].keys())

            idx += 1
            self.assertEqual(filtered_rules['egress'][idx]['protocol'], ICMP)
            self.assertEqual(filtered_rules['egress'][idx]['metadata']['annotations']['name'],
                    f"stx-egr-{self.host.personality}-{net_type}-{ICMP.lower()}{ip_version}")
            self.assertEqual(filtered_rules['egress'][idx]['ipVersion'], ip_version)
            self.assertFalse('destination' in filtered_rules['egress'][idx].keys())
            self.assertFalse('source' in filtered_rules['egress'][idx].keys())

            if (ip_version == 4):
                idx += 1
                self.assertEqual(filtered_rules['egress'][idx]['protocol'], 2)
                self.assertEqual(filtered_rules['egress'][idx]['metadata']['annotations']['name'],
                        f"stx-egr-{self.host.personality}-{net_type}-igmp{ip_version}")
                self.assertEqual(filtered_rules['egress'][idx]['ipVersion'], ip_version)
                self.assertFalse('destination' in filtered_rules['egress'][idx].keys())
                self.assertFalse('source' in filtered_rules['egress'][idx].keys())

            # ingress rules
            tcp_ports = list(firewall.SUBCLOUD["tcp"].keys())
            tcp_ports.append(constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
            tcp_ports.sort()
            udp_ports = list(firewall.SUBCLOUD["udp"].keys())
            udp_ports.sort()

            idx = 0
            self.assertEqual(filtered_rules['ingress'][idx]['protocol'], "TCP")
            self.assertEqual(filtered_rules['ingress'][idx]['metadata']['annotations']['name'],
                    f"stx-ingr-{self.host.personality}-admin-tcp{ip_version}")
            self.assertEqual(filtered_rules['ingress'][idx]['ipVersion'], ip_version)

            idx += 1
            self.assertEqual(filtered_rules['ingress'][idx]['protocol'], "UDP")
            self.assertEqual(filtered_rules['ingress'][idx]['metadata']['annotations']['name'],
                    f"stx-ingr-{self.host.personality}-admin-udp{ip_version}")
            self.assertEqual(filtered_rules['ingress'][idx]['ipVersion'], ip_version)

            idx += 1
            self.assertEqual(filtered_rules['ingress'][idx]['protocol'], ICMP)
            self.assertEqual(filtered_rules['ingress'][idx]['metadata']['annotations']['name'],
                    f"stx-ingr-{self.host.personality}-admin-{ICMP.lower()}{ip_version}")
            self.assertEqual(filtered_rules['ingress'][idx]['ipVersion'], ip_version)

            if (ip_version == 4):
                idx += 1
                self.assertEqual(filtered_rules['ingress'][idx]['protocol'], 2)
                self.assertEqual(filtered_rules['ingress'][idx]['metadata']['annotations']['name'],
                        f"stx-ingr-{self.host.personality}-admin-igmp{ip_version}")
                self.assertEqual(filtered_rules['ingress'][idx]['ipVersion'], ip_version)

            idx += 1
            self.assertEqual(filtered_rules['ingress'][idx]['protocol'], "TCP")
            self.assertEqual(filtered_rules['ingress'][idx]['metadata']['annotations']['name'],
                    f"stx-ingr-{self.host.personality}-subcloud-tcp{ip_version}")
            self.assertEqual(filtered_rules['ingress'][idx]['ipVersion'], ip_version)
            self.assertEqual(filtered_rules['ingress'][idx]['destination']['ports'], tcp_ports)

            idx += 1
            self.assertEqual(filtered_rules['ingress'][idx]['protocol'], "UDP")
            self.assertEqual(filtered_rules['ingress'][idx]['metadata']['annotations']['name'],
                    f"stx-ingr-{self.host.personality}-subcloud-udp{ip_version}")
            self.assertEqual(filtered_rules['ingress'][idx]['ipVersion'], ip_version)
            self.assertEqual(filtered_rules['ingress'][idx]['destination']['ports'], udp_ports)

            idx += 1
            self.assertEqual(filtered_rules['ingress'][idx]['protocol'], ICMP)
            self.assertEqual(filtered_rules['ingress'][idx]['metadata']['annotations']['name'],
                    f"stx-ingr-{self.host.personality}-subcloud-{ICMP.lower()}{ip_version}")
            self.assertEqual(filtered_rules['ingress'][idx]['ipVersion'], ip_version)

    def _check_gnset_values(self, gnset, net_type, subnet_list):
        self.assertEqual(gnset['apiVersion'], "crd.projectcalico.org/v1")
        self.assertEqual(gnset['kind'], "GlobalNetworkSet")
        self.assertEqual(gnset['metadata']['name'], f"stx-trusted-{net_type}-subnets-gns")
        self.assertEqual(gnset['metadata']['labels']['subnets'], f"trusted-{net_type}-subnets")
        self.assertEqual(gnset['spec']['nets'], subnet_list)


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

        self._create_service_parameter_test_set()

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertTrue('platform::firewall::calico::oam::config' in hiera_data.keys())
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
                               egress_size=5, ingress_size=6)

        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=6, ingress_size=7)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::oam::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::oam::config'],
                               constants.NETWORK_TYPE_OAM, self.dbapi,
                               egress_size=3, ingress_size=3)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 4)
        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                              [constants.NETWORK_TYPE_MGMT])
        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_CLUSTER_HOST],
                              [constants.NETWORK_TYPE_CLUSTER_HOST])
        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT],
                              [constants.NETWORK_TYPE_PXEBOOT])
        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_OAM],
                              [constants.NETWORK_TYPE_OAM])
        self._check_oam_expected_IPs(self.dbapi,
                                     hiera_data['platform::firewall::calico::hostendpoint::config'])


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

        self._create_service_parameter_test_set()

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertTrue('platform::firewall::calico::oam::config' in hiera_data.keys())
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
                               egress_size=5, ingress_size=6)

        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=6, ingress_size=7)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::oam::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::oam::config'],
                               constants.NETWORK_TYPE_OAM, self.dbapi,
                               egress_size=3, ingress_size=3)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 3)
        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                              [constants.NETWORK_TYPE_MGMT,
                               constants.NETWORK_TYPE_CLUSTER_HOST,
                               constants.NETWORK_TYPE_PXEBOOT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_STORAGE],
                              [constants.NETWORK_TYPE_STORAGE])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_OAM],
                              [constants.NETWORK_TYPE_OAM])


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

        self._create_service_parameter_test_set()

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertTrue('platform::firewall::calico::admin::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::cluster_host::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::mgmt::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::pxeboot::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::storage::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::hostendpoint::config' in hiera_data.keys())

        self.assertTrue(hiera_data['platform::firewall::calico::oam::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::oam::config'],
                               constants.NETWORK_TYPE_OAM, self.dbapi,
                               egress_size=3, ingress_size=3)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)

        # do not install firewall if the network is assigned to the loopback
        self.assertFalse(hiera_data['platform::firewall::calico::admin::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::cluster_host::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::mgmt::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::pxeboot::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::storage::config'])

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 1)
        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_OAM],
                              [constants.NETWORK_TYPE_OAM])


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

        self._create_service_parameter_test_set()

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

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
                               egress_size=5, ingress_size=6)

        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=6, ingress_size=7)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::oam::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::oam::config'],
                               constants.NETWORK_TYPE_OAM, self.dbapi,
                               egress_size=3, ingress_size=3)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)

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
                              [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_STORAGE])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_OAM],
                              [constants.NETWORK_TYPE_OAM])


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
        p = mock.patch('sysinv.common.utils.is_aio_simplex_system')
        self.mock_utils_is_aio_simplex_system = p.start()
        self.mock_utils_is_aio_simplex_system.return_value = True
        self.addCleanup(p.stop)
        p = mock.patch('sysinv.puppet.platform_firewall._is_ceph_enabled')
        self.mock_platform_firewall_is_ceph_enabled = p.start()
        self.mock_platform_firewall_is_ceph_enabled.return_value = True
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

        self._create_service_parameter_test_set()

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

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
                               egress_size=5, ingress_size=6)

        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=6, ingress_size=7)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::oam::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::oam::config'],
                               constants.NETWORK_TYPE_OAM, self.dbapi,
                               egress_size=3, ingress_size=3)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.PLATFORM_CEPH_PARAMS_RGW_PORT)

        self.assertFalse(hiera_data['platform::firewall::calico::storage::config'])

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 2)

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                              [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST,
                               constants.NETWORK_TYPE_PXEBOOT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_OAM],
                              [constants.NETWORK_TYPE_OAM])
        self._check_oam_expected_IPs(self.dbapi,
                                     hiera_data['platform::firewall::calico::hostendpoint::config'])


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

        self._create_service_parameter_test_set()

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertTrue('platform::firewall::calico::oam::config' in hiera_data.keys())
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
                               egress_size=4, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=5, ingress_size=5)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=3, ingress_size=3)

        self.assertTrue(hiera_data['platform::firewall::calico::oam::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::oam::config'],
                               constants.NETWORK_TYPE_OAM, self.dbapi,
                               egress_size=3, ingress_size=3)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 5)
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

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_OAM],
                              [constants.NETWORK_TYPE_OAM])


# Controller, non-DC, Dual Stack primary IPv4
#   eth0:              oam
#   eth1:              pxeboot
#   vlan100@eth1:      mgmt
#   vlan101@eth1:      cluster-host
#   bond0@[eth2,eth3]: storage
class PlatformFirewallTestCaseControllerNonDc_Setup07(PlatformFirewallTestCaseMixin,
                                                    dbbase.BaseDualStackPrimaryIPv4Mixin,
                                                    dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseControllerNonDc_Setup07, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(PlatformFirewallTestCaseControllerNonDc_Setup07, self).setUp()
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
        super(PlatformFirewallTestCaseControllerNonDc_Setup07, self)._update_context()

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

        self._create_service_parameter_test_set()

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertTrue('platform::firewall::calico::oam::config' in hiera_data.keys())
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
                               egress_size=9, ingress_size=10)

        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=11, ingress_size=12)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=6, ingress_size=7)

        self.assertTrue(hiera_data['platform::firewall::calico::oam::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::oam::config'],
                               constants.NETWORK_TYPE_OAM, self.dbapi,
                               egress_size=6, ingress_size=6)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 5)
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

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_OAM],
                              [constants.NETWORK_TYPE_OAM])


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

    def _check_gnp_admin_source_nets(self, gnp):

        idx = 0  # admin network, TCP
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][0], "10.10.30.0/24")

        idx = 1  # admin network, UDP
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][0], "10.10.30.0/24")

        idx = 2  # admin network, ICMP
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "ICMP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][0], "10.10.30.0/24")

        idx = 3  # admin network, IGMP
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], 2)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][0], "0.0.0.0/0")

        idx = 4  # admin routes, TCP
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-admin-subnets'")

        idx = 5  # admin routes, UDP
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-admin-subnets'")

        idx = 6  # admin routes, ICMP
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "ICMP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-admin-subnets'")

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)
        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertTrue('platform::firewall::calico::oam::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::admin::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::cluster_host::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::mgmt::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::pxeboot::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::storage::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::hostendpoint::config' in hiera_data.keys())
        self.assertTrue("platform::firewall::calico::gnset::admin::config" in hiera_data.keys())
        self.assertTrue("platform::firewall::calico::gnset::mgmt::config" in hiera_data.keys())

        # these GNPs are filled
        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=6, ingress_size=7)

        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=5, ingress_size=6)

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
                               constants.NETWORK_TYPE_ADMIN, self.dbapi,
                               egress_size=4, ingress_size=7)
        self._check_gnp_admin_source_nets(hiera_data['platform::firewall::calico::admin::config'])

        self.assertTrue(hiera_data['platform::firewall::calico::oam::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::oam::config'],
                               constants.NETWORK_TYPE_OAM, self.dbapi,
                               egress_size=3, ingress_size=3)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT, False)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 5)

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

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_OAM],
                              [constants.NETWORK_TYPE_OAM])

        # check GlobalNetworkSet
        self.assertTrue(hiera_data['platform::firewall::calico::gnset::admin::config'])
        self._check_gnset_values(hiera_data['platform::firewall::calico::gnset::admin::config'],
                                 constants.NETWORK_TYPE_ADMIN,
                                 ['192.168.3.0/24', '192.168.4.0/24'])

        self.assertFalse(hiera_data['platform::firewall::calico::gnset::mgmt::config'])


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

        # ingress rules
        idx = 6
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-systemcontroller-tcp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")

        tcp_ports = list(firewall.SYSTEMCONTROLLER["tcp"].keys())
        tcp_ports.append(constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
        tcp_ports.sort()
        self.assertEqual(gnp['spec']['ingress'][idx]['destination']['ports'], tcp_ports)

        idx += 1
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-systemcontroller-udp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")

        udp_ports = list(firewall.SYSTEMCONTROLLER["udp"].keys())
        udp_ports.sort()
        self.assertEqual(gnp['spec']['ingress'][idx]['destination']['ports'], udp_ports)

        idx += 1
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "ICMP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-systemcontroller-icmp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertTrue('platform::firewall::calico::oam::config' in hiera_data.keys())
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
                               egress_size=6, ingress_size=7)

        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=5, ingress_size=9)
        self._check_gnp_values_mgmt_sysctrl(hiera_data['platform::firewall::calico::mgmt::config'])

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::oam::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::oam::config'],
                               constants.NETWORK_TYPE_OAM, self.dbapi)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.PLATFORM_DCMANAGER_PARAMS_API_PORT)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.PLATFORM_DCORCH_PARAMS_SYSINV_API_PROXY_PORT)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.PLATFORM_DCORCH_PARAMS_USM_API_PROXY_PORT)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.PLATFORM_DCORCH_PARAMS_IDENTITY_API_PROXY_PORT)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 4)

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[0][constants.NETWORK_TYPE_MGMT],
                              [constants.NETWORK_TYPE_MGMT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[0][constants.NETWORK_TYPE_CLUSTER_HOST],
                              [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_STORAGE])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[0][constants.NETWORK_TYPE_PXEBOOT],
                              [constants.NETWORK_TYPE_PXEBOOT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[0][constants.NETWORK_TYPE_OAM],
                              [constants.NETWORK_TYPE_OAM])

        # check GlobalNetworkSet
        self.assertTrue(hiera_data['platform::firewall::calico::gnset::mgmt::config'])
        self._check_gnset_values(hiera_data['platform::firewall::calico::gnset::mgmt::config'],
                                 constants.NETWORK_TYPE_MGMT,
                                 ['192.168.1.0/26', '192.168.1.128/26', '192.168.1.64/26'])

        self.assertFalse(hiera_data['platform::firewall::calico::gnset::admin::config'])


# Controller, DC, SystemController
#   eth0:              oam
#   eth1:              pxeboot
#   bond0@[eth2,eth3]: cluster-host.storage
class PlatformFirewallTestCaseControllerDcSysCtrl_Setup02(PlatformFirewallTestCaseMixin,
                                                          dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseControllerDcSysCtrl_Setup02, self).__init__(*args, **kwargs)
        self.test_interfaces = []
        self.hosts = []

    def setUp(self):
        super(PlatformFirewallTestCaseControllerDcSysCtrl_Setup02, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.
        for host in self.hosts:
            host.save(self.admin_context)
        super(PlatformFirewallTestCaseControllerDcSysCtrl_Setup02, self)._update_context()

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

        # Non-management routes
        self._create_test_route(self.test_interfaces[0][constants.NETWORK_TYPE_OAM],
                                '192.168.5.0', 24)
        self._create_test_route(self.test_interfaces[0][constants.NETWORK_TYPE_PXEBOOT],
                                '192.168.20.0', 24)

        # Controller-1

        # Non-management routes
        self._create_test_route(self.test_interfaces[1][constants.NETWORK_TYPE_OAM],
                                '192.168.5.0', 24)
        self._create_test_route(self.test_interfaces[1][constants.NETWORK_TYPE_PXEBOOT],
                                '192.168.20.0', 24)

        # Worker
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

        # ingress rules
        idx = 5
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-systemcontroller-tcp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")

        tcp_ports = list(firewall.SYSTEMCONTROLLER["tcp"].keys())
        tcp_ports.append(constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
        tcp_ports.sort()
        self.assertEqual(gnp['spec']['ingress'][idx]['destination']['ports'], tcp_ports)

        idx += 1
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-systemcontroller-udp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")

        udp_ports = list(firewall.SYSTEMCONTROLLER["udp"].keys())
        udp_ports.sort()
        self.assertEqual(gnp['spec']['ingress'][idx]['destination']['ports'], udp_ports)

        idx += 1
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "ICMP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-systemcontroller-icmp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertTrue('platform::firewall::calico::oam::config' in hiera_data.keys())
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
                               egress_size=6, ingress_size=7)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::oam::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::oam::config'],
                               constants.NETWORK_TYPE_OAM, self.dbapi)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.PLATFORM_DCMANAGER_PARAMS_API_PORT)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.PLATFORM_DCORCH_PARAMS_SYSINV_API_PROXY_PORT)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.PLATFORM_DCORCH_PARAMS_IDENTITY_API_PROXY_PORT)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 3)

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[0][constants.NETWORK_TYPE_CLUSTER_HOST],
                              [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_STORAGE])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[0][constants.NETWORK_TYPE_PXEBOOT],
                              [constants.NETWORK_TYPE_PXEBOOT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[0][constants.NETWORK_TYPE_OAM],
                              [constants.NETWORK_TYPE_OAM])

        # check GlobalNetworkSet
        self.assertFalse(hiera_data['platform::firewall::calico::gnset::mgmt::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::gnset::admin::config'])


# Controller, DC, SystemController
#   eth0:              oam
#   eth1:              pxeboot
#   vlan100@eth1:      mgmt
#   bond0@[eth2,eth3]: cluster-host.storage
class PlatformFirewallTestCaseControllerDcSysCtrl_Setup03(PlatformFirewallTestCaseMixin,
                                                          dbbase.BaseDualStackPrimaryIPv4Mixin,
                                                          dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseControllerDcSysCtrl_Setup03, self).__init__(*args, **kwargs)
        self.test_interfaces = []
        self.hosts = []

    def setUp(self):
        super(PlatformFirewallTestCaseControllerDcSysCtrl_Setup03, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.
        for host in self.hosts:
            host.save(self.admin_context)
        super(PlatformFirewallTestCaseControllerDcSysCtrl_Setup03, self)._update_context()

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

        # Common management routes in controller-0 and controller-1
        self._create_test_route(self.test_interfaces[0][constants.NETWORK_TYPE_MGMT],
                                '192.168.1.0', 26)
        self._create_test_route(self.test_interfaces[0][constants.NETWORK_TYPE_MGMT],
                                'dead:beef::0', 64, 'dead:beef::1', 6)

        # Management routes exclusive to controller-0
        self._create_test_route(self.test_interfaces[0][constants.NETWORK_TYPE_MGMT],
                                '192.168.1.64', 26)
        self._create_test_route(self.test_interfaces[0][constants.NETWORK_TYPE_MGMT],
                                'c0ca:c01a::0', 64, 'c0ca:c01a::1', 6)

        # Non-management routes
        self._create_test_route(self.test_interfaces[0][constants.NETWORK_TYPE_OAM],
                                '192.168.5.0', 24)
        self._create_test_route(self.test_interfaces[0][constants.NETWORK_TYPE_OAM],
                                '3001::0', 64, '3001::1', 6)
        self._create_test_route(self.test_interfaces[0][constants.NETWORK_TYPE_PXEBOOT],
                                '192.168.20.0', 24)
        self._create_test_route(self.test_interfaces[0][constants.NETWORK_TYPE_PXEBOOT],
                                '4001::0', 64, '4001::1', 6)

        # Controller-1

        # Common management routes in controller-0 and controller-1
        self._create_test_route(self.test_interfaces[1][constants.NETWORK_TYPE_MGMT],
                                '192.168.1.0', 26)
        self._create_test_route(self.test_interfaces[1][constants.NETWORK_TYPE_MGMT],
                                'dead:beef::0', 64, 'dead:beef::1', 6)

        # Management route exclusive to controller-1
        self._create_test_route(self.test_interfaces[1][constants.NETWORK_TYPE_MGMT],
                                '192.168.1.128', 26)
        self._create_test_route(self.test_interfaces[1][constants.NETWORK_TYPE_MGMT],
                                'c0ca:c02a::0', 64, 'c0ca:c02a::1', 6)

        # Non-management routes
        self._create_test_route(self.test_interfaces[1][constants.NETWORK_TYPE_OAM],
                                '192.168.5.0', 24)
        self._create_test_route(self.test_interfaces[1][constants.NETWORK_TYPE_OAM],
                                '3002::0', 64, '3002::1', 6)
        self._create_test_route(self.test_interfaces[1][constants.NETWORK_TYPE_PXEBOOT],
                                '192.168.20.0', 24)
        self._create_test_route(self.test_interfaces[1][constants.NETWORK_TYPE_PXEBOOT],
                                '4002::0', 64, '4002::1', 6)

        # Worker
        self._create_test_route(self.test_interfaces[2][constants.NETWORK_TYPE_MGMT],
                                '192.168.1.192', 26)
        self._create_test_route(self.test_interfaces[2][constants.NETWORK_TYPE_MGMT],
                                'c0ca:c03a::0', 64, 'c0ca:c03a::1', 6)
        self._create_test_route(self.test_interfaces[2][constants.NETWORK_TYPE_CLUSTER_HOST],
                                '192.168.6.0', 24)
        self._create_test_route(self.test_interfaces[2][constants.NETWORK_TYPE_CLUSTER_HOST],
                                'c0ca:c04a::0', 64, 'c0ca:c04a::1', 6)
        self._create_test_route(self.test_interfaces[2][constants.NETWORK_TYPE_PXEBOOT],
                                '192.168.30.0', 24)
        self._create_test_route(self.test_interfaces[2][constants.NETWORK_TYPE_PXEBOOT],
                                '4003::0', 64, '4003::1', 6)

    def _setup_configuration(self):

        self._setup_controller(0)
        self._setup_controller(1)

        self._setup_worker()

        self.host = self.hosts[0]

        self._setup_routes()

        self._create_service_parameter_test_set()
        self._set_dc_role(constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER)

    def _check_gnp_values_mgmt_sysctrl(self, gnp):

        tcp_ports = list(firewall.SYSTEMCONTROLLER["tcp"].keys())
        tcp_ports.append(constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
        tcp_ports.sort()

        udp_ports = list(firewall.SYSTEMCONTROLLER["udp"].keys())
        udp_ports.sort()

        # ingress rules
        idx = 10
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-systemcontroller-tcp4")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], 4)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")
        self.assertEqual(gnp['spec']['ingress'][idx]['destination']['ports'], tcp_ports)

        idx += 1
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-systemcontroller-udp4")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], 4)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")
        self.assertEqual(gnp['spec']['ingress'][idx]['destination']['ports'], udp_ports)

        idx += 1
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "ICMP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-systemcontroller-icmp4")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], 4)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")

        idx += 1
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-systemcontroller-tcp6")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], 6)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")
        self.assertEqual(gnp['spec']['ingress'][idx]['destination']['ports'], tcp_ports)

        idx += 1
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-systemcontroller-udp6")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], 6)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")
        self.assertEqual(gnp['spec']['ingress'][idx]['destination']['ports'], udp_ports)

        idx += 1
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "ICMPv6")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-systemcontroller-icmpv66")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], 6)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        print(config_filename)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertTrue('platform::firewall::calico::oam::config' in hiera_data.keys())
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
                               egress_size=11, ingress_size=12)

        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=9, ingress_size=16)
        self._check_gnp_values_mgmt_sysctrl(hiera_data['platform::firewall::calico::mgmt::config'])

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=6, ingress_size=7)

        self.assertTrue(hiera_data['platform::firewall::calico::oam::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::oam::config'],
                               constants.NETWORK_TYPE_OAM, self.dbapi,
                               egress_size=6, ingress_size=6)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.PLATFORM_DCMANAGER_PARAMS_API_PORT)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.PLATFORM_DCORCH_PARAMS_SYSINV_API_PROXY_PORT)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.PLATFORM_DCORCH_PARAMS_USM_API_PROXY_PORT)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.PLATFORM_DCORCH_PARAMS_IDENTITY_API_PROXY_PORT)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 4)

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[0][constants.NETWORK_TYPE_MGMT],
                              [constants.NETWORK_TYPE_MGMT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[0][constants.NETWORK_TYPE_CLUSTER_HOST],
                              [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_STORAGE])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[0][constants.NETWORK_TYPE_PXEBOOT],
                              [constants.NETWORK_TYPE_PXEBOOT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[0][constants.NETWORK_TYPE_OAM],
                              [constants.NETWORK_TYPE_OAM])

        # check GlobalNetworkSet
        self.assertTrue(hiera_data['platform::firewall::calico::gnset::mgmt::config'])
        self._check_gnset_values(hiera_data['platform::firewall::calico::gnset::mgmt::config'],
                                 constants.NETWORK_TYPE_MGMT,
                                 ['192.168.1.0/26', '192.168.1.128/26', '192.168.1.64/26',
                                  'c0ca:c01a::/64', 'c0ca:c02a::/64', 'dead:beef::/64'])

        self.assertFalse(hiera_data['platform::firewall::calico::gnset::admin::config'])


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
        idx = 6
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-subcloud-tcp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], ip_version)

        tcp_ports = list(firewall.SUBCLOUD["tcp"].keys())
        tcp_ports.append(constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
        tcp_ports.sort()
        self.assertEqual(gnp['spec']['ingress'][idx]['destination']['ports'], tcp_ports)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")

        idx += 1
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-subcloud-udp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], ip_version)

        udp_ports = list(firewall.SUBCLOUD["udp"].keys())
        udp_ports.sort()
        self.assertEqual(gnp['spec']['ingress'][idx]['destination']['ports'], udp_ports)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")

        idx += 1
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "ICMP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-subcloud-icmp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertTrue('platform::firewall::calico::oam::config' in hiera_data.keys())
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
                               egress_size=6, ingress_size=7)

        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=5, ingress_size=9)
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

        self.assertTrue(hiera_data['platform::firewall::calico::oam::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::oam::config'],
                               constants.NETWORK_TYPE_OAM, self.dbapi)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT, False)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 4)

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                              [constants.NETWORK_TYPE_MGMT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_CLUSTER_HOST],
                              [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_STORAGE])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT],
                              [constants.NETWORK_TYPE_PXEBOOT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_OAM],
                              [constants.NETWORK_TYPE_OAM])

        # check GlobalNetworkSet
        self.assertTrue(hiera_data['platform::firewall::calico::gnset::mgmt::config'])
        self._check_gnset_values(hiera_data['platform::firewall::calico::gnset::mgmt::config'],
                                 constants.NETWORK_TYPE_MGMT,
                                 ['192.168.1.0/26', '192.168.1.64/26'])

        self.assertFalse(hiera_data['platform::firewall::calico::gnset::admin::config'])


# Controller, DC, Subcloud, IPv6
#   eth0:              oam
#   eth1:              pxeboot
#   vlan100@eth1:      mgmt
#   vlan101@eth1:      admin
#   bond0@[eth2,eth3]: cluster-host.storage
class PlatformFirewallTestCaseControllerDcSubcloud_Setup03(PlatformFirewallTestCaseMixin,
                                                           dbbase.BaseIPv6Mixin,
                                                           dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseControllerDcSubcloud_Setup03, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(PlatformFirewallTestCaseControllerDcSubcloud_Setup03, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.
        self.host.save(self.admin_context)
        super(PlatformFirewallTestCaseControllerDcSubcloud_Setup03, self)._update_context()

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
                                'dead:beef::0', 64, 'dead:beef::1', 6)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                                'c0ca:c01a::0', 64, 'c0ca:c01a::1', 6)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_ADMIN],
                                'baba:baba::0', 64, 'baba:baba::1', 6)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_ADMIN],
                                '2001::0', 64, '2001::1', 6)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_OAM],
                                '3001::0', 64, '3001::1', 6)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT],
                                '4001::0', 64, '4001::1', 6)

    def _check_gnp_admin_source_nets(self, gnp):

        idx = 0  # admin and link-local networks, TCP
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][0], "fd09::/64")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][1], "fe80::/64")

        idx = 1  # admin and link-local networks, UDP
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][0], "fd09::/64")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][1], "fe80::/64")

        idx = 2  # admin and link-local networks, ICMPv6
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "ICMPv6")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][0], "fd09::/64")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][1], "fe80::/64")

        idx = 3  # admin routes, TCP
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-admin-subnets'")

        idx = 4  # admin routes, UDP
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-admin-subnets'")

        idx = 5  # admin routes, ICMPv6
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "ICMPv6")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-admin-subnets'")

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertTrue('platform::firewall::calico::oam::config' in hiera_data.keys())
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
                               egress_size=5, ingress_size=5)

        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=4, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=3, ingress_size=3)

        self.assertTrue(hiera_data['platform::firewall::calico::admin::config'])
        self._check_gnp_admin_values(hiera_data['platform::firewall::calico::admin::config'],
                               constants.NETWORK_TYPE_ADMIN, self.dbapi, egress_size=3,
                               ingress_size=6)
        self._check_gnp_admin_source_nets(hiera_data['platform::firewall::calico::admin::config'])

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 5)

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

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_OAM],
                              [constants.NETWORK_TYPE_OAM])

        # check GlobalNetworkSet
        self.assertTrue(hiera_data['platform::firewall::calico::gnset::admin::config'])
        self._check_gnset_values(hiera_data['platform::firewall::calico::gnset::admin::config'],
                                 constants.NETWORK_TYPE_ADMIN,
                                 ['2001::/64', 'baba:baba::/64'])

        self.assertFalse(hiera_data['platform::firewall::calico::gnset::mgmt::config'])


# AIO-DX, Controller, DC, Subcloud
#   eth0:              oam
#   eth1:              pxeboot
#   bond0@[eth2,eth3]: cluster-host.storage
class PlatformFirewallTestCaseControllerDcSubcloud_Setup04(PlatformFirewallTestCaseMixin,
                                                           dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseControllerDcSubcloud_Setup04, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(PlatformFirewallTestCaseControllerDcSubcloud_Setup04, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.
        self.host.save(self.admin_context)
        super(PlatformFirewallTestCaseControllerDcSubcloud_Setup04, self)._update_context()

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

        iface = self._create_bond_test("cluster0",
            constants.INTERFACE_CLASS_PLATFORM,
            [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_STORAGE])
        self.test_interfaces.update({constants.NETWORK_TYPE_CLUSTER_HOST: iface})

        self._create_service_parameter_test_set()
        self._set_dc_role(constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD)

        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_OAM],
                                '192.168.5.0', 24)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT],
                                '192.168.20.0', 24)

    def _check_gnp_values_mgmt_subcloud(self, gnp):

        ip_version = gnp['spec']['ingress'][0]['ipVersion']

        # ingress rules
        idx = 5
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-subcloud-tcp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], ip_version)

        tcp_ports = list(firewall.SUBCLOUD["tcp"].keys())
        tcp_ports.append(constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
        tcp_ports.sort()
        self.assertEqual(gnp['spec']['ingress'][idx]['destination']['ports'], tcp_ports)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")

        idx += 1
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-subcloud-udp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], ip_version)

        udp_ports = list(firewall.SUBCLOUD["udp"].keys())
        udp_ports.sort()
        self.assertEqual(gnp['spec']['ingress'][idx]['destination']['ports'], udp_ports)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")

        idx += 1
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "ICMP")
        self.assertEqual(gnp['spec']['ingress'][idx]['metadata']['annotations']['name'],
                f"stx-ingr-{self.host.personality}-subcloud-icmp{ip_version}")
        self.assertEqual(gnp['spec']['ingress'][idx]['ipVersion'], ip_version)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-mgmt-subnets'")

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertTrue('platform::firewall::calico::oam::config' in hiera_data.keys())
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
                               egress_size=6, ingress_size=7)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertFalse(hiera_data['platform::firewall::calico::admin::config'])

        self.assertTrue(hiera_data['platform::firewall::calico::oam::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::oam::config'],
                               constants.NETWORK_TYPE_OAM, self.dbapi)
        self._check_tcp_port(hiera_data['platform::firewall::calico::oam::config'],
                             constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT, False)

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 3)

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_CLUSTER_HOST],
                              [constants.NETWORK_TYPE_CLUSTER_HOST, constants.NETWORK_TYPE_STORAGE])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT],
                              [constants.NETWORK_TYPE_PXEBOOT])

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_OAM],
                              [constants.NETWORK_TYPE_OAM])

        # check GlobalNetworkSet
        self.assertFalse(hiera_data['platform::firewall::calico::gnset::admin::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::gnset::mgmt::config'])


# Controller, DC, Subcloud, Dual Stack primary IPv6
#   eth0:              oam
#   eth1:              pxeboot
#   vlan100@eth1:      mgmt
#   vlan101@eth1:      admin
#   bond0@[eth2,eth3]: cluster-host.storage
class PlatformFirewallTestCaseControllerDcSubcloud_Setup05(PlatformFirewallTestCaseMixin,
                                                           dbbase.BaseDualStackPrimaryIPv6Mixin,
                                                           dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseControllerDcSubcloud_Setup05, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(PlatformFirewallTestCaseControllerDcSubcloud_Setup05, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.
        self.host.save(self.admin_context)
        super(PlatformFirewallTestCaseControllerDcSubcloud_Setup05, self)._update_context()

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
                                'dead:beef::0', 64, 'dead:beef::1', 6)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_MGMT],
                                'c0ca:c01a::0', 64, 'c0ca:c01a::1', 6)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_ADMIN],
                                'baba:baba::0', 64, 'baba:baba::1', 6)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_ADMIN],
                                '2001::0', 64, '2001::1', 6)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_OAM],
                                '3001::0', 64, '3001::1', 6)
        self._create_test_route(self.test_interfaces[constants.NETWORK_TYPE_PXEBOOT],
                                '4001::0', 64, '4001::1', 6)

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

    def _check_gnp_admin_source_nets(self, gnp):

        idx = 0  # admin and link-local networks, TCP IPv6
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][0], "fd09::/64")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][1], "fe80::/64")

        idx += 1  # admin and link-local networks, UDP IPv6
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][0], "fd09::/64")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][1], "fe80::/64")

        idx += 1  # admin and link-local networks, ICMPv6 IPv6
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "ICMPv6")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][0], "fd09::/64")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][1], "fe80::/64")

        idx += 1  # admin network, TCP IPv4
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][0], "10.10.30.0/24")

        idx += 1  # admin network, UDP IPv4
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][0], "10.10.30.0/24")

        idx += 1  # admin network, ICMP IPv4
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "ICMP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][0], "10.10.30.0/24")

        idx += 1  # admin network, IGMP IPv4
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], 2)
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['nets'][0], "0.0.0.0/0")

        idx += 1  # admin routes, TCP IPv6
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-admin-subnets'")

        idx += 1  # admin routes, UDP IPv6
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-admin-subnets'")

        idx += 1  # admin routes, ICMPv6 IPv6
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "ICMPv6")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-admin-subnets'")

        idx += 1  # admin routes, TCP IPv4
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "TCP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-admin-subnets'")

        idx += 1  # admin routes, UDP IPv4
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "UDP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-admin-subnets'")

        idx += 1  # admin routes, ICMP IPv4
        self.assertEqual(gnp['spec']['ingress'][idx]['protocol'], "ICMP")
        self.assertEqual(gnp['spec']['ingress'][idx]['source']['selector'],
                         "subnets == 'trusted-admin-subnets'")

    def test_generate_firewall_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_host_config(self.host)  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertTrue('platform::firewall::calico::oam::config' in hiera_data.keys())
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
                               egress_size=11, ingress_size=12)

        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=9, ingress_size=10)

        self.assertTrue(hiera_data['platform::firewall::calico::pxeboot::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::pxeboot::config'],
                               constants.NETWORK_TYPE_PXEBOOT, self.dbapi,
                               egress_size=3, ingress_size=4)

        self.assertTrue(hiera_data['platform::firewall::calico::storage::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::storage::config'],
                               constants.NETWORK_TYPE_STORAGE, self.dbapi,
                               egress_size=6, ingress_size=7)

        self.assertTrue(hiera_data['platform::firewall::calico::admin::config'])
        self._check_gnp_admin_values(hiera_data['platform::firewall::calico::admin::config'],
                               constants.NETWORK_TYPE_ADMIN, self.dbapi, egress_size=7,
                               ingress_size=13)
        self._check_gnp_admin_source_nets(hiera_data['platform::firewall::calico::admin::config'])

        # the HE is filled
        self.assertTrue(hiera_data['platform::firewall::calico::hostendpoint::config'])
        self.assertEqual(len(hiera_data['platform::firewall::calico::hostendpoint::config']), 5)

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

        self._check_he_values(hiera_data['platform::firewall::calico::hostendpoint::config'],
                              self.test_interfaces[constants.NETWORK_TYPE_OAM],
                              [constants.NETWORK_TYPE_OAM])
        # check GlobalNetworkSet
        self.assertTrue(hiera_data['platform::firewall::calico::gnset::admin::config'])
        self._check_gnset_values(hiera_data['platform::firewall::calico::gnset::admin::config'],
                                 constants.NETWORK_TYPE_ADMIN,
                                 ['2001::/64', 'baba:baba::/64',
                                  '192.168.3.0/24', '192.168.4.0/24'])

        self.assertFalse(hiera_data['platform::firewall::calico::gnset::mgmt::config'])


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

        self.assertTrue('platform::firewall::calico::oam::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::admin::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::cluster_host::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::mgmt::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::pxeboot::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::storage::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::hostendpoint::config' in hiera_data.keys())

        # these GNPs are empty (not used in the current test database)
        self.assertFalse(hiera_data['platform::firewall::calico::admin::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::storage::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::oam::config'])

        # these GNPs are filled
        self.assertTrue(hiera_data['platform::firewall::calico::mgmt::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::mgmt::config'],
                               constants.NETWORK_TYPE_MGMT, self.dbapi,
                               egress_size=5, ingress_size=6)

        self.assertTrue(hiera_data['platform::firewall::calico::cluster_host::config'])
        self._check_gnp_values(hiera_data['platform::firewall::calico::cluster_host::config'],
                               constants.NETWORK_TYPE_CLUSTER_HOST, self.dbapi,
                               egress_size=6, ingress_size=7)

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
        self.assertTrue('platform::firewall::calico::oam::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::admin::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::cluster_host::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::mgmt::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::pxeboot::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::storage::config' in hiera_data.keys())
        self.assertTrue('platform::firewall::calico::hostendpoint::config' in hiera_data.keys())

        # these GNPs are empty (not used in the current test database)
        # storage nodes do not run kubernetes
        self.assertFalse(hiera_data['platform::firewall::calico::oam::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::admin::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::cluster_host::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::mgmt::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::storage::config'])
        self.assertFalse(hiera_data['platform::firewall::calico::hostendpoint::config'])


class PlatformFirewallTestCaseSystemConfig(PlatformFirewallTestCaseMixin,
                                                      dbbase.BaseHostTestCase):

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallTestCaseSystemConfig, self).__init__(*args, **kwargs)
        self.test_interfaces = dict()

    def setUp(self):
        super(PlatformFirewallTestCaseSystemConfig, self).setUp()
        self.dbapi = db_api.get_instance()
        self._setup_context()

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.

        self.host.save(self.admin_context)
        super(PlatformFirewallTestCaseSystemConfig, self)._update_context()

    def _setup_configuration(self):
        self.host = self._create_test_host(constants.CONTROLLER)

    def test_generate_system_config(self):
        hieradata_directory = self._create_hieradata_directory()
        config_filename = self._get_config_filename(hieradata_directory)
        with open(config_filename, 'w') as config_file:
            config = self.operator.platform_firewall.get_system_config()  # pylint: disable=no-member
            yaml.dump(config, config_file, default_flow_style=False)

        hiera_data = dict()
        with open(config_filename, 'r') as config_file:
            hiera_data = yaml.safe_load(config_file)

        self.assertEqual(len(hiera_data), 14)
        self.assertEqual(hiera_data["openstack::barbican::params::api_port"],
                         constants.OPENSTACK_BARBICAN_PARAMS_API_PORT)
        self.assertEqual(hiera_data["openstack::keystone::params::api_port"],
                         constants.OPENSTACK_KEYSTONE_PARAMS_API_PORT)
        self.assertEqual(hiera_data["platform::ceph::params::rgw_port"],
                         constants.PLATFORM_CEPH_PARAMS_RGW_PORT)
        self.assertEqual(hiera_data["platform::dcmanager::params::api_port"],
                         constants.PLATFORM_DCMANAGER_PARAMS_API_PORT)
        self.assertEqual(hiera_data["platform::dcorch::params::identity_api_proxy_port"],
                         constants.PLATFORM_DCORCH_PARAMS_IDENTITY_API_PROXY_PORT)
        self.assertEqual(hiera_data["platform::dcorch::params::usm_api_proxy_port"],
                         constants.PLATFORM_DCORCH_PARAMS_USM_API_PROXY_PORT)
        self.assertEqual(hiera_data["platform::dcorch::params::sysinv_api_proxy_port"],
                         constants.PLATFORM_DCORCH_PARAMS_SYSINV_API_PROXY_PORT)
        self.assertEqual(hiera_data["platform::docker::params::registry_port"],
                         constants.PLATFORM_DOCKER_PARAMS_REGISTRY_PORT)
        self.assertEqual(hiera_data["platform::docker::params::token_port"],
                         constants.PLATFORM_DOCKER_PARAMS_TOKEN_PORT)
        self.assertEqual(hiera_data["platform::fm::params::api_port"],
                         constants.PLATFORM_FM_PARAMS_API_PORT)
        self.assertEqual(hiera_data["platform::nfv::params::api_port"],
                         constants.PLATFORM_NFV_PARAMS_API_PORT)
        self.assertEqual(hiera_data["platform::patching::params::public_port"],
                         constants.PLATFORM_PATCHING_PARAMS_PUBLIC_PORT)
        self.assertEqual(hiera_data["platform::sysinv::params::api_port"],
                         constants.PLATFORM_SYSINV_PARAMS_API_PORT)
        self.assertEqual(hiera_data["platform::usm::params::public_port"],
                         constants.PLATFORM_USM_PARAMS_PUBLIC_PORT)
