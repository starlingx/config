
# Copyright (c) 2017-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy

from netaddr import IPAddress
from oslo_log import log
from sysinv.common import constants
from sysinv.common import platform_firewall as firewall
from sysinv.puppet import base
from sysinv.puppet import interface as puppet_intf

LOG = log.getLogger(__name__)

FIREWALL_GNP_MGMT_CFG = 'platform::firewall::calico::mgmt::config'
FIREWALL_GNP_CLUSTER_HOST_CFG = 'platform::firewall::calico::cluster_host::config'
FIREWALL_GNP_PXEBOOT_CFG = 'platform::firewall::calico::pxeboot::config'
FIREWALL_GNP_STORAGE_CFG = 'platform::firewall::calico::storage::config'
FIREWALL_GNP_ADMIN_CFG = 'platform::firewall::calico::admin::config'
FIREWALL_HE_INTERFACE_CFG = 'platform::firewall::calico::hostendpoint::config'

PLATFORM_FIREWALL_CLASSES = {constants.NETWORK_TYPE_PXEBOOT: FIREWALL_GNP_PXEBOOT_CFG,
                             constants.NETWORK_TYPE_MGMT: FIREWALL_GNP_MGMT_CFG,
                             constants.NETWORK_TYPE_CLUSTER_HOST: FIREWALL_GNP_CLUSTER_HOST_CFG,
                             constants.NETWORK_TYPE_STORAGE: FIREWALL_GNP_STORAGE_CFG,
                             constants.NETWORK_TYPE_ADMIN: FIREWALL_GNP_ADMIN_CFG}


class PlatformFirewallPuppet(base.BasePuppet):
    """ This class handles the platform firewall hiera data generation for puppet
    """

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallPuppet, self).__init__(*args, **kwargs)

    def get_host_config(self, host):
        """ Plugin public method

        :param host: a sysinv.object.host class object

        return: a dict containing the hiera data information
        """

        config = {
            FIREWALL_HE_INTERFACE_CFG: {},
            FIREWALL_GNP_MGMT_CFG: {},
            FIREWALL_GNP_PXEBOOT_CFG: {},
            FIREWALL_GNP_CLUSTER_HOST_CFG: {},
            FIREWALL_GNP_STORAGE_CFG: {},
            FIREWALL_GNP_ADMIN_CFG: {}
        }

        dc_role = _get_dc_role(self.dbapi)

        if (host.personality == constants.STORAGE):
            LOG.info("Do not add calico firewall to storage nodes (they do not run k8s)")
            return config

        firewall_networks = set()
        intf_ep = dict()
        for ifname in self.context['interfaces'].keys():
            intf = self.context['interfaces'][ifname]
            if (intf.ifclass == constants.INTERFACE_CLASS_PLATFORM
                    and intf.iftype != constants.INTERFACE_TYPE_VIRTUAL
                    and intf.iftype != constants.INTERFACE_TYPE_VF):
                intf_networks = self.dbapi.interface_network_get_by_interface(intf.id)
                iftype_lbl = list()
                for intf_network in intf_networks:
                    network = self.dbapi.network_get(intf_network.network_uuid)
                    if (network.type == constants.NETWORK_TYPE_OAM):
                        continue
                    if network.pool_uuid:
                        iftype_lbl.append(network.type)
                        firewall_networks.add(network)
                        intf_ep[intf.uuid] = [intf, ""]
                iftype_lbl.sort()
                if (intf.uuid in intf_ep.keys()):
                    intf_ep[intf.uuid][1] = '.'.join(iftype_lbl)

        # since we selected the networks that will receive firewall in the interface_network DB,
        # when the pxeboot is not present we need to allow the pxeboot firewall in the management
        # interface, if the mgmt is an ethernet device.
        is_pxeboot_present = [network.type for network in firewall_networks
                              if network.type == constants.NETWORK_TYPE_PXEBOOT]
        is_mgmt_present = [network.type for network in firewall_networks
                            if network.type == constants.NETWORK_TYPE_MGMT]
        if not is_pxeboot_present and is_mgmt_present:
            # first add the pxeboot label in the management interface, if ethernet
            for intf_uuid in intf_ep.keys():
                if constants.NETWORK_TYPE_MGMT in intf_ep[intf_uuid][1]:
                    intf = intf_ep[intf_uuid][0]
                    iftype = intf_ep[intf_uuid][1]
                    if intf.iftype == constants.INTERFACE_TYPE_ETHERNET:
                        intf_ep[intf_uuid][1] = iftype + "." + constants.NETWORK_TYPE_PXEBOOT
            # second, add the pxeboot network object to the list of firewalls
            pxe_net = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_PXEBOOT)
            firewall_networks.add(pxe_net)

        if (firewall_networks):
            self._get_hostendpoints(host, intf_ep, config[FIREWALL_HE_INTERFACE_CFG])

            self._get_basic_firewall_gnp(host, firewall_networks, config)
            networks = {network.type: network for network in firewall_networks}

            if (config[FIREWALL_GNP_MGMT_CFG]):
                self._set_rules_mgmt(config[FIREWALL_GNP_MGMT_CFG],
                                    networks[constants.NETWORK_TYPE_MGMT], host)

            if (config[FIREWALL_GNP_CLUSTER_HOST_CFG]):
                self._set_rules_cluster_host(config[FIREWALL_GNP_CLUSTER_HOST_CFG],
                                    networks[constants.NETWORK_TYPE_CLUSTER_HOST], host)

            if (config[FIREWALL_GNP_PXEBOOT_CFG]):
                self._set_rules_pxeboot(config[FIREWALL_GNP_PXEBOOT_CFG],
                                    networks[constants.NETWORK_TYPE_PXEBOOT], host)

            if (config[FIREWALL_GNP_STORAGE_CFG]):
                self._set_rules_storage(config[FIREWALL_GNP_STORAGE_CFG],
                                    networks[constants.NETWORK_TYPE_STORAGE], host)

            if (host.personality == constants.CONTROLLER):
                if (dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
                    if (config[FIREWALL_GNP_ADMIN_CFG]):
                        self._set_rules_subcloud_admin(config[FIREWALL_GNP_ADMIN_CFG],
                                                    networks[constants.NETWORK_TYPE_ADMIN],
                                                    host.personality)
                    else:
                        self._set_rules_subcloud_mgmt(config[FIREWALL_GNP_MGMT_CFG],
                                                    networks[constants.NETWORK_TYPE_MGMT],
                                                    host.personality)

                elif (dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
                    self._set_rules_systemcontroller(config[FIREWALL_GNP_MGMT_CFG],
                                                    networks[constants.NETWORK_TYPE_MGMT],
                                                    host.personality)

        return config

    def _get_hostendpoints(self, host, intf_ep, config):
        """ Fill the HostEndpoint hiera data

        :param host: a sysinv.object.host class object
        :param intf_ep: a dict with key as interface uuid and value with a list with the
                        sysinv.object.interface object and the string to be used in the ifname
                        label
        :param config: the dict containing the hiera data to be filled
        """

        for uuid in intf_ep.keys():

            intf = intf_ep[uuid][0]
            iftype = intf_ep[uuid][1]

            host_endpoints = dict()
            hep_name = host.hostname + "-" + intf.ifname + "-if-hep"

            host_endpoints["apiVersion"] = "crd.projectcalico.org/v1"
            host_endpoints["kind"] = "HostEndpoint"
            host_endpoints.update({"metadata": dict()})
            host_endpoints["metadata"].update({"name": hep_name})
            host_endpoints["metadata"].update({"labels": dict()})
            host_endpoints["metadata"]["labels"].update({"nodetype": host.personality})
            host_endpoints["metadata"]["labels"].update({"ifname":
                                                        f"{host.hostname}.{intf.ifname}"})
            host_endpoints["metadata"]["labels"].update({"iftype": iftype})

            host_endpoints.update({"spec": dict()})
            host_endpoints["spec"].update({"node": host.hostname})
            # host_endpoints["spec"].update({"expectedIPs": list()})
            interfaceName = puppet_intf.get_interface_os_ifname(self.context, intf)
            host_endpoints["spec"].update({"interfaceName": interfaceName})
            config[hep_name] = copy.copy(host_endpoints)

    def _get_basic_firewall_gnp(self, host, firewall_networks, config):
        """ Fill the GlobalNetworkPolicy basic hiera data (no filter rules)

        :param host: a sysinv.object.host class object
        :param firewall_networks: a set containing the platform networks that will require a
                                  firewall to be configured.
        :param config: the dict containing the hiera data to be filled
        """

        for network in firewall_networks:
            if (network.type == constants.NETWORK_TYPE_OAM):
                continue

            gnp_name = host.personality + "-" + network.type + "-if-gnp"
            addr_pool = self.dbapi.address_pool_get(network.pool_uuid)
            ip_version = IPAddress(f"{addr_pool.network}").version
            nodetype_selector = f"has(nodetype) && nodetype == '{host.personality}'"
            iftype_selector = f"has(iftype) && iftype contains '{network.type}'"
            selector = f"{nodetype_selector} && {iftype_selector}"
            ICMP = "ICMP"
            if (ip_version == 6):
                ICMP = "ICMPv6"

            firewall_gnp = dict()
            firewall_gnp["apiVersion"] = "crd.projectcalico.org/v1"
            firewall_gnp["kind"] = "GlobalNetworkPolicy"
            firewall_gnp["metadata"] = {"name": gnp_name}

            firewall_gnp["spec"] = dict()
            firewall_gnp["spec"].update({"applyOnForward": True})
            firewall_gnp["spec"].update({"order": 100})
            firewall_gnp["spec"].update({"selector": selector})
            firewall_gnp["spec"].update({"types": ["Ingress", "Egress"]})
            firewall_gnp["spec"].update({"egress": list()})

            for proto in ["TCP", "UDP", ICMP]:
                rule = {"metadata": dict()}
                rule["metadata"] = {"annotations": dict()}
                rule["metadata"]["annotations"] = {"name":
                    f"stx-egr-{host.personality}-{network.type}-{proto.lower()}{ip_version}"}
                rule.update({"protocol": proto})
                rule.update({"ipVersion": ip_version})
                rule.update({"action": "Allow"})
                firewall_gnp["spec"]["egress"].append(rule)

            firewall_gnp["spec"].update({"ingress": list()})
            for proto in ["TCP", "UDP", ICMP]:
                rule = {"metadata": dict()}
                rule["metadata"] = {"annotations": dict()}
                rule["metadata"]["annotations"] = {"name":
                    f"stx-ingr-{host.personality}-{network.type}-{proto.lower()}{ip_version}"}
                rule.update({"protocol": proto})
                rule.update({"ipVersion": ip_version})
                rule.update({"action": "Allow"})
                firewall_gnp["spec"]["ingress"].append(rule)
            config[PLATFORM_FIREWALL_CLASSES[network.type]] = copy.copy(firewall_gnp)

    def _set_rules_mgmt(self, gnp_config, network, host):
        """ Fill the management network specific filtering data

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        """
        addr_pool = self.dbapi.address_pool_get(network.pool_uuid)
        ip_version = IPAddress(f"{addr_pool.network}").version
        self._add_source_net_filter(gnp_config["spec"]["ingress"],
                                    f"{addr_pool.network}/{addr_pool.prefix}")
        if (ip_version == 6):
            self._add_source_net_filter(gnp_config["spec"]["ingress"], "fe80::/64")
        if (ip_version == 4):
            # add rule to allow DHCP requests (dhcp-offer have src addr == 0.0.0.0)
            # worker/storage nodes request IP dynamically
            rule = self._get_dhcp_rule(host.personality, "UDP", ip_version)
            gnp_config["spec"]["ingress"].append(rule)

    def _set_rules_cluster_host(self, gnp_config, network, host):
        """ Fill the cluster-host network specific filtering data

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        """

        addr_pool = self.dbapi.address_pool_get(network.pool_uuid)
        ip_version = IPAddress(f"{addr_pool.network}").version
        self._add_source_net_filter(gnp_config["spec"]["ingress"],
                                    f"{addr_pool.network}/{addr_pool.prefix}")

        # add cluster-pod to cover the cases where there is no tunneling, the pod traffic goes
        # directly in the cluster-host interface
        cpod_net = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_CLUSTER_POD)
        if cpod_net:
            cpod_pool = self.dbapi.address_pool_get(cpod_net.pool_uuid)
            cpod_ip_version = IPAddress(f"{cpod_pool.network}").version
            if (cpod_ip_version == ip_version):
                self._add_source_net_filter(gnp_config["spec"]["ingress"],
                                            f"{cpod_pool.network}/{cpod_pool.prefix}")
        else:
            LOG.info("Cannot find cluster-pod network to add to cluster-host firewall")

        # copy the TCP rule and do the same for SCTP
        sctp_egr_rule = copy.deepcopy(gnp_config["spec"]["egress"][0])
        sctp_egr_rule["protocol"] = "SCTP"
        sctp_egr_rule["metadata"]["annotations"]["name"] = \
            f"stx-egr-{host.personality}-{network.type}-sctp{ip_version}"
        gnp_config["spec"]["egress"].append(sctp_egr_rule)
        sctp_ingr_rule = copy.deepcopy(gnp_config["spec"]["ingress"][0])
        sctp_ingr_rule["protocol"] = "SCTP"
        sctp_ingr_rule["metadata"]["annotations"]["name"] = \
            f"stx-ingr-{host.personality}-{network.type}-sctp{ip_version}"
        gnp_config["spec"]["ingress"].append(sctp_ingr_rule)

        if (ip_version == 6):
            # add link-local network too
            self._add_source_net_filter(gnp_config["spec"]["ingress"], "fe80::/64")

        if (ip_version == 4):
            # add rule to allow DHCP requests (dhcp-offer have src addr == 0.0.0.0)
            rule = self._get_dhcp_rule(host.personality, "UDP", ip_version)
            gnp_config["spec"]["ingress"].append(rule)

    def _set_rules_pxeboot(self, gnp_config, network, host):
        """ Fill the pxeboot network specific filtering data

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        """

        addr_pool = self.dbapi.address_pool_get(network.pool_uuid)
        ip_version = IPAddress(f"{addr_pool.network}").version
        self._add_source_net_filter(gnp_config["spec"]["ingress"],
                                    f"{addr_pool.network}/{addr_pool.prefix}")
        if (ip_version == 6):
            self._add_source_net_filter(gnp_config["spec"]["ingress"], "fe80::/64")
        if (ip_version == 4):
            # add rule to allow DHCP requests (dhcp-offer have src addr == 0.0.0.0)
            rule = self._get_dhcp_rule(host.personality, "UDP", ip_version)
            gnp_config["spec"]["ingress"].append(rule)

    def _set_rules_storage(self, gnp_config, network, host):
        """ Fill the storage network specific filtering data

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        """

        addr_pool = self.dbapi.address_pool_get(network.pool_uuid)
        ip_version = IPAddress(f"{addr_pool.network}").version
        self._add_source_net_filter(gnp_config["spec"]["ingress"],
                                    f"{addr_pool.network}/{addr_pool.prefix}")
        if (ip_version == 6):
            self._add_source_net_filter(gnp_config["spec"]["ingress"], "fe80::/64")
        if (ip_version == 4):
            # add rule to allow DHCP requests (dhcp-offer have src addr == 0.0.0.0)
            rule = self._get_dhcp_rule(host.personality, "UDP", ip_version)
            gnp_config["spec"]["ingress"].append(rule)

    def _add_source_net_filter(self, rule_list, source_net):
        """ Add source network in the rule list

        :param rule_list: the list containing the firewall rules that need to receive the source
                          network value
        :param source_net: the string containing the value
        """
        for rule in rule_list:
            if ("source" in rule.keys()):
                if ("nets" in rule["source"].keys()):
                    rule["source"]["nets"].append(source_net)
                else:
                    rule["source"].update({"nets": [source_net]})
            else:
                rule.update({"source": {"nets": [source_net]}})

    def _set_rules_subcloud_admin(self, gnp_config, network, host_personality):
        """ Add filtering rules for admin network in a subcloud installation

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        :param host_personality: the node personality (controller, storage, or worker)
        """

        # the admin network is a special case that is not needed for internal cluster communication,
        # only for communication with the System Controller
        gnp_config["spec"]["ingress"].clear()

        addr_pool = self.dbapi.address_pool_get(network.pool_uuid)
        ip_version = IPAddress(f"{addr_pool.network}").version
        ICMP = "ICMP"
        if ip_version == 6:
            ICMP = "ICMPv6"

        rules = list()
        for proto in ["TCP", "UDP", ICMP]:
            rule = {"metadata": dict()}
            rule["metadata"] = {"annotations": dict()}
            rule["metadata"]["annotations"] = {"name":
                f"stx-ingr-{host_personality}-subcloud-{proto.lower()}{ip_version}"}
            rule.update({"protocol": proto})
            rule.update({"ipVersion": ip_version})
            rule.update({"action": "Allow"})
            if (proto == "TCP"):
                rule.update({"destination": {"ports": self._get_subcloud_tcp_ports()}})
            elif (proto == "UDP"):
                rule.update({"destination": {"ports": self._get_subcloud_udp_ports()}})
            gnp_config["spec"]["ingress"].append(rule)
            rules.append(rule)

        networks = self._get_routes_networks(network.type)
        for network in networks:
            self._add_source_net_filter(rules, network)

    def _set_rules_subcloud_mgmt(self, gnp_config, network, host_personality):
        """ Add filtering rules for mgmt network in a subcloud installation

        If the subcloud keeps using the mgmt network to communicate with the system controller
        we add the L4 port filtering into this GNP

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        :param host_personality: the node personality (controller, storage, or worker)
        """

        addr_pool = self.dbapi.address_pool_get(network.pool_uuid)
        ip_version = IPAddress(f"{addr_pool.network}").version
        ICMP = "ICMP"
        if ip_version == 6:
            ICMP = "ICMPv6"

        rules = list()
        for proto in ["TCP", "UDP", ICMP]:
            rule = {"metadata": dict()}
            rule["metadata"] = {"annotations": dict()}
            rule["metadata"]["annotations"] = {"name":
                f"stx-ingr-{host_personality}-subcloud-{proto.lower()}{ip_version}"}
            rule.update({"protocol": proto})
            rule.update({"ipVersion": ip_version})
            rule.update({"action": "Allow"})
            if (proto == "TCP"):
                rule.update({"destination": {"ports": self._get_subcloud_tcp_ports()}})
            elif (proto == "UDP"):
                rule.update({"destination": {"ports": self._get_subcloud_udp_ports()}})
            gnp_config["spec"]["ingress"].append(rule)
            rules.append(rule)

        networks = self._get_routes_networks(network.type)
        for network in networks:
            self._add_source_net_filter(rules, network)

    def _get_routes_networks(self, network_type):
        routes = self.dbapi.routes_get_by_network_type_and_host_personality(
                network_type, constants.CONTROLLER)
        networks = set()
        for route in routes:
            network = route.network + '/' + str(route.prefix)
            networks.add(network)
        networks = list(networks)
        networks.sort()
        return networks

    def _set_rules_systemcontroller(self, gnp_config, network, host_personality):
        """ Add filtering rules for mgmt network in a system controller installation

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        :param host_personality: the node personality (controller, storage, or worker)
        """

        rules = []
        addr_pool = self.dbapi.address_pool_get(network.pool_uuid)
        ip_version = IPAddress(f"{addr_pool.network}").version
        ICMP = "ICMP"
        if ip_version == 6:
            ICMP = "ICMPv6"

        for proto in ["TCP", "UDP", ICMP]:
            rule = {"metadata": dict()}
            rule["metadata"] = {"annotations": dict()}
            rule["metadata"]["annotations"] = {"name":
                f"stx-ingr-{host_personality}-systemcontroller-{proto.lower()}{ip_version}"}
            rule.update({"protocol": proto})
            rule.update({"ipVersion": ip_version})
            rule.update({"action": "Allow"})
            if (proto == "TCP"):
                tcp_list = self._get_systemcontroller_tcp_ports()
                rule.update({"destination": {"ports": tcp_list}})
            elif (proto == "UDP"):
                udp_list = self._get_systemcontroller_udp_ports()
                rule.update({"destination": {"ports": udp_list}})
            gnp_config["spec"]["ingress"].append(rule)
            rules.append(rule)

        networks = self._get_routes_networks(network.type)
        for network in networks:
            self._add_source_net_filter(rules, network)

    def _get_subcloud_tcp_ports(self):
        """ Get the TCP L4 ports for subclouds
        """
        port_list = list(firewall.SUBCLOUD["tcp"].keys())
        port_list.append(self._get_http_service_port())
        port_list.sort()
        return port_list

    def _get_subcloud_udp_ports(self):
        """ Get the UDP L4 ports for subclouds
        """
        port_list = list(firewall.SUBCLOUD["udp"].keys())
        port_list.sort()
        return port_list

    def _get_systemcontroller_tcp_ports(self):
        """ Get the TCP L4 ports for systemcontroller
        """
        port_list = list(firewall.SYSTEMCONTROLLER["tcp"].keys())
        port_list.append(self._get_http_service_port())
        port_list.sort()
        return port_list

    def _get_systemcontroller_udp_ports(self):
        """ Get the UDP L4 ports for systemcontroller
        """
        port_list = list(firewall.SYSTEMCONTROLLER["udp"].keys())
        port_list.sort()
        return port_list

    def _get_http_service_port(self):
        """ Get the HTTP port from the service-parameter database
        """
        tcp_port = 0
        if _is_https_enabled(self.dbapi):
            https_port = self.dbapi.service_parameter_get_one(service="http",
                                                              section="config",
                                                              name="https_port")
            tcp_port = int(https_port.value)
        else:
            http_port = self.dbapi.service_parameter_get_one(service="http",
                                                             section="config",
                                                             name="http_port")
            tcp_port = int(http_port.value)
        return tcp_port

    def _get_dhcp_rule(self, personality, proto, ip_version):
        rule = {"metadata": dict()}
        rule["metadata"] = {"annotations": dict()}
        rule["metadata"]["annotations"] = {"name":
            f"stx-ingr-{personality}-dhcp-{proto.lower()}{ip_version}"}
        rule.update({"protocol": proto})
        rule.update({"ipVersion": ip_version})
        rule.update({"action": "Allow"})
        rule.update({"destination": {"ports": [67]}})
        return rule


def _get_dc_role(dbapi):
    """ Get the DC role from the i_system database
    """
    if dbapi is None:
        return None
    system = dbapi.isystem_get_one()
    system_dc_role = system.get('distributed_cloud_role', None)
    return system_dc_role


def _is_https_enabled(dbapi):
    """ Get the HTTPS enabled from the i_system database
    """
    if dbapi is None:
        return False
    system = dbapi.isystem_get_one()
    return system.capabilities.get('https_enabled', False)
