
# Copyright (c) 2017-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy

from oslo_log import log
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import platform_firewall as firewall
from sysinv.common.storage_backend_conf import StorageBackendConfig
from sysinv.common import utils as cutils
from sysinv.puppet import base
from sysinv.puppet import interface as puppet_intf

LOG = log.getLogger(__name__)

FIREWALL_GNP_MGMT_CFG = 'platform::firewall::calico::mgmt::config'
FIREWALL_GNP_CLUSTER_HOST_CFG = 'platform::firewall::calico::cluster_host::config'
FIREWALL_GNP_PXEBOOT_CFG = 'platform::firewall::calico::pxeboot::config'
FIREWALL_GNP_STORAGE_CFG = 'platform::firewall::calico::storage::config'
FIREWALL_GNP_ADMIN_CFG = 'platform::firewall::calico::admin::config'
FIREWALL_HE_INTERFACE_CFG = 'platform::firewall::calico::hostendpoint::config'
FIREWALL_GNP_OAM_CFG = 'platform::firewall::calico::oam::config'
FIREWALL_EXTRA_FILTER_CFG = 'platform::firewall::extra::config'

PLATFORM_FIREWALL_CLASSES = {constants.NETWORK_TYPE_PXEBOOT: FIREWALL_GNP_PXEBOOT_CFG,
                             constants.NETWORK_TYPE_MGMT: FIREWALL_GNP_MGMT_CFG,
                             constants.NETWORK_TYPE_CLUSTER_HOST: FIREWALL_GNP_CLUSTER_HOST_CFG,
                             constants.NETWORK_TYPE_STORAGE: FIREWALL_GNP_STORAGE_CFG,
                             constants.NETWORK_TYPE_ADMIN: FIREWALL_GNP_ADMIN_CFG,
                             constants.NETWORK_TYPE_OAM: FIREWALL_GNP_OAM_CFG}

LINK_LOCAL = "fe80::/64"
LINK_LOCAL_MC = "ff02::/16"

IPSEC_NETWORKS = [constants.NETWORK_TYPE_MGMT]


class PlatformFirewallPuppet(base.BasePuppet):
    """ This class handles the platform firewall hiera data generation for puppet
    """

    def __init__(self, *args, **kwargs):
        super(PlatformFirewallPuppet, self).__init__(*args, **kwargs)

    def get_system_config(self):
        return firewall.SYSTEM_CONFIG

    def _address_pools_get_by_network(self, network_id):
        # NOTE(BQian) might need to optimize network_addrpool_get_all if needed
        network_addrpools = self.dbapi.network_addrpool_get_all()
        pool_ids = [o.address_pool_id for o in network_addrpools if o.network_id == network_id]

        address_pools = self.dbapi.address_pools_get_all_lite()
        addr_pools = [o for o in address_pools if o.id in pool_ids]
        return addr_pools

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
            FIREWALL_GNP_ADMIN_CFG: {},
            FIREWALL_GNP_OAM_CFG: {},
            FIREWALL_EXTRA_FILTER_CFG: {}
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
                    if (network.type == constants.NETWORK_TYPE_OAM and network.pool_uuid
                            and host.personality == constants.CONTROLLER):
                        iftype_lbl.append(network.type)
                        firewall_networks.add(network)
                        intf_ep[intf.uuid] = [intf, ""]
                    elif network.pool_uuid:
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
                    # add to the untagged interfaces
                    if (intf.iftype == constants.INTERFACE_TYPE_ETHERNET) \
                            or (intf.iftype == constants.INTERFACE_TYPE_AE):
                        intf_ep[intf_uuid][1] = iftype + "." + constants.NETWORK_TYPE_PXEBOOT
            # second, add the pxeboot network object to the list of firewalls
            pxe_net = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_PXEBOOT)
            firewall_networks.add(pxe_net)

        if (firewall_networks):
            self._get_hostendpoints(host, intf_ep, config[FIREWALL_HE_INTERFACE_CFG])

            self._get_basic_firewall_gnp(host, firewall_networks, config)
            networks = {network.type: network for network in firewall_networks}

            if (config[FIREWALL_GNP_OAM_CFG]):
                self._set_rules_oam(config[FIREWALL_GNP_OAM_CFG],
                                    networks[constants.NETWORK_TYPE_OAM], host, dc_role)

            if (config[FIREWALL_GNP_MGMT_CFG]):
                self._set_rules_mgmt(config[FIREWALL_GNP_MGMT_CFG],
                                    networks[constants.NETWORK_TYPE_MGMT], host)

            if (config[FIREWALL_GNP_ADMIN_CFG]):
                self._set_rules_admin(config[FIREWALL_GNP_ADMIN_CFG],
                                      networks[constants.NETWORK_TYPE_ADMIN], host)

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
                    if config[FIREWALL_GNP_ADMIN_CFG]:
                        self._set_rules_subcloud_admin(config[FIREWALL_GNP_ADMIN_CFG],
                                                    networks[constants.NETWORK_TYPE_ADMIN],
                                                    host.personality)
                    elif config[FIREWALL_GNP_MGMT_CFG]:
                        self._set_rules_subcloud_mgmt(config[FIREWALL_GNP_MGMT_CFG],
                                                    networks[constants.NETWORK_TYPE_MGMT],
                                                    host.personality)

                elif (dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER and
                        config[FIREWALL_GNP_MGMT_CFG]):
                    self._set_rules_systemcontroller(config[FIREWALL_GNP_MGMT_CFG],
                                                    networks[constants.NETWORK_TYPE_MGMT],
                                                    host.personality)

        self._set_extra_rules(config)
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
            interfaceName = puppet_intf.get_interface_os_ifname(self.context, intf)
            host_endpoints["spec"].update({"interfaceName": interfaceName})

            # adding only for OAM for compatibility with old implementation
            if constants.NETWORK_TYPE_OAM in iftype:
                hep_name = host.hostname + "-oam-if-hep"
                host_endpoints["metadata"]["name"] = hep_name
                self._add_hep_expected_ip(host, constants.NETWORK_TYPE_OAM, host_endpoints)

            config[hep_name] = copy.copy(host_endpoints)

    def _add_gnp_proto_rules(self, host, network, ip_version, firewall_gnp, proto_name,
            proto_id=None):
        """ Add rules for the specified protocol in the GlobalNetworkPolicy hiera data

        :param host: a sysinv.object.host class object
        :param network: the network to which the rule will be added
        :param ip_version: the IP version
        :param firewall_gnp: the dict containing the hiera data of the specified network
        :param proto_name: the name of the protocol for the label
        :param proto_id: the number of the protocol
        """

        if proto_id is None:
            proto_id = proto_name

        for direction, label in {"egress": "egr", "ingress": "ingr"}.items():
            rule = {"metadata": dict()}
            rule["metadata"] = {"annotations": dict()}
            rule["metadata"]["annotations"] = {"name":
                f"stx-{label}-{host.personality}-{network.type}-{proto_name.lower()}{ip_version}"}
            rule.update({"protocol": proto_id})
            rule.update({"ipVersion": ip_version})
            rule.update({"action": "Allow"})
            firewall_gnp["spec"][direction].append(rule)

    def _get_basic_firewall_gnp(self, host, firewall_networks, config):
        """ Fill the GlobalNetworkPolicy basic hiera data (no filter rules)

        :param host: a sysinv.object.host class object
        :param firewall_networks: a set containing the platform networks that will require a
                                  firewall to be configured.
        :param config: the dict containing the hiera data to be filled
        """

        for network in firewall_networks:

            gnp_name = host.personality + "-" + network.type + "-if-gnp"
            nodetype_selector = f"has(nodetype) && nodetype == '{host.personality}'"
            iftype_selector = f"has(iftype) && iftype contains '{network.type}'"
            selector = f"{nodetype_selector} && {iftype_selector}"

            firewall_gnp = dict()
            firewall_gnp["apiVersion"] = "crd.projectcalico.org/v1"
            firewall_gnp["kind"] = "GlobalNetworkPolicy"
            firewall_gnp["metadata"] = {"name": gnp_name}

            firewall_gnp["spec"] = dict()
            firewall_gnp["spec"].update({"applyOnForward": False})
            firewall_gnp["spec"].update({"order": 100})
            firewall_gnp["spec"].update({"selector": selector})
            firewall_gnp["spec"].update({"types": ["Ingress", "Egress"]})
            firewall_gnp["spec"].update({"egress": list()})
            firewall_gnp["spec"].update({"ingress": list()})

            addr_pools = self._address_pools_get_by_network(network.id)
            for addr_pool in addr_pools:
                ip_version = addr_pool.family
                ICMP = "ICMP"
                if ip_version == 6:
                    ICMP = "ICMPv6"

                for proto in ["TCP", "UDP", ICMP]:
                    self._add_gnp_proto_rules(host, network, ip_version, firewall_gnp, proto)

                if network.type in IPSEC_NETWORKS:
                    self._add_gnp_proto_rules(host, network, ip_version, firewall_gnp, "ESP", 50)

            config[PLATFORM_FIREWALL_CLASSES[network.type]] = firewall_gnp

    def _set_rules_oam(self, gnp_config, network, host, dc_role):
        """ Fill the OAM network specific filtering data

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        :param host: a sysinv.object.host class object
        :param dc_role: the DC role (system-controller or subcloud)
        """

        # OAM exists in previous versions, and it uses noTetype instead of noDetype
        # for upgrade's sake keep both.
        label_old = "(has(nodetype) && nodetype == 'controller')"
        label_current = "(has(notetype) && notetype == 'controller')"
        iftype_current = "has(iftype) && iftype contains 'oam'"
        gnp_config["spec"]['selector'] = f"({label_old} || {label_current}) && {iftype_current}"

        tcp_ports = self._get_oam_common_tcp_ports()

        if (dc_role != constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
            http_service_port = self._get_http_service_port()
            if (http_service_port):
                if (http_service_port not in tcp_ports):
                    tcp_ports.remove(constants.PLATFORM_FIREWALL_HTTP_PORT)
                    tcp_ports.append(http_service_port)
            else:
                tcp_ports.remove(constants.PLATFORM_FIREWALL_HTTP_PORT)
        else:
            tcp_ports.remove(constants.PLATFORM_FIREWALL_HTTP_PORT)

        if (dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
            tcp_ports.extend(self._get_oam_dc_tcp_ports())

        if (not _is_ceph_enabled(self.dbapi)):
            tcp_ports.remove(constants.PLATFORM_CEPH_PARAMS_RGW_PORT)

        udp_ports = self._get_oam_common_udp_ports()

        tcp_ports.sort()
        udp_ports.sort()
        for rule in gnp_config["spec"]["ingress"]:
            if rule["protocol"] == "TCP":
                rule.update({"destination": {"ports": tcp_ports}})
            elif rule["protocol"] == "UDP":
                rule.update({"destination": {"ports": udp_ports}})

        addr_pools = self._address_pools_get_by_network(network.id)
        for addr_pool in addr_pools:
            ip_version = addr_pool.family
            self._add_destination_net_filter(gnp_config["spec"]["ingress"],
                                             f"{addr_pool.network}/{addr_pool.prefix}")
            if (ip_version == constants.IPV6_FAMILY):
                for rule in gnp_config["spec"]["ingress"]:
                    if rule["protocol"] == "ICMPv6":
                        rule["destination"]["nets"].append(LINK_LOCAL)
                        rule["destination"]["nets"].append(LINK_LOCAL_MC)

    def _copy_tcp_rule(self, config, direction, ip_version):
        for rule in config[direction]:
            if rule["protocol"] == "TCP" and rule["ipVersion"] == ip_version:
                return copy.deepcopy(rule)

    def _set_rules_mgmt(self, gnp_config, network, host):
        """ Fill the management network specific filtering data

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        """
        addr_pools = self._address_pools_get_by_network(network.id)
        for addr_pool in addr_pools:
            ip_version = addr_pool.family
            self._add_source_net_filter(gnp_config["spec"]["ingress"],
                                        f"{addr_pool.network}/{addr_pool.prefix}", ip_version)

            if (ip_version == 6):
                self._add_source_net_filter(gnp_config["spec"]["ingress"], LINK_LOCAL, ip_version)

            if (ip_version == 4):
                # add rule to allow DHCP requests (dhcp-offer have src addr == 0.0.0.0)
                # worker/storage nodes request IP dynamically
                rule = self._get_dhcp_rule(host.personality, "UDP", constants.IPV4_FAMILY)
                gnp_config["spec"]["ingress"].append(rule)

                # copy the TCP rule and do the same for IGMP
                igmp_proto = 2
                igmp_egr_rule = self._copy_tcp_rule(gnp_config["spec"], "egress", ip_version)
                igmp_egr_rule["protocol"] = igmp_proto
                igmp_egr_rule["metadata"]["annotations"]["name"] = \
                    f"stx-egr-{host.personality}-{network.type}-igmp{constants.IPV4_FAMILY}"
                gnp_config["spec"]["egress"].append(igmp_egr_rule)
                igmp_ingr_rule = self._copy_tcp_rule(gnp_config["spec"], "ingress", ip_version)
                igmp_ingr_rule["protocol"] = igmp_proto
                igmp_ingr_rule["metadata"]["annotations"]["name"] = \
                    f"stx-ingr-{host.personality}-{network.type}-igmp{constants.IPV4_FAMILY}"
                # Allow 0.0.0.0/32 for the case the switch sends IGMP queries from
                # a VLAN without the IP address configured.
                igmp_ingr_rule["source"]["nets"].append("0.0.0.0/32")
                gnp_config["spec"]["ingress"].append(igmp_ingr_rule)

    def _set_rules_admin(self, gnp_config, network, host):
        """ Fill the admin network specific filtering data

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        """
        addr_pools = self._address_pools_get_by_network(network.id)
        for addr_pool in addr_pools:
            ip_version = addr_pool.family
            self._add_source_net_filter(gnp_config["spec"]["ingress"],
                                        f"{addr_pool.network}/{addr_pool.prefix}", ip_version)
            if (ip_version == 6):
                self._add_source_net_filter(gnp_config["spec"]["ingress"], LINK_LOCAL, ip_version)
            if (ip_version == 4):
                # copy the TCP rule and do the same for IGMP
                igmp_proto = 2
                igmp_egr_rule = self._copy_tcp_rule(gnp_config["spec"], "egress", ip_version)
                igmp_egr_rule["protocol"] = igmp_proto
                igmp_egr_rule["metadata"]["annotations"]["name"] = \
                    f"stx-egr-{host.personality}-{network.type}-igmp{ip_version}"
                gnp_config["spec"]["egress"].append(igmp_egr_rule)
                igmp_ingr_rule = self._copy_tcp_rule(gnp_config["spec"], "ingress", ip_version)
                igmp_ingr_rule["protocol"] = igmp_proto
                igmp_ingr_rule["metadata"]["annotations"]["name"] = \
                    f"stx-ingr-{host.personality}-{network.type}-igmp{ip_version}"
                # Allow 0.0.0.0/32 for the case the switch sends IGMP queries from
                # a VLAN without the IP address configured.
                igmp_ingr_rule["source"]["nets"].append("0.0.0.0/32")
                gnp_config["spec"]["ingress"].append(igmp_ingr_rule)

    def _set_rules_cluster_host(self, gnp_config, network, host):
        """ Fill the cluster-host network specific filtering data

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        """

        cpod_pool_index = {}
        cpod_net = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_CLUSTER_POD)
        if cpod_net:
            cpod_pools = self._address_pools_get_by_network(cpod_net.id)
            for cpod_pool in cpod_pools:
                cpod_pool_index[cpod_pool.family] = cpod_pool
        else:
            LOG.info("Cannot find cluster-pod network to add to cluster-host firewall")

        addr_pools = self._address_pools_get_by_network(network.id)
        for addr_pool in addr_pools:
            ip_version = addr_pool.family
            self._add_source_net_filter(gnp_config["spec"]["ingress"],
                                        f"{addr_pool.network}/{addr_pool.prefix}", ip_version)

            # add cluster-pod to cover the cases where there is no tunneling, the pod traffic goes
            # directly in the cluster-host interface
            cpod_pool = cpod_pool_index.get(ip_version, None)
            if cpod_pool:
                self._add_source_net_filter(gnp_config["spec"]["ingress"],
                                            f"{cpod_pool.network}/{cpod_pool.prefix}", ip_version)

            # copy the TCP rule and do the same for SCTP
            sctp_egr_rule = self._copy_tcp_rule(gnp_config["spec"], "egress", ip_version)
            sctp_egr_rule["protocol"] = "SCTP"
            sctp_egr_rule["metadata"]["annotations"]["name"] = \
                f"stx-egr-{host.personality}-{network.type}-sctp{ip_version}"
            gnp_config["spec"]["egress"].append(sctp_egr_rule)
            sctp_ingr_rule = self._copy_tcp_rule(gnp_config["spec"], "ingress", ip_version)
            sctp_ingr_rule["protocol"] = "SCTP"
            sctp_ingr_rule["metadata"]["annotations"]["name"] = \
                f"stx-ingr-{host.personality}-{network.type}-sctp{ip_version}"
            gnp_config["spec"]["ingress"].append(sctp_ingr_rule)

            if (ip_version == 6):
                # add link-local network too
                self._add_source_net_filter(gnp_config["spec"]["ingress"], LINK_LOCAL, ip_version)

            if (ip_version == 4):
                # add rule to allow DHCP requests (dhcp-offer have src addr == 0.0.0.0)
                rule = self._get_dhcp_rule(host.personality, "UDP", ip_version)
                gnp_config["spec"]["ingress"].append(rule)

                # copy the TCP rule and do the same for IGMP
                igmp_proto = 2
                igmp_egr_rule = self._copy_tcp_rule(gnp_config["spec"], "egress", ip_version)
                igmp_egr_rule["protocol"] = igmp_proto
                igmp_egr_rule["metadata"]["annotations"]["name"] = \
                    f"stx-egr-{host.personality}-{network.type}-igmp{ip_version}"
                gnp_config["spec"]["egress"].append(igmp_egr_rule)
                igmp_ingr_rule = self._copy_tcp_rule(gnp_config["spec"], "ingress", ip_version)
                igmp_ingr_rule["protocol"] = igmp_proto
                igmp_ingr_rule["metadata"]["annotations"]["name"] = \
                    f"stx-ingr-{host.personality}-{network.type}-igmp{ip_version}"
                # Allow 0.0.0.0/32 for the case the switch sends IGMP queries from
                # a VLAN without the IP address configured.
                igmp_ingr_rule["source"]["nets"].append("0.0.0.0/32")
                gnp_config["spec"]["ingress"].append(igmp_ingr_rule)

    def _set_rules_pxeboot(self, gnp_config, network, host):
        """ Fill the pxeboot network specific filtering data

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        """

        addr_pools = self._address_pools_get_by_network(network.id)
        for addr_pool in addr_pools:
            ip_version = addr_pool.family
            self._add_source_net_filter(gnp_config["spec"]["ingress"],
                                        f"{addr_pool.network}/{addr_pool.prefix}", ip_version)
            if (ip_version == 6):
                self._add_source_net_filter(gnp_config["spec"]["ingress"], LINK_LOCAL, ip_version)
            if (ip_version == 4):
                # add rule to allow DHCP requests (dhcp-offer have src addr == 0.0.0.0)
                rule = self._get_dhcp_rule(host.personality, "UDP", ip_version)
                gnp_config["spec"]["ingress"].append(rule)

    def _set_rules_storage(self, gnp_config, network, host):
        """ Fill the storage network specific filtering data

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        """

        addr_pools = self._address_pools_get_by_network(network.id)
        for addr_pool in addr_pools:
            ip_version = addr_pool.family
            self._add_source_net_filter(gnp_config["spec"]["ingress"],
                                        f"{addr_pool.network}/{addr_pool.prefix}", ip_version)
            if (ip_version == 6):
                self._add_source_net_filter(gnp_config["spec"]["ingress"], LINK_LOCAL, ip_version)
            if (ip_version == 4):
                # add rule to allow DHCP requests (dhcp-offer have src addr == 0.0.0.0)
                rule = self._get_dhcp_rule(host.personality, "UDP", ip_version)
                gnp_config["spec"]["ingress"].append(rule)

    def _add_source_net_filter(self, rule_list, source_net, ip_version):
        """ Add source network in the rule list

        :param rule_list: the list containing the firewall rules that need to receive the source
                          network value
        :param source_net: the string containing the value
        """
        for rule in rule_list:
            if rule["ipVersion"] != ip_version:
                continue
            if ("source" in rule.keys()):
                if ("nets" in rule["source"].keys()):
                    rule["source"]["nets"].append(source_net)
                else:
                    rule["source"].update({"nets": [source_net]})
            else:
                rule.update({"source": {"nets": [source_net]}})

    def _add_destination_net_filter(self, rule_list, destination_net):
        """ Add destination network in the rule list

        :param rule_list: the list containing the firewall rules that need to receive the
                          destination network value
        :param destination_net: the string containing the value
        """
        for rule in rule_list:
            if ("destination" in rule.keys()):
                if ("nets" in rule["destination"].keys()):
                    rule["destination"]["nets"].append(destination_net)
                else:
                    rule["destination"].update({"nets": [destination_net]})
            else:
                rule.update({"destination": {"nets": [destination_net]}})

    def _set_rules_subcloud_admin(self, gnp_config, network, host_personality):
        """ Add filtering rules for admin network in a subcloud installation

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        :param host_personality: the node personality (controller, storage, or worker)
        """

        routes_networks = self._get_routes_networks(network.type)

        addr_pools = self._address_pools_get_by_network(network.id)
        for addr_pool in addr_pools:
            ip_version = addr_pool.family
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
                rules.append(rule)

            for route_network in routes_networks[ip_version]:
                self._add_source_net_filter(rules, route_network, ip_version)

            for rule in rules:
                gnp_config["spec"]["ingress"].append(rule)

    def _set_rules_subcloud_mgmt(self, gnp_config, network, host_personality):
        """ Add filtering rules for mgmt network in a subcloud installation

        If the subcloud keeps using the mgmt network to communicate with the system controller
        we add the L4 port filtering into this GNP

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        :param host_personality: the node personality (controller, storage, or worker)
        """

        routes_networks = self._get_routes_networks(network.type)

        addr_pools = self._address_pools_get_by_network(network.id)
        for addr_pool in addr_pools:
            ip_version = addr_pool.family
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

            for route_network in routes_networks[ip_version]:
                self._add_source_net_filter(rules, route_network, ip_version)

    def _get_routes_networks(self, network_type):
        routes = self.dbapi.routes_get_by_network_type_and_host_personality(
                network_type, constants.CONTROLLER)
        network_sets = {constants.IPV4_FAMILY: set(), constants.IPV6_FAMILY: set()}
        networks = {}
        for route in routes:
            network = route.network + '/' + str(route.prefix)
            network_sets[int(route.family)].add(network)
        for family, net_set in network_sets.items():
            net_list = list(net_set)
            net_list.sort()
            networks[family] = net_list
        return networks

    def _set_rules_systemcontroller(self, gnp_config, network, host_personality):
        """ Add filtering rules for mgmt network in a system controller installation

        :param gnp_config: the dict containing the hiera data to be filled
        :param network: the sysinv.object.network object for this network
        :param host_personality: the node personality (controller, storage, or worker)
        """

        routes_networks = self._get_routes_networks(network.type)

        rules = []
        addr_pools = self._address_pools_get_by_network(network.id)
        for addr_pool in addr_pools:
            ip_version = addr_pool.family
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

            for route_network in routes_networks[ip_version]:
                self._add_source_net_filter(rules, route_network, ip_version)

    def _set_extra_rules(self, config):
        pass

    def _get_subcloud_tcp_ports(self):
        """ Get the TCP L4 ports for subclouds
        """
        port_list = list(firewall.SUBCLOUD["tcp"].keys())
        http_service_port = self._get_http_service_port()
        if (http_service_port):
            port_list.append(http_service_port)
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
        http_service_port = self._get_http_service_port()
        if (http_service_port):
            port_list.append(http_service_port)
        port_list.sort()
        return port_list

    def _get_systemcontroller_udp_ports(self):
        """ Get the UDP L4 ports for systemcontroller
        """
        port_list = list(firewall.SYSTEMCONTROLLER["udp"].keys())
        port_list.sort()
        return port_list

    def _get_oam_common_tcp_ports(self):
        """ Get the TCP L4 ports for OAM networks
        """
        port_list = list(firewall.OAM_COMMON["tcp"])
        port_list.sort()
        return port_list

    def _get_oam_common_udp_ports(self):
        """ Get the TCP L4 ports for OAM networks
        """
        port_list = list(firewall.OAM_COMMON["udp"])
        port_list.sort()
        return port_list

    def _get_oam_dc_tcp_ports(self):
        """ Get the TCP L4 ports for subclouds
        """
        port_list = list(firewall.OAM_DC["tcp"])
        port_list.sort()
        return port_list

    def _get_http_service_port(self):
        """ Get the HTTP port from the service-parameter database
        """
        tcp_port = 0
        service_name = "http_port"
        if _is_https_enabled(self.dbapi):
            service_name = "https_port"

        try:
            web_port = self.dbapi.service_parameter_get_one(service="http",
                                                            section="config",
                                                            name=service_name)
            tcp_port = int(web_port.value)
        except exception.NotFound:
            LOG.info("cannot retrieve web service port")

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

    def _add_hep_expected_ip(self, host, net_type, host_endpoints):
        address_name = str()
        if cutils.is_aio_simplex_system(self.dbapi):
            address_name = cutils.format_address_name(constants.CONTROLLER_HOSTNAME, net_type)
        else:
            if host.hostname == constants.CONTROLLER_0_HOSTNAME:
                address_name = cutils.format_address_name(constants.CONTROLLER_0_HOSTNAME, net_type)
            elif host.hostname == constants.CONTROLLER_1_HOSTNAME:
                address_name = cutils.format_address_name(constants.CONTROLLER_1_HOSTNAME, net_type)

        addresses = self.dbapi.address_get_by_name(address_name)
        address_texts = [str(address.address) for address in addresses]
        if (address_texts):
            if ("expectedIPs" in host_endpoints["spec"].keys()):
                host_endpoints["spec"]["expectedIPs"].extend(address_texts)
            else:
                host_endpoints["spec"].update({"expectedIPs": address_texts})
        else:
            LOG.info(f"cannot find address:{address_name} for net_type:{net_type} expectedIPs")


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


def _is_ceph_enabled(dbapi):
    ceph_backend = StorageBackendConfig.get_backend_conf(
        dbapi, constants.CINDER_BACKEND_CEPH)
    if not ceph_backend:
        return False  # ceph is not configured

    _, ceph_mon_ips = StorageBackendConfig.get_ceph_mon_ip_addresses(
        dbapi)

    if not ceph_mon_ips:
        return False  # system configuration is not yet ready
    return True
