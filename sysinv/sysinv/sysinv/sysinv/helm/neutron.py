#
# Copyright (c) 2018-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils
from sysinv.helm import common
from sysinv.helm import openstack

LOG = logging.getLogger(__name__)

DATA_NETWORK_TYPES = [constants.NETWORK_TYPE_DATA]
SRIOV_NETWORK_TYPES = [constants.NETWORK_TYPE_PCI_SRIOV]


class NeutronHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the neutron chart"""

    CHART = common.HELM_CHART_NEUTRON

    SERVICE_NAME = common.HELM_CHART_NEUTRON
    AUTH_USERS = ['neutron']
    SERVICE_USERS = ['nova']

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'pod': {
                    'replicas': {
                        'server': self._num_controllers()
                    },
                },
                'conf': {
                    'plugins': {
                        'ml2_conf': self._get_neutron_ml2_config()
                    },
                    'overrides': {
                        'neutron_ovs-agent': {
                            'hosts': self._get_per_host_overrides()
                        },
                        'neutron_dhcp-agent': {
                            'hosts': self._get_per_host_overrides()
                        },
                        'neutron_l3-agent': {
                            'hosts': self._get_per_host_overrides()
                        },
                        'neutron_metadata-agent': {
                            'hosts': self._get_per_host_overrides()
                        },
                        'neutron_sriov-agent': {
                            'hosts': self._get_per_host_overrides()
                        },
                    },
                    'paste': {
                        'app:neutronversions': {
                            'paste.app_factory':
                                'neutron.pecan_wsgi.app:versions_factory'
                        },
                    },
                },
                'endpoints': self._get_endpoints_overrides(),
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_per_host_overrides(self):
        host_list = []
        hosts = self.dbapi.ihost_get_list()

        for host in hosts:
            host_labels = self.dbapi.label_get_by_host(host.id)
            if (host.invprovision in [constants.PROVISIONED,
                                      constants.PROVISIONING] or
                    host.ihost_action in [constants.UNLOCK_ACTION,
                                          constants.FORCE_UNLOCK_ACTION]):
                if (constants.WORKER in utils.get_personalities(host) and
                        utils.has_openstack_compute(host_labels)):

                    hostname = str(host.hostname)
                    host_neutron = {
                        'name': hostname,
                        'conf': {
                            'plugins': {
                                'openvswitch_agent': self._get_dynamic_ovs_agent_config(host),
                                'sriov_agent': self._get_dynamic_sriov_agent_config(host),
                            }
                        }
                    }
                    # if ovs runs on host, auto bridge add is covered by sysinv
                    if utils.get_vswitch_type(self.dbapi) == constants.VSWITCH_TYPE_NONE:
                        host_neutron['conf'].update({
                            'auto_bridge_add': self._get_host_bridges(host)})
                    host_list.append(host_neutron)

        return host_list

    def _interface_sort_key(self, iface):
        """
        Sort interfaces by interface type placing ethernet interfaces ahead of
        aggregated ethernet interfaces, and vlan interfaces last.
        """
        if iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET:
            return 0, iface['ifname']
        elif iface['iftype'] == constants.INTERFACE_TYPE_AE:
            return 1, iface['ifname']
        else:  # if iface['iftype'] == constants.INTERFACE_TYPE_VLAN:
            return 2, iface['ifname']

    def _get_datapath_type(self):
        if (utils.get_vswitch_type(self.dbapi) ==
                constants.VSWITCH_TYPE_OVS_DPDK):
            return "netdev"
        else:
            return "system"

    def _get_host_bridges(self, host):
        bridges = {}
        index = 0
        for iface in sorted(self.dbapi.iinterface_get_by_ihost(host.id),
                            key=self._interface_sort_key):
            if self._is_data_network_type(iface):
                if any(dn.datanetwork_network_type in
                       [constants.DATANETWORK_TYPE_FLAT,
                        constants.DATANETWORK_TYPE_VLAN] for dn in
                       self._get_interface_datanets(iface)):
                    # obtain the assigned bridge for interface
                    brname = 'br-phy%d' % index
                    port_name = self._get_interface_port_name(iface)
                    bridges[brname] = port_name.encode('utf8', 'strict')
                    index += 1
        return bridges

    def _get_dynamic_ovs_agent_config(self, host):
        local_ip = None
        tunnel_types = None
        bridge_mappings = ""
        index = 0
        for iface in sorted(self.dbapi.iinterface_get_by_ihost(host.id),
                            key=self._interface_sort_key):
            if self._is_data_network_type(iface):
                # obtain the assigned bridge for interface
                brname = 'br-phy%d' % index
                if brname:
                    datanets = self._get_interface_datanets(iface)
                    for datanet in datanets:
                        dn_name = datanet['datanetwork_name'].strip()
                        LOG.debug('_get_dynamic_ovs_agent_config '
                                  'host=%s datanet=%s', host.hostname, dn_name)
                        if (datanet.datanetwork_network_type ==
                                constants.DATANETWORK_TYPE_VXLAN):
                            local_ip = self._get_interface_primary_address(
                                self.context, host, iface)
                            tunnel_types = constants.DATANETWORK_TYPE_VXLAN
                        elif (datanet.datanetwork_network_type in
                              [constants.DATANETWORK_TYPE_FLAT,
                               constants.DATANETWORK_TYPE_VLAN]):
                            bridge_mappings += ('%s:%s,' % (dn_name, brname))
                            index += 1

        agent = {}
        ovs = {
            'integration_bridge': 'br-int',
            'datapath_type': self._get_datapath_type(),
            'vhostuser_socket_dir': '/var/run/openvswitch',
        }

        if tunnel_types:
            agent['tunnel_types'] = tunnel_types
        if local_ip:
            ovs['local_ip'] = local_ip
        if bridge_mappings:
            ovs['bridge_mappings'] = str(bridge_mappings)

        # https://access.redhat.com/documentation/en-us/
        # red_hat_enterprise_linux_openstack_platform/7/html/
        # networking_guide/bridge-mappings
        # required for vlan, not flat, vxlan:
        #     ovs['network_vlan_ranges'] = physnet1:10:20,physnet2:21:25

        return {
            'agent': agent,
            'ovs': ovs,
        }

    def _get_dynamic_sriov_agent_config(self, host):
        physical_device_mappings = ""
        for iface in sorted(self.dbapi.iinterface_get_by_ihost(host.id),
                            key=self._interface_sort_key):
            if self._is_sriov_network_type(iface):
                # obtain the assigned datanets for interface
                datanets = self._get_interface_datanets(iface)
                port_name = self._get_interface_port_name(iface)
                for datanet in datanets:
                    dn_name = datanet['datanetwork_name'].strip()
                    physical_device_mappings += ('%s:%s,' % (dn_name, port_name))
        sriov_nic = {
            'physical_device_mappings': str(physical_device_mappings),
        }

        return {
            'securitygroup': {
                'firewall_driver': 'noop',
            },
            # Mitigate host OS memory leak of cgroup session-*scope files
            # and kernel slab resources. The leak is triggered using 'sudo'
            # which utilizes the host dbus-daemon. The sriov agent frequently
            # polls devices via 'ip link show' using run_as_root=True, but
            # does not actually require 'sudo'.
            'agent': {
                'root_helper': '',
            },
            'sriov_nic': sriov_nic,
        }

    def _get_ml2_physical_network_mtus(self):
        ml2_physical_network_mtus = []
        datanetworks = self.dbapi.datanetworks_get_all()
        for datanetwork in datanetworks:
            dn_str = str(datanetwork.name) + ":" + str(datanetwork.mtu)
            ml2_physical_network_mtus.append(dn_str)

        return ",".join(ml2_physical_network_mtus)

    def _get_flat_networks(self):
        flat_nets = []
        datanetworks = self.dbapi.datanetworks_get_all()
        for datanetwork in datanetworks:
            if datanetwork.network_type == constants.DATANETWORK_TYPE_FLAT:
                flat_nets.append(str(datanetwork.name))
        return ",".join(flat_nets)

    def _get_neutron_ml2_config(self):
        ml2_config = {
            'ml2': {
                'physical_network_mtus': self._get_ml2_physical_network_mtus()
            },
            'ml2_type_flat': {
                'flat_networks': self._get_flat_networks()
            }
        }
        LOG.info("_get_neutron_ml2_config=%s" % ml2_config)
        return ml2_config

    def _is_data_network_type(self, iface):
        return iface.ifclass == constants.INTERFACE_CLASS_DATA

    def _is_sriov_network_type(self, iface):
        return iface.ifclass == constants.INTERFACE_CLASS_PCI_SRIOV

    def _get_interface_datanets(self, iface):
        """
        Return the data networks of the supplied interface as a list.
        """

        ifdatanets = self.dbapi.interface_datanetwork_get_by_interface(
            iface.uuid)
        return ifdatanets

    def _get_interface_port_name(self, iface):
        """
        Determine the port name of the underlying device.
        """
        if (iface['iftype'] == constants.INTERFACE_TYPE_VF and iface['uses']):
            lower_iface = self.dbapi.iinterface_get(iface['uses'][0])
            if lower_iface:
                return self._get_interface_port_name(lower_iface)
        assert iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET
        port = self.dbapi.port_get_by_interface(iface.id)
        if port:
            return port[0]['name']

    def _get_interface_primary_address(self, context, host, iface):
        """
        Determine the primary IP address on an interface (if any).  If multiple
        addresses exist then the first address is returned.
        """
        for address in self.dbapi.addresses_get_by_host(host.id):
            if address.ifname == iface.ifname:
                return address.address

        return None

    def _get_endpoints_overrides(self):
        overrides = {
            'identity': {
                'auth': self._get_endpoints_identity_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS),
            },
            'network': {
                'host_fqdn_override':
                    self._get_endpoints_host_fqdn_overrides(
                        self.SERVICE_NAME),
                'port': self._get_endpoints_port_api_public_overrides(),
                'scheme': self._get_endpoints_scheme_public_overrides(),
            },
            'oslo_cache': {
                'auth': {
                    'memcache_secret_key':
                        self._get_common_password('auth_memcache_key')
                }
            },
            'oslo_db': {
                'auth': self._get_endpoints_oslo_db_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS)
            },
            'oslo_messaging': {
                'auth': self._get_endpoints_oslo_messaging_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS)
            },
        }

        # Service user passwords already exist in other chart overrides
        for user in self.SERVICE_USERS:
            overrides['identity']['auth'].update({
                user: {
                    'region_name': self._region_name(),
                    'password': self._get_or_generate_password(
                        user, common.HELM_NS_OPENSTACK, user)
                }
            })

        return overrides

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)
