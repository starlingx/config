#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils
from sysinv.openstack.common import log as logging
from . import common
from . import openstack

from sqlalchemy.orm.exc import NoResultFound

LOG = logging.getLogger(__name__)

DATA_NETWORK_TYPES = [constants.NETWORK_TYPE_DATA]


class NeutronHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the neutron chart"""

    CHART = constants.HELM_CHART_NEUTRON
    SUPPORTED_NAMESPACES = [
        common.HELM_NS_OPENSTACK
    ]

    SERVICE_NAME = 'neutron'
    AUTH_USERS = ['neutron']
    SERVICE_USERS = ['nova']

    @property
    def docker_repo_source(self):
        return common.DOCKER_SRC_STX

    @property
    def docker_repo_tag(self):
        return common.DOCKER_SRCS[self.docker_repo_source][common.IMG_TAG_KEY]

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'pod': {
                    'user': {
                        'neutron': {
                            'uid': 0
                        }
                    }
                },
                'network': {
                    'interface': {
                        'tunnel': 'docker0'
                    },
                },
                'conf': {
                    'neutron': self._get_neutron_config(),
                    'plugins': {
                        'ml2_conf': self._get_neutron_ml2_config(),
                    },
                    'dhcp_agent': {
                        'DEFAULT': {
                            'resync_interval': 30,
                            'enable_isolated_metadata': True,
                            'enable_metadata_network': False,
                            'interface_driver': 'openvswitch',
                        },
                    },
                    'l3_agent': {
                        'DEFAULT': {
                            'interface_driver': 'openvswitch',
                            'agent_mode': 'dvr_snat',
                            'metadata_port': 80,
                        },
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
                    }
                },
                'endpoints': self._get_endpoints_overrides(),
                'images': self._get_images_overrides(),
            }
        }

        self.update_dynamic_options(overrides[common.HELM_NS_OPENSTACK]['conf'])

        self.update_from_service_parameters(overrides[common.HELM_NS_OPENSTACK]['conf'])

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_service_parameters(self, service=None):
        service_parameters = []
        if self.dbapi is None:
            return service_parameters
        try:
            service_parameters = self.dbapi.service_parameter_get_all(
                service=service)
        except NoResultFound:
            pass
        return service_parameters

    def update_dynamic_options(self, overrides):
        if utils.is_virtual():
            overrides['neutron']['vhost']['vhost_user_enabled'] = False

    def update_from_service_parameters(self, overrides):
        service_parameters = self._get_service_parameters(service=constants.SERVICE_TYPE_NETWORK)
        for param in service_parameters:
            if param.section == constants.SERVICE_PARAM_SECTION_NETWORK_DEFAULT:
                if param.name == constants.SERVICE_PARAM_NAME_DEFAULT_SERVICE_PLUGINS:
                    overrides['neutron']['DEFAULT']['service_plugins'] = str(param.value)
                if param.name == constants.SERVICE_PARAM_NAME_DEFAULT_DNS_DOMAIN:
                    overrides['neutron']['DEFAULT']['dns_domain'] = str(param.value)
                if param.name == constants.SERVICE_PARAM_NAME_BASE_MAC:
                    overrides['neutron']['DEFAULT']['base_mac'] = str(param.value)
                if param.name == constants.SERVICE_PARAM_NAME_DVR_BASE_MAC:
                    overrides['neutron']['DEFAULT']['dvr_base_mac'] = str(param.value)
            elif param.section == constants.SERVICE_PARAM_SECTION_NETWORK_ML2:
                if param.name == constants.SERVICE_PARAM_NAME_ML2_MECHANISM_DRIVERS:
                    overrides['plugins']['ml2_conf']['ml2']['mechanism_drivers'] = str(param.value)
                if param.name == constants.SERVICE_PARAM_NAME_ML2_EXTENSION_DRIVERS:
                    overrides['plugins']['ml2_conf']['ml2']['extension_drivers'] = str(param.value)
                if param.name == constants.SERVICE_PARAM_NAME_ML2_TENANT_NETWORK_TYPES:
                    overrides['plugins']['ml2_conf']['ml2']['tenant_network_types'] = str(param.value)
            elif param.section == constants.SERVICE_PARAM_SECTION_NETWORK_DHCP:
                if param.name == constants.SERVICE_PARAM_NAME_DHCP_FORCE_METADATA:
                    overrides['dhcp_agent']['DEFAULT']['force_metadata'] = str(param.value)

    def _get_per_host_overrides(self):
        host_list = []
        hosts = self.dbapi.ihost_get_list()

        for host in hosts:
            if (host.invprovision == constants.PROVISIONED):
                if constants.COMPUTE in utils.get_personalities(host):

                    hostname = str(host.hostname)
                    host_neutron = {
                        'name': hostname,
                        'conf': {
                            'plugins': {
                                'openvswitch_agent': self._get_dynamic_ovs_agent_config(host)
                            }
                        }
                    }
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
                    providernets = self._get_interface_providernets(iface)
                    for providernet in providernets:
                        address = self._get_interface_primary_address(
                            self.context, host, iface)
                        if address:
                            local_ip = address
                            tunnel_types = constants.NEUTRON_PROVIDERNET_VXLAN
                        else:
                            bridge_mappings += ('%s:%s,' % (providernet, brname))
                index += 1

        agent = {}
        ovs = {
            'integration_bridge': 'br-int',
            'datapath_type': 'netdev',
            'vhostuser_socket_dir': '/var/run/openvswitch',
        }

        if tunnel_types:
            agent['tunnel_types'] = tunnel_types
        if local_ip:
            ovs['local_ip'] = local_ip
        if bridge_mappings:
            ovs['bridge_mappings'] = str(bridge_mappings)

        return {
            'agent': agent,
            'ovs': ovs,
            'securitygroup': {
                'firewall_driver': 'noop',
            },
        }

    def _get_neutron_config(self):
        neutron_config = {
            'DEFAULT': {
                'l3_ha': False,
                'min_l3_agents_per_router': 1,
                'max_l3_agents_per_router': 1,
                'l3_ha_network_type': 'vxlan',
                'dhcp_agents_per_network': 1,
                'max_overflow': 64,
                'max_pool_size': 1,
                'idle_timeout': 60,
                'router_status_managed': True,
                'vlan_transparent': True,
                'wsgi_default_pool_size': 100,
                'router_scheduler_driver':
                    'neutron.scheduler.l3_host_agent_scheduler.HostBasedScheduler',
                'network_scheduler_driver':
                    'neutron.scheduler.dhcp_host_agent_scheduler.HostBasedScheduler',
                'notify_nova_on_port_data_changes': True,
                'notify_nova_on_port_status_changes': True,
                'host_driver':
                    'neutron.plugins.wrs.drivers.host.DefaultHostDriver',
                'control_exchange': 'neutron',
                'core_plugin': 'neutron.plugins.ml2.plugin.Ml2Plugin',
                'state_path': '/var/run/neutron',
                'syslog_log_facility': 'local2',
                'use_syslog': True,
                'pnet_audit_enabled': False,
                'driver': 'messagingv2',
                'enable_proxy_headers_parsing': True,
                'lock_path': '/var/run/neutron/lock',
                'log_format': '[%(name)s] %(message)s',
                'policy_file': '/etc/neutron/policy.json',
                'service_plugins': 'router',
                'dns_domain': 'openstacklocal',
            },
            'vhost': {
                'vhost_user_enabled': True,
            },
            'agent': {
                'root_helper': 'sudo',
            },
        }

        return neutron_config

    def _get_neutron_ml2_config(self):
        ml2_config = {
            'ml2': {
                'type_drivers': 'managed_flat,managed_vlan,managed_vxlan',
                'tenant_network_types': 'vlan,vxlan',
                'mechanism_drivers': 'openvswitch,sriovnicswitch,l2population',
                'path_mtu': 0,

            },
            'securitygroup': {
                'firewall_driver': 'noop',
            },
        }
        return ml2_config

    def _is_data_network_type(self, iface):
        networktypelist = utils.get_network_type_list(iface)
        return bool(any(n in DATA_NETWORK_TYPES for n in networktypelist))

    def _get_interface_providernets(self, iface):
        """
        Return the provider networks of the supplied interface as a list.
        """
        providernetworks = iface['providernetworks']
        if not providernetworks:
            return []
        return [x.strip() for x in providernetworks.split(',')]

    def _get_interface_primary_address(self, context, host, iface):
        """
        Determine the primary IP address on an interface (if any).  If multiple
        addresses exist then the first address is returned.
        """
        for address in self.dbapi.addresses_get_by_host(host.id):
            if address.ifname == iface.ifname:
                return address.address

        return None

    def _get_images_overrides(self):
        heat_image = self._operator.chart_operators[
            constants.HELM_CHART_HEAT].docker_image
        return {
            'tags': {
                'bootstrap': heat_image,
                'db_init': heat_image,
                'neutron_db_sync': self.docker_image,
                'db_drop': heat_image,
                'ks_user': heat_image,
                'ks_service': heat_image,
                'ks_endpoints': heat_image,
                'neutron_server': self.docker_image,
                'neutron_dhcp': self.docker_image,
                'neutron_metadata': self.docker_image,
                'neutron_l3': self.docker_image,
                'neutron_openvswitch_agent': self.docker_image,
                'neutron_linuxbridge_agent': self.docker_image,
                # TODO (rchurch): Fix this... Suffix tied to a release???
                # 'neutron_sriov_agent': '{}{}'.format(self.docker_image,'-sriov-1804'),
                # 'neutron_sriov_agent_init': '{}{}'.format(self.docker_image,'-sriov-1804'),
                'neutron_sriov_agent': self.docker_image,
                'neutron_sriov_agent_init': self.docker_image,
            }
        }

    def _get_endpoints_identity_users_overrides(self):
        overrides = {}
        overrides.update(self._get_common_users_overrides(self.SERVICE_NAME))

        for user in self.AUTH_USERS:
            overrides.update({
                user: {
                    'region_name': self._region_name(),
                    'password': self._get_keyring_password(self.SERVICE_NAME, user)
                }
            })
        for user in self.SERVICE_USERS:
            overrides.update({
                user: {
                    'region_name': self._region_name(),
                    'password': self._get_keyring_password(user, user)
                }
            })
        return overrides

    def _get_endpoints_identity_overrides(self):
        return {'auth': self._get_endpoints_identity_users_overrides()}

    def _get_endpoints_overrides(self):
        return {
            'identity': self._get_endpoints_identity_overrides(),
        }
