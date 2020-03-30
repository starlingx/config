#
# Copyright (c) 2018-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
import os

from oslo_log import log as logging
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import interface
from sysinv.common import utils
from sysinv.common.storage_backend_conf import StorageBackendConfig
from sysinv.helm import common
from sysinv.helm import openstack

LOG = logging.getLogger(__name__)

# Align ephemeral rbd_user with the cinder rbd_user so that the same libvirt
# secret can be used for accessing both pools. This also aligns with the
# behavior defined in nova/virt/libvirt/volume/net.py:_set_auth_config_rbd()
RBD_POOL_USER = "cinder"

DEFAULT_NOVA_PCI_ALIAS = [
    {"vendor_id": constants.NOVA_PCI_ALIAS_QAT_PF_VENDOR,
     "product_id": constants.NOVA_PCI_ALIAS_QAT_DH895XCC_PF_DEVICE,
     "name": constants.NOVA_PCI_ALIAS_QAT_DH895XCC_PF_NAME},
    {"vendor_id": constants.NOVA_PCI_ALIAS_QAT_VF_VENDOR,
     "product_id": constants.NOVA_PCI_ALIAS_QAT_DH895XCC_VF_DEVICE,
     "name": constants.NOVA_PCI_ALIAS_QAT_DH895XCC_VF_NAME},
    {"vendor_id": constants.NOVA_PCI_ALIAS_QAT_PF_VENDOR,
     "product_id": constants.NOVA_PCI_ALIAS_QAT_C62X_PF_DEVICE,
     "name": constants.NOVA_PCI_ALIAS_QAT_C62X_PF_NAME},
    {"vendor_id": constants.NOVA_PCI_ALIAS_QAT_VF_VENDOR,
     "product_id": constants.NOVA_PCI_ALIAS_QAT_C62X_VF_DEVICE,
     "name": constants.NOVA_PCI_ALIAS_QAT_C62X_VF_NAME},
    {"name": constants.NOVA_PCI_ALIAS_GPU_NAME}
]


class NovaHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the nova chart"""

    CHART = common.HELM_CHART_NOVA

    SERVICE_NAME = common.HELM_CHART_NOVA
    AUTH_USERS = ['nova', ]
    SERVICE_USERS = ['neutron', 'ironic', 'placement']
    NOVNCPROXY_SERVICE_NAME = 'novncproxy'
    NOVNCPROXY_NODE_PORT = '30680'

    def get_overrides(self, namespace=None):

        ssh_privatekey, ssh_publickey = \
            self._get_or_generate_ssh_keys(self.SERVICE_NAME, common.HELM_NS_OPENSTACK)
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'manifests': self._get_compute_ironic_manifests(),
                'pod': {
                    'mounts': {
                        'nova_compute': {
                            'nova_compute': self._get_mount_overrides()
                        }
                    },
                    'replicas': {
                        'api_metadata': self._num_controllers(),
                        'placement': self._num_controllers(),
                        'osapi': self._num_controllers(),
                        'conductor': self._num_controllers(),
                        'consoleauth': self._num_controllers(),
                        'scheduler': self._num_controllers(),
                        'novncproxy': self._num_controllers()
                    }
                },
                'conf': {
                    'ceph': {
                        'ephemeral_storage': self._get_rbd_ephemeral_storage()
                    },
                    'nova': {
                        'libvirt': {
                            'virt_type': self._get_virt_type(),
                        },
                        'vnc': {
                            'novncproxy_base_url': self._get_novncproxy_base_url(),
                        },
                        'pci': self._get_pci_alias(),
                    },
                    'overrides': {
                        'nova_compute': {
                            'hosts': self._get_per_host_overrides()
                        }
                    },
                    'ssh_private': ssh_privatekey,
                    'ssh_public': ssh_publickey,
                },
                'endpoints': self._get_endpoints_overrides(),
                'network': {
                    'sshd': {
                        'from_subnet': self._get_ssh_subnet(),
                    },
                    'novncproxy': {
                        'node_port': {
                            'enabled': self._get_network_node_port_overrides()
                        }
                    }
                },
                'ceph_client': self._get_ceph_client_overrides(),
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_mount_overrides(self):
        overrides = self._get_mount_uefi_overrides()
        # mount /dev/pts in order to get console log
        overrides['volumes'].append({
            'name': 'dev-pts',
            'hostPath': {'path': '/dev/pts'}
        })
        overrides['volumeMounts'].append({
            'name': 'dev-pts',
            'mountPath': '/dev/pts'
        })
        return overrides

    def _get_compute_ironic_manifests(self):
        ironic_operator = self._operator.chart_operators[
            common.HELM_CHART_IRONIC]
        enabled = ironic_operator._is_enabled(constants.HELM_APP_OPENSTACK,
                common.HELM_CHART_IRONIC, common.HELM_NS_OPENSTACK)
        return {
            'statefulset_compute_ironic': enabled
        }

    def _get_endpoints_overrides(self):
        overrides = {
            'identity': {
                'name': 'keystone',
                'auth': self._get_endpoints_identity_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS),
            },
            'compute': {
                'host_fqdn_override':
                    self._get_endpoints_host_fqdn_overrides(self.SERVICE_NAME),
                'port': self._get_endpoints_port_api_public_overrides(),
                'scheme': self._get_endpoints_scheme_public_overrides(),
            },
            'compute_novnc_proxy': {
                'host_fqdn_override':
                    self._get_endpoints_host_fqdn_overrides(
                        self.NOVNCPROXY_SERVICE_NAME),
                'port': self._get_endpoints_port_api_public_overrides(),
                'scheme': self._get_endpoints_scheme_public_overrides(),
            },
            'oslo_cache': {
                'auth': {
                    'memcache_secret_key':
                        self._get_common_password('auth_memcache_key')
                }
            },
            'oslo_messaging': {
                'auth': self._get_endpoints_oslo_messaging_overrides(
                    self.SERVICE_NAME, [self.SERVICE_NAME])
            },
        }

        db_passwords = {'auth': self._get_endpoints_oslo_db_overrides(
            self.SERVICE_NAME, [self.SERVICE_NAME])}
        overrides.update({
            'oslo_db': db_passwords,
            'oslo_db_api': copy.deepcopy(db_passwords),
            'oslo_db_cell0': copy.deepcopy(db_passwords),
        })

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

    def _get_novncproxy_base_url(self):
        # Get the openstack endpoint public domain name
        endpoint_domain = self._get_service_parameter(
            constants.SERVICE_TYPE_OPENSTACK,
            constants.SERVICE_PARAM_SECTION_OPENSTACK_HELM,
            constants.SERVICE_PARAM_NAME_ENDPOINT_DOMAIN)
        if endpoint_domain is not None:
            location = "%s.%s" % (self.NOVNCPROXY_SERVICE_NAME,
                                  str(endpoint_domain.value).lower())
        else:
            if self._is_ipv6_cluster_service():
                location = "[%s]:%s" % (self._get_oam_address(),
                                        self.NOVNCPROXY_NODE_PORT)
            else:
                location = "%s:%s" % (self._get_oam_address(),
                                        self.NOVNCPROXY_NODE_PORT)
        url = "%s://%s/vnc_auto.html" % (self._get_public_protocol(),
                                         location)
        return url

    def _get_virt_type(self):
        if utils.is_virtual():
            return 'qemu'
        else:
            return 'kvm'

    def _update_host_cpu_maps(self, host, default_config):
        host_cpus = self._get_host_cpu_list(host, threads=True)
        if host_cpus:
            vm_cpus = self._get_host_cpu_list(
                host, function=constants.APPLICATION_FUNCTION, threads=True)
            vm_cpu_list = [c.cpu for c in vm_cpus]
            vm_cpu_fmt = "\"%s\"" % utils.format_range_set(vm_cpu_list)
            default_config.update({'vcpu_pin_set': vm_cpu_fmt})

            shared_cpus = self._get_host_cpu_list(
                host, function=constants.SHARED_FUNCTION, threads=True)
            shared_cpu_map = {c.numa_node: c.cpu for c in shared_cpus}
            shared_cpu_fmt = "\"%s\"" % ','.join(
                "%r:%r" % (node, cpu) for node, cpu in shared_cpu_map.items())
            default_config.update({'shared_pcpu_map': shared_cpu_fmt})

    def _get_pci_pt_whitelist(self, host, iface_context):
        # Process all configured PCI passthrough interfaces and add them to
        # the list of devices to whitelist
        devices = []
        for iface in iface_context['interfaces'].values():
            if iface['ifclass'] in [constants.INTERFACE_CLASS_PCI_PASSTHROUGH]:
                port = interface.get_interface_port(iface_context, iface)
                dnames = interface._get_datanetwork_names(iface_context, iface)
                device = {
                    'address': port['pciaddr'],
                    'physical_network': dnames,
                }
                LOG.debug('_get_pci_pt_whitelist '
                          'host=%s, device=%s', host.hostname, device)
                devices.append(device)

        # Process all enabled PCI devices configured for PT and SRIOV and
        # add them to the list of devices to whitelist.
        # Since we are now properly initializing the qat driver and
        # restarting sysinv, we need to add VF devices to the regular
        # whitelist instead of the sriov whitelist
        pci_devices = self.dbapi.pci_device_get_by_host(host.id)
        for pci_device in pci_devices:
            if pci_device.enabled:
                device = {
                    'address': pci_device.pciaddr,
                }
                LOG.debug('_get_pci_pt_whitelist '
                          'host=%s, device=%s', host.hostname, device)
                devices.append(device)

        return devices

    def _get_pci_sriov_whitelist(self, host, iface_context):
        # Process all configured SRIOV interfaces and add each VF
        # to the list of devices to whitelist
        devices = []
        for iface in iface_context['interfaces'].values():
            if iface['ifclass'] in [constants.INTERFACE_CLASS_PCI_SRIOV]:
                port = interface.get_sriov_interface_port(iface_context, iface)
                dnames = interface._get_datanetwork_names(iface_context, iface)
                vf_addrs = port['sriov_vfs_pci_address'].split(",")
                vf_addrs = interface.get_sriov_interface_vf_addrs(iface_context, iface, vf_addrs)
                if vf_addrs:
                    for vf_addr in vf_addrs:
                        device = {
                            'address': vf_addr,
                            'physical_network': dnames,
                        }
                        LOG.debug('_get_pci_sriov_whitelist '
                                  'host=%s, device=%s', host.hostname, device)
                        devices.append(device)

        return devices

    def _get_pci_alias(self):
        """
        Generate multistring values containing global PCI alias
        configuration for QAT and GPU devices.

        The multistring type with list of JSON string values is used
        to generate one-line-per-entry formatting, since JSON list of
        dict is not supported by nova.
        """
        alias_config = DEFAULT_NOVA_PCI_ALIAS[:]
        LOG.debug('_get_pci_alias: aliases = %s', alias_config)
        multistring = self._oslo_multistring_override(
            name='alias', values=alias_config)
        return multistring

    def _update_host_pci_whitelist(self, host, pci_config):
        """
        Generate multistring values containing PCI passthrough
        and SR-IOV devices.

        The multistring type with list of JSON string values is used
        to generate one-line-per-entry pretty formatting.
        """
        # obtain interface information specific to this host
        iface_context = {
            'ports': interface._get_port_interface_id_index(
                self.dbapi, host),
            'interfaces': interface._get_interface_name_index(
                self.dbapi, host),
            'interfaces_datanets': interface._get_interface_name_datanets(
                self.dbapi, host),
            'addresses': interface._get_address_interface_name_index(
                self.dbapi, host),
        }

        # This host's list of PCI passthrough and SR-IOV device dictionaries
        devices = []
        devices.extend(self._get_pci_pt_whitelist(host, iface_context))
        devices.extend(self._get_pci_sriov_whitelist(host, iface_context))
        if not devices:
            return

        # Convert device list into passthrough_whitelist multistring
        multistring = self._oslo_multistring_override(
            name='passthrough_whitelist', values=devices)
        if multistring is not None:
            pci_config.update(multistring)

    def _update_host_storage(self, host, default_config, libvirt_config):
        remote_storage = False
        labels = self.dbapi.label_get_all(host.id)
        for label in labels:
            if (label.label_key == common.LABEL_REMOTE_STORAGE and
                    label.label_value == common.LABEL_VALUE_ENABLED):
                remote_storage = True
                break

        rbd_pool = constants.CEPH_POOL_EPHEMERAL_NAME
        rbd_ceph_conf = os.path.join(constants.CEPH_CONF_PATH,
                                     constants.SB_TYPE_CEPH_CONF_FILENAME)

        # If NOVA is a service on a ceph-external backend, use the ephemeral_pool
        # and ceph_conf file that are stored in that DB entry.
        # If NOVA is not on any ceph-external backend, it must be on the internal
        # ceph backend with default "ephemeral" pool and default "/etc/ceph/ceph.conf"
        # config file
        sb_list = self.dbapi.storage_backend_get_list_by_type(
            backend_type=constants.SB_TYPE_CEPH_EXTERNAL)
        if sb_list:
            for sb in sb_list:
                if constants.SB_SVC_NOVA in sb.services:
                    ceph_ext_obj = self.dbapi.storage_ceph_external_get(sb.id)
                    rbd_pool = sb.capabilities.get('ephemeral_pool')
                    rbd_ceph_conf = \
                        constants.CEPH_CONF_PATH + os.path.basename(ceph_ext_obj.ceph_conf)

        if remote_storage:
            libvirt_config.update({'images_type': 'rbd',
                                   'images_rbd_pool': rbd_pool,
                                   'images_rbd_ceph_conf': rbd_ceph_conf})
        else:
            libvirt_config.update({'images_type': 'default'})

    def _update_host_addresses(self, host, default_config, vnc_config, libvirt_config):
        interfaces = self.dbapi.iinterface_get_by_ihost(host.id)
        addresses = self.dbapi.addresses_get_by_host(host.id)
        cluster_host_network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        cluster_host_iface = None
        for iface in interfaces:
            interface_network = {'interface_id': iface.id,
                                 'network_id': cluster_host_network.id}
            try:
                self.dbapi.interface_network_query(interface_network)
                cluster_host_iface = iface
            except exception.InterfaceNetworkNotFoundByHostInterfaceNetwork:
                pass

        if cluster_host_iface is None:
            return
        cluster_host_ip = None
        ip_family = None
        for addr in addresses:
            if addr.interface_id == cluster_host_iface.id:
                cluster_host_ip = addr.address
                ip_family = addr.family

        default_config.update({'my_ip': cluster_host_ip})
        if ip_family == 4:
            vnc_config.update({'vncserver_listen': '0.0.0.0'})
        elif ip_family == 6:
            vnc_config.update({'vncserver_listen': '::0'})

        libvirt_config.update({'live_migration_inbound_addr': cluster_host_ip})
        vnc_config.update({'vncserver_proxyclient_address': cluster_host_ip})

    def _get_ssh_subnet(self):
        cluster_host_network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        address_pool = self.dbapi.address_pool_get(cluster_host_network.pool_uuid)
        return '%s/%s' % (str(address_pool.network), str(address_pool.prefix))

    def _update_reserved_memory(self, host, default_config):
        host_memory = self.dbapi.imemory_get_by_ihost(host.id)
        reserved_pages = []
        reserved_host_memory = 0
        for cell in host_memory:
            reserved_4K_pages = 'node:%d,size:4,count:%d' % (
                                cell.numa_node,
                                cell.platform_reserved_mib * constants.NUM_4K_PER_MiB)
            reserved_pages.append(reserved_4K_pages)
            # vswitch pages will be either 2M or 1G
            reserved_vswitch_pages = 'node:%d,size:%d,count:%d' % (cell.numa_node,
                                     cell.vswitch_hugepages_size_mib * constants.Ki,
                                     cell.vswitch_hugepages_nr)
            reserved_pages.append(reserved_vswitch_pages)
            reserved_host_memory += cell.platform_reserved_mib
            reserved_host_memory += cell.vswitch_hugepages_size_mib * cell.vswitch_hugepages_nr

        multistring = self._oslo_multistring_override(
            name='reserved_huge_pages', values=reserved_pages)
        if multistring is not None:
            default_config.update(multistring)
        default_config.update({'reserved_host_memory_mb': reserved_host_memory})

    def _get_interface_numa_nodes(self, context):
        # Process all ethernet interfaces with physical port and add each port numa_node to
        # the dict of interface_numa_nodes
        interface_numa_nodes = {}

        # Update the numa_node of this interface and its all used_by interfaces
        def update_iface_numa_node(iface, numa_node):
            if iface['ifname'] in interface_numa_nodes:
                interface_numa_nodes[iface['ifname']].add(numa_node)
            else:
                interface_numa_nodes[iface['ifname']] = set([numa_node])
            upper_ifnames = iface['used_by'] or []
            for upper_ifname in upper_ifnames:
                upper_iface = context['interfaces'][upper_ifname]
                update_iface_numa_node(upper_iface, numa_node)

        for iface in context['interfaces'].values():
            if iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET:
                port = context['ports'][iface['id']]
                if port and port.numa_node >= 0:
                    update_iface_numa_node(iface, port.numa_node)

        return interface_numa_nodes

    def _update_host_neutron_physnet(self, host, neutron_config, per_physnet_numa_config):
        '''
        Generate physnets configuration option and dynamically-generate
        configuration groups to enable nova feature numa-aware-vswitches.
        '''
        # obtain interface information specific to this host
        iface_context = {
            'ports': interface._get_port_interface_id_index(
                self.dbapi, host),
            'interfaces': interface._get_interface_name_index(
                self.dbapi, host),
            'interfaces_datanets': interface._get_interface_name_datanets(
                self.dbapi, host),
        }

        # find out the numa_nodes of ports which the physnet(datanetwork) is bound with
        physnet_numa_nodes = {}
        tunneled_net_numa_nodes = set()
        interface_numa_nodes = self._get_interface_numa_nodes(iface_context)
        for iface in iface_context['interfaces'].values():
            if iface['ifname'] not in interface_numa_nodes:
                continue
            # Only the physnets with valid numa_node can be insert into physnet_numa_nodes
            # or tunneled_net_numa_nodes
            if_numa_nodes = interface_numa_nodes[iface['ifname']]
            for datanet in interface.get_interface_datanets(iface_context, iface):
                if datanet['network_type'] in [constants.DATANETWORK_TYPE_FLAT,
                                                constants.DATANETWORK_TYPE_VLAN]:
                    dname = str(datanet['name'])
                    if dname in physnet_numa_nodes:
                        physnet_numa_nodes[dname] = if_numa_nodes | physnet_numa_nodes[dname]
                    else:
                        physnet_numa_nodes[dname] = if_numa_nodes
                elif datanet['network_type'] in [constants.DATANETWORK_TYPE_VXLAN]:
                    tunneled_net_numa_nodes = if_numa_nodes | tunneled_net_numa_nodes

        if physnet_numa_nodes:
            physnet_names = ','.join(physnet_numa_nodes.keys())
            neutron_config.update({'physnets': physnet_names})
            # For L2-type networks, configuration group name must be set with 'neutron_physnet_{datanet.name}'
            # For L3-type networks, configuration group name must be set with 'neutron_tunneled'
            for dname in physnet_numa_nodes.keys():
                group_name = 'neutron_physnet_' + dname
                numa_nodes = ','.join('%s' % n for n in physnet_numa_nodes[dname])
                per_physnet_numa_config.update({group_name: {'numa_nodes': numa_nodes}})
        if tunneled_net_numa_nodes:
            numa_nodes = ','.join('%s' % n for n in tunneled_net_numa_nodes)
            per_physnet_numa_config.update({'neutron_tunneled': {'numa_nodes': numa_nodes}})

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
                    default_config = {}
                    vnc_config = {}
                    libvirt_config = {}
                    pci_config = {}
                    neutron_config = {}
                    per_physnet_numa_config = {}
                    self._update_host_cpu_maps(host, default_config)
                    self._update_host_storage(host, default_config, libvirt_config)
                    self._update_host_addresses(host, default_config, vnc_config,
                                                libvirt_config)
                    self._update_host_pci_whitelist(host, pci_config)
                    self._update_reserved_memory(host, default_config)
                    self._update_host_neutron_physnet(host, neutron_config, per_physnet_numa_config)
                    host_nova = {
                        'name': hostname,
                        'conf': {
                            'nova': {
                                'DEFAULT': default_config,
                                'vnc': vnc_config,
                                'libvirt': libvirt_config,
                                'pci': pci_config if pci_config else None,
                                'neutron': neutron_config
                            }
                        }
                    }
                    host_nova['conf']['nova'].update(per_physnet_numa_config)
                    host_list.append(host_nova)
        return host_list

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)

    def _get_rbd_ephemeral_storage(self):
        ephemeral_storage_conf = {}
        ephemeral_pools = []

        # Get the values for replication and min replication from the storage
        # backend attributes.
        replication, min_replication = \
            StorageBackendConfig.get_ceph_pool_replication(self.dbapi)

        # For now, the ephemeral pool will only be on the primary Ceph tier
        rule_name = "{0}{1}{2}".format(
            constants.SB_TIER_DEFAULT_NAMES[
                constants.SB_TIER_TYPE_CEPH],
            constants.CEPH_CRUSH_TIER_SUFFIX,
            "-ruleset").replace('-', '_')

        # Form the dictionary with the info for the ephemeral pool.
        # If needed, multiple pools can be specified.
        ephemeral_pool = {
            'rbd_pool_name': constants.CEPH_POOL_EPHEMERAL_NAME,
            'rbd_user': RBD_POOL_USER,
            'rbd_crush_rule': rule_name,
            'rbd_replication': replication,
            'rbd_chunk_size': constants.CEPH_POOL_EPHEMERAL_PG_NUM
        }
        ephemeral_pools.append(ephemeral_pool)

        ephemeral_storage_conf = {
            'type': 'rbd',
            'rbd_pools': ephemeral_pools
        }

        return ephemeral_storage_conf

    def _get_network_node_port_overrides(self):
        # If openstack endpoint FQDN is configured, disable node_port 30680
        # which will enable the Ingress for the novncproxy service
        endpoint_fqdn = self._get_service_parameter(
            constants.SERVICE_TYPE_OPENSTACK,
            constants.SERVICE_PARAM_SECTION_OPENSTACK_HELM,
            constants.SERVICE_PARAM_NAME_ENDPOINT_DOMAIN)
        if endpoint_fqdn:
            return False
        else:
            return True
