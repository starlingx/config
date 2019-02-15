#
# Copyright (c) 2018-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
import os

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import interface
from sysinv.common import utils
from sysinv.openstack.common import log as logging
from sysinv.helm import common
from sysinv.helm import openstack

LOG = logging.getLogger(__name__)


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
    {"class_id": constants.NOVA_PCI_ALIAS_GPU_CLASS,
     "name": constants.NOVA_PCI_ALIAS_GPU_NAME}
]

SERVICE_PARAM_NOVA_PCI_ALIAS = [
                constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU,
                constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU_PF,
                constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU_VF,
                constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_DH895XCC_PF,
                constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_DH895XCC_VF,
                constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_C62X_PF,
                constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_C62X_VF,
                constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_USER]


class NovaHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the nova chart"""

    CHART = constants.HELM_CHART_NOVA

    SERVICE_NAME = 'nova'
    AUTH_USERS = ['nova', 'placement']
    SERVICE_USERS = ['neutron', 'ironic']

    def get_overrides(self, namespace=None):

        ssh_privatekey, ssh_publickey = \
            self._get_or_generate_ssh_keys(self.SERVICE_NAME, common.HELM_NS_OPENSTACK)
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'pod': {
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
                'images': self._get_images_overrides(),
                'network': {
                    'sshd': {
                        'from_subnet': self._get_ssh_subnet(),
                    }
                }
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_images_overrides(self):
        heat_image = self._operator.chart_operators[
            constants.HELM_CHART_HEAT].docker_image
        return {
            'tags': {
                'bootstrap': heat_image,
                'db_drop': heat_image,
                'db_init': heat_image,
                'ks_user': heat_image,
                'ks_service': heat_image,
                'ks_endpoints': heat_image,
                'nova_api': self.docker_image,
                'nova_cell_setup': self.docker_image,
                'nova_cell_setup_init': heat_image,
                'nova_compute': self.docker_image,
                'nova_compute_ironic': self.docker_image,
                'nova_compute_ssh': self.docker_image,
                'nova_conductor': self.docker_image,
                'nova_consoleauth': self.docker_image,
                'nova_db_sync': self.docker_image,
                'nova_novncproxy': self.docker_image,
                'nova_placement': self.docker_image,
                'nova_scheduler': self.docker_image,
                'nova_spiceproxy': self.docker_image,
                'nova_spiceproxy_assets': self.docker_image
            }
        }

    def _get_endpoints_overrides(self):
        overrides = {
            'identity': {
                'name': 'keystone',
                'auth': self._get_endpoints_identity_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS),
            },
            'oslo_cache': {
                'auth': {
                    'memcached_secret_key':
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
            location = "%s.%s" % (constants.HELM_CHART_HORIZON,
                                  str(endpoint_domain.value).lower())
        else:
            location = self._get_oam_address()
        url = "http://%s:6080/vnc_auto.html" % location
        return url

    def _get_virt_type(self):
        if utils.is_virtual():
            return 'qemu'
        else:
            return 'kvm'

    def _get_host_cpu_list(self, host, function=None, threads=False):
        """
        Retreive a list of CPUs for the host, filtered by function and thread
        siblings (if supplied)
        """
        cpus = []
        for c in self.dbapi.icpu_get_by_ihost(host.id):
            if c.thread != 0 and not threads:
                continue
            if c.allocated_function == function or not function:
                cpus.append(c)
        return cpus

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
                    'class_id': pci_device.pclass_id
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
                port = interface.get_interface_port(iface_context, iface)
                dnames = interface._get_datanetwork_names(iface_context, iface)
                vf_addrs = port['sriov_vfs_pci_address']
                if vf_addrs:
                    for vf_addr in vf_addrs.split(","):
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
        service_parameters = self._get_service_parameter_configs(
            constants.SERVICE_TYPE_NOVA)

        alias_config = DEFAULT_NOVA_PCI_ALIAS[:]

        if service_parameters is not None:
            for p in SERVICE_PARAM_NOVA_PCI_ALIAS:
                value = self._service_parameter_lookup_one(
                    service_parameters,
                    constants.SERVICE_PARAM_SECTION_NOVA_PCI_ALIAS,
                    p, None)
                if value is not None:
                    # Replace any references to device_id with product_id
                    # This is to align with the requirements of the
                    # Nova PCI request alias schema.
                    # (sysinv used device_id, nova uses product_id)
                    value = value.replace("device_id", "product_id")

                    aliases = value.rstrip(';').split(';')
                    for alias_str in aliases:
                        alias = dict((str(k), str(v)) for k, v in
                                     (x.split('=') for x in
                                      alias_str.split(',')))
                        alias_config.append(alias)

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
            if addr.interface_uuid == cluster_host_iface.uuid:
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

    def _get_per_host_overrides(self):
        host_list = []
        hosts = self.dbapi.ihost_get_list()

        for host in hosts:
            if (host.invprovision in [constants.PROVISIONED,
                                      constants.PROVISIONING]):
                if constants.WORKER in utils.get_personalities(host):

                    hostname = str(host.hostname)
                    default_config = {}
                    vnc_config = {}
                    libvirt_config = {}
                    pci_config = {}
                    self._update_host_cpu_maps(host, default_config)
                    self._update_host_storage(host, default_config, libvirt_config)
                    self._update_host_addresses(host, default_config, vnc_config,
                                                libvirt_config)
                    self._update_host_pci_whitelist(host, pci_config)
                    host_nova = {
                        'name': hostname,
                        'conf': {
                            'nova': {
                                'DEFAULT': default_config,
                                'vnc': vnc_config,
                                'libvirt': libvirt_config,
                                'pci': pci_config if pci_config else None,
                            }
                        }
                    }
                    host_list.append(host_nova)
        return host_list

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)
