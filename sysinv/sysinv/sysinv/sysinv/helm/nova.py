#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
import os

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils
from sysinv.openstack.common import log as logging
from sysinv.helm import common
from sysinv.helm import openstack

LOG = logging.getLogger(__name__)


SCHEDULER_FILTERS_COMMON = [
    'RetryFilter',
    'ComputeFilter',
    'BaremetalFilter',
    'AvailabilityZoneFilter',
    'AggregateInstanceExtraSpecsFilter',
    'ComputeCapabilitiesFilter',
    'ImagePropertiesFilter',
    'VCpuModelFilter',
    'NUMATopologyFilter',
    'ServerGroupAffinityFilter',
    'ServerGroupAntiAffinityFilter',
    'PciPassthroughFilter',
    'DiskFilter',
]


class NovaHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the nova chart"""

    CHART = constants.HELM_CHART_NOVA

    SERVICE_NAME = 'nova'
    AUTH_USERS = ['nova', 'placement']
    SERVICE_USERS = ['neutron', 'ironic']

    def get_overrides(self, namespace=None):
        scheduler_filters = SCHEDULER_FILTERS_COMMON

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
                        # set replicas for novncproxy once it's validated.
                    },
                    'user': {
                        'nova': {
                            'uid': 0
                        }
                    }
                },
                'manifests': {
                    'cron_job_cell_setup': False,
                    'cron_job_service_cleaner': False
                },
                'conf': {
                    'ceph': {
                        'enabled': True
                    },
                    'nova': {
                        'DEFAULT': {
                            'default_mempages_size': 2048,
                            'reserved_host_memory_mb': 0,
                            'compute_monitors': 'cpu.virt_driver',
                            'running_deleted_instance_poll_interval': 60,
                            'mkisofs_cmd': '/usr/bin/genisoimage',
                            'network_allocate_retries': 2,
                            'force_raw_images': False,
                            'concurrent_disk_operations': 2,
                            # Set number of block device allocate retries and interval
                            # for volume create when VM boots and creates a new volume.
                            # The total block allocate retries time is set to 2 hours
                            # to satisfy the volume allocation time on slow RPM disks
                            # which may take 1 hour and a half per volume when several
                            # volumes are created in parallel.
                            'block_device_allocate_retries_interval': 3,
                            'block_device_allocate_retries': 2400,
                            'disk_allocation_ratio': 1.0,
                            'cpu_allocation_ratio': 16.0,
                            'ram_allocation_ratio': 1.0,
                            'remove_unused_original_minimum_age_seconds': 3600,
                            'enable_new_services': False,
                            'map_new_hosts': False
                        },
                        'libvirt': {
                            'virt_type': self._get_virt_type(),
                            'cpu_mode': 'none',
                            'live_migration_completion_timeout': 180,
                            'live_migration_permit_auto_converge': True,
                            'mem_stats_period_seconds': 0,
                            'rbd_secret_uuid': None,
                            'rbd_user': None,
                            # Allow up to 1 day for resize confirm
                            'remove_unused_resized_minimum_age_seconds': 86400
                        },
                        'database': {
                            'max_overflow': 64,
                            'idle_timeout': 60,
                            'max_pool_size': 1
                        },
                        'api_database': {
                            'max_overflow': 64,
                            'idle_timeout': 60,
                            'max_pool_size': 1
                        },
                        'cell0_database': {
                            'max_overflow': 64,
                            'idle_timeout': 60,
                            'max_pool_size': 1
                        },
                        'placement': {
                            'os_interface': 'internal'
                        },
                        'neutron': {
                            'default_floating_pool': 'public'
                        },
                        'notifications': {
                            'notification_format': 'unversioned'
                        },
                        'filter_scheduler': {
                            'enabled_filters': scheduler_filters,
                            'ram_weight_multiplier': 0.0,
                            'disk_weight_multiplier': 0.0,
                            'io_ops_weight_multiplier': -5.0,
                            'pci_weight_multiplier': 0.0,
                            'soft_affinity_weight_multiplier': 0.0,
                            'soft_anti_affinity_weight_multiplier': 0.0
                        },
                        'scheduler': {
                            'periodic_task_interval': -1,
                            'discover_hosts_in_cells_interval': 30
                        },
                        'metrics': {
                            'required': False,
                            'weight_setting_multi': 'vswitch.multi_avail=100.0',
                            'weight_setting': 'vswitch.max_avail=100.0'
                        },
                        'vnc': {
                            'novncproxy_base_url': self._get_novncproxy_base_url(),
                        },
                        'upgrade_levels': 'None'
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
                        'enabled': True,
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
        oam_addr = self._get_oam_address(),
        url = "http://%s:6080/vnc_auto.html" % oam_addr
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

    def _update_host_memory(self, host, default_config):
        vswitch_2M_pages = []
        vswitch_1G_pages = []
        vm_4K_pages = []
        # The retrieved information is not necessarily ordered by numa node.
        host_memory = self.dbapi.imemory_get_by_ihost(host.id)
        # This makes it ordered by numa node.
        memory_numa_list = utils.get_numa_index_list(host_memory)
        # Process them in order of numa node.
        for node, memory_list in memory_numa_list.items():
            memory = memory_list[0]
            # first the 4K memory
            vm_hugepages_nr_4K = memory.vm_hugepages_nr_4K if (
                    memory.vm_hugepages_nr_4K is not None) else 0
            vm_4K_pages.append(vm_hugepages_nr_4K)
            # Now the vswitch memory of each hugepage size.
            vswitch_2M_page = 0
            vswitch_1G_page = 0
            if memory.vswitch_hugepages_size_mib == constants.MIB_2M:
                vswitch_2M_page = memory.vswitch_hugepages_nr
            elif memory.vswitch_hugepages_size_mib == constants.MIB_1G:
                vswitch_1G_page = memory.vswitch_hugepages_nr
            vswitch_2M_pages.append(vswitch_2M_page)
            vswitch_1G_pages.append(vswitch_1G_page)
        # Build up the config values.
        vswitch_2M = "\"%s\"" % ','.join([str(i) for i in vswitch_2M_pages])
        vswitch_1G = "\"%s\"" % ','.join([str(i) for i in vswitch_1G_pages])
        vm_4K = "\"%s\"" % ','.join([str(i) for i in vm_4K_pages])
        # Add the new entries to the DEFAULT config section.
        default_config.update({
            'compute_vm_4K_pages': vm_4K,
            'compute_vswitch_2M_pages': vswitch_2M,
            'compute_vswitch_1G_pages': vswitch_1G,
        })

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
                    self._update_host_cpu_maps(host, default_config)
                    self._update_host_storage(host, default_config, libvirt_config)
                    self._update_host_addresses(host, default_config, vnc_config,
                                                libvirt_config)
                    self._update_host_memory(host, default_config)
                    host_nova = {
                        'name': hostname,
                        'conf': {
                            'nova': {
                                'DEFAULT': default_config,
                                'vnc': vnc_config,
                                'libvirt': libvirt_config,
                            }
                        }
                    }
                    host_list.append(host_nova)
        return host_list

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)
