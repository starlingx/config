#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import os
import re
import shutil
import subprocess

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils

from sysinv.puppet import openstack
from sysinv.puppet import interface


SCHEDULER_FILTERS_COMMON = [
    'RetryFilter',
    'ComputeFilter',
    'BaremetalFilter',
    'AvailabilityZoneFilter',
    'AggregateInstanceExtraSpecsFilter',
    'RamFilter',
    'ComputeCapabilitiesFilter',
    'ImagePropertiesFilter',
    'CoreFilter',
    'VCpuModelFilter',
    'NUMATopologyFilter',
    'ServerGroupAffinityFilter',
    'ServerGroupAntiAffinityFilter',
    'PciPassthroughFilter',
    'DiskFilter',
    'AggregateProviderNetworkFilter',
]

SCHEDULER_FILTERS_STANDARD = [
]

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


class NovaPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for nova configuration"""

    SERVICE_NAME = 'nova'
    SERVICE_PORT = 8774
    SERVICE_PATH = 'v2.1/%(tenant_id)s'
    SERVICE_API_NAME = 'nova-api'
    SERVICE_API_PORT = 18774
    DATABASE_NOVA_API = 'nova_api'
    SERVICE_METADATA = 'nova-metadata'
    PLACEMENT_NAME = 'placement'
    PLACEMENT_PORT = 8778
    SERIALPROXY_PORT = 6083

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)

        api_dbuser = self._get_database_username(self.SERVICE_API_NAME)

        return {
            'nova::db::postgresql::user': dbuser,

            'nova::db::postgresql_api::user': api_dbuser,
        }

    def get_secure_static_config(self):
        ssh_config_dir = os.path.join(self.CONFIG_WORKDIR, 'ssh_config')
        migration_key = os.path.join(ssh_config_dir, 'nova_migration_key')
        system_host_key = os.path.join(ssh_config_dir, 'system_host_key')

        # Generate the keys.
        if os.path.exists(ssh_config_dir):
            shutil.rmtree(ssh_config_dir)

        os.makedirs(ssh_config_dir)

        try:
            cmd = ['ssh-keygen', '-t', 'rsa', '-b' '2048', '-N', '',
                   '-f', migration_key]
            with open(os.devnull, "w") as fnull:
                subprocess.check_call(cmd, stdout=fnull, stderr=fnull)
        except subprocess.CalledProcessError:
            raise exception.SysinvException('Failed to generate nova rsa key')

        # Generate an ecdsa key for the system, which will be used on all
        # controller/worker nodes. When external ssh connections to the
        # controllers are made, this key will be stored in the known_hosts file
        # and allow connections after the controller swacts. The ecdsa key
        # has precedence over the rsa key, which is why we use ecdsa.
        try:
            cmd = ['ssh-keygen', '-t', 'ecdsa', '-b', '256', '-N', '',
                   '-f', system_host_key]
            with open(os.devnull, "w") as fnull:
                subprocess.check_call(cmd, stdout=fnull, stderr=fnull)
        except subprocess.CalledProcessError:
            raise exception.SysinvException(
                'Failed to generate nova ecdsa key')

        # Read the public/private migration keys
        with open(migration_key) as fp:
            migration_private = fp.read().strip()
        with open('%s.pub' % migration_key) as fp:
            migration_header, migration_public, _ = fp.read().strip().split()

        # Read the public/private host keys
        with open(system_host_key) as fp:
            host_private = fp.read().strip()
        with open('%s.pub' % system_host_key) as fp:
            host_header, host_public, _ = fp.read().strip().split()

        # Add our pre-generated system host key to /etc/ssh/ssh_known_hosts
        ssh_keys = {
            'system_host_key': {
                'ensure': 'present',
                'name': '*',
                'host_aliases': [],
                'type': host_header,
                'key': host_public
            }
        }

        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)
        kspass_placement = self._get_service_password(self.PLACEMENT_NAME)

        api_dbpass = self._get_database_password(self.SERVICE_API_NAME)

        return {
            'nova::db::postgresql::password': dbpass,

            'nova::db::postgresql_api::password': api_dbpass,

            'nova::keystone::auth::password': kspass,

            'nova::keystone::auth_placement::password': kspass_placement,

            'nova::keystone::authtoken::password': kspass,

            'nova::api::neutron_metadata_proxy_shared_secret':
                self._get_service_password(self.SERVICE_METADATA),

            'nova_api_proxy::config::admin_password': kspass,

            'nova::network::neutron::neutron_password':
                self._get_neutron_password(),

            'nova::placement::password': self._get_placement_password(),

            'openstack::nova::compute::ssh_keys': ssh_keys,
            'openstack::nova::compute::host_key_type': 'ssh-ecdsa',
            'openstack::nova::compute::host_private_key': host_private,
            'openstack::nova::compute::host_public_key': host_public,
            'openstack::nova::compute::host_public_header': host_header,
            'openstack::nova::compute::migration_key_type': 'ssh-rsa',
            'openstack::nova::compute::migration_private_key':
                migration_private,
            'openstack::nova::compute::migration_public_key':
                migration_public,
        }

    def get_system_config(self):
        system = self._get_system()

        scheduler_filters = SCHEDULER_FILTERS_COMMON
        if system.system_type == constants.TIS_STD_BUILD:
            scheduler_filters.extend(SCHEDULER_FILTERS_STANDARD)

        glance_host = self._operator.glance.get_glance_address()

        ksuser = self._get_service_user_name(self.SERVICE_NAME)

        config = {
            'nova::glance_api_servers':
                self._operator.glance.get_glance_url(),
            'nova::os_region_name':
                self._operator.cinder.get_region_name(),

            'nova::keystone::auth::region': self._region_name(),
            'nova::keystone::auth::public_url': self.get_public_url(),
            'nova::keystone::auth::internal_url': self.get_internal_url(),
            'nova::keystone::auth::admin_url': self.get_admin_url(),
            'nova::keystone::auth::auth_name': ksuser,
            'nova::keystone::auth::tenant': self._get_service_tenant_name(),

            'nova::keystone::auth_placement::region':
                self._region_name(),
            'nova::keystone::auth_placement::public_url':
                self.get_placement_public_url(),
            'nova::keystone::auth_placement::internal_url':
                self.get_placement_internal_url(),
            'nova::keystone::auth_placement::admin_url':
                self.get_placement_admin_url(),
            'nova::keystone::auth_placement::auth_name':
                self._get_service_user_name(self.PLACEMENT_NAME),
            'nova::keystone::auth_placement::tenant':
                self._get_service_tenant_name(),

            'nova::keystone::authtoken::auth_url':
                self._keystone_identity_uri(),
            'nova::keystone::authtoken::auth_uri':
                self._keystone_auth_uri(),
            'nova::keystone::authtoken::region_name':
                self._keystone_region_name(),
            'nova::keystone::authtoken::project_name':
                self._get_service_tenant_name(),
            'nova::keystone::authtoken::user_domain_name':
                self._get_service_user_domain_name(),
            'nova::keystone::authtoken::project_domain_name':
                self._get_service_project_domain_name(),
            'nova::keystone::authtoken::username': ksuser,

            'nova::network::neutron::neutron_url':
                self._operator.neutron.get_internal_url(),
            'nova::network::neutron::neutron_auth_url':
                self._keystone_identity_uri(),
            'nova::network::neutron::neutron_username':
                self._get_neutron_user_name(),
            'nova::network::neutron::neutron_region_name':
                self._operator.neutron.get_region_name(),
            'nova::network::neutron::neutron_project_name':
                self._get_service_tenant_name(),
            'nova::network::neutron::neutron_user_domain_name':
                self._get_service_user_domain_name(),
            'nova::network::neutron::neutron_project_domain_name':
                self._get_service_project_domain_name(),

            'nova::placement::auth_url':
                self._keystone_identity_uri(),
            'nova::placement::username':
                self._get_placement_user_name(),
            'nova::placement::os_region_name':
                self.get_placement_region_name(),
            'nova::placement::project_name':
                self._get_service_tenant_name(),

            'nova::scheduler::filter::scheduler_default_filters':
                scheduler_filters,

            'nova::vncproxy::host': self._get_management_address(),
            'nova::serialproxy::serialproxy_host': self._get_management_address(),

            'nova::api::api_bind_address': self._get_management_address(),
            'nova::api::metadata_listen': self._get_management_address(),
            'nova::api::glance_host': glance_host,
            'nova::api::compute_link_prefix':
                self._get_compute_url(),
            'nova::api::glance_link_prefix':
                self._operator.glance.get_public_url(),

            'openstack::nova::params::region_name':
                self.get_region_name(),

            'nova_api_proxy::config::osapi_compute_listen':
                self._get_management_address(),
            'nova_api_proxy::config::osapi_proxy_listen':
                self._get_management_address(),
            'nova_api_proxy::config::admin_user': ksuser,
            'nova_api_proxy::config::user_domain_name':
                self._get_service_user_domain_name(),
            'nova_api_proxy::config::project_domain_name':
                self._get_service_project_domain_name(),
            'nova_api_proxy::config::admin_tenant_name':
                self._get_service_tenant_name(),
            'nova_api_proxy::config::auth_uri':
                self._keystone_auth_uri(),
            'nova_api_proxy::config::identity_uri':
                self._keystone_identity_uri(),

            'nova::compute::vncproxy_host':
                self._get_oam_address(),

            # NOTE(knasim): since the HAPROXY frontend for the
            # VNC proxy is always over HTTP, the reverse path proxy
            # should always be over HTTP, despite the public protocol
            'nova::compute::vncproxy_protocol':
                self._get_private_protocol(),

            'nova::pci::aliases': self._get_pci_alias(),
            'openstack::nova::params::service_create': self._to_create_services(),

            'nova::compute::serial::base_url':
                self._get_nova_serial_baseurl(),
            'nova::compute::serial::proxyclient_address':
                self._get_management_address(),
        }

        # no need to configure nova endpoint as the proxy provides
        # the endpoints in SystemController
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
            config.update({
                'nova::keystone::auth::configure_endpoint': False,
                'nova::keystone::auth_placement::configure_endpoint': False,
                'openstack::nova::params::configure_endpoint': False,
            })

        return config

    def get_secure_system_config(self):
        config = {
            'nova::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
            'nova::api_database_connection':
                self._format_database_connection(
                    self.SERVICE_API_NAME, database=self.DATABASE_NOVA_API),
        }

        return config

    def get_host_config(self, host):
        config = {}
        if constants.WORKER in host.subfunctions:
            # nova storage and compute configuration is required for hosts
            # with a compute function only
            config.update(self._get_compute_config(host))
            config.update(self._get_storage_config(host))
        return config

    def get_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT,
                                            path=self.SERVICE_PATH)

    def get_internal_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT,
                                             path=self.SERVICE_PATH)

    def get_admin_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT,
                                             path=self.SERVICE_PATH)

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)

    def get_placement_public_url(self):
        return self._format_public_endpoint(self.PLACEMENT_PORT)

    def get_placement_internal_url(self):
        return self._format_private_endpoint(self.PLACEMENT_PORT)

    def get_placement_admin_url(self):
        return self._format_private_endpoint(self.PLACEMENT_PORT)

    def get_placement_region_name(self):
        return self._get_service_region_name(self.PLACEMENT_NAME)

    def _get_compute_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT)

    def _get_neutron_password(self):
        return self._get_service_password(self._operator.neutron.SERVICE_NAME)

    def _get_placement_password(self):
        return self._get_service_password(self.PLACEMENT_NAME)

    def _get_neutron_user_name(self):
        return self._get_service_user_name(self._operator.neutron.SERVICE_NAME)

    def _get_placement_user_name(self):
        return self._get_service_user_name(self.PLACEMENT_NAME)

    def _get_pci_alias(self):
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

        return alias_config

    def _get_compute_config(self, host):
        return {
            'nova::compute::enabled': self._enable_nova_compute(),
            'nova::compute::libvirt::manage_libvirt_services':
                self._enable_nova_compute(),
            'nova::migration::libvirt::configure_libvirt':
                self._enable_nova_compute(),
            'nova::compute::compute_reserved_vm_memory_2M':
                self._get_reserved_memory_2M(host),
            'nova::compute::compute_reserved_vm_memory_1G':
                self._get_reserved_memory_1G(host),
            'nova::compute::vcpu_pin_set':
                self._get_vcpu_pin_set(host),
            'nova::compute::shared_pcpu_map':
                self._get_shared_pcpu_map(host),

            'openstack::nova::compute::pci::pci_pt_whitelist':
                self._get_pci_pt_whitelist(host),
            'openstack::nova::compute::pci::pci_sriov_whitelist':
                self._get_pci_sriov_whitelist(host),
            'openstack::nova::compute::iscsi_initiator_name':
                host.iscsi_initiator_name
        }

    def _get_storage_config(self, host):
        pvs = self.dbapi.ipv_get_by_ihost(host.id)

        instance_backing = constants.LVG_NOVA_BACKING_IMAGE
        concurrent_disk_operations = constants.LVG_NOVA_PARAM_DISK_OPS_DEFAULT

        final_pvs = []
        adding_pvs = []
        removing_pvs = []
        nova_lvg_uuid = None
        for pv in pvs:
            if (pv.lvm_vg_name == constants.LVG_NOVA_LOCAL and
                    pv.pv_state != constants.PV_ERR):
                pv_path = pv.disk_or_part_device_path
                if (pv.pv_type == constants.PV_TYPE_PARTITION and
                        '-part' not in pv.disk_or_part_device_path and
                        '-part' not in pv.lvm_vg_name):
                    # add the disk partition to the disk path
                    partition_number = re.match('.*?([0-9]+)$',
                                                pv.lvm_pv_name).group(1)
                    pv_path += "-part%s" % partition_number

                if (pv.pv_state == constants.PV_ADD):
                    adding_pvs.append(pv_path)
                    final_pvs.append(pv_path)
                elif(pv.pv_state == constants.PV_DEL):
                    removing_pvs.append(pv_path)
                else:
                    final_pvs.append(pv_path)
                nova_lvg_uuid = pv.ilvg_uuid

        if nova_lvg_uuid:
            lvg = self.dbapi.ilvg_get(nova_lvg_uuid)

            instance_backing = lvg.capabilities.get(
                constants.LVG_NOVA_PARAM_BACKING)
            concurrent_disk_operations = lvg.capabilities.get(
                constants.LVG_NOVA_PARAM_DISK_OPS)

        global_filter, update_filter = self._get_lvm_global_filter(host)

        values = {
            'openstack::nova::storage::final_pvs': final_pvs,
            'openstack::nova::storage::adding_pvs': adding_pvs,
            'openstack::nova::storage::removing_pvs': removing_pvs,
            'openstack::nova::storage::lvm_global_filter': global_filter,
            'openstack::nova::storage::lvm_update_filter': update_filter,
            'openstack::nova::storage::instance_backing': instance_backing,
            'openstack::nova::storage::concurrent_disk_operations':
                concurrent_disk_operations, }

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
                    images_rbd_pool = sb.capabilities.get('ephemeral_pool')
                    images_rbd_ceph_conf = \
                        constants.CEPH_CONF_PATH + os.path.basename(ceph_ext_obj.ceph_conf)

                    values.update({'openstack::nova::storage::images_rbd_pool':
                                   images_rbd_pool,
                                   'openstack::nova::storage::images_rbd_ceph_conf':
                                   images_rbd_ceph_conf, })
        return values

    # TODO(oponcea): Make lvm global_filter generic
    def _get_lvm_global_filter(self, host):
        # Always include the global LVM devices in the final list of devices
        filtered_disks = self._operator.storage.get_lvm_devices()
        removing_disks = []

        # add nova-local filter
        pvs = self.dbapi.ipv_get_by_ihost(host.id)
        for pv in pvs:
            if pv.lvm_vg_name == constants.LVG_NOVA_LOCAL:
                if pv.pv_state == constants.PV_DEL:
                    removing_disks.append(pv.disk_or_part_device_path)
                else:
                    filtered_disks.append(pv.disk_or_part_device_path)
            elif pv.lvm_vg_name == constants.LVG_CINDER_VOLUMES:
                if constants.CINDER_DRBD_DEVICE not in filtered_disks:
                    filtered_disks.append(constants.CINDER_DRBD_DEVICE)

        # The global filters contain only the final disks, while the update
        # filter contains the transient list of removing disks as well
        global_filter = self._operator.storage.format_lvm_filter(
            list(set(filtered_disks)))

        update_filter = self._operator.storage.format_lvm_filter(
            list(set(removing_disks + filtered_disks)))

        return global_filter, update_filter

    def _get_reserved_memory_2M(self, host):
        host_memory = self.dbapi.imemory_get_by_ihost(host.id)

        memory_nodes = []
        for memory in host_memory:
            if isinstance(memory.vm_hugepages_nr_2M_pending, int):
                memory_node = "\"node%d:%dkB:%d\"" % (
                    memory.numa_node, 1024 * 2,  # 2M pages
                    memory.vm_hugepages_nr_2M_pending)
                memory_nodes.append(memory_node)

        return "(%s)" % ' '.join(memory_nodes)

    def _get_reserved_memory_1G(self, host):
        host_memory = self.dbapi.imemory_get_by_ihost(host.id)

        memory_nodes = []
        for memory in host_memory:
            if isinstance(memory.vm_hugepages_nr_1G_pending, int):
                memory_node = "\"node%d:%dkB:%d\"" % (
                    memory.numa_node, 1024 * 1024,  # 1G pages
                    memory.vm_hugepages_nr_1G_pending)
                memory_nodes.append(memory_node)

        return "(%s)" % ' '.join(memory_nodes)

    def _get_vcpu_pin_set(self, host):
        vm_cpus = self._get_host_cpu_list(
            host, function=constants.APPLICATION_FUNCTION, threads=True)
        cpu_list = [c.cpu for c in vm_cpus]
        return "\"%s\"" % utils.format_range_set(cpu_list)

    def _get_shared_pcpu_map(self, host):
        shared_cpus = self._get_host_cpu_list(
            host, function=constants.SHARED_FUNCTION, threads=True)
        cpu_map = {c.numa_node: c.cpu for c in shared_cpus}
        return "\"%s\"" % ','.join(
            "%r:%r" % (node, cpu) for node, cpu in cpu_map.items())

    def _get_pci_pt_whitelist(self, host):
        # Process all configured PCI passthrough interfaces and add them to
        # the list of devices to whitelist
        devices = []
        for iface in self.context['interfaces'].values():
            if iface['ifclass'] in [constants.INTERFACE_CLASS_PCI_PASSTHROUGH]:
                port = interface.get_interface_port(self.context, iface)
                device = {
                    'address': port['pciaddr'],
                    'physical_network': iface['providernetworks']
                }
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
                devices.append(device)

        return json.dumps(devices)

    def _get_pci_sriov_whitelist(self, host):
        # Process all configured SRIOV passthrough interfaces and add them to
        # the list of devices to whitelist
        devices = []
        for iface in self.context['interfaces'].values():
            if iface['ifclass'] in [constants.INTERFACE_CLASS_PCI_SRIOV]:
                port = interface.get_interface_port(self.context, iface)
                device = {
                    'address': port['pciaddr'],
                    'physical_network': iface['providernetworks'],
                    'sriov_numvfs': iface['sriov_numvfs']
                }
                devices.append(device)

        return json.dumps(devices) if devices else None

    def _get_nova_serial_baseurl(self):
        oam_addr = self._format_url_address(self._get_oam_address())
        ws_protocol = 'ws'
        url = "%s://%s:%s" % (ws_protocol, str(oam_addr), str(self.SERIALPROXY_PORT))
        return url

    def _enable_nova_compute(self):
        if self._kubernetes_enabled():
            return False
        else:
            return True
