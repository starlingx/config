#
# Copyright (c) 2017-2019,2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import re

from sysinv.common import constants
from sysinv.common import utils
from sysinv.puppet import base


class StoragePuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for storage configuration"""

    def get_system_config(self):
        config = {}
        config.update(self._get_filesystem_config())
        return config

    def get_host_config(self, host):
        config = {}
        config.update(self._get_partition_config(host))
        config.update(self._get_lvm_config(host))
        config.update(self._get_host_fs_config(host))
        if constants.WORKER in host.subfunctions:
            config.update(self._get_worker_config(host))
        return config

    def _get_filesystem_config(self):
        config = {}

        controller_fs_list = self.dbapi.controller_fs_get_list()

        for controller_fs in controller_fs_list:
            if controller_fs.name == constants.FILESYSTEM_NAME_DATABASE:
                pgsql_gib = int(controller_fs.size) * 2
                config.update({
                    'platform::drbd::pgsql::params::lv_size': pgsql_gib
                })
            elif controller_fs.name == constants.FILESYSTEM_NAME_PLATFORM:
                config.update({
                    'platform::drbd::platform::params::lv_size': controller_fs.size
                })
            elif controller_fs.name == constants.FILESYSTEM_NAME_EXTENSION:
                config.update({
                    'platform::drbd::extension::params::lv_size':
                        controller_fs.size
                })
            elif controller_fs.name == constants.FILESYSTEM_NAME_DC_VAULT:
                config.update({
                    'platform::drbd::dc_vault::params::service_enabled':
                        True,
                    'platform::drbd::dc_vault::params::lv_size':
                        controller_fs.size,
                })
            elif controller_fs.name == constants.FILESYSTEM_NAME_ETCD:
                config.update({
                    'platform::drbd::etcd::params::lv_size':
                        controller_fs.size
                })
            elif controller_fs.name == constants.FILESYSTEM_NAME_DOCKER_DISTRIBUTION:
                config.update({
                    'platform::drbd::dockerdistribution::params::lv_size':
                        controller_fs.size
                })
            elif controller_fs.name == constants.FILESYSTEM_NAME_CEPH_DRBD:
                enabled = 'absent'
                if eval(controller_fs.state)['status'] in [
                        constants.CONTROLLER_FS_AVAILABLE,
                        constants.CONTROLLER_FS_CREATING_IN_PROGRESS,
                        constants.CONTROLLER_FS_CREATING_ON_UNLOCK,
                        constants.CONTROLLER_FS_RESIZING_IN_PROGRESS]:
                    enabled = 'present'
                config.update({
                    'platform::drbd::rook::params::ensure':
                        enabled,
                    'platform::drbd::rook::params::lv_size':
                        controller_fs.size
                })

        return config

    def _get_partition_config(self, host):
        disks = self.dbapi.idisk_get_by_ihost(host.id)
        partitions = self.dbapi.partition_get_by_ihost(host.id)

        create_actions = []
        modify_actions = []
        delete_actions = []
        check_actions = []
        shutdown_drbd_resource = None

        # Generate resource hashes that will be used to generate puppet
        # platform_manage_partition resources.  The set of data for each
        # resource instance is different depending on the specific operation
        # that needs to be performed,
        for p in partitions:
            if (p.status == constants.PARTITION_CREATE_IN_SVC_STATUS or
                    p.status == constants.PARTITION_CREATE_ON_UNLOCK_STATUS):
                partition = {
                    'req_uuid': p.uuid,
                    'ihost_uuid': p.ihost_uuid,
                    'req_guid': p.type_guid,
                    'req_size_mib': p.size_mib,
                    'part_device_path': p.device_path
                }

                for d in disks:
                    if d.uuid == p.idisk_uuid:
                        partition.update({
                            'disk_device_path': d.device_path
                        })
                        break
                create_actions.append(partition)

            elif p.status == constants.PARTITION_MODIFYING_STATUS:
                partition = {
                    'current_uuid': p.uuid,
                    'ihost_uuid': p.ihost_uuid,
                    'start_mib': p.start_mib,
                    'new_size_mib': p.size_mib,
                    'part_device_path': p.device_path,
                    'req_guid': p.type_guid,
                }
                modify_actions.append(partition)

                # Check if partition is cinder-volumes. Special care is taken
                # as this is an LVM DRBD synced partition.
                ipv_uuid = p.foripvid
                ipv = None
                if ipv_uuid:
                    ipv = self.dbapi.ipv_get(ipv_uuid)
                if ipv and ipv.lvm_vg_name == constants.LVG_CINDER_VOLUMES:
                    shutdown_drbd_resource = constants.CINDER_LVM_DRBD_RESOURCE

            elif p.status == constants.PARTITION_DELETING_STATUS:
                partition = {
                    'current_uuid': p.uuid,
                    'ihost_uuid': p.ihost_uuid,
                    'part_device_path': p.device_path,
                }
                delete_actions.append(partition)

            else:
                partition = {
                    'device_node': p.device_node,
                    'device_path': p.device_path,
                    'uuid': p.uuid,
                    'type_guid': p.type_guid,
                    'start_mib': p.start_mib,
                    'size_mib': p.size_mib,
                }
                for d in disks:
                    if d.uuid == p.idisk_uuid:
                        partition.update({
                            'disk_device_path': d.device_path
                        })
                        break
                check_actions.append(partition)

        if create_actions:
            create_config = json.dumps(create_actions)
        else:
            create_config = None

        if modify_actions:
            modify_config = json.dumps(modify_actions)
        else:
            modify_config = None

        if delete_actions:
            delete_config = json.dumps(delete_actions)
        else:
            delete_config = None

        if check_actions:
            check_config = json.dumps(check_actions)
        else:
            check_config = None

        return {
            'platform::partitions::params::create_config': create_config,
            'platform::partitions::params::modify_config': modify_config,
            'platform::partitions::params::shutdown_drbd_resource': shutdown_drbd_resource,
            'platform::partitions::params::delete_config': delete_config,
            'platform::partitions::params::check_config': check_config,
        }

    def _get_lvm_config(self, host):
        cgts_devices = []
        nova_final_devices = []
        nova_transition_devices = []
        ceph_mon_devices = []
        rook_osd_devices = []

        # LVM Global Filter is driven by:
        # - cgts-vg PVs       : all nodes
        # - cinder-volumes PVs: controllers
        # - nova-local PVs    : controllers and all workers

        # Go through the PVs and
        pvs = self.dbapi.ipv_get_by_ihost(host.id)
        for pv in pvs:
            if pv.lvm_vg_name == constants.LVG_CGTS_VG:
                # PVs for this volume group are only ever added, therefore the state of the PV doesn't matter. Make
                # sure it's added to the global filter
                cgts_devices.append(pv.disk_or_part_device_path)
            elif pv.lvm_vg_name == constants.LVG_NOVA_LOCAL:
                # Nova PV configurations may change. PVs that will be delete need to be temporarily added
                if pv.pv_state == constants.PV_DEL:
                    nova_transition_devices.append(pv.disk_or_part_device_path)
                else:
                    nova_final_devices.append(pv.disk_or_part_device_path)
            elif pv.lvm_vg_name.startswith("ceph"):
                rook_osd_devices.append(pv.disk_or_part_device_path)

        # The final_filter contain only the final global_filter devices, while the transition_filter
        # contains the transient list of removing devices as well
        final_devices = cgts_devices + nova_final_devices + ceph_mon_devices
        final_devices += rook_osd_devices
        final_filter = self._operator.storage.format_lvm_filter(final_devices)

        transition_filter = self._operator.storage.format_lvm_filter(
            list(set(nova_transition_devices + final_devices)))

        # Save the list of devices
        self.set_lvm_devices(final_devices)

        return {
            'platform::lvm::params::final_filter': final_filter,
            'platform::lvm::params::transition_filter': transition_filter,

            'platform::lvm::vg::cgts_vg::physical_volumes': cgts_devices,
            'platform::lvm::vg::nova_local::physical_volumes': nova_final_devices,
        }

    def set_lvm_devices(self, devices):
        self.context['_lvm_devices'] = devices

    def get_lvm_devices(self):
        return self.context.get('_lvm_devices', [])

    def format_lvm_filter(self, devices):
        filters = ['"a|%s|"' % f for f in devices] + ['"r|.*|"']
        return '[ %s ]' % ', '.join(filters)

    def _is_image_conversion_filesystem_enabled(self, host):
        filesystems = self.dbapi.host_fs_get_by_ihost(host.id)
        config = {}

        for fs in filesystems:
            if fs.name == constants.FILESYSTEM_NAME_IMAGE_CONVERSION:
                config.update({
                    'platform::filesystem::conversion::params::conversion_enabled': True,
                    'platform::filesystem::conversion::params::lv_size': fs.size,
                })
                return config

        config.update({
            'platform::filesystem::conversion::params::conversion_enabled': False,
        })
        return config

    def _is_instances_filesystem_enabled(self, host):
        filesystems = self.dbapi.host_fs_get_by_ihost(host.id)
        config = {}

        for fs in filesystems:
            if fs.name == constants.FILESYSTEM_NAME_INSTANCES:
                config.update({
                    'platform::filesystem::instances::params::instances_enabled': True,
                    'platform::filesystem::instances::params::lv_size': fs.size,
                })
                return config

        config.update({
            'platform::filesystem::instances::params::instances_enabled': False,
        })
        return config

    def _get_host_fs_config(self, host):
        config = {}
        conversion_config = self._is_image_conversion_filesystem_enabled(host)
        config.update(conversion_config)
        instances_config = self._is_instances_filesystem_enabled(host)
        config.update(instances_config)

        filesystems = self.dbapi.host_fs_get_by_ihost(host.id)
        for fs in filesystems:
            if fs.name == constants.FILESYSTEM_NAME_BACKUP:
                config.update({
                    'platform::filesystem::backup::params::lv_size': fs.size
                })
            elif fs.name == constants.FILESYSTEM_NAME_SCRATCH:
                config.update({
                    'platform::filesystem::scratch::params::lv_size': fs.size
                })
            elif fs.name == constants.FILESYSTEM_NAME_DOCKER:
                config.update({
                    'platform::filesystem::docker::params::lv_size': fs.size
                })
            elif fs.name == constants.FILESYSTEM_NAME_KUBELET:
                config.update({
                    'platform::filesystem::kubelet::params::lv_size': fs.size
                })
            elif fs.name == constants.FILESYSTEM_NAME_LOG:
                config.update({
                    'platform::filesystem::log::params::lv_size': fs.size
                })
            elif fs.name == constants.FILESYSTEM_NAME_VAR:
                config.update({
                    'platform::filesystem::var::params::lv_size': fs.size
                })
            elif fs.name == constants.FILESYSTEM_NAME_ROOT:
                config.update({
                    'platform::filesystem::root::params::lv_size': fs.size
                })
        return config

    def _get_worker_config(self, host):
        pvs = self.dbapi.ipv_get_by_ihost(host.id)

        final_pvs = []
        adding_pvs = []
        removing_pvs = []
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
                    pv_path = utils.get_part_device_path(pv_path, partition_number)

                if (pv.pv_state == constants.PV_ADD):
                    adding_pvs.append(pv_path)
                    final_pvs.append(pv_path)
                elif(pv.pv_state == constants.PV_DEL):
                    removing_pvs.append(pv_path)
                else:
                    final_pvs.append(pv_path)

        global_filter, update_filter = self._get_lvm_global_filter(host)

        values = {
            'platform::worker::storage::final_pvs': final_pvs,
            'platform::worker::storage::adding_pvs': adding_pvs,
            'platform::worker::storage::removing_pvs': removing_pvs,
            'platform::worker::storage::lvm_global_filter': global_filter,
            'platform::worker::storage::lvm_update_filter': update_filter}

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
