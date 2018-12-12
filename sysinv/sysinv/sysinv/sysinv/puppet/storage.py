#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json

from sysinv.common import constants

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
        return config

    def _get_filesystem_config(self):
        config = {}

        controller_fs_list = self.dbapi.controller_fs_get_list()
        for controller_fs in controller_fs_list:
            if controller_fs.name == constants.FILESYSTEM_NAME_BACKUP:
                config.update({
                    'platform::filesystem::backup::params::lv_size':
                        controller_fs.size
                })
            elif controller_fs.name == constants.FILESYSTEM_NAME_SCRATCH:
                config.update({
                    'platform::filesystem::scratch::params::lv_size':
                        controller_fs.size
                })
            elif controller_fs.name == constants.FILESYSTEM_NAME_DATABASE:
                pgsql_gib = int(controller_fs.size) * 2
                config.update({
                    'platform::drbd::pgsql::params::lv_size': pgsql_gib
                })
            elif controller_fs.name == constants.FILESYSTEM_NAME_CGCS:
                config.update({
                    'platform::drbd::cgcs::params::lv_size': controller_fs.size
                })
            elif controller_fs.name == constants.FILESYSTEM_NAME_EXTENSION:
                config.update({
                    'platform::drbd::extension::params::lv_size':
                        controller_fs.size
                })
            elif controller_fs.name == constants.FILESYSTEM_NAME_IMG_CONVERSIONS:
                config.update({
                    'platform::filesystem::img_conversions::params::lv_size':
                        controller_fs.size
                })
            elif controller_fs.name == constants.FILESYSTEM_NAME_PATCH_VAULT:
                config.update({
                    'platform::drbd::patch_vault::params::service_enabled':
                        True,
                    'platform::drbd::patch_vault::params::lv_size':
                        controller_fs.size,
                })
            elif controller_fs.name == constants.FILESYSTEM_NAME_DOCKER:
                config.update({
                    'platform::filesystem::docker::params::lv_size':
                        controller_fs.size
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
            elif controller_fs.name == constants.FILESYSTEM_NAME_GNOCCHI:
                config.update({
                    'platform::filesystem::gnocchi::params::lv_size':
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
        cinder_devices = []
        ceph_mon_devices = []

        # LVM Global Filter is driven by:
        # - cgts-vg PVs       : controllers and all storage
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
            elif pv.lvm_vg_name == constants.LVG_CINDER_VOLUMES:
                if constants.CINDER_DRBD_DEVICE not in cinder_devices:
                    cinder_devices.append(constants.CINDER_DRBD_DEVICE)

        # The final_filter contain only the final global_filter devices, while the transition_filter
        # contains the transient list of removing devices as well
        final_devices = cgts_devices + cinder_devices + nova_final_devices + ceph_mon_devices
        final_filter = self._operator.storage.format_lvm_filter(final_devices)

        transition_filter = self._operator.storage.format_lvm_filter(
            list(set(nova_transition_devices + final_devices)))

        # Save the list of devices
        self.set_lvm_devices(final_devices)

        return {
            'platform::lvm::params::final_filter': final_filter,
            'platform::lvm::params::transition_filter': transition_filter,

            'platform::lvm::vg::cgts_vg::physical_volumes': cgts_devices,
            'platform::lvm::vg::cinder_volumes::physical_volumes': cinder_devices,
            'platform::lvm::vg::nova_local::physical_volumes': nova_final_devices,
        }

    def set_lvm_devices(self, devices):
        self.context['_lvm_devices'] = devices

    def get_lvm_devices(self):
        return self.context.get('_lvm_devices', [])

    def format_lvm_filter(self, devices):
        filters = ['"a|%s|"' % f for f in devices] + ['"r|.*|"']
        return '[ %s ]' % ', '.join(filters)
