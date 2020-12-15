#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class PCIDevice(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,
            'host_id': utils.int_or_none,
            'host_uuid': utils.str_or_none,
            'name': utils.str_or_none,
            'pciaddr': utils.str_or_none,
            'pclass_id': utils.str_or_none,
            'pvendor_id': utils.str_or_none,
            'pdevice_id': utils.str_or_none,
            'pclass': utils.str_or_none,
            'pvendor': utils.str_or_none,
            'pdevice': utils.str_or_none,
            'psvendor': utils.str_or_none,
            'psdevice': utils.str_or_none,
            'numa_node': utils.int_or_none,
            'sriov_totalvfs': utils.int_or_none,
            'sriov_numvfs': utils.int_or_none,
            'sriov_vfs_pci_address': utils.str_or_none,
            'sriov_vf_driver': utils.str_or_none,
            'sriov_vf_pdevice_id': utils.str_or_none,
            'driver': utils.str_or_none,
            'enabled': utils.bool_or_none,
            'extra_info': utils.str_or_none,

            'bmc_build_version': utils.str_or_none,
            'bmc_fw_version': utils.str_or_none,
            'root_key': utils.str_or_none,
            'revoked_key_ids': utils.str_or_none,
            'boot_page': utils.str_or_none,
            'bitstream_id': utils.str_or_none,
             }

    _foreign_fields = {
        'host_uuid': 'host:uuid',
        'bmc_build_version': 'fpga:bmc_build_version',
        'bmc_fw_version': 'fpga:bmc_fw_version',
        'root_key': 'fpga:root_key',
        'revoked_key_ids': 'fpga:revoked_key_ids',
        'boot_page': 'fpga:boot_page',
        'bitstream_id': 'fpga:bitstream_id',
    }

    _optional_fields = {
        'bmc_build_version',
        'bmc_fw_version',
        'root_key',
        'revoked_key_ids',
        'boot_page',
        'bitstream_id',
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.pci_device_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.pci_device_update(self.uuid,  # pylint: disable=no-member
                                     updates)
