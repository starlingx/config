#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class FPGADevice(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,
        'host_id': utils.int_or_none,
        'host_uuid': utils.str_or_none,
        'pci_id': utils.int_or_none,
        'pciaddr': utils.str_or_none,
        'bmc_build_version': utils.str_or_none,
        'bmc_fw_version': utils.str_or_none,
        'retimer_a_version': utils.str_or_none,
        'retimer_b_version': utils.str_or_none,
        'root_key': utils.str_or_none,
        'revoked_key_ids': utils.str_or_none,
        'boot_page': utils.str_or_none,
        'bitstream_id': utils.str_or_none,
    }

    _foreign_fields = {
        'host_uuid': 'host:uuid'
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.fpga_device_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.fpga_device_update(self.uuid,  # pylint: disable=no-member
                                      updates)
