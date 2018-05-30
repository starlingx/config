#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
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
            'driver': utils.str_or_none,
            'enabled': utils.bool_or_none,
            'extra_info': utils.str_or_none,
             }

    _foreign_fields = {
        'host_uuid': 'host:uuid'
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.pci_device_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.pci_device_update(self.uuid, updates)
