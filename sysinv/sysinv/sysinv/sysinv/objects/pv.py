#
# Copyright (c) 2013-2017, 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class PV(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,
        'pv_state': utils.str_or_none,

        'pv_type': utils.str_or_none,
        'disk_or_part_uuid': utils.str_or_none,
        'disk_or_part_device_node': utils.str_or_none,
        'disk_or_part_device_path': utils.str_or_none,

        'lvm_pv_name': utils.str_or_none,
        'lvm_vg_name': utils.str_or_none,
        'lvm_pv_uuid': utils.str_or_none,
        'lvm_pv_size': utils.int_or_none,
        'lvm_pe_total': utils.int_or_none,
        'lvm_pe_alloced': utils.int_or_none,

        'capabilities': utils.dict_or_none,

        'forihostid': utils.int_or_none,
        'ihost_uuid': utils.str_or_none,
        'forilvgid': utils.int_or_none,
        'ilvg_uuid': utils.str_or_none,
    }

    _foreign_fields = {'ihost_uuid': 'host:uuid',
                       'ilvg_uuid': 'lvg:uuid'}

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ipv_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.ipv_update(self.uuid,  # pylint: disable=no-member
                              updates)
