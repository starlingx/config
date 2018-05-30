#
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class LVG(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,
        'vg_state': utils.str_or_none,

        'lvm_vg_name': utils.str_or_none,
        'lvm_vg_uuid': utils.str_or_none,
        'lvm_vg_access': utils.str_or_none,
        'lvm_max_lv': utils.int_or_none,
        'lvm_cur_lv': utils.int_or_none,
        'lvm_max_pv': utils.int_or_none,
        'lvm_cur_pv': utils.int_or_none,
        'lvm_vg_size': utils.str_or_none,
        'lvm_vg_total_pe': utils.int_or_none,
        'lvm_vg_free_pe': utils.int_or_none,

        'capabilities': utils.dict_or_none,

        'forihostid': int,
        'ihost_uuid': utils.str_or_none,
    }

    _foreign_fields = {'ihost_uuid': 'host:uuid'}

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ilvg_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.ilvg_update(self.uuid, updates)


class ilvg(LVG):
    """Alias object for RPC compatibility with older versions based on the
    old naming convention.  Object compatibility based on object version."""
    pass
