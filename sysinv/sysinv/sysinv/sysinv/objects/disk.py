#
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class Disk(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,

            'device_node': utils.str_or_none,
            'device_num': utils.int_or_none,
            'device_id': utils.str_or_none,
            'device_path': utils.str_or_none,
            'device_wwn': utils.str_or_none,
            'device_type': utils.str_or_none,
            'size_mib': utils.int_or_none,
            'available_mib': utils.int_or_none,
            'serial_id': utils.str_or_none,

            'capabilities': utils.dict_or_none,

            'forihostid': int,
            'ihost_uuid': utils.str_or_none,
            'foristorid': utils.int_or_none,
            'istor_uuid': utils.str_or_none,
            'foripvid': utils.int_or_none,
            'ipv_uuid': utils.str_or_none,
            'rpm': utils.str_or_none,
             }

    _foreign_fields = {'ihost_uuid': 'host:uuid',
                       'istor_uuid': 'stor:uuid',
                       'ipv_uuid': 'pv:uuid'}

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.idisk_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.idisk_update(self.uuid, updates)
