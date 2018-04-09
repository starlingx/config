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


class Partition(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,

        'start_mib': utils.int_or_none,
        'end_mib': utils.int_or_none,
        'size_mib': utils.int_or_none,
        'device_path': utils.str_or_none,
        'device_node': utils.str_or_none,
        'type_guid': utils.str_or_none,
        'type_name': utils.str_or_none,
        'idisk_id': utils.int_or_none,
        'foripvid': utils.int_or_none,
        'forihostid': utils.int_or_none,
        'status': int,

        'capabilities': utils.dict_or_none,

        'idisk_uuid': utils.str_or_none,
        'ipv_uuid': utils.str_or_none,
        'ihost_uuid': utils.str_or_none,
    }

    _foreign_fields = {'ihost_uuid': 'host:uuid',
                       'ipv_uuid': 'pv:uuid'}

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.partition_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.partition_update(self.uuid, updates)
