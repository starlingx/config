#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class HostFS(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,
        'name': utils.str_or_none,
        'size': utils.int_or_none,
        'logical_volume': utils.str_or_none,

        'forihostid': int,
        'ihost_uuid': utils.str_or_none,
    }

    _foreign_fields = {'ihost_uuid': 'host:uuid'}

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.host_fs_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.host_fs_update(self.uuid, updates)
