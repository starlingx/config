#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class CephMon(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
              'id': int,
              'uuid': utils.uuid_or_none,

              'device_path': utils.str_or_none,
              'ceph_mon_gib': utils.int_or_none,
              'state': utils.str_or_none,
              'task': utils.str_or_none,

              'forihostid': utils.int_or_none,
              'ihost_uuid': utils.str_or_none,
              'hostname': utils.str_or_none,
    }

    _foreign_fields = {
        'hostname': 'host:hostname',
        'ihost_uuid': 'host:uuid'
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ceph_mon_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.ceph_mon_update(self.uuid, updates)
