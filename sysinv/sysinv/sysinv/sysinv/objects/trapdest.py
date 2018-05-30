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


class TrapDest(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,
        'ip_address': utils.str_or_none,
        'community': utils.str_or_none,
        'port': utils.int_or_none,
        'type': utils.str_or_none,
        'transport': utils.str_or_none,
         }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.itrapdest_get(uuid)

    @base.remotable_classmethod
    def get_by_ip(cls, context, ip):
        return cls.dbapi.itrapdest_get_by_ip(ip)

    def save_changes(self, context, updates):
        self.dbapi.itrapdest_update(self.uuid, updates)
