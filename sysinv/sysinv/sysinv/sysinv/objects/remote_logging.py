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


class RemoteLogging(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,

        'enabled': utils.bool_or_none,
        'transport': utils.str_or_none,
        'ip_address': utils.str_or_none,
        'port': utils.str_or_none,
        'key_file': utils.str_or_none,
        'isystem_uuid': utils.str_or_none,
        'system_id': utils.int_or_none
    }

    _foreign_fields = {
        'isystem_uuid': 'system:uuid'
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.remotelogging_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.remotelogging_update(self.uuid,  # pylint: disable=no-member
                                        updates)
