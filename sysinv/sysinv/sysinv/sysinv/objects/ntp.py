#
# Copyright (c) 2013-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class NTP(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,

            'ntpservers': utils.str_or_none,

            'forisystemid': utils.int_or_none,
            'isystem_uuid': utils.str_or_none,
             }

    _foreign_fields = {
        'isystem_uuid': 'system:uuid'
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.intp_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.intp_update(self.uuid,  # pylint: disable=no-member
                               updates)
