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


class Journal(base.SysinvObject):

    dbapi = db_api.get_instance()
    fields = {
              'id': int,
              'uuid': utils.str_or_none,
              'device_path': utils.str_or_none,
              'size_mib': utils.int_or_none,
              'onistor_uuid': utils.uuid_or_none,
              'foristorid': int
             }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.journal_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.journal_update(self.uuid,  # pylint: disable=no-member
                                  updates)
