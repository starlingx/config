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


class SDNController(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {'id': utils.int_or_none,
              'uuid': utils.uuid_or_none,
              'ip_address': utils.str_or_none,
              'port': utils.int_or_none,
              'transport': utils.str_or_none,
              'state': utils.str_or_none,
              }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.sdn_controller_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.sdn_controller_update(self.uuid, updates)
