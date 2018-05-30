# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils
from sysinv.common import exception


class HostUpgrade(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {'id': int,
              'uuid': utils.uuid_or_none,
              'forihostid': utils.int_or_none,
              'software_load': utils.int_or_none,
              'target_load': utils.int_or_none,
              }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.host_upgrade_get(uuid)

    @base.remotable_classmethod
    def get_by_host_id(cls, context, host_id):
        return cls.dbapi.host_upgrade_get_by_host(host_id)

    def save_changes(self, context, updates):
        self.dbapi.host_upgrade_update(self.id, updates)
