# Copyright (c) 2015-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class SoftwareUpgrade(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {'id': int,
              'uuid': utils.uuid_or_none,
              'state': utils.str_or_none,
              'from_load': utils.int_or_none,
              'to_load': utils.int_or_none,
              'from_release': utils.str_or_none,
              'to_release': utils.str_or_none,
              }

    _foreign_fields = {
        'from_release': 'load_from:software_version',
        'to_release': 'load_to:software_version'
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.software_upgrade_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.software_upgrade_update(self.uuid, updates)
