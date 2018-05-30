#
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


class Load(base.SysinvObject):
    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,

        'state': utils.str_or_none,

        'software_version': utils.str_or_none,

        'compatible_version': utils.str_or_none,
        'required_patches': utils.str_or_none,
    }

    @base.remotable_classmethod
    def get_by_uuid(self, context, uuid):
        return self.dbapi.load_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.load_update(self.uuid, updates)
