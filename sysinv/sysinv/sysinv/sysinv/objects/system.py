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


class System(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,
            'name': utils.str_or_none,
            'system_type': utils.str_or_none,
            'system_mode': utils.str_or_none,
            'description': utils.str_or_none,
            'capabilities': utils.dict_or_none,
            'contact': utils.str_or_none,
            'location': utils.str_or_none,
            'services': utils.int_or_none,
            'software_version': utils.str_or_none,
            'timezone': utils.str_or_none,
            'security_profile': utils.str_or_none,
            'region_name': utils.str_or_none,
            'service_project_name': utils.str_or_none,
            'distributed_cloud_role': utils.str_or_none,
            'security_feature': utils.str_or_none,
             }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.isystem_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.isystem_update(self.uuid, updates)
