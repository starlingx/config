#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils

from sysinv.openstack.common import log
LOG = log.getLogger(__name__)


class Service(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
        'id': int,

        'enabled': utils.bool_or_none,
        'name': utils.str_or_none,
        'region_name': utils.str_or_none,
        'capabilities': utils.dict_or_none,
    }

    @base.remotable_classmethod
    def get_by_service_name(cls, context, name):
        return cls.dbapi.service_get(name)

    def save_changes(self, context, updates):
        self.dbapi.service_update(self.name, updates)
