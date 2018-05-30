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


class ServiceParameter(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {'uuid': utils.uuid_or_none,
              'service': utils.str_or_none,
              'section': utils.str_or_none,
              'name': utils.str_or_none,
              'value': utils.str_or_none,
              'personality': utils.str_or_none,
              'resource': utils.str_or_none,
              }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.service_parameter_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.service_parameter_update(self.uuid, updates)
