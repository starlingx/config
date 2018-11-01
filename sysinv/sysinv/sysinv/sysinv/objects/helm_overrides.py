# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class HelmOverrides(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {'name': utils.str_or_none,
              'namespace': utils.str_or_none,
              'user_overrides': utils.str_or_none,
              'system_overrides': utils.dict_or_none,
              }

    @base.remotable_classmethod
    def get_by_name(cls, context, name, namespace):
        return cls.dbapi.helm_override_get(name, namespace)

    def save_changes(self, context, updates):
        self.dbapi.helm_override_update(self.name, self.namespace, updates)
