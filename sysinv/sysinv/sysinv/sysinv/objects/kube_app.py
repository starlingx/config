# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class KubeApp(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {'id': int,
              'name': utils.str_or_none,
              'app_version': utils.str_or_none,
              'manifest_name': utils.str_or_none,
              'manifest_file': utils.str_or_none,
              'status': utils.str_or_none,
              'progress': utils.str_or_none,
              'active': utils.bool_or_none,
              'recovery_attempts': utils.int_or_zero,
              'mode': utils.str_or_none,
              'app_metadata': utils.dict_or_none
              }

    @base.remotable_classmethod
    def get_by_name(cls, context, name):
        return cls.dbapi.kube_app_get(name)

    @base.remotable_classmethod
    def get_inactive_app_by_name_version(cls, context, name, version):
        return cls.dbapi.kube_app_get_inactive_by_name_version(name, version)

    def save_changes(self, context, updates):
        self.dbapi.kube_app_update(self.id,  # pylint: disable=no-member
                                   updates)
