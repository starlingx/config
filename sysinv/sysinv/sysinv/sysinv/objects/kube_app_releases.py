#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class KubeAppReleases(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {'id': int,
              'release': utils.str_or_none,
              'namespace': utils.str_or_none,
              'version': int,

              'app_id': int,
              }

    @base.remotable_classmethod
    def get_by_id(cls, context, app_id, release, namespace):
        return cls.dbapi.kube_app_chart_release_get(app_id, release, namespace)

    def save_changes(self, context, updates):
        self.dbapi.kube_app_chart_release_update(self.app_id,  # pylint: disable=no-member
                                                 self.release,  # pylint: disable=no-member
                                                 self.namespace,  # pylint: disable=no-member
                                                 updates)
