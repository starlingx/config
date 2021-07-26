#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class KubeCmdVersion(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
        'kubeadm_version': utils.str_or_none,
        'kubelet_version': utils.str_or_none,
    }

    @base.remotable_classmethod
    def get(cls, context):
        return cls.dbapi.kube_cmd_version_get()

    def save_changes(self, context, updates):
        self.dbapi.kube_cmd_version_update(updates)
