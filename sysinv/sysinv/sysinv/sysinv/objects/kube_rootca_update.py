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


class KubeRootCAUpdate(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,

        'from_rootca_cert': utils.str_or_none,
        'to_rootca_cert': utils.str_or_none,
        'state': utils.str_or_none,
        'capabilities': utils.dict_or_none,
        'reserved_1': utils.str_or_none,
        'reserved_2': utils.str_or_none,
        'reserved_3': utils.str_or_none,
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.kube_rootca_update_get(uuid)

    @base.remotable_classmethod
    def get_one(cls, context):
        return cls.dbapi.kube_rootca_update_get_one()

    def save_changes(self, context, updates):
        self.dbapi.kube_rootca_update_update(self.uuid,  # pylint: disable=no-member
                                       updates)
