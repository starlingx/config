#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class KubeRootCAHostUpdate(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,

        'target_rootca_cert': utils.str_or_none,
        'effective_rootca_cert': utils.str_or_none,
        'state': utils.str_or_none,
        'capabilities': utils.dict_or_none,
        'reserved_1': utils.str_or_none,
        'reserved_2': utils.str_or_none,
        'reserved_3': utils.str_or_none,

        'host_id': int,
        'hostname': utils.str_or_none,
        'personality': utils.str_or_none,
    }

    _foreign_fields = {
        'hostname': 'host:hostname',
        'personality': 'host:personality',
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.kube_rootca_host_update_get(uuid)

    @base.remotable_classmethod
    def get_by_host_id(cls, context, host_id):
        return cls.dbapi.kube_rootca_host_update_get_by_host(host_id)

    def save_changes(self, context, updates):
        self.dbapi.kube_rootca_host_update_update(self.uuid,  # pylint: disable=no-member
                                            updates)
