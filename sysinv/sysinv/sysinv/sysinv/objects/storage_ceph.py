#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils
from sysinv.objects import storage_backend


class StorageCeph(storage_backend.StorageBackend):

    dbapi = db_api.get_instance()

    fields = dict({
        'cinder_pool_gib': utils.int_or_none,
        'glance_pool_gib': utils.int_or_none,
        'ephemeral_pool_gib': utils.int_or_none,
        'object_pool_gib': utils.int_or_none,
        'kube_pool_gib': utils.int_or_none,
        'object_gateway': utils.bool_or_none,
        'tier_id': utils.int_or_none,
        'tier_name': utils.str_or_none,
        'tier_uuid': utils.str_or_none,
    }, **storage_backend.StorageBackend.fields)

    _foreign_fields = dict({
        'tier_name': 'tier:name',
        'tier_uuid': 'tier:uuid',
    }, **storage_backend.StorageBackend._foreign_fields)

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.storage_ceph_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.storage_ceph_update(self.uuid,  # pylint: disable=no-member
                                       updates)
