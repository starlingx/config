#
# Copyright (c) 2020 Intel Corporation, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import storage_backend


class StorageCephRook(storage_backend.StorageBackend):

    dbapi = db_api.get_instance()

    fields = dict({}, **storage_backend.StorageBackend.fields)

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.storage_ceph_rook_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.storage_ceph_rook_update(self.uuid,  # pylint: disable=no-member
                                            updates)
