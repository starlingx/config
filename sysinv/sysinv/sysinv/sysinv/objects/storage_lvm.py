#
# Copyright (c) 2013-2017 Wind River Systems, Inc.
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


class StorageLVM(storage_backend.StorageBackend):

    dbapi = db_api.get_instance()

    fields = dict({}, **storage_backend.StorageBackend.fields)

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.storage_lvm_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.storage_lvm_update(self.uuid, updates)
