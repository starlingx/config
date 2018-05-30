#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc

CREATION_ATTRIBUTES = ['confirmed', 'name', 'services', 'capabilities']
DISPLAY_ATTRIBUTES = []
PATCH_ATTRIBUTES = []


class StorageLvm(base.Resource):
    def __repr__(self):
        return "<storage_lvm %s>" % self._info


class StorageLvmManager(base.Manager):
    resource_class = StorageLvm

    @staticmethod
    def _path(id=None):
        return '/v1/storage_lvm/%s' % id if id else '/v1/storage_lvm'

    def list(self):
        return self._list(self._path(), "storage_lvm")

    def get(self, storlvm_id=None):
        try:
            if storlvm_id:
                return self._list(self._path(storlvm_id))[0]
            else:
                return self._list(self._path(), "storage_lvm")[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(self._path(), new)

    def update(self, storlvm_id, patch):
        # path = '/v1/storage_lvm/%s' % storlvm_id
        return self._update(self._path(storlvm_id), patch)

    def delete(self, storlvm_id):
        return self._delete(self._path(storlvm_id))
