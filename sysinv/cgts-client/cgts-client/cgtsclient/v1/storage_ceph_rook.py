#
# Copyright (c) 2020 Intel Corporation, Inc.
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


class StorageCephRook(base.Resource):
    def __repr__(self):
        return "<storage_ceph_rook %s>" % self._info


class StorageCephRookManager(base.Manager):
    resource_class = StorageCephRook

    @staticmethod
    def _path(id=None):
        return '/v1/storage_ceph_rook/%s' % id if id else '/v1/storage_ceph_rook'

    def list(self):
        return self._list(self._path(), "storage_ceph_rook")

    def get(self, stor_id=None):
        try:
            if stor_id:
                return self._list(self._path(stor_id))[0]
            else:
                return self._list(self._path(), "storage_ceph_rook")[0]
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

    def delete(self, stor_id):
        return self._delete(self._path(stor_id))

    def update(self, stor_id, patch):
        return self._update(self._path(stor_id), patch)
