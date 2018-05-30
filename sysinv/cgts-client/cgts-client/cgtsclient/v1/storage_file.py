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


class StorageFile(base.Resource):
    def __repr__(self):
        return "<storage_file %s>" % self._info


class StorageFileManager(base.Manager):
    resource_class = StorageFile

    @staticmethod
    def _path(id=None):
        return '/v1/storage_file/%s' % id if id else '/v1/storage_file'

    def list(self):
        return self._list(self._path(), "storage_file")

    def get(self, storfile_id=None):
        try:
            if storfile_id:
                return self._list(self._path(storfile_id))[0]
            else:
                return self._list(self._path(), "storage_file")[0]
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

    def delete(self, storfile_id):
        return self._delete(self._path(storfile_id))

    def update(self, storfile_id, patch):
        return self._update(self._path(storfile_id), patch)
