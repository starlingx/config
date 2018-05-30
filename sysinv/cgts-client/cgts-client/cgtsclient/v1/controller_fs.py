#
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc

CREATION_ATTRIBUTES = ['name', 'size', 'logical_volume', 'replicated',
                       'isystem_uuid']


class ControllerFs(base.Resource):
    def __repr__(self):
        return "<controller_fs %s>" % self._info


class ControllerFsManager(base.Manager):
    resource_class = ControllerFs

    @staticmethod
    def _path(id=None):
        return '/v1/controller_fs/%s' % id if id else '/v1/controller_fs'

    def list(self):
        return self._list(self._path(), "controller_fs")

    def get(self, controller_fs_id):
        try:
            return self._list(self._path(controller_fs_id))[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        # path = '/v1/controller_fs'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(self._path(), new)

    def update(self, controller_fs_id, patch):
        # path = '/v1/controller_fs/%s' % controller_fs_id
        return self._update(self._path(controller_fs_id), patch)

    def delete(self, controller_fs_id):
        # path = '/v1/controller_fs/%s' % controller_fs_id
        return self._delete(self._path(controller_fs_id))

    def update_many(self, isystem_uuid, patch):
        path = '/v1/isystems/%s/controller_fs/update_many' % isystem_uuid
        resp, body = self.api.json_request(
            'PUT', path, body=patch)
        if body:
            return self.resource_class(self, body)

    def summary(self):
        path = self._path("summary")
        return self._json_get(path, {})
