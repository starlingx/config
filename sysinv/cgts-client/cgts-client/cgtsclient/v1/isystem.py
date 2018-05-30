#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['name', 'description', 'capabilities']


class isystem(base.Resource):
    def __repr__(self):
        return "<isystem %s>" % self._info


class isystemManager(base.Manager):
    resource_class = isystem

    @staticmethod
    def _path(id=None):
        return '/v1/isystems/%s' % id if id else '/v1/isystems'

    def list(self):
        return self._list(self._path(), "isystems")

    def list_ihosts(self, isystem_id):
        path = "%s/ihosts" % isystem_id
        return self._list(self._path(path), "ihosts")

    def get(self, isystem_id):
        try:
            return self._list(self._path(isystem_id))[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute()
        return self._create(self._path(), new)

    def delete(self, isystem_id):
        return self._delete(self._path(isystem_id))

    def update(self, isystem_id, patch):
        return self._update(self._path(isystem_id), patch)


def _find_isystem(cc, isystem):
    try:
        h = cc.isystem.get(isystem)
    except exc.HTTPNotFound:
        raise exc.CommandError('system not found: %s' % isystem)
    else:
        return h
