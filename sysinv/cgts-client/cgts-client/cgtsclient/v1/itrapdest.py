#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


# -*- encoding: utf-8 -*-
#
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['ip_address', 'community']


class iTrapdest(base.Resource):
    def __repr__(self):
        return "<iTrapdest %s>" % self._info


class iTrapdestManager(base.Manager):
    resource_class = iTrapdest

    @staticmethod
    def _path(id=None):
        return '/v1/itrapdest/%s' % id if id else '/v1/itrapdest'

    def list(self):
        return self._list(self._path(), "itrapdest")

    def get(self, iid):
        try:
            return self._list(self._path(iid))[0]
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

    def delete(self, iid):
        return self._delete(self._path(iid))

    def update(self, iid, patch):
        return self._update(self._path(iid), patch)
