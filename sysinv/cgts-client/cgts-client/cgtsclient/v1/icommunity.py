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


CREATION_ATTRIBUTES = ['community']


class iCommunity(base.Resource):
    def __repr__(self):
        return "<iCommunity %s>" % self._info


class iCommunityManager(base.Manager):
    resource_class = iCommunity

    @staticmethod
    def _path(id=None):
        return '/v1/icommunity/%s' % id if id else '/v1/icommunity'

    def list(self):
        return self._list(self._path(), "icommunity")

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
