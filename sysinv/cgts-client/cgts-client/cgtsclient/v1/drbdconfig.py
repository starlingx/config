#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc

CREATION_ATTRIBUTES = ['forisystemid']


class drbdconfig(base.Resource):
    def __repr__(self):
        return "<drbdconfig %s>" % self._info


class drbdconfigManager(base.Manager):
    resource_class = drbdconfig

    @staticmethod
    def _path(id=None):
        return '/v1/drbdconfig/%s' % id if id else '/v1/drbdconfig'

    def list(self):
        return self._list(self._path(), "drbdconfigs")

    def get(self, drbdconfig_id):
        try:
            return self._list(self._path(drbdconfig_id))[0]
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

    def delete(self, drbdconfig_id):
        return self._delete(self._path(drbdconfig_id))

    def update(self, drbdconfig_id, patch):
        return self._update(self._path(drbdconfig_id), patch)
