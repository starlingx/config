#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['extoamservers', 'forisystemid']


class iextoam(base.Resource):
    def __repr__(self):
        return "<iextoam %s>" % self._info


class iextoamManager(base.Manager):
    resource_class = iextoam

    @staticmethod
    def _path(id=None):
        return '/v1/iextoam/%s' % id if id else '/v1/iextoam'

    def list(self):
        return self._list(self._path(), "iextoams")

    def get(self, iextoam_id):
        try:
            return self._list(self._path(iextoam_id))[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        # path = '/v1/iextoam'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(self._path(), new)

    def delete(self, iextoam_id):
        # path = '/v1/iextoam/%s' % iextoam_id
        return self._delete(self._path(iextoam_id))

    def update(self, iextoam_id, patch):
        # path = '/v1/iextoam/%s' % iextoam_id
        return self._update(self._path(iextoam_id), patch)
