#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['nameservers', 'forisystemid']


class idns(base.Resource):
    def __repr__(self):
        return "<idns %s>" % self._info


class idnsManager(base.Manager):
    resource_class = idns

    @staticmethod
    def _path(id=None):
        return '/v1/idns/%s' % id if id else '/v1/idns'

    def list(self):
        return self._list(self._path(), "idnss")

    def get(self, idns_id):
        try:
            return self._list(self._path(idns_id))[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        # path = '/v1/idns'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(self._path(), new)

    def delete(self, idns_id):
        # path = '/v1/idns/%s' % idns_id
        return self._delete(self._path(idns_id))

    def update(self, idns_id, patch):
        # path = '/v1/idns/%s' % idns_id
        return self._update(self._path(idns_id), patch)
