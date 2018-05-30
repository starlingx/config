#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['ntpservers', 'forisystemid']


class intp(base.Resource):
    def __repr__(self):
        return "<intp %s>" % self._info


class intpManager(base.Manager):
    resource_class = intp

    @staticmethod
    def _path(id=None):
        return '/v1/intp/%s' % id if id else '/v1/intp'

    def list(self):
        return self._list(self._path(), "intps")

    def get(self, intp_id):
        try:
            return self._list(self._path(intp_id))[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        # path = '/v1/intp'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(self._path(), new)

    def delete(self, intp_id):
        # path = '/v1/intp/%s' % intp_id
        return self._delete(self._path(intp_id))

    def update(self, intp_id, patch):
        # path = '/v1/intp/%s' % intp_id
        return self._update(self._path(intp_id), patch)
