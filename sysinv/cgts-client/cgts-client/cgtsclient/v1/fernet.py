#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import base


class FernetKey(base.Resource):
    def __repr__(self):
        return "<keys %s>" % self._info


class FernetManager(base.Manager):
    resource_class = FernetKey

    @staticmethod
    def _path(id=None):
        return '/v1/fernet_repo/%s' % id if id else '/v1/fernet_repo'

    def list(self):
        return self._list(self._path(), "keys")

    def get(self, id):
        try:
            return self._list(self._path(id))[0]
        except IndexError:
            return None

    def create(self, data):
        return self._create(self._path(), data)

    def put(self, patch, id=None):
        return self._update(self._path(id), patch, http_method='PUT')
