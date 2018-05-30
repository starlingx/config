#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc

CREATION_ATTRIBUTES = ['ip_address']


class RemoteLogging(base.Resource):
    def __repr__(self):
        return "<RemoteLogging %s>" % self._info


class RemoteLoggingManager(base.Manager):
    resource_class = RemoteLogging

    @staticmethod
    def _path(id=None):
        return '/v1/remotelogging/%s' % id if id else '/v1/remotelogging'

    def list(self):
        return self._list(self._path(), "remoteloggings")

    def get(self, remotelogging_id):
        try:
            return self._list(self._path(remotelogging_id))[0]
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

    def delete(self, remotelogging_id):
        return self._delete(self._path(remotelogging_id))

    def update(self, remotelogging_id, patch):
        return self._update(self._path(remotelogging_id), patch)
