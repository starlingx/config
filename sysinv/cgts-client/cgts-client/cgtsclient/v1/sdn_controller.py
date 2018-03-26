#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['ip_address', 'port', 'transport', 'state']


class SDNController(base.Resource):
    def __repr__(self):
        return "<SdnController %s>" % self._info


class SDNControllerManager(base.Manager):
    resource_class = SDNController

    @staticmethod
    def _path(id=None):
        return '/v1/sdn_controller/%s' % id if id else '/v1/sdn_controller'

    def list(self):
        return self._list(self._path(), "sdn_controllers")

    def get(self, id):
        try:
            return self._list(self._path(id))[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        # path = /v1/sdn_controller'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(self._path(), new)

    def delete(self, id):
        # path = '/v1/sdn_controller/%s' % id
        return self._delete(self._path(id))

    def update(self, id, patch):
        # path = '/v1/sdn_controller/%s' % id
        return self._update(self._path(id), patch)
