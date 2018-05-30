#
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['infra_subnet', 'infra_start', 'infra_end',
                       'infra_mtu', 'infra_vlan_id',
                       'forisystemid']


class iinfra(base.Resource):
    def __repr__(self):
        return "<iinfra %s>" % self._info


class iinfraManager(base.Manager):
    resource_class = iinfra

    @staticmethod
    def _path(id=None):
        return '/v1/iinfra/%s' % id if id else '/v1/iinfra'

    def list(self):
        return self._list(self._path(), "iinfras")

    def get(self, iinfra_id):
        try:
            return self._list(self._path(iinfra_id))[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        # path = '/v1/iinfra'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(self._path(), new)

    def delete(self, iinfra_id):
        # path = '/v1/iinfra/%s' % iinfra_id
        return self._delete(self._path(iinfra_id))

    def update(self, iinfra_id, patch):
        # path = '/v1/iinfra/%s' % iinfra_id
        return self._update(self._path(iinfra_id), patch)
