#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['type', 'mtu', 'link_capacity', 'dynamic', 'vlan_id',
                       'pool_uuid']


class Network(base.Resource):
    def __repr__(self):
        return "<network %s>" % self._info


class NetworkManager(base.Manager):
    resource_class = Network

    def list(self):
        path = '/v1/networks'
        return self._list(path, "networks")

    def get(self, network_id):
        path = '/v1/networks/%s' % network_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/networks'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(path, new)

    def delete(self, network_id):
        path = '/v1/networks/%s' % network_id
        return self._delete(path)
