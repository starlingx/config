#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient.common import utils
from cgtsclient import exc


CREATION_ATTRIBUTES = ['type', 'name', 'dynamic', 'pool_uuid']


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


def _find_network(cc, network):
    if network.isdigit() and not utils.is_uuid_like(network):
        network_list = cc.network.list()
        for n in network_list:
            if str(n.id) == network:
                return n
        else:
            raise exc.CommandError('network not found: %s' % network)
    elif utils.is_uuid_like(network):
        try:
            h = cc.network.get(network)
        except exc.HTTPNotFound:
            raise exc.CommandError('network not found: %s' % network)
        else:
            return h
    else:
        network_list = cc.network.list()
        for n in network_list:
            if n.name == network:
                return n
        else:
            raise exc.CommandError('network not found: %s' % network)
