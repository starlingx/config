#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = [
    'address_pool_uuid', 'network_uuid'
]


class NetworkAddrPool(base.Resource):
    def __repr__(self):
        return "<network_addrpool %s>" % self._info


class NetworkAddrPoolManager(base.Manager):
    resource_class = NetworkAddrPool

    def list(self):
        path = '/v1/network_addresspools'
        return self._list(path, "network_addresspools")

    def get(self, network_addrpool_uuid):
        path = '/v1/network_addresspools/%s' % network_addrpool_uuid
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def assign(self, **kwargs):
        path = '/v1/network_addresspools'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(path, new)

    def remove(self, network_addrpool_uuid):
        path = '/v1/network_addresspools/%s' % network_addrpool_uuid
        return self._delete(path)
