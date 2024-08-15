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


CREATION_ATTRIBUTES = ['name', 'network', 'prefix', 'order', 'ranges',
                       'controller0_address', 'controller1_address',
                       'floating_address', 'gateway_address']


class AddressPool(base.Resource):
    def __repr__(self):
        return "<address pool %s>" % self._info


class AddressPoolManager(base.Manager):
    resource_class = AddressPool

    def list(self):
        path = '/v1/addrpools'
        return self._list(path, "addrpools")

    def list_by_network_type(self, network_type):
        path = "/v1/addrpools?network_type=%s" % network_type
        return self._list(path, "addrpools")

    def get(self, pool_id):
        path = '/v1/addrpools/%s' % pool_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/addrpools'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(path, new)

    def delete(self, pool_id):
        path = '/v1/addrpools/%s' % pool_id
        return self._delete(path)

    def update(self, pool_id, patch):
        path = '/v1/addrpools/%s' % pool_id
        return self._update(path, patch)


def _find_addrpool(cc, addrpool):
    if utils.is_uuid_like(addrpool):
        try:
            a = cc.address_pool.get(addrpool)
        except exc.HTTPNotFound:
            raise exc.CommandError('address pool not found: %s' % addrpool)
        else:
            return a
    else:
        addrpool_list = cc.address_pool.list()
        for a in addrpool_list:
            if a.name == addrpool:
                return a
        else:
            raise exc.CommandError('address pool not found: %s' % addrpool)
