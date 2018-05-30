#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['interface_uuid', 'pool_uuid', 'address', 'prefix',
                       'enable_dad', 'name']


class Address(base.Resource):
    def __repr__(self):
        return "<address %s>" % self._info


class AddressManager(base.Manager):
    resource_class = Address

    def list(self):
        path = '/v1/iinterfaces'
        return self._list(path, "addresses")

    def list_by_interface(self, interface_id):
        path = '/v1/iinterfaces/%s/addresses' % interface_id
        return self._list(path, "addresses")

    def list_by_host(self, host_id):
        path = '/v1/ihosts/%s/addresses' % host_id
        return self._list(path, "addresses")

    def get(self, address_id):
        path = '/v1/addresses/%s' % address_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/addresses'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(path, new)

    def delete(self, address_id):
        path = '/v1/addresses/%s' % address_id
        return self._delete(path)
