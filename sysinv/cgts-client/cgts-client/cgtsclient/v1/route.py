#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['interface_uuid', 'network', 'prefix',
                       'gateway', 'metric']


class Route(base.Resource):
    def __repr__(self):
        return "<route %s>" % self._info


class RouteManager(base.Manager):
    resource_class = Route

    def list(self):
        path = '/v1/routes'
        return self._list(path, "routes")

    def list_by_interface(self, interface_id):
        path = '/v1/iinterfaces/%s/routes' % interface_id
        return self._list(path, "routes")

    def list_by_host(self, host_id):
        path = '/v1/ihosts/%s/routes' % host_id
        return self._list(path, "routes")

    def get(self, route_id):
        path = '/v1/routes/%s' % route_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/routes'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(path, new)

    def delete(self, route_id):
        path = '/v1/routes/%s' % route_id
        return self._delete(path)
