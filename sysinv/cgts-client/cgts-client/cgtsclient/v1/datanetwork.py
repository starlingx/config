#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient.common import utils
from cgtsclient import exc


CREATION_ATTRIBUTES = [
    'network_type', 'name', 'description', 'mtu',
    'multicast_group', 'port_num', 'ttl', 'mode']


class DataNetwork(base.Resource):
    def __repr__(self):
        return "<datanetwork %s>" % self._info


class DataNetworkManager(base.Manager):
    resource_class = DataNetwork

    def list(self):
        path = '/v1/datanetworks'
        return self._list(path, "datanetworks")

    def get(self, datanetwork_id):
        path = '/v1/datanetworks/%s' % datanetwork_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/datanetworks'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(path, new)

    def update(self, datanetwork_id, patch):
        path = '/v1/datanetworks/%s' % datanetwork_id
        return self._update(path, patch)

    def delete(self, datanetwork_id):
        path = '/v1/datanetworks/%s' % datanetwork_id
        return self._delete(path)


def _find_datanetwork(cc, datanetwork):
    if datanetwork.isdigit() and not utils.is_uuid_like(datanetwork):
        datanetwork_list = cc.datanetwork.list()
        for n in datanetwork_list:
            if str(n.id) == datanetwork:
                return n
        else:
            raise exc.CommandError('datanetwork not found: %s' % datanetwork)
    elif utils.is_uuid_like(datanetwork):
        try:
            h = cc.datanetwork.get(datanetwork)
        except exc.HTTPNotFound:
            raise exc.CommandError('datanetwork not found: %s' % datanetwork)
        else:
            return h
    else:
        datanetwork_list = cc.datanetwork.list()
        for n in datanetwork_list:
            if n.name == datanetwork:
                return n
        else:
            raise exc.CommandError('datanetwork not found: %s' % datanetwork)
