#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = [
    'interface_uuid', 'datanetwork_uuid'
]


class InterfaceDataNetwork(base.Resource):
    def __repr__(self):
        return "<interface_datanetwork %s>" % self._info


class InterfaceDataNetworkManager(base.Manager):
    resource_class = InterfaceDataNetwork

    def list(self):
        path = '/v1/interface_datanetworks'
        return self._list(path, "interface_datanetworks")

    def list_by_host(self, host_uuid):
        path = '/v1/ihosts/%s/interface_datanetworks' % host_uuid
        return self._list(path, "interface_datanetworks")

    def list_by_interface(self, interface_uuid):
        path = '/v1/iinterfaces/%s/interface_datanetworks' % interface_uuid
        return self._list(path, "interface_datanetworks")

    def get(self, interface_datanetwork_uuid):
        path = '/v1/interface_datanetworks/%s' % interface_datanetwork_uuid
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def assign(self, **kwargs):
        path = '/v1/interface_datanetworks'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(path, new)

    def remove(self, interface_datanetwork_uuid):
        path = '/v1/interface_datanetworks/%s' % interface_datanetwork_uuid
        return self._delete(path)


def get_datanetwork_names(cc, interface):
    datanetwork_names = []
    ifdns = cc.interface_datanetwork.list_by_interface(interface.uuid)
    for ifdn in ifdns:
        datanetwork_names.append(getattr(ifdn, 'datanetwork_name'))
    return datanetwork_names
