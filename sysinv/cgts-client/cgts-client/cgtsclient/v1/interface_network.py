#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = [
    'interface_uuid', 'network_uuid'
]


class InterfaceNetwork(base.Resource):
    def __repr__(self):
        return "<interface_network %s>" % self._info


class InterfaceNetworkManager(base.Manager):
    resource_class = InterfaceNetwork

    def list(self):
        path = '/v1/interface_networks'
        return self._list(path, "interface_networks")

    def list_by_host(self, host_uuid):
        path = '/v1/ihosts/%s/interface_networks' % host_uuid
        return self._list(path, "interface_networks")

    def list_by_interface(self, interface_uuid):
        path = '/v1/iinterfaces/%s/interface_networks' % interface_uuid
        return self._list(path, "interface_networks")

    def get(self, interface_network_uuid):
        path = '/v1/interface_networks/%s' % interface_network_uuid
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def assign(self, **kwargs):
        path = '/v1/interface_networks'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(path, new)

    def remove(self, interface_network_uuid):
        path = '/v1/interface_networks/%s' % interface_network_uuid
        return self._delete(path)


def get_network_names(cc, interface):
    network_names = []
    ifnets = cc.interface_network.list_by_interface(interface.uuid)
    for ifnet in ifnets:
        network_names.append(getattr(ifnet, 'network_name'))
    return network_names
