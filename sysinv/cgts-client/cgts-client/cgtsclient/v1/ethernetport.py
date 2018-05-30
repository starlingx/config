#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['host_uuid', 'name', 'mtu', 'speed', 'bootp',
                       'interface_uuid', 'pdevice', 'pclass', 'pciaddr',
                       'psdevice', 'link_mode', 'psvendor', 'pvendor']


class EthernetPort(base.Resource):
    def __repr__(self):
        return "<EthernetPort %s>" % self._info


class EthernetPortManager(base.Manager):
    resource_class = EthernetPort

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/ethernet_ports' % ihost_id
        return self._list(path, "ethernet_ports")

    def get(self, port_id):
        path = '/v1/ethernet_ports/%s' % port_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/ethernet_ports/'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute(key)
        return self._create(path, new)

    def delete(self, port_id):
        path = '/v1/ethernet_ports/%s' % port_id
        return self._delete(path)

    def update(self, port_id, patch):
        path = '/v1/ethernet_ports/%s' % port_id
        return self._update(path, patch)


def get_port_display_name(p):
    if p.name:
        return p.name
    if p.namedisplay:
        return p.namedisplay
    else:
        return '(' + str(p.uuid)[-8:] + ')'
