#
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc
from cgtsclient.v1 import port


CREATION_ATTRIBUTES = ['ifname', 'iftype', 'ihost_uuid', 'imtu', 'ifclass',
                       'networks', 'network_uuid', 'networktype', 'aemode', 'txhashpolicy',
                       'providernetworks', 'datanetworks', 'ifcapabilities', 'ports', 'imac',
                       'vlan_id', 'uses', 'used_by',
                       'ipv4_mode', 'ipv6_mode', 'ipv4_pool', 'ipv6_pool',
                       'sriov_numvfs', 'sriov_vf_driver', 'ptp_role']


class iinterface(base.Resource):
    def __repr__(self):
        return "<iinterface %s>" % self._info


class iinterfaceManager(base.Manager):
    resource_class = iinterface

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/iinterfaces' % ihost_id
        return self._list(path, "iinterfaces")

    def list_ports(self, interface_id):
        path = '/v1/iinterfaces/%s/ports' % interface_id
        return self._list(path, "ports")

    def get(self, iinterface_id):
        path = '/v1/iinterfaces/%s' % iinterface_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/iinterfaces'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(path, new)

    def delete(self, iinterface_id):
        path = '/v1/iinterfaces/%s' % iinterface_id
        return self._delete(path)

    def update(self, iinterface_id, patch):
        path = '/v1/iinterfaces/%s' % iinterface_id
        return self._update(path, patch)


def _get_ports(cc, ihost, interface):
    ports = cc.iinterface.list_ports(interface.uuid)
    port_list = [port.get_port_display_name(p) for p in ports]

    interface.ports = port_list

    if interface.iftype == 'ethernet':
        interface.dpdksupport = [p.dpdksupport for p in ports]
    elif interface.iftype == 'vlan':
        interfaces = cc.iinterface.list(ihost.uuid)
        for u in interface.uses:
            for j in interfaces:
                if j.ifname == str(u):
                    if j.iftype == 'ethernet':
                        uses_ports = cc.iinterface.list_ports(j.uuid)
                        interface.dpdksupport = [p.dpdksupport for p in uses_ports]
                    elif j.iftype == 'ae':
                        for ae_u in j.uses:
                            for k in interfaces:
                                if k.ifname == str(ae_u):
                                    uses_ports = cc.iinterface.list_ports(k.uuid)
                                    interface.dpdksupport = [p.dpdksupport for p in uses_ports]
    elif interface.iftype == 'ae':
        interfaces = cc.iinterface.list(ihost.uuid)
        for u in interface.uses:
            for j in interfaces:
                if j.ifname == str(u):
                    uses_ports = cc.iinterface.list_ports(j.uuid)
                    interface.dpdksupport = [p.dpdksupport for p in uses_ports]
    elif interface.iftype == 'vf':
        interfaces = cc.iinterface.list(ihost.uuid)
        for u in interface.uses:
            u = next(j for j in interfaces if j.ifname == str(u))
            _get_ports(cc, ihost, u)
            if u.dpdksupport:
                interface.dpdksupport = u.dpdksupport


def _find_interface(cc, ihost, ifnameoruuid):
    interfaces = cc.iinterface.list(ihost.uuid)
    for i in interfaces:
        if i.ifname == ifnameoruuid or i.uuid == ifnameoruuid:
            break
    else:
        raise exc.CommandError('Interface not found: host %s interface %s' %
                               (ihost.hostname, ifnameoruuid))
    return i
