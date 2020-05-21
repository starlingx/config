#
# Copyright (c) 2015-2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import base
from cgtsclient import exc


class PciDevice(base.Resource):
    def __repr__(self):
        return "<PciDevice %s>" % self._info


class PciDeviceManager(base.Manager):
    resource_class = PciDevice

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/pci_devices' % ihost_id
        return self._list(path, "pci_devices")

    def list_all(self):
        path = '/v1/pci_devices'
        return self._list(path, "pci_devices")

    def get(self, pci_id):
        path = '/v1/pci_devices/%s' % pci_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def update(self, pci_id, patch):
        path = '/v1/pci_devices/%s' % pci_id
        return self._update(path, patch)


def get_pci_device_display_name(p):
    if p.name:
        return p.name
    else:
        return '(' + str(p.uuid)[-8:] + ')'


def find_device(cc, host, nameorpciaddr):
    devices = cc.pci_device.list(host.uuid)
    for d in devices:
        if d.name == nameorpciaddr or d.pciaddr == nameorpciaddr:
            return d
    else:
        raise exc.CommandError('PCI device not found: host %s device %s' %
                               (host.hostname, nameorpciaddr))
