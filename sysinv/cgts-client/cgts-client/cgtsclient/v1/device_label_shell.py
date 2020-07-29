#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils
from cgtsclient.v1 import pci_device


def _print_device_label_show(obj):
    fields = ['uuid', 'label_key', 'label_value']
    data = [(f, getattr(obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('nameorpciaddr',
           metavar='<devicename or address>',
           help="Name or PCI address of device")
def do_host_device_label_list(cc, args):
    """List device labels"""
    host = ihost_utils._find_ihost(cc, args.hostnameorid)
    device = pci_device.find_device(cc, host, args.nameorpciaddr)
    device_labels = cc.device_label.list()
    for dl in device_labels[:]:
        if dl.pcidevice_uuid != device.uuid:
            device_labels.remove(dl)
        else:
            setattr(dl, 'hostname', host.hostname)
            setattr(dl, 'devicename', device.name)
    field_labels = ['hostname', 'PCI device name', 'label key', 'label value']
    fields = ['hostname', 'devicename', 'label_key', 'label_value']
    utils.print_list(device_labels, fields, field_labels, sortby=1)


def do_device_label_list(cc, args):
    """List all device labels"""
    device_labels = cc.device_label.list()
    for dl in device_labels[:]:
        if dl.pcidevice_uuid is None:
            setattr(dl, 'devicename', "")
            setattr(dl, 'hostname', "")
        else:
            pci_device = cc.pci_device.get(dl.pcidevice_uuid)
            setattr(dl, 'devicename', getattr(pci_device, 'name'))
            host = ihost_utils._find_ihost(cc, getattr(pci_device, 'host_uuid'))
            setattr(dl, 'hostname', host.hostname)
    field_labels = ['hostname', 'PCI device name', 'label key', 'label value']
    fields = ['hostname', 'devicename', 'label_key', 'label_value']
    utils.print_list(device_labels, fields, field_labels, sortby=1)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('nameorpciaddr',
           metavar='<pci name or address>',
           help="Name or PCI address of device")
@utils.arg('attributes',
           metavar='<name=value>',
           nargs='+',
           action='append',
           default=[],
           help="List of device labels")
@utils.arg('--overwrite',
           action='store_true',
           help="Allow existing label values to be overwritten")
def do_host_device_label_assign(cc, args):
    """Assign a label to a device of a host"""
    attributes = utils.args_array_to_list_dict(args.attributes[0])
    parameters = ["overwrite=" + str(args.overwrite)]
    host = ihost_utils._find_ihost(cc, args.hostnameorid)
    device = pci_device.find_device(cc, host, args.nameorpciaddr)
    attributes.append({'pcidevice_uuid': device.uuid})
    new_device_labels = cc.device_label.assign(attributes, parameters)
    for p in new_device_labels.device_labels:
        uuid = p['uuid']
        if uuid is not None:
            try:
                device_label = cc.device_label.get(uuid)
            except exc.HTTPNotFound:
                raise exc.CommandError('Host device label not found: %s' % uuid)
            _print_device_label_show(device_label)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('nameorpciaddr',
           metavar='<pci name or address>',
           help="Name or PCI address of device")
@utils.arg('attributes',
           metavar='<name>',
           nargs='+',
           action='append',
           default=[],
           help="List of device label keys")
def do_host_device_label_remove(cc, args):
    """Remove a device label from a device of a host"""
    host = ihost_utils._find_ihost(cc, args.hostnameorid)
    device = pci_device.find_device(cc, host, args.nameorpciaddr)
    for i in args.attributes[0]:
        device_labels = cc.device_label.list()
        found = False
        for lbl in device_labels:
            if (lbl.pcidevice_uuid == device.uuid and lbl.label_key == i):
                cc.device_label.remove(lbl.uuid)
                print('Deleted device label (%s, %s) for host %s device %s' %
                      (lbl.label_key, lbl.label_value, host.hostname, device.name))
                found = True
        if not found:
            print('Host device label not found: host %s, device %s, label key %s ' %
                  (host.hostname, device.name, i))
