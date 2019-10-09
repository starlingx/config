#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils


def _print_device_show(device):
    fields = ['name', 'pciaddr', 'pclass_id', 'pvendor_id', 'pdevice_id',
              'pclass', 'pvendor', 'pdevice', 'numa_node', 'enabled',
              'sriov_totalvfs', 'sriov_numvfs', 'sriov_vfs_pci_address',
              'extra_info', 'created_at', 'updated_at']

    labels = ['name', 'address', 'class id', 'vendor id', 'device id',
              'class name', 'vendor name', 'device name', 'numa_node',
              'enabled', 'sriov_totalvfs', 'sriov_numvfs',
              'sriov_vfs_pci_address', 'extra_info', 'created_at',
              'updated_at']

    data = [(f, getattr(device, f, '')) for f in fields]
    utils.print_tuple_list(data, labels)


def _find_device(cc, host, nameorpciaddr):
    devices = cc.pci_device.list(host.uuid)
    for d in devices:
        if d.name == nameorpciaddr or d.pciaddr == nameorpciaddr:
            break
    else:
        raise exc.CommandError('PCI devices not found: host %s device %s' % (host.id, nameorpciaddr))
    return d


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('nameorpciaddr',
           metavar='<pci name or address>',
           help="Name or PCI address of device")
def do_host_device_show(cc, args):
    """Show device attributes."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    device = _find_device(cc, ihost, args.nameorpciaddr)
    _print_device_show(device)
    return


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('-a', '--all',
           action='store_true',
           help='List all devices, including those that are not enabled')
def do_host_device_list(cc, args):
    """List devices."""

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    devices = cc.pci_device.list(ihost.uuid)
    for device in devices[:]:
        if not args.all:
            if not device.enabled:
                devices.remove(device)

    fields = ['name', 'pciaddr', 'pclass_id', 'pvendor_id', 'pdevice_id',
              'pclass', 'pvendor', 'pdevice', 'numa_node', 'enabled']

    labels = ['name', 'address', 'class id', 'vendor id', 'device id',
              'class name', 'vendor name', 'device name', 'numa_node',
              'enabled']

    utils.print_list(devices, fields, labels, sortby=1)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('nameorpciaddr',
           metavar='<pci name or address>',
           help="Name or PCI address of device")
@utils.arg('-n', '--name',
           metavar='<new devicename>',
           help='The new name of the device')
@utils.arg('-e', '--enabled',
           metavar='<enabled status>',
           help='The enabled status of the device')
def do_host_device_modify(cc, args):
    """Modify device availability for worker nodes."""

    rwfields = ['enabled',
                'name']

    host = ihost_utils._find_ihost(cc, args.hostnameorid)

    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in rwfields and not (v is None))

    device = _find_device(cc, host, args.nameorpciaddr)

    fields = device.__dict__
    fields.update(user_specified_fields)

    patch = []
    for (k, v) in user_specified_fields.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})

    if patch:
        try:
            device = cc.pci_device.update(device.uuid, patch)
            _print_device_show(device)
        except exc.HTTPNotFound:
            raise exc.CommandError('Device update failed: host %s device %s : update %s' % (args.hostnameorid, args.nameorpciaddr, patch))
