#
# Copyright (c) 2015-2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils

# PCI Device Class ID in hexadecimal string
PCI_DEVICE_CLASS_FPGA = '120000'


def _print_device_show(device):
    fields = ['name', 'pciaddr', 'pclass_id', 'pvendor_id', 'pdevice_id',
              'pclass', 'pvendor', 'pdevice', 'numa_node', 'enabled',
              'sriov_totalvfs', 'sriov_numvfs', 'sriov_vfs_pci_address',
              'sriov_vf_pdevice_id', 'extra_info', 'created_at', 'updated_at']

    labels = ['name', 'address', 'class id', 'vendor id', 'device id',
              'class name', 'vendor name', 'device name', 'numa_node',
              'enabled', 'sriov_totalvfs', 'sriov_numvfs',
              'sriov_vfs_pci_address', 'sriov_vf_pdevice_id',
              'extra_info', 'created_at', 'updated_at']

    pclass_id = getattr(device, 'pclass_id')
    if pclass_id == PCI_DEVICE_CLASS_FPGA:
        fields += ['root_key', 'revoked_key_ids',
                   'boot_page', 'bitstream_id',
                   'bmc_build_version', 'bmc_fw_version',
                   'driver', 'sriov_vf_driver']
        labels += ['root_key', 'revoked_key_ids',
                   'boot_page', 'bitstream_id',
                   'bmc_build_version', 'bmc_fw_version',
                   'driver', 'sriov_vf_driver']

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
@utils.arg('-d', '--driver',
           metavar='<new driver>',
           help='The new driver of the device')
@utils.arg('-v', '--vf-driver',
           dest='sriov_vf_driver',
           metavar='<new VF driver>',
           help='The new VF driver of the device')
@utils.arg('-N', '--num-vfs',
           dest='sriov_numvfs',
           metavar='<sriov numvfs>',
           help='The number of SR-IOV VFs of the device')
def do_host_device_modify(cc, args):
    """Modify device availability for worker nodes."""

    rwfields = ['enabled',
                'name',
                'driver',
                'sriov_numvfs',
                'sriov_vf_driver']

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
