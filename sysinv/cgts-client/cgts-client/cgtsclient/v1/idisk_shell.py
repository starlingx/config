#
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from cgtsclient.common import constants
from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils
import math
from six.moves import input


def _print_idisk_show(idisk):
    fields = ['device_node', 'device_num', 'device_type', 'device_path',
              'size_mib', 'available_mib', 'rpm', 'serial_id', 'uuid',
              'ihost_uuid', 'istor_uuid', 'ipv_uuid', 'created_at',
              'updated_at']
    labels = ['device_node', 'device_num', 'device_type', 'device_path',
              'size_gib', 'available_gib', 'rpm', 'serial_id', 'uuid',
              'ihost_uuid', 'istor_uuid', 'ipv_uuid', 'created_at',
              'updated_at']
    data = [(f, getattr(idisk, f, '')) for f in fields]
    utils.print_tuple_list(data, labels)


def _find_disk(cc, ihost, disknameoruuid):
    disks = cc.idisk.list(ihost.uuid)
    for p in disks:
        if p.device_node == disknameoruuid or p.uuid == disknameoruuid:
            break
    else:
        raise exc.CommandError('Disk not found: host %s disk %s' %
                               (ihost.id, disknameoruuid))
    return p


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('device_nodeoruuid',
           metavar='<disk name or uuid>',
           help="Name or UUID of disk")
def do_host_disk_show(cc, args):
    """Show disk attributes."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    idisk = _find_disk(cc, ihost, args.device_nodeoruuid)

    # Convert size from mib to gib and round it down
    idisk.size_mib = math.floor(float(idisk.size_mib) / 1024 * 1000) / 1000.0
    idisk.available_mib = math.floor(float(idisk.available_mib) / 1024 * 1000) / 1000.0

    _print_idisk_show(idisk)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_disk_list(cc, args):
    """List disks."""

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    idisks = cc.idisk.list(ihost.uuid)

    field_labels = ['uuid', 'device_node', 'device_num', 'device_type',
                    'size_gib', 'available_gib', 'rpm', 'serial_id',
                    'device_path']
    fields = ['uuid', 'device_node', 'device_num', 'device_type',
              'size_mib', 'available_mib', 'rpm', 'serial_id',
              'device_path']

    # Convert size from mib to gib and round it down
    for i in idisks:
        i.size_mib = math.floor(float(i.size_mib) / 1024 * 1000) / 1000.0
        i.available_mib = math.floor(float(i.available_mib) / 1024 * 1000) / 1000.0

    utils.print_list(idisks, fields, field_labels, sortby=1)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('device_name_path_uuid',
           metavar='<device name or path or UUID>',
           help='Name or uuid of disk on the host [REQUIRED]')
@utils.arg('--confirm',
           action='store_true',
           default=False,
           help='Provide acknowledgement that the operation should continue as'
           ' the action is not reversible.')
def do_host_disk_wipe(cc, args):
    """Wipe disk and GPT format it."""

    if not args.confirm:
        warning_message = \
            ("WARNING: This operation is irreversible and all data on the "
             "specified disk will be lost.\n"
             "Continue [yes/N]: ")
        confirm = input(warning_message)
        if confirm != 'yes':
            print("Operation cancelled.")
            return

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    idisk = _find_disk(cc, ihost, args.device_name_path_uuid)

    if not idisk:
        raise exc.CommandError(
            "No disk found on host \'%s\' by device path or uuid %s" %
            (ihost.hostname, args.device_name_path_uuid))

    fields = dict()
    fields['partition_table'] = constants.PARTITION_TABLE_GPT

    patch = []
    for (k, v) in fields.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})

    try:
        updated_idisk = cc.idisk.update(idisk.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError(
            "ERROR: Failed to wipe and GPT format disk %s "
            "host %s; update %s"
            % (args.hostname_or_id, args.partition_path_or_uuid, patch))
