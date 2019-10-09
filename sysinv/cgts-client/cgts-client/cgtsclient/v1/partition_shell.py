#
# Copyright (c) 2017-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from cgtsclient.common import constants
from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import idisk as idisk_utils
from cgtsclient.v1 import ihost as ihost_utils
from cgtsclient.v1 import partition as part_utils
import math


PARTITION_MAP = {'lvm_phys_vol': constants.USER_PARTITION_PHYSICAL_VOLUME}


def _print_partition_show(partition):
    fields = ['device_path', 'device_node', 'type_guid', 'type_name',
              'start_mib', 'end_mib', 'size_mib', 'uuid', 'ihost_uuid',
              'idisk_uuid', 'ipv_uuid', 'status', 'created_at', 'updated_at']
    labels = ['device_path', 'device_node', 'type_guid', 'type_name',
              'start_mib', 'end_mib', 'size_mib', 'uuid', 'ihost_uuid',
              'idisk_uuid', 'ipv_uuid', 'status', 'created_at', 'updated_at']
    partition.status = constants.PARTITION_STATUS_MSG[partition.status]
    data = [(f, getattr(partition, f, '')) for f in fields]
    utils.print_tuple_list(data, labels)


@utils.arg('hostname_or_id',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('device_path_or_uuid',
           metavar='<partition device path or uuid>',
           help="Name or UUID of the disk partition")
def do_host_disk_partition_show(cc, args):
    """Show disk partition attributes."""
    ihost = ihost_utils._find_ihost(cc, args.hostname_or_id)
    ipartition = part_utils._find_partition(cc, ihost,
                                            args.device_path_or_uuid)
    if not ipartition:
        raise exc.CommandError('Partition not found on host \'%s\' '
                               'by device path or uuid: %s' %
                               (ihost.hostname, args.device_path_or_uuid))

    _print_partition_show(ipartition)


@utils.arg('hostname_or_id',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('--disk',
           metavar='<idisk_uuid>',
           nargs='?',
           default=None,
           help="uuid of disk")
def do_host_disk_partition_list(cc, args):
    """List disk partitions."""
    ihost = ihost_utils._find_ihost(cc, args.hostname_or_id)
    if args.disk:
        idisk = idisk_utils._find_disk(cc, args.hostname_or_id, args.disk)

        if not idisk:
            raise exc.CommandError('Disk not found: %s' % args.disk)

        ipartitions = cc.partition.list(ihost.uuid, idisk.uuid)
    else:
        ipartitions = cc.partition.list(ihost.uuid, None)

    for p in ipartitions:
        p.status = constants.PARTITION_STATUS_MSG[p.status]

        p.size_mib = math.floor(float(p.size_mib) / 1024 * 1000) / 1000.0

    field_labels = ['uuid', 'device_path', 'device_node', 'type_guid',
                    'type_name', 'size_gib', 'status']
    fields = ['uuid', 'device_path', 'device_node', 'type_guid', 'type_name',
              'size_mib', 'status']

    utils.print_list(ipartitions, fields, field_labels, sortby=1)


@utils.arg('hostname_or_id',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('disk_path_or_uuid',
           metavar='<disk path or uuid>',
           help="UUID of the disk to place the partition [REQUIRED]")
@utils.arg('size_gib',
           metavar='<partition size in GiB>',
           help="Requested size of the new partition in GiB [REQUIRED]")
@utils.arg('-t', '--partition_type',
           metavar='<partition type>',
           choices=['lvm_phys_vol'],
           default='lvm_phys_vol',
           help=("Type of parition. "
                 "Allowed values: lvm_phys_vol"))
def do_host_disk_partition_add(cc, args):
    """Add a disk partition to a disk of a specified host."""

    field_list = ['size_gib', 'partition_type']
    integer_fields = ['size_gib']

    user_fields = dict((k, v) for (k, v) in vars(args).items()
                       if k in field_list and not (v is None))

    for f in user_fields:
        try:
            if f in integer_fields:
                user_fields[f] = int(user_fields[f])
        except ValueError:
            raise exc.CommandError('Partition size must be an integer '
                                   'greater than 0: %s' % user_fields[f])

    # Convert size from gib to mib
    user_fields['size_mib'] = user_fields.pop('size_gib') * 1024

    # Get the ihost object
    ihost = ihost_utils._find_ihost(cc, args.hostname_or_id)
    idisk = idisk_utils._find_disk(cc, ihost, args.disk_path_or_uuid)

    if not idisk:
        raise exc.CommandError('Disk not found: %s' % args.disk_path_or_uuid)

    # default values
    fields = {'ihost_uuid': ihost.uuid,
              'idisk_uuid': idisk.uuid,
              'size_mib': 0}

    fields.update(user_fields)

    # Set the requested partition GUID
    fields['type_guid'] = PARTITION_MAP[fields['partition_type']]
    fields.pop('partition_type', None)

    if not fields['size_mib']:
        raise exc.CommandError('Partition size must be greater than 0.')

    try:
        partition = cc.partition.create(**fields)
    except exc.HTTPNotFound:
        raise exc.CommandError('Partition create failed: host %s: fields %s' %
                               (args.hostnameorid, fields))

    puuid = getattr(partition, 'uuid', '')
    try:
        ipartition = cc.partition.get(puuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created Partition UUID not found: %s' % puuid)

    _print_partition_show(ipartition)


@utils.arg('hostname_or_id',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('partition_path_or_uuid',
           metavar='<partition path or uuid>',
           help="UUID of the partition [REQUIRED]")
def do_host_disk_partition_delete(cc, args):
    """Delete a disk partition."""

    # Get the ihost object
    ihost = ihost_utils._find_ihost(cc, args.hostname_or_id)
    partition = part_utils._find_partition(cc, ihost,
                                           args.partition_path_or_uuid)
    if not partition:
        raise exc.CommandError('Partition not found on host \'%s\' '
                               'by device path or uuid: %s' %
                               (ihost.hostname, args.partition_path_or_uuid))

    try:
        cc.partition.delete(partition.uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Partition delete failed: host %s: '
                               'partition %s' % (args.hostnameorid,
                                                 args.partition_path_or_uuid))


@utils.arg('hostname_or_id',
           metavar='<hostname or id>',
           help="Name or ID of the host [REQUIRED]")
@utils.arg('partition_path_or_uuid',
           metavar='<partition path or uuid>',
           help="UUID of the partition [REQUIRED]")
@utils.arg('-s', '--size_gib',
           metavar='<partition size in GiB>',
           help=("Update the desired size of the partition"))
def do_host_disk_partition_modify(cc, args):
    """Modify the attributes of a Disk Partition."""

    # Get all the fields from the command arguments
    field_list = ['size_gib']
    integer_fields = ['size_gib']

    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in field_list and not (v is None))

    if not user_specified_fields:
        raise exc.CommandError('No update parameters specified, '
                               'partition is unchanged.')

    for f in user_specified_fields:
        try:
            if f in integer_fields:
                user_specified_fields[f] = int(user_specified_fields[f])
        except ValueError:
            raise exc.CommandError('Partition size must be an integer '
                                   'greater than 0: %s' % user_specified_fields[f])

    # Convert size from gib to mib
    user_specified_fields['size_mib'] = user_specified_fields.pop('size_gib') * 1024

    # Get the ihost object
    ihost = ihost_utils._find_ihost(cc, args.hostname_or_id)

    # Get the partition
    partition = part_utils._find_partition(cc, ihost,
                                           args.partition_path_or_uuid)
    if not partition:
        raise exc.CommandError('Partition not found on host \'%s\' '
                               'by device path or uuid: %s' %
                               (ihost.hostname, args.partition_path_or_uuid))

    patch = []
    for (k, v) in user_specified_fields.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})

    # Update the partition attributes
    try:
        updated_partition = cc.partition.update(partition.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError(
            "ERROR: Partition update failed: "
            "host %s partition %s : update %s"
            % (args.hostname_or_id, args.partition_path_or_uuid, patch))

    _print_partition_show(updated_partition)
