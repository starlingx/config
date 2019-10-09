#
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import idisk as idisk_utils
from cgtsclient.v1 import ihost as ihost_utils
from cgtsclient.v1 import ilvg as ilvg_utils
from cgtsclient.v1 import partition as partition_utils
import math


def _print_ipv_show(ipv):
    labels = ['uuid', 'pv_state', 'pv_type', 'disk_or_part_uuid',
              'disk_or_part_device_node', 'disk_or_part_device_path',
              'lvm_pv_name', 'lvm_vg_name', 'lvm_pv_uuid',
              'lvm_pv_size_gib', 'lvm_pe_total', 'lvm_pe_alloced', 'ihost_uuid',
              'created_at', 'updated_at']
    fields = ['uuid', 'pv_state', 'pv_type', 'disk_or_part_uuid',
              'disk_or_part_device_node', 'disk_or_part_device_path',
              'lvm_pv_name', 'lvm_vg_name', 'lvm_pv_uuid',
              'lvm_pv_size', 'lvm_pe_total', 'lvm_pe_alloced', 'ihost_uuid',
              'created_at', 'updated_at']
    ipv.lvm_pv_size = math.floor(float(ipv.lvm_pv_size) / (1024 ** 3) * 1000) / 1000.0
    data = [(f, getattr(ipv, f, '')) for f in fields]
    utils.print_tuple_list(data, labels)


def _find_pv(cc, ihost, pvuuid):
    pvs = cc.ipv.list(ihost.uuid)
    for i in pvs:
        if i.uuid == pvuuid:
            break
    else:
        raise exc.CommandError('PV not found: host %s PV %s' %
                               (ihost.hostname, pvuuid))
    return i


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('pvuuid',
           metavar='<pv uuid>',
           help="UUID of pv")
def do_host_pv_show(cc, args):
    """Show Physical Volume attributes."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    i = _find_pv(cc, ihost, args.pvuuid)
    _print_ipv_show(i)


# Make the PV state data clearer to the end user
def _adjust_state_data(vg_name, state):
    if state == "adding":
        state = "adding (on unlock)"
    if state == "removing":
        state = "removing (on unlock)"
    return state


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_pv_list(cc, args):
    """List Physical Volumes."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    ipvs = cc.ipv.list(ihost.uuid)

    # Adjust state to be more user friendly
    for pv in ipvs:
        pv.pv_state = _adjust_state_data(pv.lvm_vg_name, pv.pv_state)

    field_labels = ['uuid', 'lvm_pv_name', 'disk_or_part_uuid',
                    'disk_or_part_device_node', 'disk_or_part_device_path',
                    'pv_state', 'pv_type', 'lvm_vg_name', 'ihost_uuid']
    fields = ['uuid', 'lvm_pv_name', 'disk_or_part_uuid',
              'disk_or_part_device_node', 'disk_or_part_device_path',
              'pv_state', 'pv_type', 'lvm_vg_name', 'ihost_uuid']
    utils.print_list(ipvs, fields, field_labels, sortby=0)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('lvgname',
           metavar='<lvg name>',
           help='Name of local volume group on the host [REQUIRED]')
@utils.arg('device_name_path_uuid',
           metavar='<device name or path or UUID>',
           help='Name or uuid of disk on the host [REQUIRED]')
def do_host_pv_add(cc, args):
    """Add a Physical Volume."""

    field_list = ['disk_or_part_uuid']

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    ilvg = ilvg_utils._find_ilvg(cc, ihost, args.lvgname)

    fields = {}
    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in field_list and not (v is None))
    fields.update(user_specified_fields)

    fields['ihost_uuid'] = ihost.uuid
    fields['ilvg_uuid'] = ilvg.uuid

    idisk = idisk_utils._find_disk(cc, ihost,
                                   args.device_name_path_uuid)
    if idisk:
        fields['disk_or_part_uuid'] = idisk.uuid
        fields['pv_type'] = 'disk'
    else:
        partition = partition_utils._find_partition(cc, ihost,
                                                    args.device_name_path_uuid)
        if partition:
            fields['disk_or_part_uuid'] = partition.uuid
            fields['pv_type'] = 'partition'

    if not idisk and not partition:
        raise exc.CommandError("No disk or partition found on host \'%s\' "
                               "by device path or uuid %s" %
                               (ihost.hostname, args.device_name_path_uuid))

    try:
        ipv = cc.ipv.create(**fields)
    except exc.HTTPNotFound:
        raise exc.CommandError("Physical volume creation failed: host %s: "
                               "fields %s" % (args.hostnameorid, fields))

    suuid = getattr(ipv, 'uuid', '')
    try:
        ipv = cc.ipv.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError("Created physical volume UUID not found: "
                               "%s" % suuid)

    _print_ipv_show(ipv)


@utils.arg('ipvuuid',
           metavar='<pv uuid>',
           help='uuid of the physical volume [REQUIRED]')
def do_host_pv_delete(cc, args):
    """Delete a Physical Volume."""
    try:
        cc.ipv.delete(args.ipvuuid)
    except exc.HTTPNotFound as ex:
        raise exc.CommandError("Physical volume deletion failed. "
                               "Reason: %s" % str(ex))
