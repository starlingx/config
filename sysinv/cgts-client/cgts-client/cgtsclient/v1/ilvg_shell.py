#!/usr/bin/env python
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
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
from cgtsclient.v1 import ilvg as ilvg_utils
from oslo_serialization import jsonutils


def _print_ilvg_show(ilvg):
    labels = ['lvm_vg_name', 'vg_state', 'uuid', 'ihost_uuid', 'lvm_vg_access',
              'lvm_max_lv', 'lvm_cur_lv', 'lvm_max_pv', 'lvm_cur_pv',
              'lvm_vg_size_gib', 'lvm_vg_total_pe', 'lvm_vg_free_pe', 'created_at',
              'updated_at', 'parameters']

    fields = ['lvm_vg_name', 'vg_state', 'uuid', 'ihost_uuid', 'lvm_vg_access',
              'lvm_max_lv', 'lvm_cur_lv', 'lvm_max_pv', 'lvm_cur_pv',
              'lvm_vg_size', 'lvm_vg_total_pe', 'lvm_vg_free_pe', 'created_at',
              'updated_at']

    # convert size from Byte to GiB
    ilvg.lvm_vg_size = utils.convert_size_from_bytes(ilvg.lvm_vg_size,
                                                     constants.GiB)

    data = [(f, getattr(ilvg, f, '')) for f in fields]

    # rename capabilities for display purposes and add to display list
    data.append(('parameters', getattr(ilvg, 'capabilities', '')))

    utils.print_tuple_list(data, labels)


def _find_lvg(cc, ihost, lvguuid):
    lvgs = cc.ilvg.list(ihost.uuid)
    for i in lvgs:
        if i.uuid == lvguuid:
            break
    else:
        raise exc.CommandError('Local Volume Group not found: host %s lvg %s' %
                               (ihost.hostname, lvguuid))
    return i


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('lvgnameoruuid',
           metavar='<lvg name or uuid>',
           help="Name or UUID of lvg [REQUIRED]")
def do_host_lvg_show(cc, args):
    """Show Local Volume Group attributes."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    ilvg = ilvg_utils._find_ilvg(cc, ihost, args.lvgnameoruuid)
    _print_ilvg_show(ilvg)


# Make the LVG state data clearer to the end user
def _adjust_state_data(vg_name, state):
    if state == "adding":
        state = "adding (on unlock)"
    if state == "removing":
        state = "removing (on unlock)"
    return state


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
def do_host_lvg_list(cc, args):
    """List Local Volume Groups."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    ilvgs = cc.ilvg.list(ihost.uuid)

    # Adjust state to be more user friendly
    for lvg in ilvgs:
        lvg.vg_state = _adjust_state_data(lvg.lvm_vg_name, lvg.vg_state)

        # convert size from Byte to GiB
        lvg.lvm_vg_size = utils.convert_size_from_bytes(lvg.lvm_vg_size,
                                                        constants.GiB)

    field_labels = ['UUID', 'LVG Name', 'State', 'Access',
                    'Size (GiB)', 'Current PVs', 'Current LVs']
    fields = ['uuid', 'lvm_vg_name', 'vg_state', 'lvm_vg_access',
              'lvm_vg_size', 'lvm_cur_pv', 'lvm_cur_lv']
    utils.print_list(ilvgs, fields, field_labels, sortby=0)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('lvm_vg_name',
           metavar='<lvg name>',
           help="Name of the Local Volume Group [REQUIRED]")
def do_host_lvg_add(cc, args):
    """Add a Local Volume Group."""

    field_list = ['lvm_vg_name']

    # default values
    fields = {'lvm_vg_name': 'nova-local'}

    # Get the ihost object
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in field_list and not (v is None))

    if 'lvm_vg_name' in user_specified_fields.keys():
        user_specified_fields['lvm_vg_name'] =\
            user_specified_fields['lvm_vg_name'].replace(" ", "")
    fields.update(user_specified_fields)

    try:
        fields['ihost_uuid'] = ihost.uuid

        ilvg = cc.ilvg.create(**fields)
    except exc.HTTPNotFound:
        raise exc.CommandError('Lvg create failed: host %s: fields %s' %
                               (args.hostnameorid, fields))

    suuid = getattr(ilvg, 'uuid', '')
    try:
        ilvg = cc.ilvg.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created Lvg UUID not found: %s' % suuid)

    _print_ilvg_show(ilvg)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('lvm_vg_name',
           metavar='<lvg name>',
           help="Name of the Local Volume Group [REQUIRED]")
def do_host_lvg_delete(cc, args):
    """Delete a Local Volume Group."""

    # Get the ihost object
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    ilvg = ilvg_utils._find_ilvg(cc, ihost, args.lvm_vg_name)

    try:
        cc.ilvg.delete(ilvg.uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Local Volume Group delete failed: host %s: '
                               'lvg %s' % (args.hostnameorid,
                                           args.lvm_vg_name))


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of the host [REQUIRED]")
@utils.arg('lvgnameoruuid',
           metavar='<lvm name or uuid>',
           help="Name or UUID of lvg [REQUIRED]")
@utils.arg('-b', '--instance_backing',
           metavar='<instance backing>',
           choices=['lvm', 'image', 'remote'],
           help=("Type of instance backing. "
                 "Allowed values: lvm, image, remote. [nova-local]"))
@utils.arg('-c', '--concurrent_disk_operations',
           metavar='<concurrent disk operations>',
           help=("Set the number of concurrent I/O intensive disk operations "
                 "such as glance image downloads, image format conversions, "
                 "etc. [nova-local]"))
@utils.arg('-s', '--instances_lv_size_gib',
           metavar='<instances_lv size in GiB>',
           help=("Set the desired size (in GiB) of the instances LV that is "
                 "used for /etc/nova/instances. Example: For a 50GB volume, "
                 "use 50. Required when instance backing is \"lvm\". "
                 "[nova-local]"))
@utils.arg('-l', '--lvm_type',
           metavar='<lvm_type>',
           choices=['thick', 'thin'],
           help=("Determines the thick or thin provisioning format "
                 "of the LVM volume group. [cinder-volumes]"))
def do_host_lvg_modify(cc, args):
    """Modify the attributes of a Local Volume Group."""

    # Get all the fields from the command arguments
    field_list = ['hostnameorid', 'lvgnameoruuid',
                  'instance_backing', 'instances_lv_size_gib',
                  'concurrent_disk_operations', 'lvm_type']
    fields = dict((k, v) for (k, v) in vars(args).items()
                  if k in field_list and not (v is None))

    all_caps_list = ['instance_backing', 'instances_lv_size_gib',
                     'concurrent_disk_operations', 'lvm_type']
    integer_fields = ['instances_lv_size_gib', 'concurrent_disk_operations']
    requested_caps_dict = {}

    for cap in all_caps_list:
        if cap in fields:
            try:
                if cap in integer_fields:
                    requested_caps_dict[cap] = int(fields[cap])
                else:
                    requested_caps_dict[cap] = fields[cap]
                if cap == 'instances_lv_size_gib':
                    requested_caps_dict['instances_lv_size_mib'] = \
                        requested_caps_dict.pop('instances_lv_size_gib') * 1024
            except ValueError:
                raise exc.CommandError('instances_lv size must be an integer '
                                       'greater than 0: %s' % fields[cap])

    # Get the ihost object
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    # Get the volume group
    lvg = ilvg_utils._find_ilvg(cc, ihost, args.lvgnameoruuid)

    # format the arguments
    patch = []
    patch.append({'path': '/capabilities',
                  'value': jsonutils.dumps(requested_caps_dict),
                  'op': 'replace'})

    # Update the volume group attributes
    try:
        ilvg = cc.ilvg.update(lvg.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError(
            "ERROR: Local Volume Group update failed: "
            "host %s volume group %s : update %s"
            % (args.hostnameorid, args.lvgnameoruuid, patch))

    _print_ilvg_show(ilvg)
