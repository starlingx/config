#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
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


def _print_ceph_mon_show(ceph_mon):

    fields = ['uuid', 'ceph_mon_gib',
              'created_at', 'updated_at',
              'state', 'task']
    data = [(f, getattr(ceph_mon, f)) for f in fields]
    utils.print_tuple_list(data)


def _print_ceph_mon_list(cc):
    field_labels = ['uuid', 'ceph_mon_gib',
                    'hostname', 'state', 'task']
    fields = ['uuid', 'ceph_mon_gib', 'hostname',
              'state', 'task']
    ceph_mons = cc.ceph_mon.list()
    utils.print_list(ceph_mons, fields, field_labels, sortby=0)


@utils.arg('controller',
           metavar='<controller>',
           choices=[constants.CONTROLLER_0_HOSTNAME,
                    constants.CONTROLLER_1_HOSTNAME],
           help='Specify controller host name <%s | %s> ' % (
                   constants.CONTROLLER_0_HOSTNAME,
                   constants.CONTROLLER_1_HOSTNAME))
@utils.arg('attributes',
           metavar='<path=value>',
           nargs='+',
           action='append',
           default=[],
           help="Ceph mon parameters to apply, "
                "Supported parameters: ceph_mon_gib.")
def do_ceph_mon_modify(cc, args):
    controller = vars(args).get('controller', None)
    patch = utils.args_array_to_patch("replace", args.attributes[0])
    patch.append({
        'op': 'replace', 'path': '/controller', 'value': controller
    })

    # Obtain the host whose ceph monitor we want to modify.
    ihost = ihost_utils._find_ihost(cc, controller)
    ceph_mon = cc.ceph_mon.list(ihost.uuid)[0]

    changes = dict(v.split("=", 1) for v in args.attributes[0])
    if changes.get('ceph_mon_gib', None) and \
            changes['ceph_mon_gib'] != getattr(ceph_mon, 'ceph_mon_gib'):

        for ceph_mon in cc.ceph_mon.list():
            cc.ceph_mon.update(ceph_mon.uuid, patch)
        _print_ceph_mon_list(cc)
        print("\nNOTE: ceph_mon_gib for both controllers are changed.")
    else:
        ceph_mon = cc.ceph_mon.update(ceph_mon.uuid, patch)
        _print_ceph_mon_show(ceph_mon)

    print("\nSystem configuration has changed.\nplease follow the "
          "administrator guide to complete configuring system.\n")


def do_ceph_mon_list(cc, args):
    """List ceph mons"""
    _print_ceph_mon_list(cc)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="name or ID of host [REQUIRED]")
def do_ceph_mon_show(cc, args):
    """Show ceph_mon of a specific host."""

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    ceph_mons = cc.ceph_mon.list()
    for ceph_mon in ceph_mons:
        hostname = getattr(ceph_mon, 'hostname', '')
        if hostname == ihost.hostname:
            _print_ceph_mon_show(ceph_mon)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help='name or ID of host [REQUIRED]')
def do_ceph_mon_add(cc, args):
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    fields = {}

    fields['ihost_uuid'] = ihost.uuid
    try:
        ceph_mon = cc.ceph_mon.create(**fields)
    except exc.HTTPNotFound:
        raise exc.CommandError(
            "Ceph mon creation failed: "
            "host %s: " % args.hostnameorid)

    if ceph_mon and len(ceph_mon.ceph_mon):
        suuid = ceph_mon.ceph_mon[0].get('uuid', '')
    else:
        raise exc.CommandError(
            "Created ceph_mon has invalid data.")
    try:
        ceph_mon = cc.ceph_mon.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError("Created ceph monitor UUID not found: "
                               "%s" % suuid)

    _print_ceph_mon_show(ceph_mon)


@utils.arg('hostnameorid',
           help='hostname for compute')
def do_ceph_mon_delete(cc, args):
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    try:
        cc.ceph_mon.delete(ihost.uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError("failed to delete ceph_mon")
