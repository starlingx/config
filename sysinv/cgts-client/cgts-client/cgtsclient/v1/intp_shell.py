#
# Copyright (c) 2013-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc


def _print_intp_show(intp):
    fields = ['uuid', 'ntpservers', 'isystem_uuid', 'created_at', 'updated_at']
    data = [(f, getattr(intp, f, '')) for f in fields]
    utils.print_tuple_list(data)


def do_ntp_show(cc, args):
    """Show NTP (Network Time Protocol) attributes."""

    intps = cc.intp.list()
    # intp = cc.intp.get(args.uuid)

    _print_intp_show(intps[0])


def donot_config_ntp_list(cc, args):
    """List ntps."""

    intps = cc.intp.list()

    field_labels = ['uuid', 'ntpservers']
    fields = ['uuid', 'ntpservers']
    utils.print_list(intps, fields, field_labels, sortby=1)


@utils.arg('cname',
           metavar='<ntp name>',
           help="Name of ntp [REQUIRED]")
def donot_ntp_add(cc, args):
    """Add an ntp."""

    field_list = ['cname']

    fields = {}

    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in field_list and not (v is None))

    fields.update(user_specified_fields)

    try:
        intp = cc.intp.create(**fields)
        suuid = getattr(intp, 'uuid', '')

    except exc.HTTPNotFound:
        raise exc.CommandError('NTP create failed: name: %s, fields %s ' %
                               (args.cname, fields))

    try:
        intp = cc.intp.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('ntp not found: %s' % suuid)

    _print_intp_show(intp)


@utils.arg('attributes',
           metavar='<path=value>',
           nargs='*',
           action='append',
           default=[],
           help="NTP attributes to modify ")
def do_ntp_modify(cc, args):
    """Modify NTP attributes."""

    intps = cc.intp.list()
    intp = intps[0]
    op = "replace"

    for attribute in args.attributes:
        if 'ntpservers=' in attribute:
            ntpservers = attribute[0].split('=')[1]
            if not ntpservers.strip():
                args.attributes[0][0] = 'ntpservers=NC'

    # We need to apply the manifests
    if not any('action=' in att for att in args.attributes[0]):
        args.attributes[0].append('action=apply')

    patch = utils.args_array_to_patch(op, args.attributes[0])
    try:
        intp = cc.intp.update(intp.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('NTP not found: %s' % intp.uuid)

    _print_intp_show(intp)
