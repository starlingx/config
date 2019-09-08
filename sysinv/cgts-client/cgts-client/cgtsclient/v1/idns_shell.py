#
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc


def _print_idns_show(idns):
    fields = ['uuid', 'nameservers', 'isystem_uuid',
              'created_at', 'updated_at']
    data = [(f, getattr(idns, f, '')) for f in fields]
    utils.print_tuple_list(data)


def do_dns_show(cc, args):
    """Show DNS (Domain Name Server) attributes."""

    idnss = cc.idns.list()

    # idns = cc.idns.get(idnss[0])

    _print_idns_show(idnss[0])


def donot_dns_list(cc, args):
    """List dnss."""

    idnss = cc.idns.list()

    field_labels = ['uuid', 'nameservers']
    fields = ['uuid', 'nameservers']
    utils.print_list(idnss, fields, field_labels, sortby=1)


@utils.arg('cname',
           metavar='<dns name>',
           help="Name of dns [REQUIRED]")
def donot_dns_add(cc, args):
    """Add an dns."""

    field_list = ['cname']

    fields = {}

    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in field_list and not (v is None))

    fields.update(user_specified_fields)

    try:
        idns = cc.idns.create(**fields)
        suuid = getattr(idns, 'uuid', '')

    except exc.HTTPNotFound:
        raise exc.CommandError('DNS create failed: name %s, fields %s ' %
                               (args.cname, fields))

    try:
        idns = cc.idns.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('dns not found: %s' % suuid)

    _print_idns_show(idns)


@utils.arg('attributes',
           metavar='<path=value>',
           nargs='+',
           action='append',
           default=[],
           help="DNS attributes to modify ")
def do_dns_modify(cc, args):
    """Modify DNS attributes."""

    idnss = cc.idns.list()
    idns = idnss[0]
    op = "replace"

    for attribute in args.attributes:
        if 'nameservers=' in attribute:
            nameservers = attribute[0].split('=')[1]
            if not nameservers.strip():
                args.attributes[0][0] = 'nameservers=NC'

    if not any('action=' in att for att in args.attributes[0]):
        args.attributes[0].append('action=apply')

    patch = utils.args_array_to_patch(op, args.attributes[0])
    try:
        idns = cc.idns.update(idns.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('DNS not found: %s' % idns.uuid)

    _print_idns_show(idns)
