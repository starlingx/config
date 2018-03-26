#!/usr/bin/env python
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


def _print_iinfra_show(iinfra):
    fields = ['uuid', 'infra_subnet', 'infra_start', 'infra_end',
              'infra_mtu', 'infra_vlan_id',
              'isystem_uuid', 'created_at', 'updated_at']
    data = [(f, getattr(iinfra, f, '')) for f in fields]
    utils.print_tuple_list(data)


def do_infra_show(cc, args):
    """Show infrastructure network attributes."""

    iinfras = cc.iinfra.list()
    if not iinfras:
        print "Infrastructure network not configured"
        return

    iinfra = iinfras[0]

    _print_iinfra_show(iinfra)


@utils.arg('subnet',
           metavar='<network subnet>',
           help="Network subnet")
@utils.arg('--start',
           metavar='<ip-address>',
           help="The start IP address in subnet")
@utils.arg('--end',
           metavar='<ip-address>',
           help="The end IP address in subnet")
@utils.arg('--mtu',
           metavar='<mtu>',
           help='The MTU of the infrastructure interface')
@utils.arg('--vlan_id',
           metavar='<vlan_id>',
           help='The VLAN id of the infrastructure interface')
def do_infra_add(cc, args):
    """Add an Infrastructure network."""
    field_list = ['subnet', 'start', 'end', 'mtu', 'vlan_id']

    # Prune input fields down to required/expected values
    data = dict(('infra_' + k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    infra = cc.iinfra.create(**data)

    _print_iinfra_show(infra)


@utils.arg('attributes',
           metavar='<path=value>',
           nargs='+',
           action='append',
           default=[],
           help="Infrastructure Network attributes to modify ")
def do_infra_modify(cc, args):
    """Modify infrastructure network IP attributes."""

    iinfras = cc.iinfra.list()
    if not iinfras:
        print "Infrastructure network not configured"
        return

    iinfra = iinfras[0]

    # caused by the split on parameters without a '='
    for entry in args.attributes[0]:
        if(entry.count("=") != 1):
            raise exc.CommandError('infra-modify parameters must be '
                                   'of the form property=value')

    patch = utils.args_array_to_patch("replace", args.attributes[0])
    try:
        iinfra = cc.iinfra.update(iinfra.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('Infrastructure network not found: %s' %
                               iinfra.uuid)

    _print_iinfra_show(iinfra)


def do_infra_apply(cc, args):
    infras = cc.iinfra.list()
    if not infras:
        print "Infrastructure network not configured"
        return

    infra = infras[0]

    patch = utils.args_array_to_patch("replace", ['action=apply'])
    try:
        cc.iinfra.update(infra.uuid, patch)
        print("\nApplying infrastructure network configuration to active "
              "controller.\n"
              "Please wait for configuration to be applied before unlocking "
              "additional hosts.\n")
    except exc.HTTPNotFound:
        raise exc.CommandError('Infrastructure network not found: %s' %
                               infra.uuid)
