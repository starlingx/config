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


def _print_network_show(obj):
    fields = ['id', 'uuid', 'name', 'type', 'dynamic', 'pool_uuid']
    data = [(f, getattr(obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('network_uuid',
           metavar='<network_uuid>',
           help="UUID of IP network")
def do_network_show(cc, args):
    """Show IP network details."""
    labels = ['id', 'uuid', 'name', 'type', 'dynamic', 'pool_uuid']
    fields = ['id', 'uuid', 'name', 'type', 'dynamic', 'pool_uuid']
    network = cc.network.get(args.network_uuid)
    data = [(f, getattr(network, f, '')) for f in fields]
    utils.print_tuple_list(data, tuple_labels=labels)


def do_network_list(cc, args):
    """List IP networks on host."""
    labels = ['id', 'uuid', 'name', 'type', 'dynamic', 'pool_uuid']
    fields = ['id', 'uuid', 'name', 'type', 'dynamic', 'pool_uuid']
    networks = cc.network.list()
    utils.print_list(networks, fields, labels, sortby=1)


@utils.arg('name',
           metavar='<network_name>',
           help="Name of network [REQUIRED]")
@utils.arg('type',
           metavar='<network type>',
           help="Type of network [REQUIRED]")
@utils.arg('dynamic',
           metavar='<dynamic>',
           choices=['true', 'false', 'True', 'False'],
           help="dynamic [REQUIRED]")
@utils.arg('pool_uuid',
           metavar='<pool_uuid>',
           help="The uuid of the address pool [REQUIRED]")
def do_network_add(cc, args):
    """Add a network."""

    field_list = ['name', 'type', 'dynamic', 'pool_uuid']

    # make sure dynamic is lower
    if args.dynamic is not None:
        args.dynamic = args.dynamic.lower()

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    network = cc.network.create(**data)
    uuid = getattr(network, 'uuid', '')
    try:
        network = cc.network.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created network UUID not found: %s' % uuid)
    _print_network_show(network)


@utils.arg('network_uuid',
           metavar='<network_uuid>',
           help="UUID of network entry")
def do_network_delete(cc, args):
    """Delete a network"""
    cc.network.delete(args.network_uuid)
    print('Deleted Network: %s' % args.network_uuid)
