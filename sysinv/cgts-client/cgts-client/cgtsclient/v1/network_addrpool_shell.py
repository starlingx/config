#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import address_pool as addrpool_utils
from cgtsclient.v1 import network as network_utils


def _print_network_addrpool_show(cc, obj):
    fields = ['uuid', 'network_name', 'address_pool_name']
    fields_labels = ['uuid', 'network_name', 'pool_name']
    data = [(fields_labels[index], getattr(obj, f, ''))
            for index, f in enumerate(fields)]
    utils.print_tuple_list(data)


def do_network_addrpool_list(cc, args):
    """List network and address pools."""
    fields = ['uuid', 'network_name', 'address_pool_name']
    fields_labels = ['uuid', 'network_name', 'addrpool_name']
    network_addrpools = cc.network_addrpool.list()
    utils.print_list(network_addrpools, fields, fields_labels, sortby=1)


@utils.arg('network_addrpool_uuid',
           metavar='<network addrpool uuid>',
           help="UUID of network addrpool entry")
def do_network_addrpool_show(cc, args):
    """Show network address-pool attributes."""
    network_addrpool = cc.network_addrpool.get(args.network_addrpool_uuid)
    _print_network_addrpool_show(cc, network_addrpool)


@utils.arg('netnameoruuid',
           metavar='<network name or uuid>',
           help="Name or UUID of IP network [REQUIRED]")
@utils.arg('addrpoolnameoruuid',
           metavar='<addrpool name or uuid>',
           help="Name or UUID of address pool [REQUIRED]")
def do_network_addrpool_assign(cc, args):
    """Assign a network to an address pool."""
    # Determine address pool and network using the given arguments
    addrpool = addrpool_utils._find_addrpool(cc, args.addrpoolnameoruuid)
    network = network_utils._find_network(cc, args.netnameoruuid)

    data = dict()
    data['address_pool_uuid'] = addrpool.uuid
    data['network_uuid'] = network.uuid

    network_addrpool = cc.network_addrpool.assign(**data)
    uuid = getattr(network_addrpool, 'uuid', '')
    try:
        network_addrpool = cc.network_addrpool.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created Network AddrPool UUID not found: %s' % uuid)
    _print_network_addrpool_show(cc, network_addrpool)


@utils.arg('network_addrpool_uuid',
           metavar='<network addrpool uuid>',
           help="UUID of network addrpool entry")
def do_network_addrpool_remove(cc, args):
    """Remove an assigned address pool from a network."""
    cc.network_addrpool.remove(args.network_addrpool_uuid)
    print('Deleted Network Addrpool: %s' % args.network_addrpool_uuid)
