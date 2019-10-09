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


def _address_range_formatter(values):
    result = []
    for start, end in values:
        result.append(str(start) + "-" + str(end))
    return result


def _address_range_pool_formatter(pool):
    return _address_range_formatter(pool.ranges)


def _print_address_pool_show(obj):
    fields = ['uuid', 'name', 'network', 'prefix', 'order', 'ranges',
              'floating_address', 'controller0_address', 'controller1_address',
              'gateway_address']
    data = [(f, getattr(obj, f, '')) for f in fields]
    utils.print_tuple_list(
        data, formatters={'ranges': _address_range_formatter})


@utils.arg('address_pool_uuid',
           metavar='<address_pool_uuid>',
           help="UUID of IP address pool")
def do_addrpool_show(cc, args):
    """Show IP address pool attributes."""
    address_pool = cc.address_pool.get(args.address_pool_uuid)
    _print_address_pool_show(address_pool)


def do_addrpool_list(cc, args):
    """List IP address pools."""
    address_pools = cc.address_pool.list()

    fields = ['uuid', 'name', 'network', 'prefix', 'order', 'ranges',
              'floating_address', 'controller0_address', 'controller1_address',
              'gateway_address']
    utils.print_list(address_pools, fields, fields, sortby=1,
                     formatters={'ranges': _address_range_pool_formatter})


@utils.arg('address_pool_uuid',
           metavar='<address_pool uuid>',
           help="UUID of IP address pool entry")
def do_addrpool_delete(cc, args):
    """Delete an IP address pool."""
    cc.address_pool.delete(args.address_pool_uuid)
    print('Deleted address pool: %s' % (args.address_pool_uuid))


def _get_range_tuples(data):
    """Split the ranges field from a comma separated list of start-end to a
       real list of (start, end) tuples.
    """
    ranges = []
    for r in data['ranges'].split(',') or []:
        start, end = r.split('-')
        ranges.append((start, end))
    return ranges


@utils.arg('name',
           metavar='<name>',
           help="Name of the Address Pool [REQUIRED]")
@utils.arg('network',
           metavar='<network address>',
           help="Network IP address [REQUIRED]")
@utils.arg('prefix',
           metavar='<network prefix>',
           help="Network IP address prefix length [REQUIRED]")
@utils.arg('--ranges',
           metavar='<ranges>',
           help="The inclusive range of addresses to allocate "
           "<startaddr1-endaddr1>[,<startaddr2-endaddr2>,...]")
@utils.arg('--order',
           metavar='<sequential | random>',
           help="The allocation order within the start/end range")
def do_addrpool_add(cc, args):
    """Add an IP address pool."""

    field_list = ['name', 'network', 'prefix', 'order', 'ranges']

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    if 'ranges' in data:
        data['ranges'] = _get_range_tuples(data)

    address_pool = cc.address_pool.create(**data)
    uuid = getattr(address_pool, 'uuid', '')
    try:
        address_pool = cc.address_pool.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created address pool UUID not found: %s' % uuid)
    _print_address_pool_show(address_pool)


@utils.arg('address_pool_uuid',
           metavar='<address_pool uuid>',
           help="UUID of IP address pool entry")
@utils.arg('--name',
           metavar='<name>',
           help="Name of the Address Pool]")
@utils.arg('--ranges',
           metavar='<ranges>',
           help="The inclusive range of addresses to allocate "
           "<startaddr1-endaddr1>[,<startaddr2-endaddr2>,...]")
@utils.arg('--order',
           metavar='<sequential | random>',
           help="The allocation order within the start/end range")
@utils.arg('--prefix',
           metavar='<prefix>',
           help="CIDR prefix, only modifiable during bootstrap phase.")
def do_addrpool_modify(cc, args):
    """Modify interface attributes."""

    rwfields = ['name', 'ranges', 'order', 'prefix']

    data = dict((k, v) for (k, v) in vars(args).items()
                if k in rwfields and not (v is None))

    if 'ranges' in data:
        data['ranges'] = _get_range_tuples(data)

    patch = []
    for (k, v) in data.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})

    address_pool = cc.address_pool.update(args.address_pool_uuid, patch)
    _print_address_pool_show(address_pool)
