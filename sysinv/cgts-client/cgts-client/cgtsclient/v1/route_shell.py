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
from cgtsclient.v1 import ihost as ihost_utils
from cgtsclient.v1 import iinterface as iinterface_utils


def _print_route_show(obj):
    fields = ['uuid',
              'interface_uuid', 'ifname', 'forihostid',
              'network', 'prefix', 'gateway', 'metric']
    data = [(f, getattr(obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('route_uuid',
           metavar='<route_uuid>',
           help="UUID of IP route")
def do_host_route_show(cc, args):
    """Show IP route attributes."""
    route = cc.route.get(args.route_uuid)
    _print_route_show(route)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_route_list(cc, args):
    """List IP routes on host."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    routes = cc.route.list_by_host(ihost.uuid)

    field_labels = ['uuid', 'ifname', 'network', 'prefix', 'gateway', 'metric']
    fields = ['uuid', 'ifname', 'network', 'prefix', 'gateway', 'metric']
    utils.print_list(routes, fields, field_labels, sortby=1)


@utils.arg('route_uuid',
           metavar='<route uuid>',
           help="UUID of IP route entry")
def do_host_route_delete(cc, args):
    """Delete an IP route."""
    cc.route.delete(args.route_uuid)
    print('Deleted Route: %s' % (args.route_uuid))


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('ifnameorid',
           metavar='<interface name or id>',
           help="Name of interface [REQUIRED]")
@utils.arg('network',
           metavar='<ipv4/ipv6 address>',
           help="IPv4 or IPv6 network address [REQUIRED]")
@utils.arg('prefix',
           metavar='<prefix length>',
           help="The network mask length in bits [REQUIRED]")
@utils.arg('gateway',
           metavar='<ipv4/ipv6 address>',
           help="IPv4 or IPv6 nexthop gateway address [REQUIRED]")
@utils.arg('metric',
           metavar='<metric>',
           default=1,
           nargs='?',
           help="IP route metric (default=1)")
def do_host_route_add(cc, args):
    """Add an IP route."""

    field_list = ['network', 'prefix', 'gateway', 'metric']

    # Lookup parent host and interface
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    iinterface = iinterface_utils._find_interface(cc, ihost, args.ifnameorid)

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    # Insert interface UUID
    data['interface_uuid'] = iinterface.uuid

    route = cc.route.create(**data)
    uuid = getattr(route, 'uuid', '')
    try:
        route = cc.route.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created Route UUID not found: %s' % uuid)
    _print_route_show(route)
