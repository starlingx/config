#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils
from cgtsclient.v1 import iinterface as iinterface_utils
from cgtsclient.v1 import network as network_utils


def _print_interface_network_show(cc, obj):
    fields = ['hostname', 'uuid', 'ifname', 'network_name']
    # Add a hostname column using the forihostid field
    host_id = str(getattr(obj, 'forihostid', ''))
    ihost = ihost_utils._find_ihost(cc, host_id)
    setattr(obj, 'hostname', ihost.hostname)
    data = [(f, getattr(obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('ifnameoruuid',
           metavar='<interface name or uuid>',
           nargs='?',
           help="Name of interface")
def do_interface_network_list(cc, args):
    """List network interfaces."""
    fields = ['hostname', 'uuid', 'ifname', 'network_name']
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    if args.ifnameoruuid is None:
        interface_networks = cc.interface_network.list_by_host(ihost.uuid)
    else:
        interface = iinterface_utils._find_interface(cc, ihost, args.ifnameoruuid)
        interface_networks = cc.interface_network.list_by_interface(interface.uuid)
    # Add a hostname column using the forihostid field
    for i in interface_networks[:]:
        host_id = str(getattr(i, 'forihostid', ''))
        ihost = ihost_utils._find_ihost(cc, host_id)
        setattr(i, 'hostname', ihost.hostname)
    utils.print_list(interface_networks, fields, fields, sortby=1)


@utils.arg('interface_network_uuid',
           metavar='<interface network uuid>',
           help="UUID of interface network entry")
def do_interface_network_show(cc, args):
    """Show interface network details."""
    interface_network = cc.interface_network.get(args.interface_network_uuid)
    _print_interface_network_show(cc, interface_network)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('ifnameoruuid',
           metavar='<interface name or uuid>',
           help="Name of interface [REQUIRED]")
@utils.arg('netnameoruuid',
           metavar='<network name or uuid>',
           help="Name of UUID of IP network [REQUIRED]")
def do_interface_network_assign(cc, args):
    """Assign a network to an interface."""
    # Determine host, interface, and network using the given arguments
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    interface = iinterface_utils._find_interface(cc, ihost, args.ifnameoruuid)
    network = network_utils._find_network(cc, args.netnameoruuid)

    data = dict()
    data['interface_uuid'] = interface.uuid
    data['network_uuid'] = network.uuid

    interface_network = cc.interface_network.assign(**data)
    uuid = getattr(interface_network, 'uuid', '')
    try:
        interface_network = cc.interface_network.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created Network Interface UUID not found: %s' % uuid)
    _print_interface_network_show(cc, interface_network)


@utils.arg('interface_network_uuid',
           metavar='<interface network uuid>',
           help="UUID of interface network entry")
def do_interface_network_remove(cc, args):
    """Remove an assigned network from an interface."""
    cc.interface_network.remove(args.interface_network_uuid)
    print('Deleted Interface Network: %s' % args.interface_network_uuid)
