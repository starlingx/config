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


def _print_address_show(obj):
    fields = ['uuid',
              'interface_uuid', 'ifname', 'forihostid',
              'address', 'prefix', 'enable_dad', 'pool_uuid']
    data = [(f, getattr(obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('address_uuid',
           metavar='<address_uuid>',
           help="UUID of IP address")
def do_host_addr_show(cc, args):
    """Show IP address attributes."""
    address = cc.address.get(args.address_uuid)
    _print_address_show(address)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_addr_list(cc, args):
    """List IP addresses on host."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    addresses = cc.address.list_by_host(ihost.uuid)

    field_labels = ['uuid', 'ifname', 'address', 'prefix']
    fields = ['uuid', 'ifname', 'address', 'prefix']
    utils.print_list(addresses, fields, field_labels, sortby=1)


@utils.arg('address_uuid',
           metavar='<address uuid>',
           help="UUID of IP address entry")
def do_host_addr_delete(cc, args):
    """Delete an IP address."""
    cc.address.delete(args.address_uuid)
    print('Deleted Address: %s' % (args.address_uuid))


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('ifnameorid',
           metavar='<interface name or id>',
           help="Name of interface [REQUIRED]")
@utils.arg('address',
           metavar='<ipv4/ipv6 address>',
           help="IPv4 or IPv6 address [REQUIRED]")
@utils.arg('prefix',
           metavar='<prefix length>',
           help="The network mask length in bits [REQUIRED]")
def do_host_addr_add(cc, args):
    """Add an IP address."""

    field_list = ['address', 'prefix']

    # Lookup parent host and interface
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    iinterface = iinterface_utils._find_interface(cc, ihost, args.ifnameorid)

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    # Insert interface UUID
    data['interface_uuid'] = iinterface.uuid

    address = cc.address.create(**data)
    uuid = getattr(address, 'uuid', '')
    try:
        address = cc.address.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created Address UUID not found: %s' % uuid)
    _print_address_show(address)
