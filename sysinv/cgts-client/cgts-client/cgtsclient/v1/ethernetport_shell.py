#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils


def _bootp_formatter(value):
    return bool(value)


def _bootp_port_formatter(port):
    return _bootp_formatter(port.bootp)


def _print_ethernet_port_show(port):
    fields = ['name', 'namedisplay',
              'mac', 'pciaddr',
              'numa_node',
              'autoneg', 'bootp',
              'pclass', 'pvendor', 'pdevice',
              'link_mode', 'capabilities',
              'uuid', 'host_uuid', 'interface_uuid',
              'created_at', 'updated_at']
    labels = ['name', 'namedisplay',
              'mac', 'pciaddr',
              'processor',
              'autoneg', 'bootp',
              'pclass', 'pvendor', 'pdevice',
              'link_mode', 'capabilities',
              'uuid', 'host_uuid', 'interface_uuid',
              'created_at', 'updated_at']
    data = [(f, getattr(port, f, '')) for f in fields]
    utils.print_tuple_list(data, labels,
                           formatters={'bootp': _bootp_formatter})


def _find_port(cc, ihost, portnameoruuid):
    ports = cc.ethernet_port.list(ihost.uuid)
    for p in ports:
        if p.name == portnameoruuid or p.uuid == portnameoruuid:
            break
    else:
        raise exc.CommandError('Ethernet port not found: host %s port %s' % (ihost.id, portnameoruuid))
    p.autoneg = 'Yes'   # TODO(jkung) Remove when autoneg supported in DB
    return p


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('pnameoruuid', metavar='<port name or uuid>', help="Name or UUID of port")
def do_host_ethernet_port_show(cc, args):
    """Show host ethernet port attributes."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    port = _find_port(cc, ihost, args.pnameoruuid)
    _print_ethernet_port_show(port)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_ethernet_port_list(cc, args):
    """List host ethernet ports."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    ports = cc.ethernet_port.list(ihost.uuid)
    for p in ports:
        p.autoneg = 'Yes'   # TODO(jkung) Remove when autoneg supported in DB

    field_labels = ['uuid', 'name', 'mac address', 'pci address', 'processor', 'auto neg', 'device type', 'boot i/f']
    fields = ['uuid', 'name', 'mac', 'pciaddr', 'numa_node', 'autoneg', 'pdevice', 'bootp']

    utils.print_list(ports, fields, field_labels, sortby=1,
                     formatters={'bootp': _bootp_port_formatter})
