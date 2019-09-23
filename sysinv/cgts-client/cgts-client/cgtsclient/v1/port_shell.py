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
from cgtsclient.v1 import ihost as ihost_utils


def _print_port_show(port):
    fields = ['name', 'namedisplay',
              'type', 'pciaddr', 'dev_id', 'numa_node',
              'sriov_totalvfs', 'sriov_numvfs',
              'sriov_vfs_pci_address', 'sriov_vf_driver',
              'sriov_vf_pdevice_id',
              'driver', 'pclass', 'pvendor', 'pdevice',
              'capabilities',
              'uuid', 'host_uuid', 'interface_uuid',
              'dpdksupport',
              'created_at', 'updated_at']
    labels = ['name', 'namedisplay',
              'type', 'pciaddr', 'dev_id', 'processor',
              'sriov_totalvfs', 'sriov_numvfs',
              'sriov_vfs_pci_address', 'sriov_vf_driver',
              'sriov_vf_pdevice_id',
              'driver', 'pclass', 'pvendor', 'pdevice',
              'capabilities',
              'uuid', 'host_uuid', 'interface_uuid',
              'accelerated',
              'created_at', 'updated_at']
    data = [(f, getattr(port, f, '')) for f in fields]
    utils.print_tuple_list(data, labels)


def _find_port(cc, ihost, portnameoruuid):
    ports = cc.port.list(ihost.uuid)
    for p in ports:
        if p.name == portnameoruuid or p.uuid == portnameoruuid:
            break
    else:
        raise exc.CommandError('Port not found: host %s port %s' % (ihost.id, portnameoruuid))
    return p


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('pnameoruuid', metavar='<port name or uuid>', help="Name or UUID of port")
def do_host_port_show(cc, args):
    """Show host port details."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    port = _find_port(cc, ihost, args.pnameoruuid)
    _print_port_show(port)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_port_list(cc, args):
    """List host ports."""

    from cgtsclient.common import wrapping_formatters

    terminal_width = utils.get_terminal_size()[0]

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    ports = cc.port.list(ihost.uuid)

    field_labels = ['uuid', 'name', 'type', 'pci address', 'device',
                    'processor', 'accelerated', 'device type']
    fields = ['uuid', 'name', 'type', 'pciaddr', 'dev_id', 'numa_node',
              'dpdksupport', 'pdevice']

    format_spec = wrapping_formatters.build_best_guess_formatters_using_average_widths(ports, fields, field_labels,
                                                                                       no_wrap_fields=['pciaddr'])
    # best-guess formatter does not make a good guess for
    # proper width of pdevice until terminal is > 155
    # We override that width here.
    pdevice_width = None
    if terminal_width <= 130:
        pdevice_width = .1
    elif 131 >= terminal_width <= 150:
        pdevice_width = .13
    elif 151 >= terminal_width <= 155:
        pdevice_width = .14

    if pdevice_width and format_spec["pdevice"] > pdevice_width:
        format_spec["pdevice"] = pdevice_width

    formatters = wrapping_formatters.build_wrapping_formatters(ports, fields, field_labels, format_spec)

    utils.print_list(ports, fields, field_labels, formatters=formatters, sortby=1)
