#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import datanetwork as datanetwork_utils
from cgtsclient.v1 import ihost as ihost_utils
from cgtsclient.v1 import iinterface as iinterface_utils


def _print_interface_datanetwork_show(cc, obj):
    fields = ['hostname', 'uuid', 'ifname', 'datanetwork_name']
    # Add a hostname column using the forihostid field
    host_id = str(getattr(obj, 'forihostid', ''))
    ihost = ihost_utils._find_ihost(cc, host_id)
    setattr(obj, 'hostname', ihost.hostname)
    data = [(f, getattr(obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('hostnameorid',
           metavar='<hostnameorid>',
           help="Name or ID of host")
@utils.arg('ifnameoruuid',
           metavar='<ifnameoruuid>',
           nargs='?',
           help="Name or UUID of interface")
def do_interface_datanetwork_list(cc, args):
    """List datanetwork interfaces."""
    fields = ['hostname', 'uuid', 'ifname', 'datanetwork_name']
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    if args.ifnameoruuid is None:
        interface_datanetworks = \
            cc.interface_datanetwork.list_by_host(ihost.uuid)
    else:
        interface = \
            iinterface_utils._find_interface(cc, ihost, args.ifnameoruuid)
        interface_datanetworks = \
            cc.interface_datanetwork.list_by_interface(interface.uuid)
    # Add a hostname column using the forihostid field
    for i in interface_datanetworks[:]:
        host_id = str(getattr(i, 'forihostid', ''))
        ihost = ihost_utils._find_ihost(cc, host_id)
        setattr(i, 'hostname', ihost.hostname)
    utils.print_list(interface_datanetworks, fields, fields, sortby=1)


@utils.arg('interface_datanetwork_uuid',
           metavar='<interface datanetwork uuid>',
           help="UUID of interface datanetwork entry")
def do_interface_datanetwork_show(cc, args):
    """Show interface datanetwork details."""
    interface_datanetwork = \
        cc.interface_datanetwork.get(args.interface_datanetwork_uuid)
    _print_interface_datanetwork_show(cc, interface_datanetwork)


@utils.arg('hostnameorid',
           metavar='<hostnameorid>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('ifnameoruuid',
           metavar='<ifnameoruuid>',
           help="Name or UUID of interface [REQUIRED]")
@utils.arg('datanetnameoruuid',
           metavar='<datanetnameoruuid>',
           help="Name of UUID of datanetwork [REQUIRED]")
def do_interface_datanetwork_assign(cc, args):
    """Assign a datanetwork to an interface."""
    # Determine host, interface, and datanetwork using the given arguments
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    interface = \
        iinterface_utils._find_interface(cc, ihost, args.ifnameoruuid)
    datanetwork = \
        datanetwork_utils._find_datanetwork(cc, args.datanetnameoruuid)

    data = dict()
    data['interface_uuid'] = interface.uuid
    data['datanetwork_uuid'] = datanetwork.uuid

    interface_datanetwork = cc.interface_datanetwork.assign(**data)
    uuid = getattr(interface_datanetwork, 'uuid', '')
    try:
        interface_datanetwork = cc.interface_datanetwork.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created Interface DataNetwork '
                               'UUID not found: %s' % uuid)
    _print_interface_datanetwork_show(cc, interface_datanetwork)


@utils.arg('interface_datanetwork_uuid',
           metavar='<interface_datanetwork_uuid>',
           help="UUID of interface datanetwork entry")
def do_interface_datanetwork_remove(cc, args):
    """Remove an assigned datanetwork from an interface."""
    cc.interface_datanetwork.remove(args.interface_datanetwork_uuid)
    print('Deleted Interface DataNetwork: %s' % args.interface_datanetwork_uuid)
