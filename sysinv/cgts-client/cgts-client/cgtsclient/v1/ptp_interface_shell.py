########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils
from cgtsclient.v1 import iinterface as iinterface_utils
from cgtsclient.v1 import ptp_instance as ptp_instance_utils


def _print_ptp_interface_show(ptp_interface_obj):
    fields = ['uuid', 'ifname', 'ptp_instance_name',
              'hostname', 'created_at']
    data = [(f, getattr(ptp_interface_obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('ptp_interface_uuid',
           metavar='<ptp_interface_uuid>',
           help="UUID of a PTP interface")
def do_ptp_interface_show(cc, args):
    """Show PTP interface attributes."""
    ptp_interface = cc.ptp_interface.get(args.ptp_interface_uuid)
    host_id = str(getattr(ptp_interface, 'forihostid', ''))
    ihost = ihost_utils._find_ihost(cc, host_id)
    setattr(ptp_interface, 'hostname', ihost.hostname)
    _print_ptp_interface_show(ptp_interface)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Hostname or ID of a host")
@utils.arg('ifnameorid',
           metavar='<interface name or uuid>',
           nargs='?',
           help="Interface name [OPTIONAL]")
def do_ptp_interface_list(cc, args):
    """List PTP interfaces on the specified host,
       or a subset of PTP interfaces associated
       with a given underlying interface.
    """
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    if args.ifnameorid:
        validate_interface = iinterface_utils._find_interface(cc, ihost, args.ifnameorid)
        ptp_interfaces = cc.ptp_interface.list_by_interface(ihost.uuid, validate_interface.uuid)
    else:
        ptp_interfaces = cc.ptp_interface.list_by_host(ihost.uuid)

    # Add a hostname column using the forihostid field
    for i in ptp_interfaces[:]:
        host_id = str(getattr(i, 'forihostid', ''))
        ihost = ihost_utils._find_ihost(cc, host_id)
        setattr(i, 'hostname', ihost.hostname)
    field_labels = ['uuid', 'hostname', 'ifname', 'ptp_instance_name']
    fields = ['uuid', 'hostname', 'ifname', 'ptp_instance_name']
    utils.print_list(ptp_interfaces, fields, field_labels)


@utils.arg('ptp_interface_uuid',
           metavar='<ptp_interface_uuid>',
           help="UUID of a PTP instance")
def do_ptp_interface_delete(cc, args):
    """Delete a PTP interface"""
    cc.ptp_interface.delete(args.ptp_interface_uuid)
    print('Deleted PTP interface: %s' % (args.ptp_interface_uuid))


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="The hostname or id associated with the interface and ptp instance [REQUIRED]")
@utils.arg('ifnameorid',
           metavar='<interface name or uuid>',
           help="Name or UUID of an interface [REQUIRED]")
@utils.arg('ptpinstancenameorid',
           metavar='<ptp instance name or uuid>',
           help="Name or UUID of a PTP instance [REQUIRED]")
def do_ptp_interface_add(cc, args):
    """Add a PTP interface."""
    field_list = ['interface_uuid', 'ptp_instance_uuid']

    validate_ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    validate_ptp_instance = ptp_instance_utils._find_ptp_instance(cc, args.ptpinstancenameorid)
    validate_interface = iinterface_utils._find_interface(cc, validate_ihost, args.ifnameorid)

    if validate_ihost.uuid != validate_ptp_instance.host_uuid:
        raise exc.CommandError('PTP instance %s is not on host %s.'
                               % (validate_ptp_instance.uuid, validate_ihost.hostname))

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    data["interface_uuid"] = validate_interface.uuid
    data["ptp_instance_uuid"] = validate_ptp_instance.uuid

    ptp_interface = cc.ptp_interface.create(**data)
    uuid = getattr(ptp_interface, 'uuid', '')
    try:
        ptp_interface = cc.ptp_interface.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created PTP interface UUID not found: %s'
                               % uuid)

    setattr(ptp_interface, 'hostname', validate_ihost.hostname)
    _print_ptp_interface_show(ptp_interface)
