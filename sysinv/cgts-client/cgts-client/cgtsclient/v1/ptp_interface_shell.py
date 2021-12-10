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
from cgtsclient.v1 import ptp_interface as ptp_interface_utils


def _print_ptp_interface_show(ptp_interface_obj):
    fields = ['uuid', 'interface_names', 'ptp_instance_name', 'parameters',
              'created_at']
    data = [(f, getattr(ptp_interface_obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('ptp_interface_uuid',
           metavar='<ptp_interface_uuid>',
           help="UUID of a PTP interface")
def do_ptp_interface_show(cc, args):
    """Show PTP interface attributes."""
    try:
        ptp_interface = cc.ptp_interface.get(args.ptp_interface_uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('PTP interface not found: %s'
                               % args.ptp_interface_uuid)
    _print_ptp_interface_show(ptp_interface)


def _print_ptp_interface_list(ptp_interface_list):
    field_labels = ['uuid', 'ptp_instance_name', 'parameters']
    fields = ['uuid', 'ptp_instance_name', 'parameters']
    utils.print_list(ptp_interface_list, fields, field_labels)


def do_ptp_interface_list(cc, args):
    """List all PTP interfaces."""
    ptp_interfaces = cc.ptp_interface.list()
    _print_ptp_interface_list(ptp_interfaces)


@utils.arg('ptpinstancenameorid',
           metavar='<name or UUID>',
           help="Name or UUID of a PTP instance [REQUIRED]")
def do_ptp_interface_add(cc, args):
    """Add a PTP interface."""
    field_list = ['ptp_instance_uuid']

    ptp_instance = \
        ptp_instance_utils._find_ptp_instance(cc, args.ptpinstancenameorid)

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))
    data["ptp_instance_uuid"] = ptp_instance.uuid

    ptp_interface = cc.ptp_interface.create(**data)
    uuid = getattr(ptp_interface, 'uuid', '')
    try:
        ptp_interface = cc.ptp_interface.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('PTP interface just created not found: %s'
                               % uuid)
    _print_ptp_interface_show(ptp_interface)


@utils.arg('ptp_interface_uuid',
           metavar='<ptp_interface_uuid>',
           help="UUID of a PTP instance")
def do_ptp_interface_delete(cc, args):
    """Delete a PTP interface"""
    cc.ptp_interface.delete(args.ptp_interface_uuid)
    print('Deleted PTP interface: %s' % args.ptp_interface_uuid)


def _ptp_interface_parameter_op(cc, op, ptp_interface_uuid, data):
    patch = []
    for (_k, v) in data.items():
        for uuids in v:
            for uuid in uuids:
                if not utils.is_uuid_like(uuid):
                    raise exc.CommandError("Invalid UUID '%s'" % uuid)
                patch.append({'op': op,
                              'path': '/ptp_parameters/-',
                              'value': uuid})
    ptp_interface = cc.ptp_interface.update(ptp_interface_uuid, patch)
    _print_ptp_interface_show(ptp_interface)


@utils.arg('ptp_interface_uuid',
           metavar='<UUID>',
           help="UUID of PTP interface")
@utils.arg('paramuuid',
           metavar='<parameter UUID>',
           nargs='+',
           action='append',
           default=[],
           help="UUID of PTP parameter")
def do_ptp_interface_parameter_add(cc, args):
    """Add parameter(s) to a PTP interface."""
    if len(args.paramuuid) == 0:
        raise exc.CommandError('Missing PTP parameter UUID')

    field_list = ['paramuuid']
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    _ptp_interface_parameter_op(cc, op='add',
                                ptp_interface_uuid=args.ptp_interface_uuid,
                                data=data)


@utils.arg('ptp_interface_uuid',
           metavar='<UUID>',
           help="UUID of PTP interface")
@utils.arg('paramuuid',
           metavar='<parameter UUID>',
           nargs='+',
           action='append',
           default=[],
           help="UUID of PTP parameter")
def do_ptp_interface_parameter_delete(cc, args):
    """Delete parameter(s) from a PTP interface."""
    if len(args.paramuuid) == 0:
        raise exc.CommandError('Missing PTP parameter UUID')

    field_list = ['paramuuid']
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    _ptp_interface_parameter_op(cc, op='remove',
                                ptp_interface_uuid=args.ptp_interface_uuid,
                                data=data)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Hostname or ID of a host")
@utils.arg('ifnameorid',
           metavar='<interface name or UUID>',
           nargs='?',
           help="Interface name or UUID [OPTIONAL]")
def do_host_if_ptp_list(cc, args):
    """List all PTP interfaces on the specified host,
       or a subset of PTP interfaces associated
       with a given underlying interface.
    """
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    if args.ifnameorid:
        iinterface = iinterface_utils._find_interface(cc, ihost,
                                                      args.ifnameorid)
        ptp_interfaces = cc.ptp_interface.list_by_interface(
            iinterface.uuid)
        _print_ptp_interface_list(ptp_interfaces)
    else:
        ptp_interfaces = cc.ptp_interface.list_by_host(ihost.uuid)
        field_labels = ['uuid', 'ptp_instance_name', 'interface_names']
        fields = ['uuid', 'ptp_instance_name', 'interface_names']
        utils.print_list(ptp_interfaces, fields, field_labels)


def _interface_ptp_op(cc, op, uuid, ptp_interface):
    ptp_interface_obj = ptp_interface_utils._find_ptp_interface(cc,
                                                                ptp_interface)
    ptp_interface_id = ptp_interface_obj.id
    patch = [{'op': op,
              'path': '/ptp_interfaces/-',
              'value': ptp_interface_id}]
    cc.iinterface.update(uuid, patch)

    ptp_interfaces = cc.ptp_interface.list_by_interface(uuid)
    _print_ptp_interface_list(ptp_interfaces)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="The host associated with the PTP interface")
@utils.arg('ifnameorid',
           metavar='<interface name or uuid>',
           help="Name or UUID of an interface at host")
@utils.arg('ptp_interface_uuid',
           metavar='<PTP interface UUID>',
           help="UUID of PTP interface")
def do_host_if_ptp_assign(cc, args):
    """Associate PTP to an interface at host."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    iinterface = iinterface_utils._find_interface(cc, ihost, args.ifnameorid)
    _interface_ptp_op(cc, op='add', uuid=iinterface.uuid,
                      ptp_interface=args.ptp_interface_uuid)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="The host associated with the PTP interface")
@utils.arg('ifnameorid',
           metavar='<interface name or uuid>',
           help="Name or UUID of an interface at host")
@utils.arg('ptp_interface_uuid',
           metavar='<PTP interface UUID>',
           help="UUID of PTP interface")
def do_host_if_ptp_remove(cc, args):
    """Disassociate PTP to an interface at host."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    iinterface = iinterface_utils._find_interface(cc, ihost, args.ifnameorid)
    _interface_ptp_op(cc, op='remove', uuid=iinterface.uuid,
                      ptp_interface=args.ptp_interface_uuid)
