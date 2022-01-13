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
    fields = ['uuid', 'name', 'interface_names', 'ptp_instance_name',
              'parameters', 'created_at']
    data = [(f, getattr(ptp_interface_obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of a PTP interface")
def do_ptp_interface_show(cc, args):
    """Show PTP interface attributes."""
    ptp_interface = ptp_interface_utils._find_ptp_interface(
        cc, args.nameoruuid)
    _print_ptp_interface_show(ptp_interface)


def _print_ptp_interface_list(ptp_interface_list):
    field_labels = ['uuid', 'name', 'ptp_instance_name', 'parameters']
    fields = ['uuid', 'name', 'ptp_instance_name', 'parameters']
    utils.print_list(ptp_interface_list, fields, field_labels)


def do_ptp_interface_list(cc, args):
    """List all PTP interfaces."""
    ptp_interfaces = cc.ptp_interface.list()
    _print_ptp_interface_list(ptp_interfaces)


@utils.arg('name',
           metavar='<name>',
           help="Name of PTP interface [REQUIRED]")
@utils.arg('ptpinstancenameorid',
           metavar='<PTP instance name or UUID>',
           help="Name or UUID of a PTP instance [REQUIRED]")
def do_ptp_interface_add(cc, args):
    """Add a PTP interface."""
    field_list = ['name']

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    # Check the PTP instance exists
    ptp_instance = ptp_instance_utils._find_ptp_instance(
        cc, args.ptpinstancenameorid)
    data.update({'ptp_instance_uuid': ptp_instance.uuid})

    ptp_interface = cc.ptp_interface.create(**data)
    uuid = getattr(ptp_interface, 'uuid', '')
    try:
        ptp_interface = cc.ptp_interface.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('PTP interface just created not found: %s'
                               % uuid)
    _print_ptp_interface_show(ptp_interface)


@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP interface")
def do_ptp_interface_delete(cc, args):
    """Delete a PTP interface"""
    ptp_interface = ptp_interface_utils._find_ptp_interface(
        cc, args.nameoruuid)
    uuid = ptp_interface.uuid
    cc.ptp_interface.delete(uuid)
    print('Deleted PTP interface: %s' % uuid)


def _ptp_interface_parameter_op(cc, op, interface, parameters):
    if len(parameters) == 0:
        raise exc.CommandError('Missing PTP parameter')
    ptp_interface = ptp_interface_utils._find_ptp_interface(cc, interface)
    patch = []
    for parameter in parameters:
        patch.append({'op': op,
                      'path': '/ptp_parameters/-',
                      'value': parameter})
    ptp_interface = cc.ptp_interface.update(ptp_interface.uuid, patch)
    _print_ptp_interface_show(ptp_interface)


@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP interface")
@utils.arg('parameters',
           metavar='<name=value>',
           nargs='+',
           action='append',
           default=[],
           help="PTP parameter to add")
def do_ptp_interface_parameter_add(cc, args):
    """Add parameter(s) to a PTP interface."""
    _ptp_interface_parameter_op(cc, op='add', interface=args.nameoruuid,
                                parameters=args.parameters[0])


@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP interface")
@utils.arg('parameters',
           metavar='<name=value>',
           nargs='+',
           action='append',
           default=[],
           help="PTP parameter to remove")
def do_ptp_interface_parameter_delete(cc, args):
    """Delete parameter(s) from a PTP interface."""
    _ptp_interface_parameter_op(cc, op='remove', interface=args.nameoruuid,
                                parameters=args.parameters[0])


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


def _interface_ptp_op(cc, op, host, interface, ptp_interface):
    ihost = ihost_utils._find_ihost(cc, host)
    iinterface = iinterface_utils._find_interface(cc, ihost, interface)
    ptp_interface_obj = ptp_interface_utils._find_ptp_interface(cc,
                                                                ptp_interface)
    ptp_interface_id = ptp_interface_obj.id
    patch = [{'op': op,
              'path': '/ptp_interfaces/-',
              'value': ptp_interface_id}]
    cc.iinterface.update(iinterface.uuid, patch)

    ptp_interfaces = cc.ptp_interface.list_by_interface(iinterface.uuid)
    _print_ptp_interface_list(ptp_interfaces)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="The host associated with the PTP interface")
@utils.arg('ifnameorid',
           metavar='<interface name or UUID>',
           help="Name or UUID of an interface at host")
@utils.arg('ptp_interface_nameoruuid',
           metavar='<PTP interface name or UUID>',
           help="Name or UUID of PTP interface to assign")
def do_host_if_ptp_assign(cc, args):
    """Associate PTP to an interface at host."""
    _interface_ptp_op(cc, op='add', host=args.hostnameorid,
                      interface=args.ifnameorid,
                      ptp_interface=args.ptp_interface_nameoruuid)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="The host associated with the PTP interface")
@utils.arg('ifnameorid',
           metavar='<interface name or UUID>',
           help="Name or UUID of an interface at host")
@utils.arg('ptp_interface_nameoruuid',
           metavar='<PTP interface name or UUID>',
           help="Name or UUID of PTP interface to remove")
def do_host_if_ptp_remove(cc, args):
    """Disassociate PTP to an interface at host."""
    _interface_ptp_op(cc, op='remove', host=args.hostnameorid,
                      interface=args.ifnameorid,
                      ptp_interface=args.ptp_interface_nameoruuid)
