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
from cgtsclient.v1 import ptp_instance as ptp_instance_utils


def _print_ptp_instance_show(ptp_instance_obj):
    fields = ['uuid', 'name', 'service', 'hostnames', 'parameters',
              'created_at']
    data = [(f, getattr(ptp_instance_obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance")
def do_ptp_instance_show(cc, args):
    """Show PTP instance attributes."""
    ptp_instance = ptp_instance_utils._find_ptp_instance(cc, args.nameoruuid)
    _print_ptp_instance_show(ptp_instance)


def _print_ptp_instance_list(ptp_instance_list):
    field_labels = ['uuid', 'name', 'service']
    fields = ['uuid', 'name', 'service']
    utils.print_list(ptp_instance_list, fields, field_labels)


def do_ptp_instance_list(cc, args):
    """List all PTP instances."""
    ptp_instances = cc.ptp_instance.list()
    _print_ptp_instance_list(ptp_instances)


@utils.arg('name',
           metavar='<name>',
           help="Name of PTP instance [REQUIRED]")
@utils.arg('service',
           metavar='<service type>',
           choices=['ptp4l', 'phc2sys', 'ts2phc'],
           help="Service type [REQUIRED]")
def do_ptp_instance_add(cc, args):
    """Add a PTP instance."""

    field_list = ['name', 'service']

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    ptp_instance = cc.ptp_instance.create(**data)
    uuid = getattr(ptp_instance, 'uuid', '')
    try:
        ptp_instance = cc.ptp_instance.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('PTP instance just created not found: %s' %
                               uuid)
    _print_ptp_instance_show(ptp_instance)


@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance")
def do_ptp_instance_delete(cc, args):
    """Delete a PTP instance."""
    ptp_instance = ptp_instance_utils._find_ptp_instance(cc, args.nameoruuid)
    uuid = ptp_instance.uuid
    cc.ptp_instance.delete(uuid)
    print('Deleted PTP instance: %s' % uuid)


def _ptp_instance_parameter_op(cc, op, instance, parameters):
    if len(parameters) == 0:
        raise exc.CommandError('Missing PTP parameter')
    ptp_instance = ptp_instance_utils._find_ptp_instance(cc, instance)
    patch = []
    for parameter in parameters:
        patch.append({'op': op,
                      'path': '/ptp_parameters/-',
                      'value': parameter})
    ptp_instance = cc.ptp_instance.update(ptp_instance.uuid, patch)
    _print_ptp_instance_show(ptp_instance)


@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance")
@utils.arg('parameters',
           metavar='<name=value>',
           nargs='+',
           action='append',
           default=[],
           help="PTP parameter to add")
def do_ptp_instance_parameter_add(cc, args):
    """Add parameter(s) to a PTP instance."""
    _ptp_instance_parameter_op(cc, op='add', instance=args.nameoruuid,
                               parameters=args.parameters[0])


@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance")
@utils.arg('parameters',
           metavar='<name=value>',
           nargs='+',
           action='append',
           default=[],
           help="PTP parameter to remove")
def do_ptp_instance_parameter_delete(cc, args):
    """Delete parameter(s) from a PTP instance."""
    _ptp_instance_parameter_op(cc, op='remove', instance=args.nameoruuid,
                               parameters=args.parameters[0])


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_ptp_instance_list(cc, args):
    """List PTP instances on host."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    ptp_instances = cc.ptp_instance.list_by_host(ihost.uuid)
    _print_ptp_instance_list(ptp_instances)


def _host_ptp_instance_op(cc, op, host, instance):
    ihost = ihost_utils._find_ihost(cc, host)
    ptp_instance = ptp_instance_utils._find_ptp_instance(cc,
                                                         instance)
    patch = [{'op': op, 'path': '/ptp_instances/-', 'value': ptp_instance.id}]
    cc.ihost.update(ihost.uuid, patch)

    ptp_instances = cc.ptp_instance.list_by_host(ihost.uuid)
    _print_ptp_instance_list(ptp_instances)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance to assign")
def do_host_ptp_instance_assign(cc, args):
    """Associate PTP instance(s) to host."""
    _host_ptp_instance_op(cc, op='add', host=args.hostnameorid,
                          instance=args.nameoruuid)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance to remove")
def do_host_ptp_instance_remove(cc, args):
    """Disassociate PTP instance(s) from host."""
    _host_ptp_instance_op(cc, op='remove', host=args.hostnameorid,
                          instance=args.nameoruuid)


def do_ptp_instance_apply(cc, args):
    """Apply the PTP Instance config."""

    cc.ptp_instance.apply()

    print('Applying the PTP Instance configuration')
