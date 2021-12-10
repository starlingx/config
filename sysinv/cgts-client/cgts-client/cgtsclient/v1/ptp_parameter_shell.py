########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ptp_parameter as ptp_parameter_utils


def _print_ptp_parameter_show(ptp_parameter_obj):
    fields = ['uuid', 'name', 'value', 'created_at', 'updated_at']
    data = [(f, getattr(ptp_parameter_obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('uuid',
           metavar='<uuid>',
           help="UUID of PTP parameter")
def do_ptp_parameter_show(cc, args):
    """Show PTP parameter attributes."""
    ptp_parameter = ptp_parameter_utils._find_ptp_parameter(cc, args.uuid)
    _print_ptp_parameter_show(ptp_parameter)


def _print_ptp_parameter_list(ptp_parameter_list):
    fields = ['uuid', 'name', 'value']
    labels = ['uuid', 'name', 'value']
    utils.print_list(ptp_parameter_list, fields, labels)


@utils.arg('--instance',
           metavar='<instance>',
           default=None,
           help="UUID of PTP instance")
@utils.arg('--interface',
           metavar='<interface>',
           default=None,
           help="UUID of PTP interface")
def do_ptp_parameter_list(cc, args):
    """List all PTP parameters, the ones of a specified PTP instance or
       the ones of a specified PTP interface.
    """
    if args.instance:
        if args.interface:
            raise exc.CommandError('Only a single optional argument allowed')
        else:
            ptp_parameters = cc.ptp_parameter.list_by_ptp_instance(
                args.instance)
    elif args.interface:
        ptp_parameters = cc.ptp_parameter.list_by_ptp_interface(
            args.interface)
    else:
        ptp_parameters = cc.ptp_parameter.list()

    _print_ptp_parameter_list(ptp_parameters)


@utils.arg('name',
           metavar='<name>',
           help="Name of PTP parameter [REQUIRED]")
@utils.arg('value',
           metavar='<value>',
           help="Value of PTP parameter [REQUIRED]")
def do_ptp_parameter_add(cc, args):
    """Add a PTP parameter."""

    field_list = ['name', 'value']

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    ptp_parameter = cc.ptp_parameter.create(**data)
    uuid = getattr(ptp_parameter, 'uuid', '')
    try:
        ptp_parameter = cc.ptp_parameter.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('PTP parameter just created not found: %s' %
                               uuid)
    _print_ptp_parameter_show(ptp_parameter)


@utils.arg('uuid',
           metavar='<uuid>',
           help="UUID of PTP parameter")
@utils.arg('value',
           metavar='<new value>',
           help="New value of parameter")
def do_ptp_parameter_modify(cc, args):
    """Change PTP parameter value."""

    field_list = ['value']

    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    patch = []
    for (k, v) in data.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})

    ptp_parameter = cc.ptp_parameter.update(args.uuid, patch)
    _print_ptp_parameter_show(ptp_parameter)


@utils.arg('uuid',
           metavar='<uuid>',
           help="UUID of PTP parameter")
def do_ptp_parameter_delete(cc, args):
    """Delete a PTP parameter."""
    cc.ptp_parameter.delete(args.uuid)
    print('Deleted PTP parameter: %s' % args.uuid)
