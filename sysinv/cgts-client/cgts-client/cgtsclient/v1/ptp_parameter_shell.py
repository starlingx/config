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


def _owner_formatter(values):
    result = []
    result.append(str(values['name'] +
                      " of type " + values['type'] +
                      " at " + values['hostname']))
    return result


def _print_ptp_parameter_show(ptp_parameter_obj):
    fields = ['uuid', 'name', 'value', 'type',
              'owner', 'foreign_uuid', 'created_at', 'updated_at']
    labels = ['uuid', 'name', 'value', 'type',
              'owned_by', 'owner_id', 'created_at', 'updated_at']
    data = [(f, getattr(ptp_parameter_obj, f, '')) for f in fields]
    utils.print_tuple_list(data, labels,
                           formatters={'owner': _owner_formatter})


@utils.arg('-t', '--type',
           metavar='<owner type>',
           choices=['ptp-instance', 'ptp-interface'],
           help='List PTP parameters for a specific owner type')
@utils.arg('-u', '--foreign_uuid',
           metavar='<owner uuid>',
           help='List PTP parameters associated to specified owner')
def do_ptp_parameter_list(cc, args):
    """List all PTP parameters, in any host."""
    missing = ((args.type is None) and (args.foreign_uuid is not None)) or \
              ((args.type is not None) and (args.foreign_uuid is None))
    if missing:
        raise exc.CommandError("Both 'type' and 'foreign_uuid' "
                               "must be provided")
    ptp_parameters = None
    if args.type == 'ptp-instance':
        ptp_parameters = cc.ptp_parameter.list_by_ptp_instance(
            args.foreign_uuid)
    elif args.type == 'ptp-interface':
        ptp_parameters = cc.ptp_parameter.list_by_interface(
            args.foreign_uuid)
    if ptp_parameters:
        fields = ['uuid', 'name', 'value']
        labels = ['uuid', 'name', 'value']
    else:
        ptp_parameters = cc.ptp_parameter.list()
        for ptp_parameter in ptp_parameters:
            owner_dict = getattr(ptp_parameter, 'owner', '')
            setattr(ptp_parameter, 'owner_name', owner_dict['name'])
            setattr(ptp_parameter, 'owner_host', owner_dict['hostname'])

        fields = ['uuid',
                  'name',
                  'value',
                  'type',
                  'owner_name',
                  'owner_host',
                  'foreign_uuid']
        labels = ['uuid',
                  'name',
                  'value',
                  'owner_type',
                  'owner_name',
                  'owner_host',
                  'owner_uuid']

    utils.print_list(ptp_parameters, fields, labels)


@utils.arg('uuid',
           metavar='<uuid>',
           help="UUID of PTP parameter")
def do_ptp_parameter_show(cc, args):
    """Show PTP parameter attributes."""
    ptp_parameter = ptp_parameter_utils._find_ptp_parameter(cc, args.uuid)
    _print_ptp_parameter_show(ptp_parameter)


@utils.arg('name',
           metavar='<name>',
           help="Name of PTP parameter [REQUIRED]")
@utils.arg('value',
           metavar='<value>',
           help="Value of PTP parameter [REQUIRED]")
@utils.arg('type',
           metavar='<owner type>',
           choices=['ptp-instance', 'ptp-interface'],
           help="Type of parameter owner ('ptp-instance' or 'ptp-interface') "
                "[REQUIRED]")
@utils.arg('foreign_uuid',
           metavar='<owner uuid>',
           help="UUID of parameter owner [REQUIRED]")
def do_ptp_parameter_add(cc, args):
    """Add a PTP parameter."""

    field_list = ['name', 'value', 'type', 'foreign_uuid']

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
