#
# Copyright (c) 2013-2019,2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import options


def _print_service_parameter_show(service_parameter, output_format=None):
    fields = ['uuid', 'service', 'section', 'name', 'value',
              'personality', 'resource']
    data_list = [(f, getattr(service_parameter, f, '')) for f in fields]
    data = dict(data_list)
    utils.print_dict_with_format(data, wrap=72, output_format=output_format)


@utils.arg('uuid',
           metavar='<uuid>',
           help="UUID of service parameter")
@utils.arg('--format',
           choices=['table', 'yaml', 'value'],
           help="Specify the output format, defaults to table")
def do_service_parameter_show(cc, args):
    """Show Service parameter."""
    service_parameter = cc.service_parameter.get(args.uuid)
    _print_service_parameter_show(service_parameter, args.format)


@utils.arg('--service',
           metavar='<service>',
           help="Search by service name")
@utils.arg('--section',
           metavar='<section>',
           help="Search by section name")
@utils.arg('--name',
           metavar='<name>',
           help="Search by parameter name")
@utils.arg('--column',
           action='append',
           default=[],
           help="Specify the column(s) to include, can be repeated")
@utils.arg('--format',
           choices=['table', 'yaml', 'value'],
           help="specify the output format, defaults to table")
def do_service_parameter_list(cc, args):
    """List Service parameters."""
    query = None
    field_list = ['service', 'section', 'name']
    for (k, v) in vars(args).items():
        if k in field_list and not (v is None):
            query = k + '=' + v
    parameters = cc.service_parameter.list(q=options.cli_to_array(query))

    if args.column:
        fields = args.column
    else:
        fields = ['uuid', 'service', 'section', 'name', 'value', 'personality',
                  'resource']

    utils.print_list(parameters, fields, fields, sortby=None,
                     output_format=args.format)


@utils.arg('uuid',
           metavar='<uuid>',
           help="UUID of service parameter")
def do_service_parameter_delete(cc, args):
    """Delete a Service Parameter."""

    try:
        cc.service_parameter.delete(args.uuid)
        print('Deleted service parameter: %s' % args.uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Failed to delete service parameters')
    except exc.Forbidden:
        raise exc.CommandError("The requested action is not authorized")


def _find_service_parameter(cc, service, section, name):
    service_parameters = cc.service_parameter.list()
    for p in service_parameters:
        if p.service == service and p.section == section and p.name == name:
            break
    else:
        p = None
        print('Service Parameter not found: service %s, '
              'section %s, name %s' %
              (service, section, name))
    return p


@utils.arg('service',
           metavar='<service>',
           help="Name of service [REQUIRED]")
@utils.arg('section',
           metavar='<section>',
           help="Name of section [REQUIRED]")
@utils.arg('attributes',
           metavar='<name=value>',
           nargs='+',
           action='append',
           default=[],
           help="Service Parameter attributes to modify ")
@utils.arg('--personality',
           metavar='<personality>',
           default=None,
           help="Restrict resource update to hosts of given personality")
@utils.arg('--resource',
           metavar='<resource>',
           default=None,
           help="Custom resource to be updated")
@utils.arg('--format',
           choices=['table', 'yaml', 'value'],
           help="specify the output format, defaults to table")
def do_service_parameter_modify(cc, args):
    """Modify Service Parameter attributes."""

    patch = []
    attributes = utils.extract_keypairs(args)
    if len(attributes) > 1 \
            and (args.resource is not None or args.personality is not None):
        raise exc.CommandError("Cannot specify multiple parameters with custom resource.")

    for (name, value) in attributes.items():
        service_parameter = _find_service_parameter(cc,
                                                    args.service,
                                                    args.section, name)
        if service_parameter:
            patch.append({'op': 'replace', 'path': '/name', 'value': name})
            patch.append({'op': 'replace', 'path': '/value', 'value': value})
            if args.personality:
                patch.append({'op': 'replace', 'path': '/personality', 'value': args.personality})
            if args.resource:
                patch.append({'op': 'replace', 'path': '/resource', 'value': args.resource})
            try:
                parameter = cc.service_parameter.update(service_parameter.uuid, patch)
                _print_service_parameter_show(parameter, output_format=args.format)
            except exc.HTTPNotFound:
                raise exc.CommandError("Service parameter not found: %s" % service_parameter.uuid)
            except exc.Forbidden:
                raise exc.CommandError("The requested action is not authorized")


@utils.arg('service',
           metavar='<service>',
           help="Name of service [REQUIRED]")
@utils.arg('--section',
           metavar='<section>',
           default=None,
           help="Name of section")
def do_service_parameter_apply(cc, args):
    """Apply the Service Parameters."""

    try:
        cc.service_parameter.apply(args.service, args.section)
    except exc.HTTPNotFound:
        raise exc.CommandError('Failed to apply service parameters')
    except exc.Forbidden:
        raise exc.CommandError("The requested action is not authorized")
    if args.section is not None:
        print('Applying %s service parameters for section %s' % (args.service, args.section))
    else:
        print('Applying %s service parameters' % args.service)


@utils.arg('service',
           metavar='<service>',
           help="Name of service [REQUIRED]")
@utils.arg('section',
           metavar='<section>',
           help="Name of section [REQUIRED]")
@utils.arg('attributes',
           metavar='<name=value>',
           nargs='+',
           action='append',
           default=[],
           help="Service Parameter attributes to add ")
@utils.arg('--personality',
           metavar='<personality>',
           default=None,
           help="Restrict resource update to hosts of given personality")
@utils.arg('--resource',
           metavar='<resource>',
           default=None,
           help="Custom resource to be updated")
def do_service_parameter_add(cc, args):
    """Add Service Parameter."""

    attributes = utils.extract_keypairs(args)

    if len(attributes) > 1 \
            and (args.resource is not None or args.personality is not None):
        raise exc.CommandError("Cannot specify multiple parameters with custom resource.")

    try:
        parms = cc.service_parameter.create(args.service,
                                            args.section,
                                            args.personality,
                                            args.resource,
                                            attributes)
    except exc.HTTPNotFound:
        raise exc.CommandError('Failed to create Service parameters: %s ' %
                               attributes)

    for p in parms.parameters:
        uuid = p['uuid']
        if uuid is not None:
            try:
                parameter = cc.service_parameter.get(uuid)
            except exc.HTTPNotFound:
                raise exc.CommandError('Service parameter not found: %s' % uuid)
            except exc.Forbidden:
                raise exc.CommandError("The requested action is not authorized")

            _print_service_parameter_show(parameter)
