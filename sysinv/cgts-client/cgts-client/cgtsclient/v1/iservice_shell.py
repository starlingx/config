# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#


from cgtsclient.common import utils
from cgtsclient import exc


def _print_iservice_show(iservice):
    fields = ['id', 'servicename', 'hostname', 'state', 'activity', 'reason']
    data = dict([(f, getattr(iservice, f, '')) for f in fields])
    utils.print_dict(data, wrap=72)


def do_service_list(cc, args):
    """List services."""
    iservice = cc.iservice.list()
    field_labels = ['id', 'servicename', 'hostname', 'state', 'activity']
    fields = ['id', 'servicename', 'hostname', 'state', 'activity']
    utils.print_list(iservice, fields, field_labels, sortby=1)


@utils.arg('iservice', metavar='<iservice id>', help="ID of iservice")
def do_service_show(cc, args):
    """Show a service."""
    try:
        iservice = cc.iservice.get(args.iservice)
    except exc.HTTPNotFound:
        raise exc.CommandError('service not found: %s' % args.iservice)
    else:
        _print_iservice_show(iservice)


@utils.arg('-c', '--servicename',
           metavar='<servicename>',
           help='servicename of the service [REQUIRED]')
@utils.arg('-n', '--hostname',
           metavar='<hostname>',
           help='hostname of the service [REQUIRED]')
@utils.arg('-s', '--state',
           metavar='<state>',
           help='state of the service [REQUIRED]')
@utils.arg('-a', '--activity',
           metavar="<key=value>",
           action='append',
           help="Record activity key/value metadata. ")
@utils.arg('-r', '--reason',
           metavar="<key=value>",
           action='append',
           help="Record reason key/value metadata. ")
def do_service_create(cc, args):
    """Create a new service."""
    field_list = ['servicename', 'hostname', 'state', 'activity', 'reason']
    fields = dict((k, v) for (k, v) in vars(args).items()
                  if k in field_list and not (v is None))
    # fields = utils.args_array_to_dict(fields, 'activity')
    fields = utils.args_array_to_dict(fields, 'reason')
    iservice = cc.iservice.create(**fields)

    field_list.append('uuid')
    data = dict([(f, getattr(iservice, f, '')) for f in field_list])
    utils.print_dict(data, wrap=72)


@utils.arg('iservice',
           metavar='<iservice id>',
           nargs='+',
           help="ID of iservice")
def do_service_delete(cc, args):
    """Delete a iservice."""
    for c in args.iservice:
        try:
            cc.iservice.delete(c)
        except exc.HTTPNotFound:
            raise exc.CommandError('Service not found: %s' % c)
        print('Deleted service %s' % c)


@utils.arg('iservice',
           metavar='<iservice id>',
           help="ID of iservice")
@utils.arg('attributes',
           metavar='<path=value>',
           nargs='+',
           action='append',
           default=[],
           help="Attributes to add/replace or remove ")
def donot_service_modify_lab(cc, args):
    """LAB ONLY Update a service. """
    # JKUNG comment this out prior to delivery
    patch = utils.args_array_to_patch("replace", args.attributes[0])
    try:
        iservice = cc.iservice.update(args.iservice, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('Service not found: %s' % args.iservice)
    _print_iservice_show(iservice)
