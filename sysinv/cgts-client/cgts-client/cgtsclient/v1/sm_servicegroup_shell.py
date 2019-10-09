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


def _print_iservicegroup_show(servicegroup):
    fields = ['uuid', 'name', 'hostname', 'service_group_name', 'state']
    data = dict([(f, getattr(servicegroup, f, '')) for f in fields])
    utils.print_dict(data, wrap=72)


def do_servicegroup_list(cc, args):
    """List Service Groups."""
    try:
        servicegroup = cc.sm_servicegroup.list()
    except exc.Forbidden:
        raise exc.CommandError("Not authorized. The requested action "
                               "requires 'admin' level")
    else:
        fields = ['uuid', 'service_group_name', 'node_name', 'state']
        field_labels = ['uuid', 'service_group_name', 'hostname', 'state']
        for s in servicegroup:
            if s.status:
                setattr(s, 'state', s.state + '-' + s.status)
        utils.print_list(servicegroup, fields, field_labels, sortby=1)


@utils.arg('servicegroup', metavar='<servicegroup uuid>',
           help="UUID of servicegroup")
def do_servicegroup_show(cc, args):
    """Show a Service Group."""
    try:
        servicegroup = cc.sm_servicegroup.get(args.servicegroup)
    except exc.HTTPNotFound:
        raise exc.CommandError('Service Group not found: %s' % args.servicegroup)
    except exc.Forbidden:
        raise exc.CommandError("Not authorized. The requested action "
                               "requires 'admin' level")
    else:
        if servicegroup.status:
            setattr(servicegroup, 'state', servicegroup.state + '-' +
                    servicegroup.status)
        setattr(servicegroup, 'hostname', servicegroup.node_name)
        _print_iservicegroup_show(servicegroup)


@utils.arg('-n', '--name',
           metavar='<name>',
           help='name of the service group [REQUIRED]')
@utils.arg('-s', '--state',
           metavar='<state>',
           help='state of the servicegroup [REQUIRED]')
def donot_servicegroup_create(cc, args):
    """Create a new servicegroup."""
    field_list = ['name', 'state']
    fields = dict((k, v) for (k, v) in vars(args).items()
                  if k in field_list and not (v is None))
    # fields = utils.args_array_to_dict(fields, 'activity')
    iservicegroup = cc.smapiClient.iservicegroup.create(**fields)

    field_list.append('uuid')
    data = dict([(f, getattr(iservicegroup, f, '')) for f in field_list])
    utils.print_dict(data, wrap=72)


@utils.arg('iservicegroup',
           metavar='<iservicegroup id>',
           nargs='+',
           help="ID of iservicegroup")
def donot_servicegroup_delete(cc, args):
    """Delete a servicegroup."""
    for c in args.iservicegroup:
        try:
            cc.smapiClient.iservicegroup.delete(c)
        except exc.HTTPNotFound:
            raise exc.CommandError('Service not found: %s' % c)
        print('Deleted servicegroup %s' % c)


@utils.arg('iservicegroup',
           metavar='<iservicegroup id>',
           help="ID of iservicegroup")
@utils.arg('attributes',
           metavar='<path=value>',
           nargs='+',
           action='append',
           default=[],
           help="Attributes to add/replace or remove ")
def donot_servicegroup_modify_labonly(cc, args):
    """LAB ONLY Update a servicegroup. """
    # JKUNG comment this out prior to delivery
    patch = utils.args_array_to_patch("replace", args.attributes[0])
    try:
        iservicegroup = cc.smapiClient.iservicegroup.update(args.iservicegroup, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('Service Group not found: %s' % args.iservicegroup)
    _print_iservicegroup_show(iservicegroup)
