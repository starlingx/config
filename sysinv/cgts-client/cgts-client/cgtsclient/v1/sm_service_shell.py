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
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#
import socket

from cgtsclient.common import utils
from cgtsclient import exc


def _print_service_show(service):
    fields = ['id', 'service_name', 'hostname', 'state']
    data = dict([(f, getattr(service, f, '')) for f in fields])
    data['hostname'] = getattr(service, 'node_name', '')
    utils.print_dict(data, wrap=72)


def do_service_list(cc, args):
    """List Services."""
    try:
        service = cc.sm_service.list()
    except exc.Forbidden:
        raise exc.CommandError("Not authorized. The requested action "
                               "requires 'admin' level")
    else:
        fields = ['id', 'name', 'node_name', 'state']
        field_labels = ['id', 'service_name', 'hostname', 'state']
        # remove the entry in the initial state
        clean_list = [x for x in service if x.state != 'initial']
        for s in clean_list:
            if s.status:
                setattr(s, 'state', s.state + '-' + s.status)
            if getattr(s, 'node_name', None) is None:
                setattr(s, 'node_name', socket.gethostname())

        utils.print_list(clean_list, fields, field_labels, sortby=1)


@utils.arg('service', metavar='<service id>', help="ID of service")
def do_service_show(cc, args):
    """Show a Service."""
    try:
        service = cc.sm_service.get(args.service)
    except exc.HTTPNotFound:
        raise exc.CommandError('service not found: %s' % args.service)
    except exc.Forbidden:
        raise exc.CommandError("Not authorized. The requested action "
                               "requires 'admin' level")
    else:
        if service.status:
            setattr(service, 'state', service.state + '-' + service.status)
        setattr(service, 'service_name', service.name)
        if getattr(service, 'node_name', None) is None:
            setattr(service, 'hostname', socket.gethostname())
        _print_service_show(service)


@utils.arg('service', metavar='<service name>', help="Name of service to enable")
def do_service_enable(cc, args):
    """Enable optional service"""
    values = {'enabled': True}
    patch = utils.dict_to_patch(values)

    try:
        response = cc.sm_service.update(args.service, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('service not recognized: %s' % args.service)
    except exc.Forbidden:
        raise exc.CommandError("Not authorized. The requested action "
                               "requires 'admin' level")


@utils.arg('service', metavar='<service name>', help="Name of service to disable")
def do_service_disable(cc, args):
    """Disable optional service"""
    values = {'enabled': False}
    patch = utils.dict_to_patch(values)
    try:
        response = cc.sm_service.update(args.service, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('service not recognized: %s' % args.service)
    except exc.Forbidden:
        raise exc.CommandError("Not authorized. The requested action "
                               "requires 'admin' level")
