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


def _print_sm_service_node_show(node):
    fields = ['id', 'name', 'administrative_state', 'operational_state',
              'availability_status', 'ready_state']
    data = dict([(f, getattr(node, f, '')) for f in fields])
    utils.print_dict(data, wrap=72)


def do_servicenode_list(cc, args):
    """List Service Nodes."""
    try:
        node = cc.sm_service_nodes.list()
    except exc.Forbidden:
        raise exc.CommandError("Not authorized. The requested action "
                               "requires 'admin' level")
    else:
        fields = ['id', 'name', 'administrative_state', 'operational_state',
                  'availability_status', 'ready_state']
        field_labels = ['id', 'name', 'administrative', 'operational',
                        'availability', 'ready_state']
        utils.print_list(node, fields, field_labels, sortby=1)


@utils.arg('node', metavar='<node uuid>',
           help="uuid of a Service Node")
def do_servicenode_show(cc, args):
    """Show a Service Node's attributes."""
    try:
        node = cc.sm_service_nodes.get(args.node)
    except exc.HTTPNotFound:
        raise exc.CommandError('Service Node not found: %s' % args.node)
    except exc.Forbidden:
        raise exc.CommandError("Not authorized. The requested action "
                               "requires 'admin' level")
    else:
        _print_sm_service_node_show(node)
