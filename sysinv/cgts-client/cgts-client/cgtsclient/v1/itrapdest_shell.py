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


def _print_itrapdest_show(itrapdest):
    fields = ['uuid', 'ip_address', 'community', 'port', 'type',
              'transport', 'created_at']
    data = dict([(f, getattr(itrapdest, f, '')) for f in fields])
    utils.print_dict(data, wrap=72)


def do_snmp_trapdest_list(cc, args):
    """List SNMP trap destinations."""
    itrapdest = cc.itrapdest.list()
    field_labels = ['IP Address', 'SNMP Community', 'Port', 'Type', 'Transport']
    fields = ['ip_address', 'community', 'port', 'type', 'transport']
    utils.print_list(itrapdest, fields, field_labels, sortby=1)


@utils.arg('itrapdest', metavar='<ip_address>', help="IP address of itrapdest")
def do_snmp_trapdest_show(cc, args):
    """Show a SNMP trap destination."""
    try:
        itrapdest = cc.itrapdest.get(args.itrapdest)
    except exc.HTTPNotFound:
        raise exc.CommandError('Trap Destination not found: %s' % args.itrapdest)
    else:
        _print_itrapdest_show(itrapdest)


@utils.arg('-i', '--ip_address',
           metavar='<ip_address>',
           help='IP address of the trap destination [REQUIRED]')
@utils.arg('-c', '--community',
           metavar='<community>',
           help='SNMP community string [REQUIRED]')
def do_snmp_trapdest_add(cc, args):
    """Create a new SNMP trap destination."""
    field_list = ['ip_address', 'community', 'port', 'type', 'transport']
    fields = dict((k, v) for (k, v) in vars(args).items()
                  if k in field_list and not (v is None))
    # fields = utils.args_array_to_dict(fields, 'activity')
    # fields = utils.args_array_to_dict(fields, 'reason')
    itrapdest = cc.itrapdest.create(**fields)

    field_list.append('uuid')
    data = dict([(f, getattr(itrapdest, f, '')) for f in field_list])
    utils.print_dict(data, wrap=72)


@utils.arg('itrapdest',
           metavar='<ip_address>',
           nargs='+',
           help="IP Address of itrapdest")
def do_snmp_trapdest_delete(cc, args):
    """Delete an SNMP trap destination."""
    for c in args.itrapdest:
        try:
            cc.itrapdest.delete(c)
        except exc.HTTPNotFound:
            raise exc.CommandError('IP not found: %s' % c)
        print('Deleted ip %s' % c)
