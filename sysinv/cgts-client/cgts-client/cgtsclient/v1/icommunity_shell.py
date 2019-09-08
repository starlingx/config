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


def _print_icommunity_show(icommunity):
    fields = ['uuid', 'community', 'view', 'access', 'created_at']
    data = dict([(f, getattr(icommunity, f, '')) for f in fields])
    utils.print_dict(data, wrap=72)


def do_snmp_comm_list(cc, args):
    """List community strings."""
    icommunity = cc.icommunity.list()
    field_labels = ['SNMP community', 'View', 'Access']
    fields = ['community', 'view', 'access']
    utils.print_list(icommunity, fields, field_labels, sortby=1)


@utils.arg('icommunity', metavar='<community>', help="Name of icommunity")
def do_snmp_comm_show(cc, args):
    """Show SNMP community attributes."""
    try:
        icommunity = cc.icommunity.get(args.icommunity)
    except exc.HTTPNotFound:
        raise exc.CommandError('service not found: %s' % args.icommunity)
    else:
        _print_icommunity_show(icommunity)


@utils.arg('-c', '--community',
           metavar='<community>',
           help='SNMP community string [REQUIRED]')
def do_snmp_comm_add(cc, args):
    """Add a new SNMP community."""
    field_list = ['community', 'view', 'access']
    fields = dict((k, v) for (k, v) in vars(args).items()
                  if k in field_list and not (v is None))
    # fields = utils.args_array_to_dict(fields, 'activity')
    # fields = utils.args_array_to_dict(fields, 'reason')
    icommunity = cc.icommunity.create(**fields)

    field_list.append('uuid')
    data = dict([(f, getattr(icommunity, f, '')) for f in field_list])
    utils.print_dict(data, wrap=72)


@utils.arg('icommunity',
           metavar='<icommunity name>',
           nargs='+',
           help="Name of icommunity")
def do_snmp_comm_delete(cc, args):
    """Delete an SNMP community."""
    for c in args.icommunity:
        try:
            cc.icommunity.delete(c)
        except exc.HTTPNotFound:
            raise exc.CommandError('Community not found: %s' % c)
        print('Deleted community %s' % c)
