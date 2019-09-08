#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc

DATANETWORK_TYPE_VXLAN = "vxlan"


def _print_datanetwork_show(obj):
    fields = ['id', 'uuid', 'name', 'network_type', 'mtu',
              'description']

    if obj.network_type == DATANETWORK_TYPE_VXLAN:
        fields.append('multicast_group')
        fields.append('port_num')
        fields.append('ttl')
        fields.append('mode')

    data = [(f, getattr(obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('datanetwork_id',
           metavar='<datanetwork_id>',
           help="UUID or name of datanetwork")
def do_datanetwork_show(cc, args):
    """Show datanetwork details."""

    datanetwork = cc.datanetwork.get(args.datanetwork_id)
    _print_datanetwork_show(datanetwork)


def do_datanetwork_list(cc, args):
    """List datanetworks."""

    labels = ['uuid', 'name', 'network_type', 'mtu']
    fields = ['uuid', 'name', 'network_type', 'mtu']
    datanetworks = cc.datanetwork.list()
    utils.print_list(datanetworks, fields, labels, sortby=1)


@utils.arg('name',
           metavar='<datanetwork_name>',
           help="Name of the datanetwork [REQUIRED]")
@utils.arg('network_type',
           metavar='<network_type>',
           choices=['flat', 'vlan', 'vxlan'],
           help="Type of the datanetwork [REQUIRED]")
@utils.arg('-d', '--description',
           metavar='<description>',
           help='User description of the datanetwork')
@utils.arg('-m', '--mtu',
           metavar='<mtu>',
           default=1500,
           help='MTU of the datanetwork')
@utils.arg('-p', '--port_num',
           metavar='<port_num>',
           help='port_num of the datanetwork')
@utils.arg('-g', '--multicast_group',
           metavar='<multicast_group>',
           help='multicast_group of the datanetwork')
@utils.arg('-t', '--ttl',
           metavar='<ttl>',
           help='time-to-live of the datanetwork')
@utils.arg('-M', '--mode',
           metavar='<mode>',
           choices=['dynamic', 'static'],
           default='dynamic',
           help='mode of the datanetwork')
def do_datanetwork_add(cc, args):
    """Add a datanetwork."""

    field_list = ['name', 'network_type', 'mtu', 'description',
                  'multicast_group', 'port_num', 'ttl', 'mode']

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    datanetwork = cc.datanetwork.create(**data)
    uuid = getattr(datanetwork, 'uuid', '')
    try:
        datanetwork = cc.datanetwork.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created DataNetwork UUID not found: %s' % uuid)
    _print_datanetwork_show(datanetwork)


@utils.arg('datanetwork_id',
           metavar='<datanetwork_id>',
           help="Name of the datanetwork [REQUIRED]")
@utils.arg('-m', '--mtu',
           metavar='<mtu>',
           help='MTU of the datanetwork')
@utils.arg('-d', '--description',
           metavar='<description>',
           help='User description of the datanetwork')
def do_datanetwork_modify(cc, args):
    """Modify a datanetwork."""

    rwfields = ['mtu', 'description']

    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in rwfields and not (v is None))

    patch = []
    for (k, v) in user_specified_fields.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})

    datanetwork = cc.datanetwork.update(args.datanetwork_id, patch)
    _print_datanetwork_show(datanetwork)


@utils.arg('datanetwork_uuid',
           metavar='<datanetwork_uuid>',
           help="UUID of datanetwork entry")
def do_datanetwork_delete(cc, args):
    """Delete a datanetwork."""

    cc.datanetwork.delete(args.datanetwork_uuid)
    print('Deleted DataNetwork: %s' % args.datanetwork_uuid)
