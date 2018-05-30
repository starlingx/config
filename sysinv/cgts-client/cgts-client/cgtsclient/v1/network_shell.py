#!/usr/bin/env python
#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils


@utils.arg('network_uuid',
           metavar='<network_uuid>',
           help="UUID of IP network")
def do_network_show(cc, args):
    """Show IP network details."""
    labels = ['uuid', 'type', 'mtu', 'link-capacity', 'dynamic', 'vlan',
              'pool_uuid']
    fields = ['uuid', 'type', 'mtu', 'link_capacity', 'dynamic', 'vlan_id',
              'pool_uuid']
    network = cc.network.get(args.network_uuid)
    data = [(f, getattr(network, f, '')) for f in fields]
    utils.print_tuple_list(data, tuple_labels=labels)


def do_network_list(cc, args):
    """List IP networks on host."""
    labels = ['uuid', 'type', 'mtu', 'link-capacity', 'dynamic', 'vlan',
              'pool_uuid']
    fields = ['uuid', 'type', 'mtu', 'link_capacity', 'dynamic', 'vlan_id',
              'pool_uuid']
    networks = cc.network.list()
    utils.print_list(networks, fields, labels, sortby=1)
