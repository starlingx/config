#!/usr/bin/env python
#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc
from collections import OrderedDict
from cgtsclient.v1 import ihost as ihost_utils

def _print_imemory_show(imemory):
    fields = ['memtotal_mib',
              'platform_reserved_mib',
              'memavail_mib',
              'hugepages_configured',
              'avs_hugepages_size_mib',
              'avs_hugepages_nr',
              'avs_hugepages_avail',
              'vm_hugepages_nr_4K',
              'vm_hugepages_nr_2M',
              'vm_hugepages_nr_2M_pending',
              'vm_hugepages_avail_2M',
              'vm_hugepages_nr_1G',
              'vm_hugepages_nr_1G_pending',
              'vm_hugepages_avail_1G',
              'uuid', 'ihost_uuid', 'inode_uuid',
              'created_at', 'updated_at']
    labels = ['Memory: Usable Total (MiB)',
              '        Platform     (MiB)',
              '        Available    (MiB)',
              'Huge Pages Configured',
              'AVS Huge Pages: Size (MiB)',
              '                Total',
              '                Available',
              'VM  Pages (4K): Total',
              'VM  Huge Pages (2M): Total',
              '                Total Pending',
              '                Available',
              'VM  Huge Pages (1G): Total',
              '                Total Pending',
              '                Available',
              'uuid', 'ihost_uuid', 'inode_uuid',
              'created_at', 'updated_at']

    data = [(f, getattr(imemory, f, '')) for f in fields]

    for d in data:
        if d[0] == 'vm_hugepages_nr_2M_pending':
            if d[1] is None:
                fields.remove(d[0])
                labels.pop(labels.index('                Total Pending'))

        if d[0] == 'vm_hugepages_nr_1G_pending':
            if d[1] is None:
                fields.remove(d[0])
                labels.pop(len(labels)-labels[::-1].
                           index('                Total Pending')-1)

    data = [(f, getattr(imemory, f, '')) for f in fields]
    utils.print_tuple_list(data, labels)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('numa_node',
           metavar='<processor>',
           help="processor")
def do_host_memory_show(cc, args):
    """Show memory attributes."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    inodes = cc.inode.list(ihost.uuid)
    imemorys = cc.imemory.list(ihost.uuid)
    for m in imemorys:
        for n in inodes:
            if m.inode_uuid == n.uuid:
                if int(n.numa_node) == int(args.numa_node):
                    _print_imemory_show(m)
                    return
    else:
        raise exc.CommandError('Processor not found: host %s processor %s' %
                                (ihost.hostname, args.numa_node)) 


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_memory_list(cc, args):
    """List memory nodes."""

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    inodes = cc.inode.list(ihost.uuid)
    imemorys = cc.imemory.list(ihost.uuid)
    for m in imemorys:
        for n in inodes:
            if m.inode_uuid == n.uuid:
                m.numa_node = n.numa_node
                break

    fields = ['numa_node',
              'memtotal_mib',
              'platform_reserved_mib',
              'memavail_mib',
              'hugepages_configured',
              'avs_hugepages_size_mib',
              'avs_hugepages_nr',
              'avs_hugepages_avail',
              'vm_hugepages_nr_4K',
              'vm_hugepages_nr_2M',
              'vm_hugepages_avail_2M',
              'vm_hugepages_nr_2M_pending',
              'vm_hugepages_nr_1G',
              'vm_hugepages_avail_1G',
              'vm_hugepages_nr_1G_pending',
              'vm_hugepages_use_1G']

    field_labels = ['processor',
              'mem_total(MiB)',
              'mem_platform(MiB)',
              'mem_avail(MiB)',
              'hugepages(hp)_configured',
              'avs_hp_size(MiB)',
              'avs_hp_total',
              'avs_hp_avail',
              'vm_total_4K',
              'vm_hp_total_2M',
              'vm_hp_avail_2M',
              'vm_hp_pending_2M',
              'vm_hp_total_1G',
              'vm_hp_avail_1G',
              'vm_hp_pending_1G',
              'vm_hp_use_1G']

    utils.print_list(imemorys, fields, field_labels, sortby=1)

@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('numa_node',
           metavar='<processor>',
           help="processor")

@utils.arg('-m', '--platform_reserved_mib',
           metavar='<Platform Reserved MiB>',
           help='The amount of platform memory (MiB) for the numa node')

@utils.arg('-2M', '--vm_hugepages_nr_2M_pending',
           metavar='<2M hugepages number>',
           help='The number of 2M vm huge pages for the numa node')

@utils.arg('-1G', '--vm_hugepages_nr_1G_pending',
           metavar='<1G hugepages number>',
           help='The number of 1G vm huge pages for the numa node')
def do_host_memory_modify(cc, args):
    """Modify platform reserved and/or libvirt vm huge page memory attributes for compute nodes."""

    rwfields = ['platform_reserved_mib',
                'vm_hugepages_nr_2M_pending',
                'vm_hugepages_nr_1G_pending']

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                  if k in rwfields and not (v is None))

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    inodes = cc.inode.list(ihost.uuid)
    imemorys = cc.imemory.list(ihost.uuid)
    mem = None
    for m in imemorys:
        for n in inodes:
            if m.inode_uuid == n.uuid:
                if int(n.numa_node) == int(args.numa_node):
                    mem = m
                    break 
        if mem:
            break

    if mem is None:
        raise exc.CommandError('Processor not found: host %s processor %s' %
                                (ihost.hostname, args.numa_node))

    patch = []
    for (k, v) in user_specified_fields.items():
        patch.append({'op':'replace', 'path':'/'+k, 'value':v})

    if patch:
        imemory = cc.imemory.update(mem.uuid, patch)
        _print_imemory_show(imemory)

