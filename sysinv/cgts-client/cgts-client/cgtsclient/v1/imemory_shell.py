# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils


def _print_imemory_show(imemory):
    fields = ['memtotal_mib',
              'platform_reserved_mib',
              'memavail_mib',
              'hugepages_configured',
              'vswitch_hugepages_size_mib',
              'vswitch_hugepages_nr',
              'vswitch_hugepages_avail',
              'vswitch_hugepages_reqd',
              'vm_hugepages_nr_4K',
              'vm_pending_as_percentage',
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
              'vSwitch Huge Pages: Size (MiB)',
              '                    Total',
              '                    Available',
              '                    Required',
              'Application  Pages (4K): Total',
              'Application  Huge Pages Pending As Percentage',
              'Application  Huge Pages (2M): Total',
              '                Total Pending',
              '                Available',
              'Application  Huge Pages (1G): Total',
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
                labels.pop(len(labels) - labels[::-1].index('                Total Pending') - 1)

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
              'vswitch_hugepages_size_mib',
              'vswitch_hugepages_nr',
              'vswitch_hugepages_avail',
              'vswitch_hugepages_reqd',
              'vm_hugepages_nr_4K',
              'vm_pending_as_percentage',
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
                    'vs_hp_size(MiB)',
                    'vs_hp_total',
                    'vs_hp_avail',
                    'vs_hp_reqd',
                    'app_total_4K',
                    'app_hp_as_percentage',
                    'app_hp_total_2M',
                    'app_hp_avail_2M',
                    'app_hp_pending_2M',
                    'app_hp_total_1G',
                    'app_hp_avail_1G',
                    'app_hp_pending_1G',
                    'app_hp_use_1G']

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
@utils.arg('-2M', '--hugepages_nr_2M_pending',
           metavar='<2M hugepages number>',
           help='The number of 2M application huge pages for the numa node')
@utils.arg('-1G', '--hugepages_nr_1G_pending',
           metavar='<1G hugepages number>',
           help='The number of 1G application huge pages for the numa node')
@utils.arg('-f', '--function',
           metavar='<function>',
           choices=['vswitch', 'application'],
           default='application',
           help='The Memory Function.')
def do_host_memory_modify(cc, args):
    """Modify platform reserved and/or application huge page memory attributes for worker nodes."""

    rwfields = ['platform_reserved_mib',
                'hugepages_nr_2M_pending',
                'hugepages_nr_1G_pending',
                'function']

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

    function = user_specified_fields.get('function')
    vswitch_hp_size_mib = None
    percent_2M = None
    percent_1G = None

    patch = []
    for (k, v) in user_specified_fields.items():
        if k == 'function':
            continue
        if function == 'vswitch':
            if k == 'hugepages_nr_2M_pending':
                vswitch_hp_size_mib = 2
                k = 'vswitch_hugepages_reqd'
            elif k == 'hugepages_nr_1G_pending':
                vswitch_hp_size_mib = 1024
                k = 'vswitch_hugepages_reqd'
        else:
            if k == 'hugepages_nr_2M_pending':
                k = 'vm_hugepages_nr_2M_pending'
                percent_2M = "False"
                if str(v).endswith('%'):
                    percent_2M = "True"
                    v = v.rstrip("%")
                v = int(v)

            elif k == 'hugepages_nr_1G_pending':
                k = 'vm_hugepages_nr_1G_pending'
                percent_1G = "False"
                if str(v).endswith('%'):
                    percent_1G = "True"
                    v = v.rstrip("%")
                v = int(v)

        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})

    if patch:
        if (percent_2M == "True" and percent_1G == "False") or \
                (percent_2M == "False" and percent_1G == "True"):
            raise exc.CommandError('2MB hugepage and 1GB hugepage values must both be \
                                   percent or not percent. (2M as percentage: %s, 1G as \
                                   percentage: %s)' % (percent_2M, percent_1G))

        if vswitch_hp_size_mib:
            patch.append({'op': 'replace', 'path': '/vswitch_hugepages_size_mib',
                          'value': vswitch_hp_size_mib})
        if percent_2M is not None or percent_1G is not None:
            patch.append({'op': 'replace', 'path': '/vm_pending_as_percentage',
                          'value': percent_2M if percent_2M is not None else percent_1G})

        imemory = cc.imemory.update(mem.uuid, patch)
        _print_imemory_show(imemory)
