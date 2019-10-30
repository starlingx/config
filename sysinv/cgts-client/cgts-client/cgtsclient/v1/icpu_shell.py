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
from cgtsclient.v1 import icpu as icpu_utils
from cgtsclient.v1 import ihost as ihost_utils


def _print_icpu_show(icpu):
    fields = ['cpu', 'numa_node', 'core', 'thread',
              'allocated_function',
              'cpu_model', 'cpu_family',
              'capabilities',
              'uuid', 'ihost_uuid', 'inode_uuid',
              'created_at', 'updated_at']
    labels = ['logical_core', 'processor (numa_node)', 'physical_core', 'thread',
              'assigned_function',
              'processor_model', 'processor_family',
              'capabilities',
              'uuid', 'ihost_uuid', 'inode_uuid',
              'created_at', 'updated_at']
    data = [(f, getattr(icpu, f, '')) for f in fields]
    utils.print_tuple_list(data, labels,
                           formatters={'allocated_function':
                                       icpu_utils._cpu_function_formatter})


def _find_cpu(cc, ihost, cpunameoruuid):
    cpus = cc.icpu.list(ihost.uuid)

    if cpunameoruuid.isdigit():
        cpunameoruuid = int(cpunameoruuid)

    for c in cpus:
        if c.uuid == cpunameoruuid or c.cpu == cpunameoruuid:
            break
    else:
        raise exc.CommandError('CPU logical core not found: host %s cpu %s' %
                               (ihost.hostname, cpunameoruuid))
    return c


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('cpulcoreoruuid',
           metavar='<cpu l_core or uuid>',
           help="CPU logical core ID or UUID of cpu")
def do_host_cpu_show(cc, args):
    """Show cpu core attributes."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    icpu = _find_cpu(cc, ihost, args.cpulcoreoruuid)
    _print_icpu_show(icpu)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_cpu_list(cc, args):
    """List cpu cores."""

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    icpus = cc.icpu.list(ihost.uuid)

    field_labels = ['uuid', 'log_core', 'processor', 'phy_core', 'thread',
                    'processor_model', 'assigned_function']
    fields = ['uuid', 'cpu', 'numa_node', 'core', 'thread',
              'cpu_model', 'allocated_function']

    utils.print_list(icpus, fields, field_labels, sortby=1,
                     formatters={'allocated_function':
                                 icpu_utils._cpu_function_tuple_formatter})


@utils.arg('hostnameorid',
           metavar='<hostnameorid>',
           help="Name or ID of host")
@utils.arg('-f', '--function',
           metavar='<function>',
           choices=['vswitch', 'shared', 'platform', 'application-isolated'],
           required=True,
           help='The Core Function.')
@utils.arg('-p0', '--num_cores_on_processor0',
           metavar='<num_cores_on_processor0>',
           type=int,
           help='Number of cores on Processor 0.')
@utils.arg('-p1', '--num_cores_on_processor1',
           metavar='<num_cores_on_processor1>',
           type=int,
           help='Number of cores on Processor 1.')
@utils.arg('-p2', '--num_cores_on_processor2',
           metavar='<num_cores_on_processor2>',
           type=int,
           help='Number of cores on Processor 2.')
@utils.arg('-p3', '--num_cores_on_processor3',
           metavar='<num_cores_on_processor3>',
           type=int,
           help='Number of cores on Processor 3.')
def do_host_cpu_modify(cc, args):
    """Modify cpu core assignments."""
    field_list = ['function', 'allocated_function',
                  'num_cores_on_processor0', 'num_cores_on_processor1',
                  'num_cores_on_processor2', 'num_cores_on_processor3']

    capabilities = []
    sockets = []
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in field_list and not (v is None))

    cap = {'function': user_specified_fields.get('function')}

    for k, v in user_specified_fields.items():
        if k.startswith('num_cores_on_processor'):
            sockets.append({k.lstrip('num_cores_on_processor'): v})

    if sockets:
        cap.update({'sockets': sockets})
        capabilities.append(cap)
    else:
        raise exc.CommandError('Number of cores on Processor (Socket) '
                               'not provided.')

    icpus = cc.ihost.host_cpus_modify(ihost.uuid, capabilities)

    field_labels = ['uuid', 'log_core', 'processor', 'phy_core', 'thread',
                    'processor_model', 'assigned_function']
    fields = ['uuid', 'cpu', 'numa_node', 'core', 'thread',
              'cpu_model', 'allocated_function']
    utils.print_list(icpus, fields, field_labels, sortby=1,
                     formatters={'allocated_function':
                                 icpu_utils._cpu_function_tuple_formatter})
