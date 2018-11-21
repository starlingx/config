#!/usr/bin/env python
################################################################################
# Copyright (c) 2013 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
################################################################################
#
# topology.py -- gives a summary of logical cpu enumeration,
#                sockets, cores per package, threads per core,
#                total memory, and numa nodes

from __future__ import print_function
import os
import sys
import re

class Topology(object):
    """ Build up topology information.
        (i.e. logical cpu topology, NUMA nodes, memory)
    """

    def __init__(self):
        self.num_cpus    = 0
        self.num_nodes   = 0
        self.num_sockets = 0
        self.num_cores_per_pkg   = 0
        self.num_threads_per_core = 0

        self.topology = {}
        self.topology_idx = {}
        self.total_memory_MiB = 0
        self.total_memory_nodes_MiB = []

        self._get_cpu_topology()
        self._get_total_memory_MiB()
        self._get_total_memory_nodes_MiB()

    def _get_cpu_topology(self):
        '''Enumerate logical cpu topology based on parsing /proc/cpuinfo
           as function of socket_id, core_id, and thread_id. This updates
           topology and reverse index topology_idx mapping.

        :param self
        :updates self.num_cpus - number of logical cpus
        :updates self.num_nodes - number of sockets; maps to number of numa nodes
        :updates self.topology[socket_id][core_id][thread_id] = cpu
        :updates self.topology_idx[cpu] = {'s': socket_id, 'c': core_id, 't': thread_id}
        :returns None
        '''

        self.num_cpus    = 0
        self.num_nodes   = 0
        self.num_sockets = 0
        self.num_cores   = 0
        self.num_threads = 0
        self.topology = {}
        self.topology_idx = {}

        Thread_cnt = {}
        cpu = socket_id = core_id = thread_id = -1
        re_processor = re.compile(r'^[Pp]rocessor\s+:\s+(\d+)')
        re_socket = re.compile(r'^physical id\s+:\s+(\d+)')
        re_core = re.compile(r'^core id\s+:\s+(\d+)')

        with open('/proc/cpuinfo', 'r') as infile:
            for line in infile:

                match = re_processor.search(line)
                if match:
                    cpu = int(match.group(1))
                    socket_id = -1; core_id = -1; thread_id = -1
                    self.num_cpus += 1
                    continue

                match = re_socket.search(line)
                if match:
                    socket_id = int(match.group(1))
                    continue

                match = re_core.search(line)
                if match:
                    core_id = int(match.group(1))

                    if socket_id not in Thread_cnt:
                        Thread_cnt[socket_id] = {}
                    if core_id not in Thread_cnt[socket_id]:
                        Thread_cnt[socket_id][core_id] = 0
                    else:
                        Thread_cnt[socket_id][core_id] += 1
                    thread_id = Thread_cnt[socket_id][core_id]

                    if socket_id not in self.topology:
                        self.topology[socket_id] = {}
                    if core_id not in self.topology[socket_id]:
                        self.topology[socket_id][core_id] = {}

                    self.topology[socket_id][core_id][thread_id] = cpu
                    self.topology_idx[cpu] = {'s': socket_id, 'c': core_id, 't': thread_id}
                    continue
        self.num_nodes = len(self.topology.keys())

        # In the case topology not detected, hard-code structures
        if self.num_nodes == 0:
            n_sockets, n_cores, n_threads = (1, self.num_cpus, 1)
            self.topology = {}
            for socket_id in range(n_sockets):
                self.topology[socket_id] = {}
                for core_id in range(n_cores):
                    self.topology[socket_id][core_id] = {}
                    for thread_id in range(n_threads):
                        self.topology[socket_id][core_id][thread_id] = 0
            # Define Thread-Socket-Core order for logical cpu enumeration
            self.topology_idx = {}
            cpu = 0
            for thread_id in range(n_threads):
                for socket_id in range(n_sockets):
                    for core_id in range(n_cores):
                        self.topology[socket_id][core_id][thread_id] = cpu
                        self.topology_idx[cpu] = {'s': socket_id, 'c': core_id, 't': thread_id}
                        cpu += 1
            self.num_nodes = len(self.topology.keys())

        self.num_sockets          = len(self.topology.keys())
        self.num_cores_per_pkg    = len(self.topology[0].keys())
        self.num_threads_per_core = len(self.topology[0][0].keys())

        return None

    def _get_total_memory_MiB(self):
        """Get the total memory for VMs (MiB).

        :updates: total memory for VMs (MiB)

        """

        self.total_memory_MiB = 0

        # Total memory
        try:
            m = open('/proc/meminfo').read().split()
            idx_Total = m.index('MemTotal:') + 1
            self.total_memory_MiB = int(m[idx_Total]) / 1024
        except IOError:
            # silently ignore IO errors (eg. file missing)
            pass
        return None

    def _get_total_memory_nodes_MiB(self):
        """Get the total memory per numa node for VMs (MiB).

        :updates: total memory per numa node for VMs (MiB)

        """

        self.total_memory_nodes_MiB = []

        # Memory of each numa node (MiB)
        for node in range(self.num_nodes):
            Total_MiB = 0

            meminfo = "/sys/devices/system/node/node%d/meminfo" % node
            try:
                m = open(meminfo).read().split()
                idx_Total = m.index('MemTotal:') + 1
                Total_MiB = int(m[idx_Total]) / 1024
            except IOError:
                # silently ignore IO errors (eg. file missing)
                pass

            self.total_memory_nodes_MiB.append(Total_MiB)
        return None

    def _print_cpu_topology(self):
        '''Print logical cpu topology enumeration as function of:
           socket_id, core_id, and thread_id.

        :param self
        :returns None
        '''

        cpu_list = self.topology_idx.keys()
        cpu_list.sort()
        total_memory_GiB = self.total_memory_MiB/1024.0

        print('TOPOLOGY:')
        print('%16s : %5d' % ('logical cpus',     self.num_cpus))
        print('%16s : %5d' % ('sockets',          self.num_sockets))
        print('%16s : %5d' % ('cores_per_pkg',    self.num_cores_per_pkg))
        print('%16s : %5d' % ('threads_per_core', self.num_threads_per_core))
        print('%16s : %5d' % ('numa_nodes',       self.num_nodes))
        print('%16s : %5.2f %s' % ('total_memory', total_memory_GiB, 'GiB'))
        print('%16s :' % ('memory_per_node'), end=' ')
        for node in range(self.num_nodes):
            node_memory_GiB = self.total_memory_nodes_MiB[node]/1024.0
            print('%5.2f' % (node_memory_GiB), end=' ')
        print('%s' % ('GiB'))
        print('')

        print('LOGICAL CPU TOPOLOGY:')
        print("%9s :" % 'cpu_id', end=' ')
        for cpu in cpu_list:
            print("%3d" % cpu, end=' ')
        print('')
        print("%9s :" % 'socket_id', end=' ')
        for cpu in cpu_list:
            socket_id = self.topology_idx[cpu]['s']
            print("%3d" % socket_id, end=' ')
        print('')
        print("%9s :" % 'core_id', end=' ')
        for cpu in cpu_list:
            core_id = self.topology_idx[cpu]['c']
            print("%3d" % core_id, end=' ')
        print('')
        print("%9s :" % 'thread_id', end=' ')
        for cpu in cpu_list:
            thread_id = self.topology_idx[cpu]['t']
            print("%3d" % thread_id, end=' ')
        print('')
        print('')

        print('CORE TOPOLOGY:')
        print("%6s %9s %7s %9s %s" % ('cpu_id', 'socket_id', 'core_id', 'thread_id', 'affinity'))
        for cpu in cpu_list:
            affinity  = 1<<cpu
            socket_id = self.topology_idx[cpu]['s']
            core_id   = self.topology_idx[cpu]['c']
            thread_id = self.topology_idx[cpu]['t']
            print("%6d %9d %7d %9d 0x%x" \
                % (cpu, socket_id, core_id, thread_id, affinity))

        return None

#-------------------------------------------------------------------------------
''' Main Program
'''

# Get logical cpu topology
topology = Topology()
topology._print_cpu_topology()

sys.exit(0)
