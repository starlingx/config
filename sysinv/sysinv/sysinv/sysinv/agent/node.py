#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

""" inventory numa node Utilities and helper functions."""

import os
from os import listdir
from os.path import isfile
from os.path import join
import re

from oslo_log import log as logging
import tsconfig.tsconfig as tsc

LOG = logging.getLogger(__name__)

# Defines the size of one kilobyte
SIZE_KB = 1024

# Defines the size of 2 megabytes in kilobyte units
SIZE_2M_KB = 2048

# Defines the size of 1 gigabyte in kilobyte units
SIZE_1G_KB = 1048576

# Defines the size of 2 megabytes in megabyte units
SIZE_2M_MB = int(SIZE_2M_KB // SIZE_KB)

# Defines the size of 1 gigabyte in megabyte units
SIZE_1G_MB = int(SIZE_1G_KB // SIZE_KB)

# Defines the minimum size of memory for a controller node in megabyte units
CONTROLLER_MIN_MB = 6000

# Defines the minimum size of memory for a worker node in megabyte units
COMPUTE_MIN_MB = 1600

# Defines the minimum size of memory for a secondary worker node in megabyte
# units
COMPUTE_MIN_NON_0_MB = 500


class CPU(object):
    '''Class to encapsulate CPU data for System Inventory'''

    def __init__(self, cpu, numa_node, core, thread,
                 cpu_family=None, cpu_model=None, revision=None):
        '''Construct a Icpu object with the given values.'''

        self.cpu = cpu
        self.numa_node = numa_node
        self.core = core
        self.thread = thread
        self.cpu_family = cpu_family
        self.cpu_model = cpu_model
        self.revision = revision
        # self.allocated_functions = mgmt (usu. 0), vswitch

    def __eq__(self, rhs):
        return (self.cpu == rhs.cpu and
                self.numa_node == rhs.numa_node and
                self.core == rhs.core and
                self.thread == rhs.thread)

    def __ne__(self, rhs):
        return (self.cpu != rhs.cpu or
                self.numa_node != rhs.numa_node or
                self.core != rhs.core or
                self.thread != rhs.thread)

    def __str__(self):
        return "%s [%s] [%s] [%s]" % (self.cpu, self.numa_node,
                                      self.core, self.thread)

    def __repr__(self):
        return "<CPU '%s'>" % str(self)


class NodeOperator(object):
    '''Class to encapsulate CPU operations for System Inventory'''

    def __init__(self):

        self.num_cpus = 0
        self.num_nodes = 0
        self.float_cpuset = 0
        self.total_memory_mb = 0
        self.free_memory_mb = 0
        self.total_memory_nodes_mb = []
        self.free_memory_nodes_mb = []
        self.topology = {}

        # self._get_cpu_topology()
        # self._get_total_memory_mb()
        # self._get_total_memory_nodes_mb()
        # self._get_free_memory_mb()
        # self._get_free_memory_nodes_mb()

    def convert_range_string_to_list(self, s):
        olist = []
        s = s.strip()
        if s:
            for part in s.split(','):
                if '-' in part:
                    a, b = part.split('-')
                    a, b = int(a), int(b)
                    olist.extend(range(a, b + 1))
                else:
                    a = int(part)
                    olist.append(a)
        olist.sort()
        return olist

    def inodes_get_inumas_icpus(self):
        '''Enumerate logical cpu topology based on parsing /proc/cpuinfo
           as function of socket_id, core_id, and thread_id. This updates
           topology.

        :param self
        :updates self.num_cpus- number of logical cpus
        :updates self.num_nodes- number of sockets;maps to number of numa nodes
        :updates self.topology[socket_id][core_id][thread_id] = cpu
        :returns None
        '''
        self.num_cpus = 0
        self.num_nodes = 0
        self.topology = {}

        thread_cnt = {}
        cpu = socket_id = core_id = thread_id = -1
        re_processor = re.compile(r'^[Pp]rocessor\s+:\s+(\d+)')
        re_socket = re.compile(r'^physical id\s+:\s+(\d+)')
        re_core = re.compile(r'^core id\s+:\s+(\d+)')
        re_cpu_family = re.compile(r'^cpu family\s+:\s+(\d+)')
        re_cpu_model = re.compile(r'^model name\s+:\s+(\w+)')

        inumas = []
        icpus = []
        sockets = []

        with open('/proc/cpuinfo', 'r') as infile:
            icpu_attrs = {}

            for line in infile:
                match = re_processor.search(line)
                if match:
                    cpu = int(match.group(1))
                    socket_id = -1
                    core_id = -1
                    thread_id = -1
                    self.num_cpus += 1
                    continue

                match = re_cpu_family.search(line)
                if match:
                    name_value = [s.strip() for s in line.split(':', 1)]
                    name, value = name_value
                    icpu_attrs.update({'cpu_family': value})
                    continue

                match = re_cpu_model.search(line)
                if match:
                    name_value = [s.strip() for s in line.split(':', 1)]
                    name, value = name_value
                    icpu_attrs.update({'cpu_model': value})
                    continue

                match = re_socket.search(line)
                if match:
                    socket_id = int(match.group(1))
                    if socket_id not in sockets:
                        sockets.append(socket_id)
                        attrs = {
                            'numa_node': socket_id,
                            'capabilities': {},
                        }
                        inumas.append(attrs)
                    continue

                match = re_core.search(line)
                if match:
                    core_id = int(match.group(1))

                    if socket_id not in thread_cnt:
                        thread_cnt[socket_id] = {}
                    if core_id not in thread_cnt[socket_id]:
                        thread_cnt[socket_id][core_id] = 0
                    else:
                        thread_cnt[socket_id][core_id] += 1
                    thread_id = thread_cnt[socket_id][core_id]

                    if socket_id not in self.topology:
                        self.topology[socket_id] = {}
                    if core_id not in self.topology[socket_id]:
                        self.topology[socket_id][core_id] = {}

                    self.topology[socket_id][core_id][thread_id] = cpu
                    attrs = {
                        'cpu': cpu,
                        'numa_node': socket_id,
                        'core': core_id,
                        'thread': thread_id,
                        'capabilities': {},
                    }
                    icpu_attrs.update(attrs)
                    icpus.append(icpu_attrs)
                    icpu_attrs = {}
                    continue

        self.num_nodes = len(list(self.topology.keys()))

        # In the case topology not detected, hard-code structures
        if self.num_nodes == 0:
            n_sockets, n_cores, n_threads = (1, int(self.num_cpus), 1)
            self.topology = {}
            for socket_id in range(n_sockets):
                self.topology[socket_id] = {}
                if socket_id not in sockets:
                    sockets.append(socket_id)
                    attrs = {
                        'numa_node': socket_id,
                        'capabilities': {},
                    }
                    inumas.append(attrs)
                for core_id in range(n_cores):
                    self.topology[socket_id][core_id] = {}
                    for thread_id in range(n_threads):
                        self.topology[socket_id][core_id][thread_id] = 0
                        attrs = {
                            'cpu': cpu,
                            'numa_node': socket_id,
                            'core': core_id,
                            'thread': thread_id,
                            'capabilities': {},
                        }
                        icpus.append(attrs)

            # Define Thread-Socket-Core order for logical cpu enumeration
            cpu = 0
            for thread_id in range(n_threads):
                for core_id in range(n_cores):
                    for socket_id in range(n_sockets):
                        if socket_id not in sockets:
                            sockets.append(socket_id)
                            attrs = {
                                'numa_node': socket_id,
                                'capabilities': {},
                            }
                            inumas.append(attrs)
                        self.topology[socket_id][core_id][thread_id] = cpu
                        attrs = {
                            'cpu': cpu,
                            'numa_node': socket_id,
                            'core': core_id,
                            'thread': thread_id,
                            'capabilities': {},
                        }
                        icpus.append(attrs)
                        cpu += 1
            self.num_nodes = len(list(self.topology.keys()))

        LOG.debug("inumas= %s, icpus = %s" % (inumas, icpus))

        return inumas, icpus

    def _get_immediate_subdirs(self, dir):
        return [name for name in listdir(dir)
                if os.path.isdir(join(dir, name))]

    def _get_vswitch_reserved_memory(self, node):
        # Read vswitch memory from worker_reserved.conf

        vswitch_hugepages_nr = 0
        vswitch_hugepages_size = 0
        try:
            with open('/etc/platform/worker_reserved.conf', 'r') as infile:
                for line in infile:
                    if line.startswith("COMPUTE_VSWITCH_MEMORY="):
                        val = line.split("=")
                        vswitch_reserves = val[1].strip('\n')[1:-1]
                        for idx, reserve in enumerate(vswitch_reserves.split()):
                            if idx != node:
                                continue
                            reserve = reserve.split(":")
                            if reserve[0].strip('"') == "node%d" % node:
                                pages_nr = re.sub('[^0-9]', '', reserve[2])
                                pages_size = reserve[1]

                                vswitch_hugepages_nr = int(pages_nr)
                                if pages_size == "1048576kB":
                                    vswitch_hugepages_size = SIZE_1G_MB
                                else:
                                    vswitch_hugepages_size = SIZE_2M_MB
                        break
        except Exception as e:
            LOG.debug("Could not read vswitch reserved memory: %s", e)

        return vswitch_hugepages_nr, vswitch_hugepages_size

    def _inode_get_memory_hugepages(self):
        """Collect hugepage info, including vswitch, and vm.
           Collect platform reserved if config.
        :param self
        :returns list of memory nodes and attributes
        """

        imemory = []

        initial_worker_config_completed = \
            os.path.exists(tsc.INITIAL_WORKER_CONFIG_COMPLETE)

        # check if it is initial report before the huge pages are allocated
        initial_report = not initial_worker_config_completed

        # do not send report if the initial worker config is completed and
        # worker config has not finished, i.e.during subsequent
        # reboot before the manifest allocates the huge pages
        worker_config_completed = \
            os.path.exists(tsc.VOLATILE_WORKER_CONFIG_COMPLETE)
        if (initial_worker_config_completed and
                not worker_config_completed):
            return imemory

        for node in range(self.num_nodes):
            attr = {}
            total_hp_mb = 0  # Total memory (MB) currently configured in HPs
            free_hp_mb = 0

            # Check vswitch and libvirt memory
            # Loop through configured hugepage sizes of this node and record
            # total number and number free
            hugepages = "/sys/devices/system/node/node%d/hugepages" % node

            try:
                subdirs = self._get_immediate_subdirs(hugepages)

                for subdir in subdirs:
                    hp_attr = {}
                    sizesplit = subdir.split('-')
                    if sizesplit[1].startswith("1048576kB"):
                        size = SIZE_1G_MB
                    else:
                        size = SIZE_2M_MB

                    nr_hugepages = 0
                    free_hugepages = 0

                    mydir = hugepages + '/' + subdir
                    files = [f for f in listdir(mydir) if isfile(join(mydir, f))]

                    if files:
                        for file in files:
                            with open(mydir + '/' + file, 'r') as f:
                                if file.startswith("nr_hugepages"):
                                    nr_hugepages = int(f.readline())
                                if file.startswith("free_hugepages"):
                                    free_hugepages = int(f.readline())

                    total_hp_mb = total_hp_mb + int(nr_hugepages * size)
                    free_hp_mb = free_hp_mb + int(free_hugepages * size)

                    vs_hp_nr, vs_hp_size = self._get_vswitch_reserved_memory(
                        node)
                    if vs_hp_size == 0:
                        vs_hp_size = size

                    # Libvirt hugepages can be 1G and 2M
                    if size == SIZE_1G_MB:
                        hp_attr = {}
                        if vs_hp_size == size:
                            # If the huge pages are not allocated
                            if nr_hugepages != 0:
                                nr_hugepages -= vs_hp_nr
                            hp_attr.update({
                                'vswitch_hugepages_size_mib': vs_hp_size,
                                'vswitch_hugepages_nr': vs_hp_nr,
                                'vswitch_hugepages_avail': 0
                            })
                        hp_attr.update({
                            'vm_hugepages_nr_1G': nr_hugepages,
                            'vm_hugepages_avail_1G': free_hugepages,
                            'vm_hugepages_use_1G': 'True'
                        })
                    else:
                        if len(subdirs) == 1:
                            # No 1G hugepage support.
                            hp_attr = {
                                'vm_hugepages_use_1G': 'False',
                                'vm_hugepages_nr_1G': 0,
                                'vswitch_hugepages_size_mib': vs_hp_size,
                                'vswitch_hugepages_nr': vs_hp_nr,
                                'vswitch_hugepages_avail': 0
                            }
                            if nr_hugepages != 0:
                                nr_hugepages -= vs_hp_nr
                        else:
                            hp_attr = {}
                            if vs_hp_size == size and initial_report is False:
                                # User manually set 2M pages
                                if nr_hugepages != 0:
                                    nr_hugepages -= vs_hp_nr
                                hp_attr.update({
                                    'vswitch_hugepages_size_mib': vs_hp_size,
                                    'vswitch_hugepages_nr': vs_hp_nr,
                                    'vswitch_hugepages_avail': 0
                                })

                        hp_attr.update({
                            'vm_hugepages_avail_2M': free_hugepages,
                            'vm_hugepages_nr_2M': nr_hugepages
                        })

                    attr.update(hp_attr)

            except IOError:
                # silently ignore IO errors (eg. file missing)
                pass

            # Get the total memory from meminfo for this node
            re_node_memtotal = re.compile(r'^Node\s+\d+\s+MemTotal:\s+(\d+)')
            total_kb = 0   # Total Memory (KB)

            meminfo = "/sys/devices/system/node/node%d/meminfo" % node
            try:
                with open(meminfo, 'r') as infile:
                    for line in infile:
                        match = re_node_memtotal.search(line)
                        if match:
                            total_kb += int(match.group(1))
                            break

            except IOError:
                # silently ignore IO errors (eg. file missing)
                pass

            node_total_kb = total_kb

            # Read base memory from worker_reserved.conf
            base_mem_mb = 0
            with open('/etc/platform/worker_reserved.conf', 'r') as infile:
                for line in infile:
                    if "WORKER_BASE_RESERVED" in line:
                        val = line.split("=")
                        base_reserves = val[1].strip('\n')[1:-1]
                        for reserve in base_reserves.split():
                            reserve = reserve.split(":")
                            if reserve[0].strip('"') == "node%d" % node:
                                base_mem_mb = int(reserve[1].strip('MB'))

            # On small systems, clip memory overhead to more reasonable minimal
            # settings
            if (total_kb // SIZE_KB - base_mem_mb) < 1000:
                if node == 0:
                    base_mem_mb = COMPUTE_MIN_MB
                    if tsc.nodetype == 'controller':
                        base_mem_mb += CONTROLLER_MIN_MB
                else:
                    base_mem_mb = COMPUTE_MIN_NON_0_MB

            eng_kb = node_total_kb - base_mem_mb * SIZE_KB

            vswitch_mem_kb = (attr.get('vswitch_hugepages_size_mib', 0) *
                              attr.get('vswitch_hugepages_nr', 0) * SIZE_KB)

            vm_kb = (eng_kb - vswitch_mem_kb)

            max_vm_pages_2mb = vm_kb // SIZE_2M_KB
            max_vm_pages_1gb = vm_kb // SIZE_1G_KB

            attr.update({
                'vm_hugepages_possible_2M': max_vm_pages_2mb,
                'vm_hugepages_possible_1G': max_vm_pages_1gb,
            })

            attr.update({
                'numa_node': node,
                'memtotal_mib': total_hp_mb,
                'memavail_mib': free_hp_mb,
                'hugepages_configured': 'True',
                'node_memtotal_mib': node_total_kb // SIZE_KB,
            })

            imemory.append(attr)

        return imemory

    def _inode_get_memory_nonhugepages(self):
        '''Collect nonhugepage info, including platform reserved if config.
        :param self
        :returns list of memory nodes and attributes
        '''

        imemory = []
        self.total_memory_mb = 0

        re_node_memtotal = re.compile(r'^Node\s+\d+\s+MemTotal:\s+(\d+)')
        re_node_memfree = re.compile(r'^Node\s+\d+\s+MemFree:\s+(\d+)')
        re_node_filepages = re.compile(r'^Node\s+\d+\s+FilePages:\s+(\d+)')
        re_node_sreclaim = re.compile(r'^Node\s+\d+\s+SReclaimable:\s+(\d+)')

        for node in range(self.num_nodes):
            attr = {}
            total_mb = 0
            free_mb = 0

            meminfo = "/sys/devices/system/node/node%d/meminfo" % node
            try:
                with open(meminfo, 'r') as infile:
                    for line in infile:
                        match = re_node_memtotal.search(line)
                        if match:
                            total_mb += int(match.group(1))
                            continue

                        match = re_node_memfree.search(line)
                        if match:
                            free_mb += int(match.group(1))
                            continue
                        match = re_node_filepages.search(line)
                        if match:
                            free_mb += int(match.group(1))
                            continue
                        match = re_node_sreclaim.search(line)
                        if match:
                            free_mb += int(match.group(1))
                            continue

            except IOError:
                # silently ignore IO errors (eg. file missing)
                pass

            total_mb /= 1024
            free_mb /= 1024
            self.total_memory_nodes_mb.append(total_mb)
            attr = {
                'numa_node': node,
                'memtotal_mib': total_mb,
                'memavail_mib': free_mb,
                'hugepages_configured': 'False',
            }

            imemory.append(attr)

        return imemory

    def inodes_get_imemory(self):
        '''Collect logical memory topology
        :param self
        :returns list of memory nodes and attributes
        '''
        imemory = []

        if os.path.isfile("/etc/platform/worker_reserved.conf"):
            imemory = self._inode_get_memory_hugepages()
        else:
            imemory = self._inode_get_memory_nonhugepages()

        LOG.debug("imemory= %s" % imemory)

        return imemory
