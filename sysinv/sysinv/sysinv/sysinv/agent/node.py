#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

""" inventory numa node Utilities and helper functions."""

import errno
import json
import netaddr
import os
from os import listdir
from os.path import isfile, join
import random
import re
import subprocess


from sysinv.common import exception
from sysinv.common import utils
from sysinv.openstack.common import log as logging
import tsconfig.tsconfig as tsc

LOG = logging.getLogger(__name__)

# Defines per-socket AVS memory requirements (in MB) for both real and virtual
# deployments
#
AVS_REAL_MEMORY_MB = 1024
AVS_VBOX_MEMORY_MB = 512


class CPU:
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
        self.total_memory_MiB = 0
        self.free_memory_MiB = 0
        self.total_memory_nodes_MiB = []
        self.free_memory_nodes_MiB = []
        self.topology = {}

        # self._get_cpu_topology()
        # self._get_total_memory_MiB()
        # self._get_total_memory_nodes_MiB()
        # self._get_free_memory_MiB()
        # self._get_free_memory_nodes_MiB()

    def _is_strict(self):
        with open(os.devnull, "w") as fnull:
            try:
                output = subprocess.check_output(
                    ["cat", "/proc/sys/vm/overcommit_memory"],
                    stderr=fnull)
                if int(output) == 2:
                    return True
            except subprocess.CalledProcessError as e:
                LOG.info("Failed to check for overcommit, error (%s)",
                         e.output)
        return False

    def _is_hugepages_allocated(self):
        with open(os.devnull, "w") as fnull:
            try:
                output = subprocess.check_output(
                    ["cat", "/proc/sys/vm/nr_hugepages"], stderr=fnull)
                if int(output) > 0:
                    return True
            except subprocess.CalledProcessError as e:
                LOG.info("Failed to check hugepages, error (%s)", e.output)
        return False

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

        Thread_cnt = {}
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
                    socket_id = -1; core_id = -1; thread_id = -1
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
                    attrs = {'cpu': cpu,
                             'numa_node': socket_id,
                             'core': core_id,
                             'thread': thread_id,
                             'capabilities': {},
                             }
                    icpu_attrs.update(attrs)
                    icpus.append(icpu_attrs)
                    icpu_attrs = {}
                    continue

        self.num_nodes = len(self.topology.keys())

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
            self.num_nodes = len(self.topology.keys())

        LOG.debug("inumas= %s, icpus = %s" % (inumas, icpus))

        return inumas, icpus

    def _get_immediate_subdirs(self, dir):
        return [name for name in listdir(dir)
                if os.path.isdir(join(dir, name))]

    def _set_default_avs_hugesize(self):
        '''
        Set the default memory size for avs hugepages when it must fallback to
        2MB pages because there are no 1GB pages.  In a virtual environment we
        set a smaller amount of memory because AVS is configured to use a
        smaller mbuf pool.  In non-virtual environments we use the same amount
        of memory as we would if 1GB pages were available.
        '''
        hugepage_size = 2
        if utils.is_virtual():
            avs_hugepages_nr = AVS_VBOX_MEMORY_MB / hugepage_size
        else:
            avs_hugepages_nr = AVS_REAL_MEMORY_MB / hugepage_size

        ## Create a new set of dict attributes
        hp_attr = {'avs_hugepages_size_mib': hugepage_size,
                   'avs_hugepages_nr': avs_hugepages_nr,
                   'avs_hugepages_avail': 0}
        return hp_attr

    def _inode_get_memory_hugepages(self):
        '''Collect hugepage info, including avs, and vm.
           Collect platform reserved if config.
        :param self
        :returns list of memory nodes and attributes
        '''

        imemory = []
        Ki = 1024
        SZ_2M_Ki = 2048
        SZ_1G_Ki = 1048576
        controller_min_MB = 6000
        compute_min_MB = 1600
        compute_min_non0_MB = 500

        initial_compute_config_completed = \
            os.path.exists(tsc.INITIAL_COMPUTE_CONFIG_COMPLETE)

        # check if it is initial report before the huge pages are allocated
        initial_report = not initial_compute_config_completed

        # do not send report if the initial compute config is completed and
        # the huge pages have not been allocated, i.e.during subsequent
        # reboot before the manifest allocates the huge pages
        if (initial_compute_config_completed and
                not self._is_hugepages_allocated()):
            return imemory

        for node in range(self.num_nodes):
            attr = {}
            Total_HP_MiB = 0  # Total memory (MiB) currently configured in HPs
            Free_HP_MiB = 0

            # Check AVS and Libvirt memory
            # Loop through configured hugepage sizes of this node and record
            # total number and number free
            hugepages = "/sys/devices/system/node/node%d/hugepages" % node

            try:
                subdirs = self._get_immediate_subdirs(hugepages)

                for subdir in subdirs:
                    hp_attr = {}
                    sizesplit = subdir.split('-')
                    # role via size; also from /etc/nova/compute_reserved.conf
                    if sizesplit[1].startswith("1048576kB"):
                        hugepages_role = "avs"
                        size = int(SZ_1G_Ki / Ki)
                    else:
                        hugepages_role = "vm"
                        size = int(SZ_2M_Ki / Ki)

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

                    Total_HP_MiB = Total_HP_MiB + int(nr_hugepages * size)
                    Free_HP_MiB = Free_HP_MiB + int(free_hugepages * size)

                    # Libvirt hugepages can now be 1G and 2M, can't only look
                    # at 2M pages
                    if hugepages_role == "avs":
                        avs_hugepages_nr = AVS_REAL_MEMORY_MB / size
                        hp_attr = {
                               'avs_hugepages_size_mib': size,
                               'avs_hugepages_nr': avs_hugepages_nr,
                               'avs_hugepages_avail': 0,
                               'vm_hugepages_nr_1G':
                               (nr_hugepages - avs_hugepages_nr),
                               'vm_hugepages_avail_1G': free_hugepages,
                               'vm_hugepages_use_1G': 'True'
                                  }
                    else:
                        if len(subdirs) == 1:
                            hp_attr = self._set_default_avs_hugesize()
                            hp_attr.update({'vm_hugepages_use_1G': 'False'})

                        avs_hugepages_nr = hp_attr.get('avs_hugepages_nr', 0)
                        hp_attr.update({
                            'vm_hugepages_avail_2M': free_hugepages,
                            'vm_hugepages_nr_2M':
                                (nr_hugepages - avs_hugepages_nr)
                             })

                    attr.update(hp_attr)

            except IOError:
                # silently ignore IO errors (eg. file missing)
                pass

            # Get the free and total memory from meminfo for this node
            re_node_MemTotal = re.compile(r'^Node\s+\d+\s+\MemTotal:\s+(\d+)')
            re_node_MemFree = re.compile(r'^Node\s+\d+\s+\MemFree:\s+(\d+)')
            re_node_FilePages = \
                re.compile(r'^Node\s+\d+\s+\FilePages:\s+(\d+)')
            re_node_SReclaim = \
                re.compile(r'^Node\s+\d+\s+\SReclaimable:\s+(\d+)')
            re_node_CommitLimit = \
                re.compile(r'^Node\s+\d+\s+\CommitLimit:\s+(\d+)')
            re_node_Committed_AS = \
                re.compile(r'^Node\s+\d+\s+\'Committed_AS:\s+(\d+)')

            Free_KiB = 0  # Free Memory (KiB) available
            Total_KiB = 0  # Total Memory (KiB)
            limit = 0      # only used in strict accounting
            committed = 0  # only used in strict accounting

            meminfo = "/sys/devices/system/node/node%d/meminfo" % node
            try:
                with open(meminfo, 'r') as infile:
                    for line in infile:
                        match = re_node_MemTotal.search(line)
                        if match:
                            Total_KiB += int(match.group(1))
                            continue
                        match = re_node_MemFree.search(line)
                        if match:
                            Free_KiB += int(match.group(1))
                            continue
                        match = re_node_FilePages.search(line)
                        if match:
                            Free_KiB += int(match.group(1))
                            continue
                        match = re_node_SReclaim.search(line)
                        if match:
                            Free_KiB += int(match.group(1))
                            continue
                        match = re_node_CommitLimit.search(line)
                        if match:
                            limit = int(match.group(1))
                            continue
                        match = re_node_Committed_AS.search(line)
                        if match:
                            committed = int(match.group(1))
                            continue

                if self._is_strict():
                    Free_KiB = limit - committed

            except IOError:
                # silently ignore IO errors (eg. file missing)
                pass

            # Calculate PSS
            Pss_MiB = 0
            if node == 0:
                cmd = 'cat /proc/*/smaps 2>/dev/null | awk \'/^Pss:/ ' \
                      '{a += $2;} END {printf "%d\\n", a/1024.0;}\''
                try:
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                            shell=True)
                    result = proc.stdout.read().strip()
                    Pss_MiB = int(result)
                except subprocess.CalledProcessError as e:
                    LOG.error("Cannot calculate PSS (%s) (%d)", cmd,
                              e.returncode)
                except OSError as e:
                    LOG.error("Failed to execute (%s) OS error (%d)", cmd,
                              e.errno)

            # need to multiply Total_MiB by 1024 to match compute_huge
            node_total_kib = Total_HP_MiB * Ki + Free_KiB + Pss_MiB * Ki

            # Read base memory from compute_reserved.conf
            base_mem_MiB = 0
            with open('/etc/nova/compute_reserved.conf', 'r') as infile:
                for line in infile:
                    if "COMPUTE_BASE_RESERVED" in line:
                        val = line.split("=")
                        base_reserves = val[1].strip('\n')[1:-1]
                        for reserve in base_reserves.split():
                            reserve = reserve.split(":")
                            if reserve[0].strip('"') == "node%d" % node:
                                base_mem_MiB = int(reserve[1].strip('MB'))

            # On small systems, clip memory overhead to more reasonable minimal
            # settings
            if (Total_KiB / Ki - base_mem_MiB) < 1000:
                if node == 0:
                    base_mem_MiB = compute_min_MB
                    if tsc.nodetype == 'controller':
                        base_mem_MiB += controller_min_MB
                else:
                    base_mem_MiB = compute_min_non0_MB

            Eng_KiB = node_total_kib - base_mem_MiB * Ki

            vswitch_mem_kib = (attr.get('avs_hugepages_size_mib', 0) *
                               attr.get('avs_hugepages_nr', 0) * Ki)

            VM_KiB = (Eng_KiB - vswitch_mem_kib)

            max_vm_pages_2M = VM_KiB / SZ_2M_Ki
            max_vm_pages_1G = VM_KiB / SZ_1G_Ki

            attr.update({
                'vm_hugepages_possible_2M': max_vm_pages_2M,
                'vm_hugepages_possible_1G': max_vm_pages_1G,
            })

            # calculate 100% 2M pages if it is initial report and the huge
            # pages have not been allocated
            if initial_report:
                Total_HP_MiB += int(max_vm_pages_2M * (SZ_2M_Ki / Ki))
                Free_HP_MiB = Total_HP_MiB
                attr.update({
                    'vm_hugepages_nr_2M': max_vm_pages_2M,
                    'vm_hugepages_avail_2M': max_vm_pages_2M,
                    'vm_hugepages_nr_1G': 0
                })

            attr.update({
                'numa_node': node,
                'memtotal_mib': Total_HP_MiB,
                'memavail_mib': Free_HP_MiB,
                'hugepages_configured': 'True',
                'node_memtotal_mib': node_total_kib / 1024,
                   })

            imemory.append(attr)

        return imemory

    def _inode_get_memory_nonhugepages(self):
        '''Collect nonhugepage info, including platform reserved if config.
        :param self
        :returns list of memory nodes and attributes
        '''

        imemory = []
        self.total_memory_MiB = 0

        re_node_MemTotal = re.compile(r'^Node\s+\d+\s+\MemTotal:\s+(\d+)')
        re_node_MemFree = re.compile(r'^Node\s+\d+\s+\MemFree:\s+(\d+)')
        re_node_FilePages = re.compile(r'^Node\s+\d+\s+\FilePages:\s+(\d+)')
        re_node_SReclaim = re.compile(r'^Node\s+\d+\s+\SReclaimable:\s+(\d+)')

        for node in range(self.num_nodes):
            attr = {}
            Total_MiB = 0
            Free_MiB = 0

            meminfo = "/sys/devices/system/node/node%d/meminfo" % node
            try:
                with open(meminfo, 'r') as infile:
                    for line in infile:
                        match = re_node_MemTotal.search(line)
                        if match:
                            Total_MiB += int(match.group(1))
                            continue

                        match = re_node_MemFree.search(line)
                        if match:
                            Free_MiB += int(match.group(1))
                            continue
                        match = re_node_FilePages.search(line)
                        if match:
                            Free_MiB += int(match.group(1))
                            continue
                        match = re_node_SReclaim.search(line)
                        if match:
                            Free_MiB += int(match.group(1))
                            continue

            except IOError:
                # silently ignore IO errors (eg. file missing)
                pass

            Total_MiB /= 1024
            Free_MiB /= 1024
            self.total_memory_nodes_MiB.append(Total_MiB)
            attr = {
                    'numa_node': node,
                    'memtotal_mib': Total_MiB,
                    'memavail_mib': Free_MiB,
                    'hugepages_configured': 'False',
                   }

            imemory.append(attr)

        return imemory

    def inodes_get_imemory(self):
        '''Enumerate logical memory topology based on:
              if CONF.compute_hugepages:
                  self._inode_get_memory_hugepages()
              else:
                  self._inode_get_memory_nonhugepages()

        :param self
        :returns list of memory nodes and attributes
        '''
        imemory = []

        # if CONF.compute_hugepages:
        if os.path.isfile("/etc/nova/compute_reserved.conf"):
            imemory = self._inode_get_memory_hugepages()
        else:
            imemory = self._inode_get_memory_nonhugepages()

        LOG.debug("imemory= %s" % imemory)

        return imemory
