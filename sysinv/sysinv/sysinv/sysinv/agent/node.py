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
import shlex
import shutil
import signal
import six
import socket
import subprocess
import tempfile


from sysinv.common import exception
from sysinv.common import utils
from sysinv.openstack.common import log as logging

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

    def _set_default_avs_hugesize(self, attr):
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

        memtotal_mib = attr.get('memtotal_mib', 0)
        memavail_mib = attr.get('memavail_mib', 0)
        memtotal_mib = memtotal_mib - (hugepage_size * avs_hugepages_nr)
        memavail_mib = min(memtotal_mib, memavail_mib)

        ## Create a new set of dict attributes
        hp_attr = {'avs_hugepages_size_mib': hugepage_size,
                   'avs_hugepages_nr': avs_hugepages_nr,
                   'avs_hugepages_avail': 0,
                   'vm_hugepages_use_1G': 'False',
                   'memtotal_mib': memtotal_mib,
                   'memavail_mib': memavail_mib}
        return hp_attr

    def _inode_get_memory_hugepages(self):
        '''Collect hugepage info, including avs, and vm.
           Collect platform reserved if config.
        :param self
        :returns list of memory nodes and attributes
        '''

        imemory = []
        num_2M_for_1G = 512
        num_4K_for_2M = 512

        re_node_MemFreeInit = re.compile(r'^Node\s+\d+\s+\MemFreeInit:\s+(\d+)')

        for node in range(self.num_nodes):
            attr = {}
            Total_MiB = 0
            Free_MiB = 0

            # Check AVS and Libvirt memory
            hugepages = "/sys/devices/system/node/node%d/hugepages" % node

            try:
                subdirs = self._get_immediate_subdirs(hugepages)

                for subdir in subdirs:
                    hp_attr = {}
                    sizesplit = subdir.split('-')
                    # role via size; also from /etc/nova/compute_reserved.conf
                    if sizesplit[1].startswith("1048576kB"):
                        hugepages_role = "avs"
                        size = int(1048576 / 1024)
                    else:
                        hugepages_role = "vm"
                        size = int(2048 / 1024)

                    nr_hugepages = 0
                    free_hugepages = 0

                    # files = os.walk(subdir).next()[2]
                    mydir = hugepages + '/' + subdir
                    files = [f for f in listdir(mydir) if isfile(join(mydir, f))]

                    if files:
                        for file in files:
                            with open(mydir + '/' + file, 'r') as f:
                                if file.startswith("nr_hugepages"):
                                    nr_hugepages = int(f.readline())
                                if file.startswith("free_hugepages"):
                                    free_hugepages = int(f.readline())

                    # Libvirt hugepages can now be 1G and 2M, can't only look
                    # at 2M pages
                    Total_MiB = Total_MiB + int(nr_hugepages * size)
                    Free_MiB = Free_MiB + int(free_hugepages * size)

                    if hugepages_role == "avs":
                        avs_hugepages_nr = AVS_REAL_MEMORY_MB / size
                        hp_attr = {
                               'avs_hugepages_size_mib': size,
                               'avs_hugepages_nr': avs_hugepages_nr,
                               'avs_hugepages_avail': 0,
                               'vm_hugepages_nr_1G':
                               (nr_hugepages - avs_hugepages_nr),
                               'vm_hugepages_avail_1G': free_hugepages,
                                  }
                    else:
                        if len(subdirs) == 1:
                            hp_attr = {
                                   'vm_hugepages_nr_2M': (nr_hugepages - 256),
                                   'vm_hugepages_avail_2M': free_hugepages,
                                      }
                        else:
                            hp_attr = {
                                   'vm_hugepages_nr_2M': nr_hugepages,
                                   'vm_hugepages_avail_2M': free_hugepages,
                                      }

                    attr.update(hp_attr)

            except IOError:
                # silently ignore IO errors (eg. file missing)
                pass

            # Read the total possible number of libvirt (2M and 1G) hugepages,
            # and total available memory determined by compute-huge.
            hp_pages_2M = []
            hp_pages_1G = []
            tot_memory = []
            huge_total_attrs = {}
            hp_total_info = "/etc/nova/compute_hugepages_total.conf"
            try:
                with open(hp_total_info, 'r') as infile:
                    for line in infile:
                        possible_memorys = line.split("=")
                        if possible_memorys[0] == 'compute_hp_total_2M':
                            hp_pages_2M = map(int, possible_memorys[1].split(','))
                            continue

                        elif possible_memorys[0] == 'compute_hp_total_1G':
                            hp_pages_1G = map(int, possible_memorys[1].split(','))
                            continue

                        elif possible_memorys[0] == 'compute_total_MiB':
                            tot_memory = map(int, possible_memorys[1].split(','))
                            continue

            except IOError:
                # silently ignore IO errors (eg. file missing)
                pass

            huge_total_attrs = {
                    'vm_hugepages_possible_2M': hp_pages_2M[node],
                    'vm_hugepages_possible_1G': hp_pages_1G[node],
                   }

            # The remaining VM pages are allocated to 4K pages
            vm_hugepages_2M = attr.get('vm_hugepages_nr_2M')
            vm_hugepages_1G = attr.get('vm_hugepages_nr_1G')

            vm_hugepages_4K = (hp_pages_2M[node] - vm_hugepages_2M)
            if vm_hugepages_1G:
                vm_hugepages_4K -= (vm_hugepages_1G * num_2M_for_1G)

            vm_hugepages_4K = vm_hugepages_4K * num_4K_for_2M

            # Clip 4K pages, just like compute-huge.
            min_4K = 32 * 1024 / 4
            if vm_hugepages_4K < min_4K:
                vm_hugepages_4K = 0

            hp_attrs_4K = {
                    'vm_hugepages_nr_4K': vm_hugepages_4K,
                   }

            attr.update(huge_total_attrs)
            attr.update(hp_attrs_4K)

            # Include 4K pages in the displayed VM memtotal.
            # Since there is no way to track used VM 4K pages, we treat them
            # as available, but that is bogus.
            vm_4K_MiB = vm_hugepages_4K * 4 / 1024
            Total_MiB += vm_4K_MiB
            Free_MiB += vm_4K_MiB
            self.total_memory_nodes_MiB.append(Total_MiB)
            attroverview = {
                    'numa_node': node,
                    'memtotal_mib': Total_MiB,
                    'memavail_mib': Free_MiB,
                    'hugepages_configured': 'True',
                   }

            attr.update(attroverview)

            new_attrs = {}
            if 'avs_hugepages_size_mib' not in attr:
                ## No 1GB pages were found so borrow from the VM 2MB pool
                ##
                ## FIXME:
                ## It is unfortunate that memory is categorized as VM or
                ## AVS here on the compute node.  It would have been more
                ## flexible if memory parameters were collected and sent
                ## up to the controller without making any decisions about
                ## what the memory was going to be used for.  That type of
                ## decision is better left to the controller (or better
                ## yet, to the user)
                new_attrs = self._set_default_avs_hugesize(attr)
            else:
                new_attrs = {'vm_hugepages_use_1G': 'True'}

            attr.update(new_attrs)

            # Get the total memory of the numa node
            memTotal_mib = 0
            meminfo = "/sys/devices/system/node/node%d/meminfo_extra" % node
            try:
                with open(meminfo, 'r') as infile:
                    for line in infile:
                        match = re_node_MemFreeInit.search(line)
                        if match:
                            memTotal_mib = int(match.group(1))
                            continue
            except IOError:
                # silently ignore IO errors (eg. file missing)
                pass

            memTotal_mib /= 1024
            if tot_memory[node]:
                memTotal_mib = tot_memory[node]
            node_attr = {
                'node_memtotal_mib': memTotal_mib,
                 }
            attr.update(node_attr)

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
        re_node_MemFreeInit = re.compile(r'^Node\s+\d+\s+\MemFreeInit:\s+(\d+)')
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

            # WRS kernel customization to exclude kernel overheads
            meminfo = "/sys/devices/system/node/node%d/meminfo_extra" % node
            try:
                with open(meminfo, 'r') as infile:
                    for line in infile:
                        match = re_node_MemFreeInit.search(line)
                        if match:
                            Total_MiB = int(match.group(1))
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
