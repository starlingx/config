#
# Copyright (c) 2013-2016,2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

""" inventory numa node Utilities and helper functions."""

from functools import lru_cache
import os
from os import listdir
from os.path import isfile
from os.path import join
import re
from typing import Dict
from typing import List
from typing import Optional
from typing import TypedDict

from oslo_log import log as logging
import tsconfig.tsconfig as tsc
from sysinv.common import utils as cutils

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

SYSFS_NODE_PATH = '/sys/devices/system/node'
SYSFS_CPU_PATH = '/sys/devices/system/cpu'


@lru_cache(maxsize=None)
def _read_numa_nodes() -> List[int]:
    """Discover all NUMA nodes from sysfs.

    Result is cached at module level so it persists across NodeOperator
    instances. Call _read_numa_nodes.cache_clear() to force a re-read.
    Raises OSError/ValueError on failure so the caller can clear the cache
    and return a fallback without caching the error state.
    """
    node_list: List[int] = []
    try:
        for entry in listdir(SYSFS_NODE_PATH):
            match = re.match(r'^node(\d+)$', entry)
            if match and os.path.isdir(join(SYSFS_NODE_PATH, entry)):
                node_list.append(int(match.group(1)))
        node_list.sort()
    except (IOError, OSError) as err:
        LOG.warning("Unable to read NUMA node info from sysfs: %s" % err)
        raise

    if not node_list:
        LOG.warning("No NUMA nodes found in %s, falling back to node 0"
                    % SYSFS_NODE_PATH)
        raise ValueError("no NUMA node dirs found")
    return node_list


@lru_cache(maxsize=None)
def _read_cpu_model_attrs() -> Dict[str, str]:
    """Read cpu_family and cpu_model from /proc/cpuinfo.

    Result is cached at module level so it persists across NodeOperator
    instances. Call _read_cpu_model_attrs.cache_clear() to force a re-read.
    Raises on failure so the caller can clear the cache and return {}.
    """
    attrs: Dict[str, str] = {}
    cpu_family, cpu_model = None, None
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('cpu family'):
                    cpu_family = line.split(':', 1)[1].strip()
                elif line.startswith('model name'):
                    cpu_model = line.split(':', 1)[1].strip()
                if cpu_family and cpu_model:
                    break
    except Exception as err:
        LOG.warning("Unable to get CPU model info via /proc/cpuinfo: %s" % err)
        raise

    if cpu_family:
        attrs['cpu_family'] = cpu_family
    if cpu_model:
        attrs['cpu_model'] = cpu_model
    return attrs


class CpuTopology(TypedDict):
    core_id: int
    thread_siblings: List[int]


class NodeOperator(object):
    '''Class to encapsulate CPU operations for System Inventory'''

    def __init__(self):
        pass

    @property
    def _numa_nodes(self) -> List[int]:
        """Return NUMA nodes, falling back to [0] and clearing cache on error."""
        list_of_numa_nodes = [0]
        try:
            list_of_numa_nodes = _read_numa_nodes()
        except Exception:
            _read_numa_nodes.cache_clear()
        return list_of_numa_nodes

    @property
    def _cpu_model_attrs(self) -> Dict[str, str]:
        """Return CPU model attrs, falling back to {} and clearing cache on error."""
        attrs = {}
        try:
            attrs = _read_cpu_model_attrs()
        except Exception:
            _read_cpu_model_attrs.cache_clear()
        return attrs

    def _get_cpu_topology(self, cpu_id: int) -> Optional[CpuTopology]:
        """Read topology attributes for a logical CPU from sysfs."""
        cpu_dir = join(SYSFS_CPU_PATH, f"cpu{cpu_id}", "topology")
        if not os.path.isdir(cpu_dir):
            return None
        core_id = cutils.read_first_line_from_file(join(cpu_dir, 'core_id'))
        thread_siblings = cutils.read_first_line_from_file(join(cpu_dir, 'thread_siblings_list'))
        if core_id:
            return {
                'core_id': int(core_id),
                'thread_siblings': sorted(cutils.parse_range_set(thread_siblings or '')),
            }
        return None

    def _get_list_of_cpu_ids(self, node_id: int) -> List[int]:
        """Get the list of logical CPU IDs belonging to a NUMA node."""
        cpulist_path = join(SYSFS_NODE_PATH, 'node%d' % node_id, 'cpulist')
        range_string = cutils.read_first_line_from_file(cpulist_path)
        if range_string:
            return sorted(cutils.parse_range_set(range_string))
        LOG.warning(f"No cpus found for numa node {node_id}")
        return []

    def _compute_thread_id(self, cpu_id: int, thread_siblings: List[int]) -> int:
        """Determine the thread index for a CPU within its core."""
        if not thread_siblings:
            return 0
        try:
            thread_id = thread_siblings.index(cpu_id)
        except ValueError:
            LOG.warning(f"cpu{cpu_id} not in thread_siblings {thread_siblings}")
            return 0
        if thread_id > 1:
            LOG.warning(f"cpu{cpu_id} thread_id={thread_id}, siblings={thread_siblings}; expected 0 or 1")
        return thread_id

    def inodes_get_inumas_icpus(self):
        '''Enumerate logical cpu topology based on parsing sysfs.
           as function of numa_node_id, core_id, and thread_id. This updates
           topology.

        :param self
        :returns (inumas, icpus)
        '''
        inumas = []
        icpus = []

        cpu_model_attrs = self._cpu_model_attrs
        for node_id in self._numa_nodes:
            inumas.append({'numa_node': node_id, 'capabilities': {}})
            for cpu_id in self._get_list_of_cpu_ids(node_id):
                cpu_topology = self._get_cpu_topology(cpu_id)
                if cpu_topology is None:
                    continue

                thread_id = self._compute_thread_id(cpu_id, cpu_topology['thread_siblings'])
                core_id = cpu_topology['core_id']
                icpu_attrs = cpu_model_attrs | {
                    'cpu': cpu_id,
                    'numa_node': node_id,
                    'core': core_id,
                    'thread': thread_id,
                    'capabilities': {},
                }
                icpus.append(icpu_attrs)

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

        for node in self._numa_nodes:
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
                            if file.startswith("nr_hugepages"):
                                with open(mydir + '/' + file, 'r') as f:
                                    nr_hugepages = int(f.readline())
                            if file.startswith("free_hugepages"):
                                with open(mydir + '/' + file, 'r') as f:
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
                            'vm_hugepages_use_1G': True
                        })
                    else:
                        if len(subdirs) == 1:
                            # No 1G hugepage support.
                            hp_attr = {
                                'vm_hugepages_use_1G': False,
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
                'hugepages_configured': True,
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

        re_node_memtotal = re.compile(r'^Node\s+\d+\s+MemTotal:\s+(\d+)')
        re_node_memfree = re.compile(r'^Node\s+\d+\s+MemFree:\s+(\d+)')
        re_node_filepages = re.compile(r'^Node\s+\d+\s+FilePages:\s+(\d+)')
        re_node_sreclaim = re.compile(r'^Node\s+\d+\s+SReclaimable:\s+(\d+)')

        for node in self._numa_nodes:
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
            attr = {
                'numa_node': node,
                'memtotal_mib': total_mb,
                'memavail_mib': free_mb,
                'hugepages_configured': False,
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
