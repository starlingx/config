# Copyright (c) 2013-2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


import pecan

from sysinv.common import constants
from sysinv.openstack.common import log

LOG = log.getLogger(__name__)

CORE_FUNCTIONS = [
    constants.PLATFORM_FUNCTION,
    constants.VSWITCH_FUNCTION,
    constants.SHARED_FUNCTION,
    constants.VM_FUNCTION,
    constants.NO_FUNCTION
]

VSWITCH_MIN_CORES = 1
VSWITCH_MAX_CORES = 8


class CpuProfile(object):
    class CpuConfigure:
        def __init__(self):
            self.platform = 0
            self.vswitch = 0
            self.shared = 0
            self.vms = 0
            self.numa_node = 0

    # cpus is a list of icpu sorted by numa_node, core and thread
    # if not, provide a node list sorted by numa_node (id might not be reliable)
    def __init__(self, cpus, nodes=None):
        if nodes is not None:
            cpus = CpuProfile.sort_cpu_by_numa_node(cpus, nodes)
        cores = []

        self.number_of_cpu = 0
        self.cores_per_cpu = 0
        self.hyper_thread = False
        self.processors = []
        cur_processor = None

        for cpu in cpus:
            key = '{0}-{1}'.format(cpu.numa_node, cpu.core)
            if key not in cores:
                cores.append(key)
            else:
                self.hyper_thread = True
                continue

            if cur_processor is None or cur_processor.numa_node != cpu.numa_node:
                cur_processor = CpuProfile.CpuConfigure()
                cur_processor.numa_node = cpu.numa_node
                self.processors.append(cur_processor)

            if cpu.allocated_function == constants.PLATFORM_FUNCTION:
                cur_processor.platform += 1
            elif cpu.allocated_function == constants.VSWITCH_FUNCTION:
                cur_processor.vswitch += 1
            elif cpu.allocated_function == constants.SHARED_FUNCTION:
                cur_processor.shared += 1
            elif cpu.allocated_function == constants.VM_FUNCTION:
                cur_processor.vms += 1

        self.number_of_cpu = len(self.processors)
        self.cores_per_cpu = len(cores) / self.number_of_cpu

    @staticmethod
    def sort_cpu_by_numa_node(cpus, nodes):
        newlist = []
        for node in nodes:
            for cpu in cpus:
                if cpu.forinodeid == node.id:
                    cpu.numa_node = node.numa_node
                    newlist.append(cpu)
        return newlist


class HostCpuProfile(CpuProfile):
    def __init__(self, subfunctions, cpus, nodes=None):
        super(HostCpuProfile, self).__init__(cpus, nodes)
        self.subfunctions = subfunctions

    # see if a cpu profile is applicable to this host
    def profile_applicable(self, profile):
        if self.number_of_cpu == profile.number_of_cpu and \
                self.cores_per_cpu == profile.cores_per_cpu:
            return self.check_profile_core_functions(profile)
        else:
            errorstring = "Profile is not applicable to host"

        return False

    def check_profile_core_functions(self, profile):
        platform_cores = 0
        vswitch_cores = 0
        shared_cores = 0
        vm_cores = 0
        for cpu in profile.processors:
            platform_cores += cpu.platform
            vswitch_cores += cpu.vswitch
            shared_cores += cpu.shared
            vm_cores += cpu.vms

        error_string = ""
        if platform_cores == 0:
            error_string = "There must be at least one core for %s." % \
                           constants.PLATFORM_FUNCTION
        elif constants.COMPUTE in self.subfunctions and vswitch_cores == 0:
            error_string = "There must be at least one core for %s." % \
                           constants.VSWITCH_FUNCTION
        elif constants.COMPUTE in self.subfunctions and vm_cores == 0:
            error_string = "There must be at least one core for %s." % \
                           constants.VM_FUNCTION
        return error_string


def lookup_function(s):
    for f in CORE_FUNCTIONS:
        if s.lower() == f.lower():
            return f
    return s


def check_profile_core_functions(personality, profile):

    platform_cores = 0
    vswitch_cores = 0
    shared_cores = 0
    vm_cores = 0
    for cpu in profile.processors:
        platform_cores += cpu.platform
        vswitch_cores += cpu.vswitch
        shared_cores += cpu.shared
        vm_cores += cpu.vms

    error_string = ""
    if platform_cores == 0:
        error_string = "There must be at least one core for %s." % \
                       constants.PLATFORM_FUNCTION
    elif constants.COMPUTE in personality and vswitch_cores == 0:
        error_string = "There must be at least one core for %s." % \
                       constants.VSWITCH_FUNCTION
    elif constants.COMPUTE in personality and vm_cores == 0:
        error_string = "There must be at least one core for %s." % \
                       constants.VM_FUNCTION
    return error_string


def check_core_functions(personality, icpus):
    platform_cores = 0
    vswitch_cores = 0
    shared_cores = 0
    vm_cores = 0
    for cpu in icpus:
        allocated_function = cpu.allocated_function
        if allocated_function == constants.PLATFORM_FUNCTION:
            platform_cores += 1
        elif allocated_function == constants.VSWITCH_FUNCTION:
            vswitch_cores += 1
        elif allocated_function == constants.SHARED_FUNCTION:
            shared_cores += 1
        elif allocated_function == constants.VM_FUNCTION:
            vm_cores += 1

    error_string = ""
    if platform_cores == 0:
        error_string = "There must be at least one core for %s." % \
                       constants.PLATFORM_FUNCTION
    elif constants.COMPUTE in personality and vswitch_cores == 0:
        error_string = "There must be at least one core for %s." % \
                       constants.VSWITCH_FUNCTION
    elif constants.COMPUTE in personality and vm_cores == 0:
        error_string = "There must be at least one core for %s." % \
                       constants.VM_FUNCTION
    return error_string


def get_default_function(host):
    """Return the default function to be assigned to cpus on this host"""
    if constants.COMPUTE in host.subfunctions:
        return constants.VM_FUNCTION
    return constants.PLATFORM_FUNCTION


def get_cpu_function(host, cpu):
    """Return the function that is assigned to the specified cpu"""
    for s in range(0, len(host.nodes)):
        functions = host.cpu_functions[s]
        for f in CORE_FUNCTIONS:
            if cpu.cpu in functions[f]:
                return f
    return constants.NO_FUNCTION


def get_cpu_counts(host):
    """Return the CPU counts for this host by socket and function."""
    counts = {}
    for s in range(0, len(host.nodes)):
        counts[s] = {}
        for f in CORE_FUNCTIONS:
            counts[s][f] = len(host.cpu_functions[s][f])
    return counts


def init_cpu_counts(host):
    """Create empty data structures to track CPU assignments by socket and
    function."""
    host.cpu_functions = {}
    host.cpu_lists = {}
    for s in range(0, len(host.nodes)):
        host.cpu_functions[s] = {}
        for f in CORE_FUNCTIONS:
            host.cpu_functions[s][f] = []
        host.cpu_lists[s] = []


def _sort_by_coreid(cpu):
    """Sort a list of cpu database objects such that threads of the same core
    are adjacent in the list with the lowest thread number appearing first."""
    return (int(cpu.core), int(cpu.thread))


def restructure_host_cpu_data(host):
    """Reorganize the cpu list by socket and function so that it can more
    easily be consumed by other utilities."""
    init_cpu_counts(host)
    host.sockets = len(host.nodes or [])
    host.hyperthreading = False
    host.physical_cores = 0
    if not host.cpus:
        return
    host.cpu_model = host.cpus[0].cpu_model
    cpu_list = sorted(host.cpus, key=_sort_by_coreid)
    for cpu in cpu_list:
        inode = pecan.request.dbapi.inode_get(inode_id=cpu.forinodeid)
        cpu.numa_node = inode.numa_node
        if cpu.thread == 0:
            host.physical_cores += 1
        elif cpu.thread > 0:
            host.hyperthreading = True
        function = cpu.allocated_function or get_default_function(host)
        host.cpu_functions[cpu.numa_node][function].append(int(cpu.cpu))
        host.cpu_lists[cpu.numa_node].append(int(cpu.cpu))


def check_core_allocations(host, cpu_counts, func):
    """Check that minimum and maximum core values are respected."""
    total_platform_cores = 0
    total_vswitch_cores = 0
    total_shared_cores = 0
    for s in range(0, len(host.nodes)):
        available_cores = len(host.cpu_lists[s])
        platform_cores = cpu_counts[s][constants.PLATFORM_FUNCTION]
        vswitch_cores = cpu_counts[s][constants.VSWITCH_FUNCTION]
        shared_cores = cpu_counts[s][constants.SHARED_FUNCTION]
        requested_cores = platform_cores + vswitch_cores + shared_cores
        if requested_cores > available_cores:
            return ("More total logical cores requested than present on "
                    "'Processor %s' (%s cores)." % (s, available_cores))
        total_platform_cores += platform_cores
        total_vswitch_cores += vswitch_cores
        total_shared_cores += shared_cores
    if func.lower() == constants.PLATFORM_FUNCTION.lower():
        if ((constants.CONTROLLER in host.subfunctions) and
                (constants.COMPUTE in host.subfunctions)):
            if total_platform_cores < 2:
                return "%s must have at least two cores." % \
                       constants.PLATFORM_FUNCTION
        elif total_platform_cores == 0:
            return "%s must have at least one core." % \
                   constants.PLATFORM_FUNCTION
    if constants.COMPUTE in (host.subfunctions or host.personality):
        if func.lower() == constants.VSWITCH_FUNCTION.lower():
            if host.hyperthreading:
                total_physical_cores = total_vswitch_cores / 2
            else:
                total_physical_cores = total_vswitch_cores
            if total_physical_cores < VSWITCH_MIN_CORES:
                return ("The %s function must have at least %s core(s)." %
                        (constants.VSWITCH_FUNCTION.lower(), VSWITCH_MIN_CORES))
            elif total_physical_cores > VSWITCH_MAX_CORES:
                return ("The %s function can only be assigned up to %s cores." %
                        (constants.VSWITCH_FUNCTION.lower(), VSWITCH_MAX_CORES))
        reserved_for_vms = len(host.cpus) - total_platform_cores - total_vswitch_cores
        if reserved_for_vms <= 0:
            return "There must be at least one unused core for %s." % \
                   constants. VM_FUNCTION
    else:
        if total_platform_cores != len(host.cpus):
            return "All logical cores must be reserved for platform use"
    return ""


def update_core_allocations(host, cpu_counts):
    """Update the per socket/function cpu list based on the newly requested
    counts."""
    # Remove any previous assignments
    for s in range(0, len(host.nodes)):
        for f in CORE_FUNCTIONS:
            host.cpu_functions[s][f] = []
    # Set new assignments
    for s in range(0, len(host.nodes)):
        cpu_list = host.cpu_lists[s] if s in host.cpu_lists else []
        # Reserve for the platform first
        for i in range(0, cpu_counts[s][constants.PLATFORM_FUNCTION]):
            host.cpu_functions[s][constants.PLATFORM_FUNCTION].append(
                cpu_list.pop(0))
        # Reserve for the vswitch next
        for i in range(0, cpu_counts[s][constants.VSWITCH_FUNCTION]):
            host.cpu_functions[s][constants.VSWITCH_FUNCTION].append(
                cpu_list.pop(0))
        # Reserve for the shared next
        for i in range(0, cpu_counts[s][constants.SHARED_FUNCTION]):
            host.cpu_functions[s][constants.SHARED_FUNCTION].append(
                cpu_list.pop(0))
        # Assign the remaining cpus to the default function for this host
        host.cpu_functions[s][get_default_function(host)] += cpu_list
    return
