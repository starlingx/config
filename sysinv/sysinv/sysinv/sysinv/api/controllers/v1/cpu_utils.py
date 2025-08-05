# Copyright (c) 2013-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


import pecan
import wsme

from oslo_log import log
from sysinv.common import constants
from sysinv.common import utils as cutils

LOG = log.getLogger(__name__)

CORE_FUNCTIONS = [
    constants.PLATFORM_FUNCTION,
    constants.VSWITCH_FUNCTION,
    constants.SHARED_FUNCTION,
    constants.APPLICATION_FUNCTION,
    constants.ISOLATED_FUNCTION,
    constants.NO_FUNCTION
]

VSWITCH_MIN_CORES = 0
VSWITCH_MAX_CORES = 8
DRBD_CPU_MASK_LIMIT = 112


def lookup_function(s):
    for f in CORE_FUNCTIONS:
        if s.lower() == f.lower():
            return f
    return s


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
        elif allocated_function == constants.APPLICATION_FUNCTION:
            vm_cores += 1

    error_string = ""
    if platform_cores == 0:
        error_string = "There must be at least one core for %s." % \
                       constants.PLATFORM_FUNCTION
    elif constants.WORKER in personality and vswitch_cores == 0:
        error_string = "There must be at least one core for %s." % \
                       constants.VSWITCH_FUNCTION
    elif constants.WORKER in personality and vm_cores == 0:
        error_string = "There must be at least one core for %s." % \
                       constants.APPLICATION_FUNCTION
    return error_string


def get_default_function(host):
    """Return the default function to be assigned to cpus on this host"""
    if constants.WORKER in host.subfunctions:
        return constants.APPLICATION_FUNCTION
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


def append_ht_sibling(host, cpu_list):
    """Append to cpu_list the hyperthread siblings for the cpus in the list"""
    # TODO: Add UTs for this.

    # There's probably a more efficient way to do this.
    cpus_to_add = []
    for cpu_num in cpu_list:
        # Get node/core for specified cpu number
        for cpu in host.cpus:
            if cpu.cpu == cpu_num:
                # We've found the cpu of interest, now check for siblings
                for cpu2 in host.cpus:
                    if cpu2.numa_node == cpu.numa_node and \
                       cpu2.core == cpu.core and \
                       cpu2.thread != cpu.thread:
                        cpus_to_add.append(cpu2.cpu)
                        break
                break
    # Add in the HT siblings, then remove any duplicates.
    cpus_to_add.extend(cpu_list)
    return list(set(cpus_to_add))


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


def check_power_manager(host):
    """Check if power manager is present. If so, CPU MHZ
    cannot be configured."""

    labels = pecan.request.dbapi.label_get_by_host(host)

    if cutils.has_power_management_enabled(labels):
        raise wsme.exc.ClientSideError(
            "Host CPU MHz cannot be configured "
            "if Power Manager is enabled.")


def check_core_allocations(host, cpu_counts, cpu_lists=None):
    """Check that minimum and maximum core values are respected."""

    if cpu_lists:
        # Verify no overlaps in cpulists for different functions. Not all
        # functions are guaranteed to be present as keys in cpu_lists.
        cpulist = []
        for function in CORE_FUNCTIONS:
            functionlist = cpu_lists.get(function, [])
            if set(cpulist).intersection(functionlist):
                raise wsme.exc.ClientSideError(
                    "Some CPUs are specified for more than one function.")
            cpulist.extend(functionlist)

    # NOTE: contrary to the variable names, these are actually logical CPUs
    # rather than cores, so if hyperthreading is enabled they're SMT siblings.
    total_platform_cores = 0
    total_vswitch_cores = 0
    total_shared_cores = 0
    total_isolated_cores = 0
    for s in range(0, len(host.nodes)):
        available_cores = len(host.cpu_lists[s])
        platform_cores = cpu_counts[s][constants.PLATFORM_FUNCTION]
        vswitch_cores = cpu_counts[s][constants.VSWITCH_FUNCTION]
        shared_cores = cpu_counts[s][constants.SHARED_FUNCTION]
        isolated_cores = cpu_counts[s][constants.ISOLATED_FUNCTION]
        requested_cores = \
            platform_cores + vswitch_cores + shared_cores + isolated_cores
        if requested_cores > available_cores:
            raise wsme.exc.ClientSideError(
                "More total logical cores requested than present on Processor "
                "%s (%s cores)." % (s, available_cores))
        total_platform_cores += platform_cores
        total_vswitch_cores += vswitch_cores
        total_shared_cores += shared_cores
        total_isolated_cores += isolated_cores

    # Add any cpus specified via ranges to the totals.
    # Note: Can't specify by both count and range for the same function.
    if cpu_lists:
        total_platform_cores += len(cpu_lists.get(constants.PLATFORM_FUNCTION, []))
        total_vswitch_cores += len(cpu_lists.get(constants.VSWITCH_FUNCTION, []))
        total_shared_cores += len(cpu_lists.get(constants.SHARED_FUNCTION, []))
        total_isolated_cores += len(cpu_lists.get(constants.ISOLATED_FUNCTION, []))

    # Validate Platform cores (actually logical CPUs)
    if ((constants.CONTROLLER in host.subfunctions) and
            (constants.WORKER in host.subfunctions)):
        if total_platform_cores < 2:
            raise wsme.exc.ClientSideError("%s must have at least two cores." %
                                           constants.PLATFORM_FUNCTION)
    elif total_platform_cores == 0:
        raise wsme.exc.ClientSideError("%s must have at least one core." %
                                       constants.PLATFORM_FUNCTION)

    # Validate shared cores (actually logical CPUs)
    for s in range(0, len(host.nodes)):
        shared_cores = cpu_counts[s][constants.SHARED_FUNCTION]
        if host.hyperthreading:
            shared_cores /= 2
        if shared_cores > 1:
            raise wsme.exc.ClientSideError(
                '%s cores are limited to 1 per processor.'
                % constants.SHARED_FUNCTION)

    # Validate vswitch cores (actually logical CPUs)
    if total_vswitch_cores != 0:
        vswitch_type = cutils.get_vswitch_type(pecan.request.dbapi)
        if constants.VSWITCH_TYPE_NONE == vswitch_type:
            raise wsme.exc.ClientSideError(
                ('vSwitch cpus can only be used with a vswitch_type '
                 'specified.'))

    vswitch_physical_cores = total_vswitch_cores
    if host.hyperthreading:
        vswitch_physical_cores /= 2
    if vswitch_physical_cores > VSWITCH_MAX_CORES:
        raise wsme.exc.ClientSideError(
            "The %s function can only be assigned up to %s cores." %
            (constants.VSWITCH_FUNCTION.lower(), VSWITCH_MAX_CORES))

    reserved_for_applications = len(host.cpus) - total_platform_cores - \
                       total_vswitch_cores - total_isolated_cores
    if reserved_for_applications <= 0:
        raise wsme.exc.ClientSideError(
            "There must be at least one unused core for %s." %
            constants.APPLICATION_FUNCTION)


def check_drbd_platform_limitation(ihost):
    # No limit if all cpu are for platform function (e.g. DC central controller)
    is_all_platform = True
    for cpu in ihost.cpus:
        function = get_cpu_function(ihost, cpu)
        if function != constants.PLATFORM_FUNCTION:
            is_all_platform = False
            break
    if not is_all_platform:
        for cpu in ihost.cpus:
            function = get_cpu_function(ihost, cpu)
            if function == constants.PLATFORM_FUNCTION and cpu.cpu >= DRBD_CPU_MASK_LIMIT:
                raise wsme.exc.ClientSideError(
                    "platform function need to be assign to cpu log_core id lower than %d." % DRBD_CPU_MASK_LIMIT)


def node_from_cpu(host, cpu_num):
    for cpu in host.cpus:
        if cpu.cpu == cpu_num:
            return cpu.numa_node
    raise wsme.exc.ClientSideError("Specified CPU %s is invalid." % cpu_num)


def update_core_allocations(host, cpu_counts, cpulists=None):
    """Update the per socket/function cpu list based on the newly requested
    counts."""
    # Remove any previous assignments
    for s in range(0, len(host.nodes)):
        for f in CORE_FUNCTIONS:
            host.cpu_functions[s][f] = []

    # Make per-numa-node lists of available CPUs
    cpu_lists = {}
    for s in range(0, len(host.nodes)):
        cpu_lists[s] = list(host.cpu_lists[s]) if s in host.cpu_lists else []

    # We need to reserve all of the cpulist-specified CPUs first, then
    # reserve by counts.
    for function in CORE_FUNCTIONS:
        if cpulists and function in cpulists:
            for cpu in cpulists[function]:
                node = node_from_cpu(host, cpu)
                host.cpu_functions[node][function].append(cpu)
                cpu_lists[node].remove(cpu)

    for s in range(0, len(host.nodes)):
        # Create cpu list for drbd cpu mask limitation
        # Platform function will be assigned cpu in this list first.
        list_drbd_limit = [
            c for c in cpu_lists[s] if c < DRBD_CPU_MASK_LIMIT
        ]

        # Reserve for the platform first
        for i in range(0, cpu_counts[s][constants.PLATFORM_FUNCTION]):
            if len(list_drbd_limit) > 0:
                p_cpu = list_drbd_limit.pop(0)
                host.cpu_functions[s][constants.PLATFORM_FUNCTION].append(
                    p_cpu)
                cpu_lists[s].remove(p_cpu)
            else:
                host.cpu_functions[s][constants.PLATFORM_FUNCTION].append(
                    cpu_lists[s].pop(0))

        # Reserve for the vswitch next
        for i in range(0, cpu_counts[s][constants.VSWITCH_FUNCTION]):
            host.cpu_functions[s][constants.VSWITCH_FUNCTION].append(
                cpu_lists[s].pop(0))

        # Reserve for the shared next
        for i in range(0, cpu_counts[s][constants.SHARED_FUNCTION]):
            host.cpu_functions[s][constants.SHARED_FUNCTION].append(
                cpu_lists[s].pop(0))

        # Reserve for the isolated next
        for i in range(0, cpu_counts[s][constants.ISOLATED_FUNCTION]):
            host.cpu_functions[s][constants.ISOLATED_FUNCTION].append(
                cpu_lists[s].pop(0))

        # Assign the remaining cpus to the default function for this host
        host.cpu_functions[s][get_default_function(host)] += cpu_lists[s]

    return
