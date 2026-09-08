# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Tests for hyperthread sibling CPU function assignment in cpu_utils.

For any host with hyperthreading enabled and any allocation of CPUs to
functions (by count or cpulist), update_core_allocations() must assign both
sibling threads of every physical core to the same function.

These are deterministic, parameterized tests (sweeping small combinations
via itertools.product with subTest) so no external test-only dependency is
required and no global module state is mutated.
"""

import itertools
import unittest

import wsme

from sysinv.api.controllers.v1 import cpu_utils
from sysinv.common import constants


# ---------------------------------------------------------------------------
# Mock Host Infrastructure
# ---------------------------------------------------------------------------

class MockCpu(object):
    """Minimal mock of a CPU database object."""

    def __init__(self, cpu_id, numa_node, core, thread):
        self.cpu = cpu_id
        self.numa_node = numa_node
        self.core = core
        self.thread = thread
        self.allocated_function = None
        self.cpu_model = "Intel(R) Xeon(R)"


class MockHost(object):
    """Minimal mock of a host object used by cpu_utils functions."""

    def __init__(self, cpus, nodes, subfunctions=None):
        self.cpus = cpus
        self.nodes = nodes
        self.subfunctions = subfunctions or [constants.WORKER,
                                             constants.CONTROLLER]
        self.hyperthreading = True
        self.physical_cores = 0
        self.cpu_model = "Intel(R) Xeon(R)"
        # Initialize cpu_functions and cpu_lists
        self.cpu_functions = {}
        self.cpu_lists = {}
        for s in range(len(self.nodes)):
            self.cpu_functions[s] = {}
            for f in cpu_utils.CORE_FUNCTIONS:
                self.cpu_functions[s][f] = []
            self.cpu_lists[s] = []

        # Build cpu_lists per NUMA node sorted by (core, thread) -
        # mimicking restructure_host_cpu_data behavior
        sorted_cpus = sorted(self.cpus, key=lambda c: (c.core, c.thread))
        for cpu in sorted_cpus:
            if cpu.thread == 0:
                self.physical_cores += 1
            self.cpu_lists[cpu.numa_node].append(cpu.cpu)


def build_round_robin_host(num_nodes, physical_cores_per_node):
    """
    Build a mock host with Round Robin MADT-style non-contiguous CPU
    numbering.

    In Round Robin MADT enumeration, logical CPU IDs are assigned by
    cycling through cores across NUMA nodes. This creates large gaps
    between sibling thread IDs.

    Thread 0 IDs are assigned first (sequentially cycling nodes),
    then Thread 1 IDs continue from where Thread 0 left off.

    So for 2 nodes with 16 cores each (32 physical cores total):
      Node 0, Core 0, Thread 0 = CPU 0
      Node 1, Core 0, Thread 0 = CPU 1
      Node 0, Core 1, Thread 0 = CPU 2
      Node 1, Core 1, Thread 0 = CPU 3
      ...
      Node 0, Core 15, Thread 0 = CPU 30
      Node 1, Core 15, Thread 0 = CPU 31
      Node 0, Core 0, Thread 1 = CPU 32
      Node 1, Core 0, Thread 1 = CPU 33
      ...

    Siblings are separated by total_physical_cores IDs (e.g., 32).
    """
    cpus = []

    # Thread 0 IDs: 0 to total_physical_cores - 1
    cpu_id = 0
    for core_idx in range(physical_cores_per_node):
        for node_idx in range(num_nodes):
            cpus.append(MockCpu(
                cpu_id=cpu_id,
                numa_node=node_idx,
                core=core_idx,
                thread=0
            ))
            cpu_id += 1

    # Thread 1 IDs: total_physical_cores to 2*total_physical_cores - 1
    for core_idx in range(physical_cores_per_node):
        for node_idx in range(num_nodes):
            cpus.append(MockCpu(
                cpu_id=cpu_id,
                numa_node=node_idx,
                core=core_idx,
                thread=1
            ))
            cpu_id += 1

    nodes = list(range(num_nodes))
    return MockHost(cpus, nodes)


def build_drbd_straddle_host(num_cores):
    """
    Build an HT host on a single node where thread-0 CPUs are below the
    DRBD_CPU_MASK_LIMIT (908) and their thread-1 siblings are above it.

    Thread 0: CPU IDs 900..900+num_cores-1 (below limit)
    Thread 1: CPU IDs 910..910+num_cores-1 (above limit)
    """
    cpus = []
    for core in range(num_cores):
        cpus.append(MockCpu(
            cpu_id=900 + core, numa_node=0, core=core, thread=0))
        cpus.append(MockCpu(
            cpu_id=910 + core, numa_node=0, core=core, thread=1))
    return MockHost(cpus, [0])


def check_sibling_property(host):
    """
    Check that all sibling threads of a physical core are assigned to the
    same function.

    Returns a list of violations: tuples of
    (numa_node, core, cpu_a, func_a, cpu_b, func_b)
    """
    violations = []

    # Build mapping: cpu_id -> function
    cpu_to_function = {}
    for s in range(len(host.nodes)):
        for f in cpu_utils.CORE_FUNCTIONS:
            for cpu_id in host.cpu_functions[s][f]:
                cpu_to_function[cpu_id] = f

    # Find all sibling pairs and check they're in the same function
    checked_cores = set()
    for cpu in host.cpus:
        core_key = (cpu.numa_node, cpu.core)
        if core_key in checked_cores:
            continue
        checked_cores.add(core_key)

        # Find all threads for this core
        siblings = [c for c in host.cpus
                    if c.numa_node == cpu.numa_node and c.core == cpu.core]

        if len(siblings) < 2:
            continue  # No sibling pair (non-HT)

        # Check all siblings have the same function
        funcs_for_core = []
        for sib in siblings:
            func = cpu_to_function.get(sib.cpu)
            if func is not None:
                funcs_for_core.append((sib.cpu, func))

        if len(funcs_for_core) >= 2:
            unique_funcs = set(f for _, f in funcs_for_core)
            if len(unique_funcs) > 1:
                violations.append((
                    cpu.numa_node, cpu.core,
                    funcs_for_core[0][0], funcs_for_core[0][1],
                    funcs_for_core[1][0], funcs_for_core[1][1]
                ))

    return violations


def _format_violations(violations):
    return "; ".join(
        "Node %d Core %d: CPU %d -> %s, CPU %d -> %s" %
        (node, core, cpu_a, func_a, cpu_b, func_b)
        for node, core, cpu_a, func_a, cpu_b, func_b in violations
    )


def _make_empty_cpu_counts(num_nodes):
    """Create an empty cpu_counts dict for all nodes."""
    cpu_counts = {}
    for s in range(num_nodes):
        cpu_counts[s] = {
            constants.PLATFORM_FUNCTION: 0,
            constants.VSWITCH_FUNCTION: 0,
            constants.SHARED_FUNCTION: 0,
            constants.ISOLATED_FUNCTION: 0,
            constants.APPLICATION_FUNCTION: 0,
            constants.NO_FUNCTION: 0,
        }
    return cpu_counts


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCpuSiblingThreadSplitBugCondition(unittest.TestCase):
    """
    Deterministic (parameterized) tests to surface the bug condition where
    sibling threads are split across functions in update_core_allocations().
    """

    def test_ht_siblings_same_function_drbd_split(self):
        """
        Property: For ALL physical cores on an HT-enabled host where
        thread-0 CPUs are below DRBD_CPU_MASK_LIMIT and thread-1 CPUs
        are above it, both sibling threads SHALL be assigned to the same
        function after update_core_allocations().

        This specifically targets the DRBD limit filtering bug: platform
        CPUs are picked from list_drbd_limit (thread-0 only) while their
        siblings (thread-1, above limit) remain in the general pool and
        get assigned to a different function.

        The hypothesis strategy that generated even counts over small ranges
        is emulated here with an explicit itertools.product sweep.
        """
        num_cores = 8  # 8 physical cores -> 16 logical CPUs
        total_logical = num_cores * 2  # 16

        # Sweep even counts, mirroring the ranges the property test explored:
        #   platform in {2, 4, 6, 8, 10, 12}
        #   vswitch  in {0, 2, 4, 6}
        #   shared   in {0, 2}
        #   isolated in {0, 2, 4}
        for platform_count, vswitch_count, shared_count, isolated_count in \
                itertools.product(
                    range(2, 13, 2), range(0, 7, 2),
                    range(0, 3, 2), range(0, 5, 2)):

            total_requested = (platform_count + vswitch_count +
                               shared_count + isolated_count)

            # Skip if total exceeds available (leave at least 2 for app)
            if total_requested >= total_logical - 2:
                continue

            with self.subTest(platform=platform_count, vswitch=vswitch_count,
                              shared=shared_count, isolated=isolated_count):
                host = build_drbd_straddle_host(num_cores)

                cpu_counts = _make_empty_cpu_counts(1)
                cpu_counts[0][constants.PLATFORM_FUNCTION] = platform_count
                cpu_counts[0][constants.VSWITCH_FUNCTION] = vswitch_count
                cpu_counts[0][constants.SHARED_FUNCTION] = shared_count
                cpu_counts[0][constants.ISOLATED_FUNCTION] = isolated_count

                cpu_utils.update_core_allocations(host, cpu_counts)

                violations = check_sibling_property(host)
                self.assertEqual(
                    violations, [],
                    "Sibling threads split across functions! Violations: %s"
                    % _format_violations(violations))

    def test_round_robin_platform_allocation_sweep(self):
        """
        Round Robin MADT-style non-contiguous host. Siblings must share a
        function across a range of platform/vswitch/shared/isolated
        allocations.

        2 NUMA nodes, 16 physical cores per node (64 logical CPUs).
        Round Robin numbering: Thread 0 IDs [0..31], Thread 1 IDs [32..63].

        This sweeps small even combinations (the space the hypothesis
        strategy previously explored) deterministically via itertools.product.
        """
        num_nodes = 2
        cores_per_node = 16
        total_logical_per_node = cores_per_node * 2  # 32

        for platform_count, vswitch_count, shared_count, isolated_count in \
                itertools.product(
                    range(2, 11, 2), range(0, 7, 2),
                    range(0, 3, 2), range(0, 5, 2)):

            total_requested = (platform_count + vswitch_count +
                               shared_count + isolated_count)
            # Leave at least one core (2 logical) for the default function.
            if total_requested >= total_logical_per_node - 2:
                continue

            with self.subTest(platform=platform_count, vswitch=vswitch_count,
                              shared=shared_count, isolated=isolated_count):
                host = build_round_robin_host(
                    num_nodes=num_nodes,
                    physical_cores_per_node=cores_per_node)

                cpu_counts = _make_empty_cpu_counts(num_nodes)
                for s in range(num_nodes):
                    cpu_counts[s][constants.PLATFORM_FUNCTION] = platform_count
                    cpu_counts[s][constants.VSWITCH_FUNCTION] = vswitch_count
                    cpu_counts[s][constants.SHARED_FUNCTION] = shared_count
                    cpu_counts[s][constants.ISOLATED_FUNCTION] = isolated_count

                cpu_utils.update_core_allocations(host, cpu_counts)

                violations = check_sibling_property(host)
                self.assertEqual(
                    violations, [],
                    "Sibling threads split across functions! Violations: %s"
                    % _format_violations(violations))

    def test_specific_round_robin_platform_allocation(self):
        """
        Specific deterministic anchor mimicking the reported bug scenario.

        2 NUMA nodes, 16 physical cores per node (64 logical CPUs).
        Allocate 8 platform + 4 vswitch CPUs on node 0; siblings must not
        split.
        """
        host = build_round_robin_host(num_nodes=2,
                                      physical_cores_per_node=16)

        cpu_counts = _make_empty_cpu_counts(2)
        # Request 8 platform + 4 vswitch CPUs on node 0
        cpu_counts[0][constants.PLATFORM_FUNCTION] = 8
        cpu_counts[0][constants.VSWITCH_FUNCTION] = 4

        cpu_utils.update_core_allocations(host, cpu_counts)

        violations = check_sibling_property(host)
        self.assertEqual(
            violations, [],
            "Sibling threads split across functions! Violations: %s"
            % _format_violations(violations))

    def test_cpulist_splitting_siblings_is_rejected(self):
        """
        Option A semantics: specifying only one thread of an SMT sibling pair
        via cpulist must be REJECTED by check_core_allocations() rather than
        silently pulling the sibling into the same function.

        Node 0 thread-0 CPUs for cores 0,1,2,3: [0, 2, 4, 6]
        Their siblings (thread 1): [32, 34, 36, 38] are NOT specified, so the
        cpulist would split SMT siblings across functions -> reject.

        vswitch count is kept at 0 so the rejection (which runs before the
        vswitch_type lookup) does not require a live pecan request.
        """
        host = build_round_robin_host(num_nodes=2,
                                      physical_cores_per_node=16)

        cpu_counts = _make_empty_cpu_counts(2)

        # Specify platform CPUs via cpulist - only thread 0 CPUs from node 0.
        cpulists = {
            constants.PLATFORM_FUNCTION: [0, 2, 4, 6],
        }

        self.assertRaises(
            wsme.exc.ClientSideError,
            cpu_utils.check_core_allocations,
            host, cpu_counts, cpulists)

    def test_cpulist_siblings_different_functions_is_rejected(self):
        """
        Option A semantics: if both threads of an SMT sibling pair are
        explicitly specified but assigned to DIFFERENT functions, reject.

        CPU 0 (core 0, thread 0) and CPU 32 (core 0, thread 1) are siblings.
        Assigning CPU 0 to platform and CPU 32 to vswitch must be rejected.

        The sibling-mismatch check runs before the vswitch_type lookup, so
        no live pecan request is needed even though vswitch CPUs appear in
        the cpulist.
        """
        host = build_round_robin_host(num_nodes=2,
                                      physical_cores_per_node=16)

        cpu_counts = _make_empty_cpu_counts(2)

        cpulists = {
            constants.PLATFORM_FUNCTION: [0],
            constants.VSWITCH_FUNCTION: [32],
        }

        self.assertRaises(
            wsme.exc.ClientSideError,
            cpu_utils.check_core_allocations,
            host, cpu_counts, cpulists)

    def test_odd_count_on_ht_host_is_rejected(self):
        """
        On a hyperthreaded host, CPUs are assigned a full physical core
        (both SMT siblings) at a time, so each per-function count must be
        even. check_core_allocations() must reject an odd count rather
        than allow update_core_allocations() to overshoot and split a
        core.

        1 node, 4 physical cores (8 logical CPUs), HT enabled.
        Request 1 platform logical CPU (odd) -> reject.
        """
        cpus = []
        for core in range(4):
            cpus.append(MockCpu(cpu_id=core, numa_node=0,
                                core=core, thread=0))
        for core in range(4):
            cpus.append(MockCpu(cpu_id=4 + core, numa_node=0,
                                core=core, thread=1))

        host = MockHost(cpus, [0])

        cpu_counts = _make_empty_cpu_counts(1)
        cpu_counts[0][constants.PLATFORM_FUNCTION] = 1

        self.assertRaises(
            wsme.exc.ClientSideError,
            cpu_utils.check_core_allocations,
            host, cpu_counts)

    def test_even_count_on_ht_host_is_accepted(self):
        """
        The complement of the odd-count check: an even per-function count
        on a hyperthreaded host passes check_core_allocations().

        1 node, 4 physical cores (8 logical CPUs), HT enabled.
        Request 2 platform logical CPUs (even) -> accepted.
        """
        cpus = []
        for core in range(4):
            cpus.append(MockCpu(cpu_id=core, numa_node=0,
                                core=core, thread=0))
        for core in range(4):
            cpus.append(MockCpu(cpu_id=4 + core, numa_node=0,
                                core=core, thread=1))

        host = MockHost(cpus, [0])

        cpu_counts = _make_empty_cpu_counts(1)
        cpu_counts[0][constants.PLATFORM_FUNCTION] = 2

        # Should not raise.
        cpu_utils.check_core_allocations(host, cpu_counts)

    def test_cpulist_siblings_same_function_is_accepted(self):
        """
        Option A semantics: specifying BOTH threads of every SMT sibling pair
        for the same function is valid and honoured exactly (no extra CPUs
        auto-included, no sibling split).

        Cores 0,1: thread-0 CPUs [0, 2], thread-1 siblings [32, 34].
        Specify all four for platform -> accepted and assigned as given.
        """
        host = build_round_robin_host(num_nodes=2,
                                      physical_cores_per_node=16)

        cpu_counts = _make_empty_cpu_counts(2)

        cpulists = {
            constants.PLATFORM_FUNCTION: [0, 2, 32, 34],
        }

        # Should not raise.
        cpu_utils.check_core_allocations(host, cpu_counts, cpulists)

        cpu_utils.update_core_allocations(host, cpu_counts, cpulists=cpulists)

        # Exactly the specified CPUs are assigned to platform (no more).
        self.assertEqual(
            sorted(host.cpu_functions[0][constants.PLATFORM_FUNCTION]),
            [0, 2, 32, 34])

        # And no siblings were split across functions.
        violations = check_sibling_property(host)
        self.assertEqual(
            violations, [],
            "cpulist siblings split! Violations: %s"
            % _format_violations(violations))

    def test_drbd_limit_sibling_split(self):
        """
        Test DRBD limit edge case: when one sibling is below
        DRBD_CPU_MASK_LIMIT (908) and the other is above it.

        Thread 0: CPU IDs 900-907 (all below DRBD_CPU_MASK_LIMIT=908)
        Thread 1: CPU IDs 910-917 (all above DRBD_CPU_MASK_LIMIT=908)

        Platform allocation from list_drbd_limit picks thread 0; the fix
        must keep the thread-1 sibling with it rather than leaving it in the
        general pool for a different function.
        """
        host = build_drbd_straddle_host(8)

        cpu_counts = _make_empty_cpu_counts(1)
        cpu_counts[0][constants.PLATFORM_FUNCTION] = 4
        cpu_counts[0][constants.VSWITCH_FUNCTION] = 4

        cpu_utils.update_core_allocations(host, cpu_counts)

        violations = check_sibling_property(host)
        self.assertEqual(
            violations, [],
            "DRBD limit caused sibling split! Violations: %s"
            % _format_violations(violations))

    def test_odd_platform_count_triggers_boundary_split(self):
        """
        Test that an odd-numbered platform allocation does not leave a
        sibling split at the function boundary.

        With 1 node, 4 physical cores, 8 logical CPUs:
        Thread 0: [0, 1, 2, 3], Thread 1: [4, 5, 6, 7]

        cpu_lists[0] sorted by (core, thread) = [0, 4, 1, 5, 2, 6, 3, 7]

        Allocate 3 platform CPUs (odd number): on unfixed code core 1's
        threads would land in different functions; the fix keeps siblings
        together.
        """
        cpus = []
        for core in range(4):
            cpus.append(MockCpu(cpu_id=core, numa_node=0, core=core, thread=0))
        for core in range(4):
            cpus.append(MockCpu(cpu_id=4 + core, numa_node=0,
                                core=core, thread=1))

        host = MockHost(cpus, [0])

        cpu_counts = _make_empty_cpu_counts(1)
        cpu_counts[0][constants.PLATFORM_FUNCTION] = 3

        cpu_utils.update_core_allocations(host, cpu_counts)

        violations = check_sibling_property(host)
        self.assertEqual(
            violations, [],
            "Boundary split! Violations: %s"
            % _format_violations(violations))
