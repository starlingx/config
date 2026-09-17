# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Preservation tests for CPU function allocation in cpu_utils.

These tests verify that update_core_allocations() produces consistent,
correct results on both non-HT and HT systems.

For any host, the update_core_allocations() function SHALL:
- Assign platform CPUs first from the pool below DRBD_CPU_MASK_LIMIT (908)
- Maintain allocation priority order:
  platform -> vswitch -> shared -> isolated -> default
- Assign the correct total number of CPUs to each function matching requested
  counts
- Assign remaining CPUs to the default function (APPLICATION for workers,
  PLATFORM otherwise)

The property-based coverage that was previously implemented with hypothesis
has been converted to deterministic, parameterized tests (sweeping small
combinations via itertools.product with subTest) so no external test-only
dependency is required and no global module state is mutated.
"""

import itertools
import unittest

from sysinv.api.controllers.v1 import cpu_utils
from sysinv.common import constants


# ---------------------------------------------------------------------------
# Mock Host Infrastructure (Non-HT)
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
        self.hyperthreading = False  # Non-HT for preservation tests
        self.physical_cores = 0
        self.cpu_model = "Intel(R) Xeon(R)"
        self.cpu_functions = {}
        self.cpu_lists = {}
        for s in range(len(self.nodes)):
            self.cpu_functions[s] = {}
            for f in cpu_utils.CORE_FUNCTIONS:
                self.cpu_functions[s][f] = []
            self.cpu_lists[s] = []

        # Build cpu_lists per NUMA node sorted by (core, thread)
        sorted_cpus = sorted(self.cpus, key=lambda c: (c.core, c.thread))
        for cpu in sorted_cpus:
            if cpu.thread == 0:
                self.physical_cores += 1
            self.cpu_lists[cpu.numa_node].append(cpu.cpu)


def build_non_ht_host(num_nodes, cores_per_node, cpu_id_start=0):
    """
    Build a non-HT mock host with sequential CPU IDs.

    Args:
        num_nodes: Number of NUMA nodes (1-4)
        cores_per_node: Number of physical cores per node
        cpu_id_start: Starting CPU ID (for DRBD limit testing)

    Returns:
        MockHost with hyperthreading=False
    """
    cpus = []
    cpu_id = cpu_id_start
    for node in range(num_nodes):
        for core in range(cores_per_node):
            cpus.append(MockCpu(
                cpu_id=cpu_id,
                numa_node=node,
                core=core,
                thread=0
            ))
            cpu_id += 1
    nodes = list(range(num_nodes))
    return MockHost(cpus, nodes)


def _make_empty_cpu_counts(num_nodes):
    """Create empty cpu_counts dict for all nodes."""
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
# Deterministic parameter generation (replacing hypothesis strategies)
# ---------------------------------------------------------------------------

def _non_ht_configs():
    """
    Yield (host, cpu_counts, description) tuples covering a range of non-HT
    host sizes and valid allocations.

    Replaces the hypothesis non_ht_host_with_counts() strategy with a
    deterministic sweep over small values, keeping the count reasonable while
    still exercising multiple nodes, platform/vswitch/shared/isolated
    combinations and always leaving at least one CPU for the default
    function.
    """
    for num_nodes in (1, 2, 3):
        for cores_per_node in (4, 8, 16):
            for platform, vswitch, shared, isolated in itertools.product(
                    (1, 2, 4), (0, 2), (0, 1), (0, 2)):
                # Leave at least 1 CPU for the default function on each node.
                if platform + vswitch + shared + isolated >= cores_per_node:
                    continue
                host = build_non_ht_host(num_nodes, cores_per_node)
                cpu_counts = _make_empty_cpu_counts(num_nodes)
                for s in range(num_nodes):
                    cpu_counts[s][constants.PLATFORM_FUNCTION] = platform
                    cpu_counts[s][constants.VSWITCH_FUNCTION] = vswitch
                    cpu_counts[s][constants.SHARED_FUNCTION] = shared
                    cpu_counts[s][constants.ISOLATED_FUNCTION] = isolated
                desc = ("nodes=%d cores=%d p=%d v=%d s=%d i=%d" %
                        (num_nodes, cores_per_node, platform, vswitch,
                         shared, isolated))
                yield host, cpu_counts, desc


def _non_ht_drbd_configs():
    """
    Yield (host, cpu_counts, below_count, description) tuples where CPUs
    straddle DRBD_CPU_MASK_LIMIT (908).

    Replaces the hypothesis non_ht_host_near_drbd_limit() strategy.
    """
    for cores_per_node in (6, 8, 12):
        for below_count in range(2, min(6, cores_per_node - 2) + 1):
            cpu_id_start = cpu_utils.DRBD_CPU_MASK_LIMIT - below_count
            max_platform = min(cores_per_node - 1, below_count + 3)
            for platform in range(below_count, max_platform + 1):
                available = cores_per_node - platform
                vswitch_options = [0]
                if available > 1:
                    vswitch_options.append(min(available - 1, 2))
                for vswitch in vswitch_options:
                    host = build_non_ht_host(
                        1, cores_per_node, cpu_id_start=cpu_id_start)
                    cpu_counts = _make_empty_cpu_counts(1)
                    cpu_counts[0][constants.PLATFORM_FUNCTION] = platform
                    cpu_counts[0][constants.VSWITCH_FUNCTION] = vswitch
                    desc = ("cores=%d below=%d p=%d v=%d" %
                            (cores_per_node, below_count, platform, vswitch))
                    yield host, cpu_counts, below_count, desc


# ---------------------------------------------------------------------------
# Non-HT Preservation Tests
# ---------------------------------------------------------------------------

class TestCpuUtilsPreservationNonHT(unittest.TestCase):
    """
    Parameterized tests verifying preservation of non-HT system behavior.
    """

    def test_total_cpu_counts_match_requested(self):
        """
        The total number of CPUs assigned to each explicitly requested
        function matches the requested count. Remaining CPUs go to the
        default function.
        """
        for host, cpu_counts, desc in _non_ht_configs():
            with self.subTest(config=desc):
                cpu_utils.update_core_allocations(host, cpu_counts)

                for s in range(len(host.nodes)):
                    for function in [constants.PLATFORM_FUNCTION,
                                     constants.VSWITCH_FUNCTION,
                                     constants.SHARED_FUNCTION,
                                     constants.ISOLATED_FUNCTION]:
                        actual = len(host.cpu_functions[s][function])
                        expected = cpu_counts[s][function]
                        self.assertEqual(
                            actual, expected,
                            "Node %d, %s: expected %d CPUs, got %d" %
                            (s, function, expected, actual))

                    total_assigned = sum(
                        len(host.cpu_functions[s][f])
                        for f in cpu_utils.CORE_FUNCTIONS)
                    total_available = len(host.cpu_lists[s])
                    self.assertEqual(
                        total_assigned, total_available,
                        "Node %d: total assigned %d != available %d" %
                        (s, total_assigned, total_available))

    def test_default_function_gets_remaining_cpus(self):
        """
        Remaining CPUs (not assigned to platform, vswitch, shared, or
        isolated) go to the default function. For worker hosts, default is
        APPLICATION_FUNCTION.
        """
        for host, cpu_counts, desc in _non_ht_configs():
            with self.subTest(config=desc):
                cpu_utils.update_core_allocations(host, cpu_counts)

                default_function = cpu_utils.get_default_function(host)
                self.assertEqual(default_function,
                                 constants.APPLICATION_FUNCTION)

                for s in range(len(host.nodes)):
                    total_requested = (
                        cpu_counts[s][constants.PLATFORM_FUNCTION] +
                        cpu_counts[s][constants.VSWITCH_FUNCTION] +
                        cpu_counts[s][constants.SHARED_FUNCTION] +
                        cpu_counts[s][constants.ISOLATED_FUNCTION])
                    expected_default = \
                        len(host.cpu_lists[s]) - total_requested
                    actual_default = \
                        len(host.cpu_functions[s][default_function])
                    self.assertEqual(
                        actual_default, expected_default,
                        "Node %d: default function (%s) expected %d CPUs, "
                        "got %d" % (s, default_function, expected_default,
                                    actual_default))

    def test_allocation_priority_order_maintained(self):
        """
        CPUs are assigned in strict priority order from the available pool:
        platform first, then vswitch, shared, isolated, with remaining going
        to default.

        For non-HT systems with all CPUs below the DRBD limit, the CPU IDs
        assigned to each function are contiguous slices of the sorted
        cpu_lists in that order.
        """
        for host, cpu_counts, desc in _non_ht_configs():
            with self.subTest(config=desc):
                original_lists = {}
                for s in range(len(host.nodes)):
                    original_lists[s] = list(host.cpu_lists[s])

                cpu_utils.update_core_allocations(host, cpu_counts)

                for s in range(len(host.nodes)):
                    orig = original_lists[s]

                    platform_cpus = \
                        host.cpu_functions[s][constants.PLATFORM_FUNCTION]
                    vswitch_cpus = \
                        host.cpu_functions[s][constants.VSWITCH_FUNCTION]
                    shared_cpus = \
                        host.cpu_functions[s][constants.SHARED_FUNCTION]
                    isolated_cpus = \
                        host.cpu_functions[s][constants.ISOLATED_FUNCTION]
                    default_cpus = host.cpu_functions[s][
                        cpu_utils.get_default_function(host)]

                    assigned_order = (platform_cpus + vswitch_cpus +
                                      shared_cpus + isolated_cpus +
                                      default_cpus)

                    all_below_drbd = all(c < cpu_utils.DRBD_CPU_MASK_LIMIT
                                         for c in orig)
                    if all_below_drbd:
                        self.assertEqual(
                            assigned_order, orig,
                            "Node %d: assignment order doesn't match "
                            "cpu_lists order.\nExpected: %s\nGot: %s" %
                            (s, orig, assigned_order))

    def test_drbd_limit_compliance(self):
        """
        Platform CPUs are preferentially assigned from the pool of CPUs below
        DRBD_CPU_MASK_LIMIT (908). Only when that pool is exhausted are CPUs
        >= 908 used for platform.
        """
        for host, cpu_counts, below_count, desc in _non_ht_drbd_configs():
            with self.subTest(config=desc):
                cpu_utils.update_core_allocations(host, cpu_counts)

                platform_cpus = \
                    host.cpu_functions[0][constants.PLATFORM_FUNCTION]
                platform_below = [c for c in platform_cpus
                                  if c < cpu_utils.DRBD_CPU_MASK_LIMIT]
                platform_above = [c for c in platform_cpus
                                  if c >= cpu_utils.DRBD_CPU_MASK_LIMIT]

                requested = cpu_counts[0][constants.PLATFORM_FUNCTION]
                expected_below = min(below_count, requested)
                self.assertEqual(
                    len(platform_below), expected_below,
                    "Expected %d platform CPUs below DRBD limit, got %d.\n"
                    "Platform CPUs: %s\nBelow limit count available: %d" %
                    (expected_below, len(platform_below), platform_cpus,
                     below_count))

                expected_above = max(0, requested - below_count)
                self.assertEqual(
                    len(platform_above), expected_above,
                    "Expected %d platform CPUs above DRBD limit, got %d" %
                    (expected_above, len(platform_above)))

    def test_no_cpu_assigned_to_multiple_functions(self):
        """
        Each CPU is assigned to exactly one function. No CPU appears in
        multiple function lists.
        """
        for host, cpu_counts, desc in _non_ht_configs():
            with self.subTest(config=desc):
                cpu_utils.update_core_allocations(host, cpu_counts)

                for s in range(len(host.nodes)):
                    all_assigned = []
                    for f in cpu_utils.CORE_FUNCTIONS:
                        all_assigned.extend(host.cpu_functions[s][f])
                    self.assertEqual(
                        len(all_assigned), len(set(all_assigned)),
                        "Node %d: duplicate CPU assignment detected! "
                        "Assignments: %s" % (s, {
                            f: host.cpu_functions[s][f]
                            for f in cpu_utils.CORE_FUNCTIONS
                            if host.cpu_functions[s][f]}))

    def test_all_cpus_accounted_for(self):
        """
        Every CPU in cpu_lists is assigned to some function. No CPUs are lost
        during allocation.
        """
        for host, cpu_counts, desc in _non_ht_configs():
            with self.subTest(config=desc):
                original_cpus = set()
                for s in range(len(host.nodes)):
                    original_cpus.update(host.cpu_lists[s])

                cpu_utils.update_core_allocations(host, cpu_counts)

                assigned_cpus = set()
                for s in range(len(host.nodes)):
                    for f in cpu_utils.CORE_FUNCTIONS:
                        assigned_cpus.update(host.cpu_functions[s][f])

                self.assertEqual(
                    assigned_cpus, original_cpus,
                    "CPU mismatch! Missing: %s, Extra: %s" %
                    (original_cpus - assigned_cpus,
                     assigned_cpus - original_cpus))


class TestCpuUtilsPreservationDeterministic(unittest.TestCase):
    """
    Deterministic preservation tests verifying specific observed behaviors.
    These serve as regression anchors for the observations made on unfixed
    code.
    """

    def test_non_ht_8_cores_2_platform(self):
        """
        Observed: non-HT host with 8 cores on node 0, allocate 2 platform.
        Platform gets first 2 CPUs [0, 1], application gets rest [2..7].
        """
        host = build_non_ht_host(1, 8)
        cpu_counts = _make_empty_cpu_counts(1)
        cpu_counts[0][constants.PLATFORM_FUNCTION] = 2

        cpu_utils.update_core_allocations(host, cpu_counts)

        self.assertEqual(
            host.cpu_functions[0][constants.PLATFORM_FUNCTION], [0, 1])
        self.assertEqual(
            host.cpu_functions[0][constants.APPLICATION_FUNCTION],
            [2, 3, 4, 5, 6, 7])

    def test_non_ht_16_cores_platform_and_vswitch(self):
        """
        Observed: non-HT host with 16 cores, allocate 2 platform + 2 vswitch.
        Platform [0,1], vswitch [2,3], application [4..15].
        """
        host = build_non_ht_host(1, 16)
        cpu_counts = _make_empty_cpu_counts(1)
        cpu_counts[0][constants.PLATFORM_FUNCTION] = 2
        cpu_counts[0][constants.VSWITCH_FUNCTION] = 2

        cpu_utils.update_core_allocations(host, cpu_counts)

        self.assertEqual(
            host.cpu_functions[0][constants.PLATFORM_FUNCTION], [0, 1])
        self.assertEqual(
            host.cpu_functions[0][constants.VSWITCH_FUNCTION], [2, 3])
        self.assertEqual(
            host.cpu_functions[0][constants.APPLICATION_FUNCTION],
            [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])

    def test_non_ht_drbd_limit_straddle(self):
        """
        Observed: CPUs 906-913 (2 below DRBD limit, 6 above), 4 platform.
        Platform gets [906, 907] from DRBD pool first, then [908, 909].
        """
        host = build_non_ht_host(1, 8, cpu_id_start=906)
        cpu_counts = _make_empty_cpu_counts(1)
        cpu_counts[0][constants.PLATFORM_FUNCTION] = 4

        cpu_utils.update_core_allocations(host, cpu_counts)

        platform = host.cpu_functions[0][constants.PLATFORM_FUNCTION]
        self.assertEqual(platform, [906, 907, 908, 909])
        # First 2 are below DRBD limit
        self.assertTrue(all(c < 908 for c in platform[:2]))

    def test_non_ht_all_functions_allocated(self):
        """
        Observed: 20 cores, allocate all functions.
        Platform [0..3], Vswitch [4..7], Shared [8,9],
        Isolated [10..13], Application [14..19].
        """
        host = build_non_ht_host(1, 20)
        cpu_counts = _make_empty_cpu_counts(1)
        cpu_counts[0][constants.PLATFORM_FUNCTION] = 4
        cpu_counts[0][constants.VSWITCH_FUNCTION] = 4
        cpu_counts[0][constants.SHARED_FUNCTION] = 2
        cpu_counts[0][constants.ISOLATED_FUNCTION] = 4

        cpu_utils.update_core_allocations(host, cpu_counts)

        self.assertEqual(
            host.cpu_functions[0][constants.PLATFORM_FUNCTION],
            [0, 1, 2, 3])
        self.assertEqual(
            host.cpu_functions[0][constants.VSWITCH_FUNCTION],
            [4, 5, 6, 7])
        self.assertEqual(
            host.cpu_functions[0][constants.SHARED_FUNCTION],
            [8, 9])
        self.assertEqual(
            host.cpu_functions[0][constants.ISOLATED_FUNCTION],
            [10, 11, 12, 13])
        self.assertEqual(
            host.cpu_functions[0][constants.APPLICATION_FUNCTION],
            [14, 15, 16, 17, 18, 19])

    def test_non_ht_multi_node(self):
        """
        Observed: 2 NUMA nodes, 8 cores each, different allocations per node.
        Each node allocates independently.
        """
        cpus = []
        for node in range(2):
            for core in range(8):
                cpus.append(MockCpu(node * 8 + core, node, core, 0))
        host = MockHost(cpus, [0, 1])

        cpu_counts = {
            0: {constants.PLATFORM_FUNCTION: 2,
                constants.VSWITCH_FUNCTION: 2,
                constants.SHARED_FUNCTION: 0,
                constants.ISOLATED_FUNCTION: 0,
                constants.APPLICATION_FUNCTION: 0,
                constants.NO_FUNCTION: 0},
            1: {constants.PLATFORM_FUNCTION: 2,
                constants.VSWITCH_FUNCTION: 0,
                constants.SHARED_FUNCTION: 2,
                constants.ISOLATED_FUNCTION: 0,
                constants.APPLICATION_FUNCTION: 0,
                constants.NO_FUNCTION: 0}
        }

        cpu_utils.update_core_allocations(host, cpu_counts)

        # Node 0
        self.assertEqual(
            host.cpu_functions[0][constants.PLATFORM_FUNCTION], [0, 1])
        self.assertEqual(
            host.cpu_functions[0][constants.VSWITCH_FUNCTION], [2, 3])
        self.assertEqual(
            host.cpu_functions[0][constants.APPLICATION_FUNCTION],
            [4, 5, 6, 7])

        # Node 1
        self.assertEqual(
            host.cpu_functions[1][constants.PLATFORM_FUNCTION], [8, 9])
        self.assertEqual(
            host.cpu_functions[1][constants.SHARED_FUNCTION], [10, 11])
        self.assertEqual(
            host.cpu_functions[1][constants.APPLICATION_FUNCTION],
            [12, 13, 14, 15])

    def test_non_ht_single_cpu_per_function(self):
        """
        Minimal case: 1 CPU per function allocated.
        """
        host = build_non_ht_host(1, 6)
        cpu_counts = _make_empty_cpu_counts(1)
        cpu_counts[0][constants.PLATFORM_FUNCTION] = 1
        cpu_counts[0][constants.VSWITCH_FUNCTION] = 1
        cpu_counts[0][constants.SHARED_FUNCTION] = 1
        cpu_counts[0][constants.ISOLATED_FUNCTION] = 1

        cpu_utils.update_core_allocations(host, cpu_counts)

        self.assertEqual(
            host.cpu_functions[0][constants.PLATFORM_FUNCTION], [0])
        self.assertEqual(
            host.cpu_functions[0][constants.VSWITCH_FUNCTION], [1])
        self.assertEqual(
            host.cpu_functions[0][constants.SHARED_FUNCTION], [2])
        self.assertEqual(
            host.cpu_functions[0][constants.ISOLATED_FUNCTION], [3])
        self.assertEqual(
            host.cpu_functions[0][constants.APPLICATION_FUNCTION], [4, 5])


# ---------------------------------------------------------------------------
# HT Mock Host Infrastructure
# ---------------------------------------------------------------------------

class MockHostHT(MockHost):
    """Mock host with hyperthreading enabled (two threads per core)."""

    def __init__(self, cpus, nodes, subfunctions=None):
        super(MockHostHT, self).__init__(
            cpus, nodes, subfunctions=subfunctions)
        self.hyperthreading = True


def build_ht_host(num_nodes, cores_per_node, cpu_id_start=0):
    """
    Build an HT mock host with two threads per physical core.

    Thread-0 CPU IDs are assigned first (contiguous), then thread-1 CPU IDs
    continue after all thread-0 IDs. This mimics a common enumeration where
    siblings are not necessarily adjacent by ID but are grouped by
    (numa_node, core).

    Args:
        num_nodes: Number of NUMA nodes.
        cores_per_node: Physical cores per node.
        cpu_id_start: Starting CPU ID (for DRBD limit testing).

    Returns:
        MockHostHT with hyperthreading=True. Each node has
        cores_per_node * 2 logical CPUs.
    """
    total_cores = num_nodes * cores_per_node
    cpus = []
    cpu_id = cpu_id_start

    # Thread 0 for all cores/nodes first.
    for node in range(num_nodes):
        for core in range(cores_per_node):
            cpus.append(MockCpu(
                cpu_id=cpu_id, numa_node=node, core=core, thread=0))
            cpu_id += 1

    # Thread 1 (siblings) after all thread-0 IDs.
    for node in range(num_nodes):
        for core in range(cores_per_node):
            cpus.append(MockCpu(
                cpu_id=cpu_id, numa_node=node, core=core, thread=1))
            cpu_id += 1

    assert cpu_id - cpu_id_start == total_cores * 2
    nodes = list(range(num_nodes))
    return MockHostHT(cpus, nodes)


def _sibling_pairs(host):
    """Return list of (cpu_a, cpu_b) sibling pairs grouped by (node, core)."""
    cores = {}
    for cpu in host.cpus:
        cores.setdefault((cpu.numa_node, cpu.core), []).append(cpu.cpu)
    pairs = []
    for cpu_nums in cores.values():
        if len(cpu_nums) == 2:
            pairs.append((cpu_nums[0], cpu_nums[1]))
    return pairs


def _ht_configs():
    """
    Yield (host, cpu_counts, description) tuples covering a range of HT host
    sizes and valid allocations.

    Counts are always EVEN because a logical-CPU count on an HT system is
    consumed as sibling pairs (2 logical CPUs per physical core). Always
    leaves at least one full core (2 logical CPUs) for the default function.

    Replaces the hypothesis ht_host_with_counts() strategy.
    """
    for num_nodes in (1, 2, 3):
        for cores_per_node in (4, 8, 16):
            available = cores_per_node * 2
            for platform_c, vswitch_c, shared_c, isolated_c in \
                    itertools.product((1, 2, 4), (0, 1, 2), (0, 1), (0, 1, 2)):
                platform = platform_c * 2
                vswitch = vswitch_c * 2
                shared = shared_c * 2
                isolated = isolated_c * 2
                # Leave at least one core (2 logical CPUs) for default.
                if platform + vswitch + shared + isolated >= available:
                    continue
                host = build_ht_host(num_nodes, cores_per_node)
                cpu_counts = _make_empty_cpu_counts(num_nodes)
                for s in range(num_nodes):
                    cpu_counts[s][constants.PLATFORM_FUNCTION] = platform
                    cpu_counts[s][constants.VSWITCH_FUNCTION] = vswitch
                    cpu_counts[s][constants.SHARED_FUNCTION] = shared
                    cpu_counts[s][constants.ISOLATED_FUNCTION] = isolated
                desc = ("nodes=%d cores=%d p=%d v=%d s=%d i=%d" %
                        (num_nodes, cores_per_node, platform, vswitch,
                         shared, isolated))
                yield host, cpu_counts, desc


def _ht_drbd_configs():
    """
    Yield (host, cpu_counts, description) tuples whose CPU IDs straddle
    DRBD_CPU_MASK_LIMIT (908): thread-0 IDs below the limit and thread-1
    sibling IDs above it.

    Replaces the hypothesis ht_host_near_drbd_limit() strategy.
    """
    for cores_per_node in (4, 6, 8):
        cpu_id_start = cpu_utils.DRBD_CPU_MASK_LIMIT - cores_per_node
        max_platform_cores = min(cores_per_node - 1, 3)
        for platform_cores in range(1, max_platform_cores + 1):
            host = build_ht_host(1, cores_per_node, cpu_id_start=cpu_id_start)
            cpu_counts = _make_empty_cpu_counts(1)
            cpu_counts[0][constants.PLATFORM_FUNCTION] = platform_cores * 2
            desc = ("cores=%d platform_cores=%d" %
                    (cores_per_node, platform_cores))
            yield host, cpu_counts, desc


class TestCpuUtilsPreservationHT(unittest.TestCase):
    """
    Parameterized tests verifying that the SAME count/order/DRBD
    preservation properties that hold on non-HT systems also hold on
    HT-enabled systems. The sibling-pairing property itself is covered
    separately in test_cpu_utils_sibling_split.py.
    """

    def test_ht_total_cpu_counts_match_requested(self):
        """
        The total number of logical CPUs assigned to each explicitly
        requested function matches the requested (already-doubled) count on
        each NUMA node.
        """
        for host, cpu_counts, desc in _ht_configs():
            with self.subTest(config=desc):
                cpu_utils.update_core_allocations(host, cpu_counts)

                for s in range(len(host.nodes)):
                    for function in [constants.PLATFORM_FUNCTION,
                                     constants.VSWITCH_FUNCTION,
                                     constants.SHARED_FUNCTION,
                                     constants.ISOLATED_FUNCTION]:
                        actual = len(host.cpu_functions[s][function])
                        expected = cpu_counts[s][function]
                        self.assertEqual(
                            actual, expected,
                            "Node %d, %s: expected %d logical CPUs, got %d" %
                            (s, function, expected, actual))

                    total_assigned = sum(
                        len(host.cpu_functions[s][f])
                        for f in cpu_utils.CORE_FUNCTIONS)
                    total_available = len(host.cpu_lists[s])
                    self.assertEqual(
                        total_assigned, total_available,
                        "Node %d: total assigned %d != available %d" %
                        (s, total_assigned, total_available))

    def test_ht_default_function_gets_remaining_cpus(self):
        """
        Remaining logical CPUs (not assigned to platform, vswitch, shared or
        isolated) go to the default function (APPLICATION for workers).
        """
        for host, cpu_counts, desc in _ht_configs():
            with self.subTest(config=desc):
                cpu_utils.update_core_allocations(host, cpu_counts)

                default_function = cpu_utils.get_default_function(host)
                self.assertEqual(default_function,
                                 constants.APPLICATION_FUNCTION)

                for s in range(len(host.nodes)):
                    total_requested = (
                        cpu_counts[s][constants.PLATFORM_FUNCTION] +
                        cpu_counts[s][constants.VSWITCH_FUNCTION] +
                        cpu_counts[s][constants.SHARED_FUNCTION] +
                        cpu_counts[s][constants.ISOLATED_FUNCTION])
                    expected_default = \
                        len(host.cpu_lists[s]) - total_requested
                    actual_default = \
                        len(host.cpu_functions[s][default_function])
                    self.assertEqual(
                        actual_default, expected_default,
                        "Node %d: default function (%s) expected %d CPUs, "
                        "got %d" % (s, default_function, expected_default,
                                    actual_default))

    def test_ht_allocation_priority_order_maintained(self):
        """
        Allocation follows strict priority order
        platform -> vswitch -> shared -> isolated -> default. On HT systems,
        siblings are pulled in with their thread-0 partner, so we verify that
        for each function (in priority order) the thread-0 CPU that seeds a
        pair is consumed no later than any thread-0 CPU seeding a
        lower-priority function's pair.
        """
        for host, cpu_counts, desc in _ht_configs():
            with self.subTest(config=desc):
                cpu_utils.update_core_allocations(host, cpu_counts)

                thread0_ids = sorted(
                    c.cpu for c in host.cpus if c.thread == 0)
                seed_rank = {cpu: rank
                             for rank, cpu in enumerate(thread0_ids)}

                for s in range(len(host.nodes)):
                    ordered_functions = [
                        constants.PLATFORM_FUNCTION,
                        constants.VSWITCH_FUNCTION,
                        constants.SHARED_FUNCTION,
                        constants.ISOLATED_FUNCTION,
                        cpu_utils.get_default_function(host),
                    ]

                    prev_max_rank = -1
                    for function in ordered_functions:
                        assigned = host.cpu_functions[s][function]
                        ranks = [seed_rank[c] for c in assigned
                                 if c in seed_rank]
                        if not ranks:
                            continue
                        self.assertGreater(
                            min(ranks), prev_max_rank,
                            "Node %d: function %s consumed a core out of "
                            "priority order (min rank %d <= previous max %d)"
                            % (s, function, min(ranks), prev_max_rank))
                        prev_max_rank = max(ranks)

    def test_ht_no_cpu_assigned_to_multiple_functions(self):
        """
        Each logical CPU is assigned to exactly one function.
        """
        for host, cpu_counts, desc in _ht_configs():
            with self.subTest(config=desc):
                cpu_utils.update_core_allocations(host, cpu_counts)

                for s in range(len(host.nodes)):
                    all_assigned = []
                    for f in cpu_utils.CORE_FUNCTIONS:
                        all_assigned.extend(host.cpu_functions[s][f])
                    self.assertEqual(
                        len(all_assigned), len(set(all_assigned)),
                        "Node %d: duplicate CPU assignment detected! "
                        "Assignments: %s" % (s, {
                            f: host.cpu_functions[s][f]
                            for f in cpu_utils.CORE_FUNCTIONS
                            if host.cpu_functions[s][f]}))

    def test_ht_all_cpus_accounted_for(self):
        """
        Every logical CPU in cpu_lists is assigned to some function; none are
        lost or duplicated.
        """
        for host, cpu_counts, desc in _ht_configs():
            with self.subTest(config=desc):
                original_cpus = set()
                for s in range(len(host.nodes)):
                    original_cpus.update(host.cpu_lists[s])

                cpu_utils.update_core_allocations(host, cpu_counts)

                assigned_cpus = set()
                for s in range(len(host.nodes)):
                    for f in cpu_utils.CORE_FUNCTIONS:
                        assigned_cpus.update(host.cpu_functions[s][f])

                self.assertEqual(
                    assigned_cpus, original_cpus,
                    "CPU mismatch! Missing: %s, Extra: %s" %
                    (original_cpus - assigned_cpus,
                     assigned_cpus - original_cpus))

    def test_ht_drbd_limit_compliance(self):
        """
        Platform CPUs are preferentially seeded from the pool below
        DRBD_CPU_MASK_LIMIT (908). On HT hosts the thread-0 anchor of each
        platform pair should be drawn from below the limit as long as such
        CPUs remain available.
        """
        for host, cpu_counts, desc in _ht_drbd_configs():
            with self.subTest(config=desc):
                cpu_utils.update_core_allocations(host, cpu_counts)

                platform_cpus = \
                    host.cpu_functions[0][constants.PLATFORM_FUNCTION]

                below_available = [c for c in host.cpu_lists[0]
                                   if c < cpu_utils.DRBD_CPU_MASK_LIMIT]
                platform_below = [c for c in platform_cpus
                                  if c < cpu_utils.DRBD_CPU_MASK_LIMIT]

                requested_pairs = \
                    cpu_counts[0][constants.PLATFORM_FUNCTION] // 2
                expected_below = min(len(below_available), requested_pairs)
                self.assertEqual(
                    len(platform_below), expected_below,
                    "Expected %d platform CPUs below DRBD limit, got %d.\n"
                    "Platform CPUs: %s" %
                    (expected_below, len(platform_below), platform_cpus))


class TestCpuUtilsPreservationHTDeterministic(unittest.TestCase):
    """
    Deterministic HT preservation regression anchors.
    """

    def test_ht_8_cores_platform_and_vswitch(self):
        """
        HT host, 1 node, 8 physical cores (16 logical CPUs).
        thread-0 IDs [0..7], thread-1 sibling IDs [8..15].
        cpu_lists[0] sorted by (core, thread) = [0, 8, 1, 9, 2, 10, ...].
        Request 4 platform + 2 vswitch logical CPUs.
        Platform -> 2 cores [0, 8, 1, 9]; vswitch -> 1 core [2, 10];
        application -> remaining.
        """
        host = build_ht_host(1, 8)
        cpu_counts = _make_empty_cpu_counts(1)
        cpu_counts[0][constants.PLATFORM_FUNCTION] = 4
        cpu_counts[0][constants.VSWITCH_FUNCTION] = 2

        cpu_utils.update_core_allocations(host, cpu_counts)

        self.assertEqual(
            sorted(host.cpu_functions[0][constants.PLATFORM_FUNCTION]),
            [0, 1, 8, 9])
        self.assertEqual(
            sorted(host.cpu_functions[0][constants.VSWITCH_FUNCTION]),
            [2, 10])
        self.assertEqual(
            sorted(host.cpu_functions[0][constants.APPLICATION_FUNCTION]),
            [3, 4, 5, 6, 7, 11, 12, 13, 14, 15])

        # Sanity: no sibling split.
        cpu_to_function = {}
        for f in cpu_utils.CORE_FUNCTIONS:
            for c in host.cpu_functions[0][f]:
                cpu_to_function[c] = f
        for a, b in _sibling_pairs(host):
            self.assertEqual(
                cpu_to_function.get(a), cpu_to_function.get(b),
                "Siblings %d/%d split across functions" % (a, b))

    def test_ht_all_functions_allocated(self):
        """
        HT host, 1 node, 16 physical cores (32 logical CPUs).
        Request 4 platform + 4 vswitch + 2 shared + 4 isolated logical CPUs.
        Verify counts and that all CPUs are accounted for with no splits.
        """
        host = build_ht_host(1, 16)
        cpu_counts = _make_empty_cpu_counts(1)
        cpu_counts[0][constants.PLATFORM_FUNCTION] = 4
        cpu_counts[0][constants.VSWITCH_FUNCTION] = 4
        cpu_counts[0][constants.SHARED_FUNCTION] = 2
        cpu_counts[0][constants.ISOLATED_FUNCTION] = 4

        cpu_utils.update_core_allocations(host, cpu_counts)

        self.assertEqual(
            len(host.cpu_functions[0][constants.PLATFORM_FUNCTION]), 4)
        self.assertEqual(
            len(host.cpu_functions[0][constants.VSWITCH_FUNCTION]), 4)
        self.assertEqual(
            len(host.cpu_functions[0][constants.SHARED_FUNCTION]), 2)
        self.assertEqual(
            len(host.cpu_functions[0][constants.ISOLATED_FUNCTION]), 4)
        self.assertEqual(
            len(host.cpu_functions[0][constants.APPLICATION_FUNCTION]),
            32 - 4 - 4 - 2 - 4)

        cpu_to_function = {}
        for f in cpu_utils.CORE_FUNCTIONS:
            for c in host.cpu_functions[0][f]:
                cpu_to_function[c] = f
        for a, b in _sibling_pairs(host):
            self.assertEqual(
                cpu_to_function.get(a), cpu_to_function.get(b),
                "Siblings %d/%d split across functions" % (a, b))

    def test_ht_drbd_limit_straddle(self):
        """
        HT host where thread-0 IDs are below DRBD limit and thread-1 sibling
        IDs are above it. Platform pairs must still seed from below the limit
        while keeping siblings together.

        4 cores: thread-0 IDs [904..907] (< 908), thread-1 IDs [908..911].
        Request 4 platform logical CPUs (2 pairs). Platform should get
        [904, 908, 905, 909] (2 below-limit anchors + their above siblings).
        """
        host = build_ht_host(
            1, 4, cpu_id_start=cpu_utils.DRBD_CPU_MASK_LIMIT - 4)
        cpu_counts = _make_empty_cpu_counts(1)
        cpu_counts[0][constants.PLATFORM_FUNCTION] = 4

        cpu_utils.update_core_allocations(host, cpu_counts)

        platform = sorted(
            host.cpu_functions[0][constants.PLATFORM_FUNCTION])
        self.assertEqual(platform, [904, 905, 908, 909])
        # Two anchors below the limit.
        below = [c for c in platform if c < cpu_utils.DRBD_CPU_MASK_LIMIT]
        self.assertEqual(len(below), 2)
