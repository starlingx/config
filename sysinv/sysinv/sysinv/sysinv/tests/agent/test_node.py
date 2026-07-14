#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Tests for sysinv agent node utilities."""

import mock

from sysinv.agent import node as node_module
from sysinv.agent.node import NodeOperator
from sysinv.common import utils as cutils
from sysinv.tests import base


class TestInvalidateCache(base.TestCase):

    def test_cache_clear_removes_cached_value(self):
        with mock.patch('sysinv.agent.node.listdir', return_value=['node0']), \
                mock.patch('os.path.isdir', return_value=True):
            node_module._read_numa_nodes.cache_clear()
            node_module._read_numa_nodes()  # populate cache
        node_module._read_numa_nodes.cache_clear()
        self.assertEqual(node_module._read_numa_nodes.cache_info().currsize, 0)

    def test_cache_clear_is_noop_when_empty(self):
        node_module._read_numa_nodes.cache_clear()  # should not raise


class TestNumaNodes(base.TestCase):

    def setUp(self):
        super(TestNumaNodes, self).setUp()
        node_module._read_numa_nodes.cache_clear()

    def tearDown(self):
        super(TestNumaNodes, self).tearDown()
        node_module._read_numa_nodes.cache_clear()

    def _make_node_op(self):
        return NodeOperator()

    @mock.patch('sysinv.agent.node.listdir')
    @mock.patch('os.path.isdir')
    def test_single_node(self, mock_isdir, mock_listdir):
        mock_listdir.return_value = ['node0', 'cpu0']
        mock_isdir.return_value = True
        op = self._make_node_op()
        self.assertEqual([0], op._numa_nodes)

    @mock.patch('sysinv.agent.node.listdir')
    @mock.patch('os.path.isdir')
    def test_multiple_nodes_sorted(self, mock_isdir, mock_listdir):
        mock_listdir.return_value = ['node3', 'node1', 'node0', 'node2']
        mock_isdir.return_value = True
        op = self._make_node_op()
        self.assertEqual([0, 1, 2, 3], op._numa_nodes)

    @mock.patch('sysinv.agent.node.listdir')
    def test_sysfs_error_falls_back_to_node0(self, mock_listdir):
        mock_listdir.side_effect = OSError('no such file')
        op = self._make_node_op()
        self.assertEqual([0], op._numa_nodes)

    @mock.patch('sysinv.agent.node.listdir')
    def test_sysfs_error_clears_cache(self, mock_listdir):
        mock_listdir.side_effect = OSError('no such file')
        op = self._make_node_op()
        self.assertRaises(OSError, node_module._read_numa_nodes)
        self.assertEqual(0, node_module._read_numa_nodes.cache_info().currsize)
        _ = op._numa_nodes  # safe wrapper clears cache on error
        self.assertEqual(0, node_module._read_numa_nodes.cache_info().currsize)

    @mock.patch('sysinv.agent.node.listdir')
    @mock.patch('os.path.isdir')
    def test_no_node_dirs_falls_back_to_node0(self, mock_isdir, mock_listdir):
        mock_listdir.return_value = ['online', 'possible', 'cpu0']
        mock_isdir.return_value = True
        op = self._make_node_op()
        self.assertEqual([0], op._numa_nodes)

    @mock.patch('sysinv.agent.node.listdir')
    @mock.patch('os.path.isdir')
    def test_no_node_dirs_clears_cache(self, mock_isdir, mock_listdir):
        mock_listdir.return_value = ['online', 'possible', 'cpu0']
        mock_isdir.return_value = True
        op = self._make_node_op()
        self.assertRaises(ValueError, node_module._read_numa_nodes)
        self.assertEqual(0, node_module._read_numa_nodes.cache_info().currsize)
        _ = op._numa_nodes  # safe wrapper clears cache on error
        self.assertEqual(0, node_module._read_numa_nodes.cache_info().currsize)

    @mock.patch('sysinv.agent.node.listdir')
    @mock.patch('os.path.isdir')
    def test_non_node_entries_ignored(self, mock_isdir, mock_listdir):
        mock_listdir.return_value = ['node0', 'online', 'possible', 'node1']
        mock_isdir.return_value = True
        op = self._make_node_op()
        self.assertEqual([0, 1], op._numa_nodes)

    @mock.patch('sysinv.agent.node.listdir')
    @mock.patch('os.path.isdir')
    def test_cache_shared_across_instances(self, mock_isdir, mock_listdir):
        mock_listdir.return_value = ['node0', 'node1']
        mock_isdir.return_value = True
        op1 = NodeOperator()
        op2 = NodeOperator()
        result1 = op1._numa_nodes
        result2 = op2._numa_nodes
        self.assertEqual(result1, result2)
        self.assertEqual(1, node_module._read_numa_nodes.cache_info().currsize)


class TestCpuModelAttrs(base.TestCase):

    def setUp(self):
        super(TestCpuModelAttrs, self).setUp()
        node_module._read_cpu_model_attrs.cache_clear()

    def tearDown(self):
        super(TestCpuModelAttrs, self).tearDown()
        node_module._read_cpu_model_attrs.cache_clear()

    def _make_node_op(self):
        return NodeOperator()

    def test_reads_family_and_model(self):
        cpuinfo = 'cpu family\t: 6\nmodel name\t: Intel(R) Xeon(R)\n'
        op = self._make_node_op()
        with mock.patch('builtins.open', mock.mock_open(read_data=cpuinfo)):
            result = op._cpu_model_attrs
        self.assertEqual({'cpu_family': '6', 'cpu_model': 'Intel(R) Xeon(R)'}, result)

    def test_read_error_returns_empty(self):
        op = self._make_node_op()
        with mock.patch('builtins.open', side_effect=IOError('no such file')):
            result = op._cpu_model_attrs
        self.assertEqual({}, result)

    def test_read_error_clears_cache(self):
        op = self._make_node_op()
        with mock.patch('builtins.open', side_effect=IOError('no such file')):
            self.assertRaises(IOError, node_module._read_cpu_model_attrs)
        self.assertEqual(0, node_module._read_cpu_model_attrs.cache_info().currsize)
        with mock.patch('builtins.open', side_effect=IOError('no such file')):
            _ = op._cpu_model_attrs  # safe wrapper clears cache on error
        self.assertEqual(0, node_module._read_cpu_model_attrs.cache_info().currsize)

    def test_cache_shared_across_instances(self):
        cpuinfo = 'cpu family\t: 6\nmodel name\t: Intel(R) Xeon(R)\n'
        op1 = NodeOperator()
        op2 = NodeOperator()
        with mock.patch('builtins.open', mock.mock_open(read_data=cpuinfo)):
            result1 = op1._cpu_model_attrs
            result2 = op2._cpu_model_attrs
        self.assertEqual(result1, result2)
        self.assertEqual(1, node_module._read_cpu_model_attrs.cache_info().currsize)


class TestGetCpuTopology(base.TestCase):

    def setUp(self):
        super(TestGetCpuTopology, self).setUp()
        self.node_op = NodeOperator()

    @mock.patch('os.path.isdir', return_value=False)
    def test_missing_topology_dir_returns_none(self, _):
        self.assertIsNone(self.node_op._get_cpu_topology(0))

    @mock.patch('os.path.isdir', return_value=True)
    def test_valid_topology(self, _):
        def fake_read(path):
            if path.endswith('core_id'):
                return '2'
            if path.endswith('thread_siblings_list'):
                return '4,5'
            return None

        with mock.patch.object(cutils, 'read_first_line_from_file',
                               side_effect=fake_read):
            result = self.node_op._get_cpu_topology(4)

        self.assertEqual({'core_id': 2, 'thread_siblings': [4, 5]}, result)

    @mock.patch('os.path.isdir', return_value=True)
    def test_missing_core_id_returns_none(self, _):
        with mock.patch.object(cutils, 'read_first_line_from_file',
                               return_value=None):
            self.assertIsNone(self.node_op._get_cpu_topology(0))


class TestGetListOfCpuIds(base.TestCase):

    def setUp(self):
        super(TestGetListOfCpuIds, self).setUp()
        self.node_op = NodeOperator()

    def test_returns_cpu_list(self):
        with mock.patch.object(cutils, 'read_first_line_from_file',
                               return_value='0-3'):
            self.assertEqual([0, 1, 2, 3],
                             self.node_op._get_list_of_cpu_ids(0))

    def test_sysfs_read_failure_returns_empty(self):
        with mock.patch.object(cutils, 'read_first_line_from_file',
                               return_value=None):
            self.assertEqual([], self.node_op._get_list_of_cpu_ids(0))


class TestComputeThreadId(base.TestCase):

    def setUp(self):
        super(TestComputeThreadId, self).setUp()
        self.node_op = NodeOperator()

    def test_first_sibling_is_thread_0(self):
        self.assertEqual(0, self.node_op._compute_thread_id(4, [4, 5]))

    def test_second_sibling_is_thread_1(self):
        self.assertEqual(1, self.node_op._compute_thread_id(5, [4, 5]))

    def test_empty_siblings_returns_0(self):
        self.assertEqual(0, self.node_op._compute_thread_id(0, []))

    def test_cpu_not_in_siblings_returns_0(self):
        self.assertEqual(0, self.node_op._compute_thread_id(9, [4, 5]))


class TestInodesGetInumasIcpus(base.TestCase):
    """Integration-style tests for inodes_get_inumas_icpus."""

    def _make_op(self, numa_nodes, cpulist_by_node, topology_by_cpu):
        op = NodeOperator()

        node_module._read_numa_nodes.cache_clear()
        node_module._read_cpu_model_attrs.cache_clear()

        self.patch_numa = mock.patch(
            'sysinv.agent.node._read_numa_nodes',
            return_value=numa_nodes)
        self.patch_cpu = mock.patch(
            'sysinv.agent.node._read_cpu_model_attrs',
            return_value={'cpu_family': '6', 'cpu_model': 'Intel(R) Xeon(R)'})
        self.patch_numa.start()
        self.patch_cpu.start()
        self.addCleanup(self.patch_numa.stop)
        self.addCleanup(self.patch_cpu.stop)

        def fake_get_list_of_cpu_ids(node_id):
            return cpulist_by_node.get(node_id, [])

        def fake_get_cpu_topology(cpu_id):
            return topology_by_cpu.get(cpu_id)

        op._get_list_of_cpu_ids = fake_get_list_of_cpu_ids
        op._get_cpu_topology = fake_get_cpu_topology
        return op

    def test_single_node_two_cpus(self):
        op = self._make_op(
            numa_nodes=[0],
            cpulist_by_node={0: [0, 1]},
            topology_by_cpu={
                0: {'core_id': 0, 'thread_siblings': [0, 1]},
                1: {'core_id': 0, 'thread_siblings': [0, 1]},
            },
        )
        inumas, icpus = op.inodes_get_inumas_icpus()

        self.assertEqual([{'numa_node': 0, 'capabilities': {}}], inumas)
        self.assertEqual(2, len(icpus))
        self.assertEqual(0, icpus[0]['thread'])
        self.assertEqual(1, icpus[1]['thread'])
        self.assertEqual(0, icpus[0]['numa_node'])

    def test_two_nodes(self):
        op = self._make_op(
            numa_nodes=[0, 1],
            cpulist_by_node={0: [0, 1], 1: [2, 3]},
            topology_by_cpu={
                0: {'core_id': 0, 'thread_siblings': [0, 1]},
                1: {'core_id': 0, 'thread_siblings': [0, 1]},
                2: {'core_id': 0, 'thread_siblings': [2, 3]},
                3: {'core_id': 0, 'thread_siblings': [2, 3]},
            },
        )
        inumas, icpus = op.inodes_get_inumas_icpus()

        self.assertEqual(2, len(inumas))
        self.assertEqual(0, inumas[0]['numa_node'])
        self.assertEqual(1, inumas[1]['numa_node'])
        self.assertEqual(4, len(icpus))
        numa_nodes_reported = {c['numa_node'] for c in icpus}
        self.assertEqual({0, 1}, numa_nodes_reported)

    def test_cpu_with_no_topology_is_skipped(self):
        op = self._make_op(
            numa_nodes=[0],
            cpulist_by_node={0: [0, 1]},
            topology_by_cpu={
                0: {'core_id': 0, 'thread_siblings': [0, 1]},
                # cpu 1 has no topology entry -> returns None -> skipped
            },
        )
        _, icpus = op.inodes_get_inumas_icpus()
        self.assertEqual(1, len(icpus))
        self.assertEqual(0, icpus[0]['cpu'])

    def test_cpu_model_attrs_merged(self):
        op = self._make_op(
            numa_nodes=[0],
            cpulist_by_node={0: [0]},
            topology_by_cpu={
                0: {'core_id': 0, 'thread_siblings': [0]},
            },
        )
        _, icpus = op.inodes_get_inumas_icpus()
        self.assertEqual('6', icpus[0]['cpu_family'])
        self.assertEqual('Intel(R) Xeon(R)', icpus[0]['cpu_model'])

    def test_numa_node_always_set_on_every_cpu(self):
        """Every icpu dict must have numa_node explicitly set."""
        op = self._make_op(
            numa_nodes=[0, 1],
            cpulist_by_node={0: [0], 1: [1]},
            topology_by_cpu={
                0: {'core_id': 0, 'thread_siblings': [0]},
                1: {'core_id': 0, 'thread_siblings': [1]},
            },
        )
        _, icpus = op.inodes_get_inumas_icpus()
        for cpu in icpus:
            self.assertIn('numa_node', cpu)


class TestNonConsecutiveCoreId(base.TestCase):
    """Tests for hardware with non-consecutive or bizarre core_id enumerations.

    Some platforms (e.g. AMD Genoa/Bergamo, certain Intel SKUs with disabled
    cores) report core_ids that are non-consecutive, non-zero-based, or
    otherwise irregular.  The agent must faithfully pass them through without
    remapping or dropping CPUs.
    """

    def _make_op(self, numa_nodes, cpulist_by_node, topology_by_cpu):
        op = NodeOperator()
        node_module._read_numa_nodes.cache_clear()
        node_module._read_cpu_model_attrs.cache_clear()

        self.patch_numa = mock.patch(
            'sysinv.agent.node._read_numa_nodes',
            return_value=numa_nodes)
        self.patch_cpu = mock.patch(
            'sysinv.agent.node._read_cpu_model_attrs',
            return_value={})
        self.patch_numa.start()
        self.patch_cpu.start()
        self.addCleanup(self.patch_numa.stop)
        self.addCleanup(self.patch_cpu.stop)

        op._get_list_of_cpu_ids = lambda node_id: cpulist_by_node.get(node_id, [])
        op._get_cpu_topology = lambda cpu_id: topology_by_cpu.get(cpu_id)
        return op

    def tearDown(self):
        super(TestNonConsecutiveCoreId, self).tearDown()
        node_module._read_numa_nodes.cache_clear()
        node_module._read_cpu_model_attrs.cache_clear()

    def test_non_consecutive_core_ids_preserved(self):
        """core_ids with gaps (e.g. 0,2,4,6) are passed through unchanged."""
        op = self._make_op(
            numa_nodes=[0],
            cpulist_by_node={0: [0, 1, 2, 3]},
            topology_by_cpu={
                0: {'core_id': 0, 'thread_siblings': [0, 1]},
                1: {'core_id': 0, 'thread_siblings': [0, 1]},
                2: {'core_id': 2, 'thread_siblings': [2, 3]},
                3: {'core_id': 2, 'thread_siblings': [2, 3]},
            },
        )
        _, icpus = op.inodes_get_inumas_icpus()
        core_ids = [c['core'] for c in icpus]
        self.assertEqual([0, 0, 2, 2], core_ids)

    def test_large_non_consecutive_core_ids(self):
        """core_ids starting at a high value (e.g. AMD CCD offset) are preserved."""
        op = self._make_op(
            numa_nodes=[0],
            cpulist_by_node={0: [0, 1, 2, 3]},
            topology_by_cpu={
                0: {'core_id': 32, 'thread_siblings': [0, 1]},
                1: {'core_id': 32, 'thread_siblings': [0, 1]},
                2: {'core_id': 48, 'thread_siblings': [2, 3]},
                3: {'core_id': 48, 'thread_siblings': [2, 3]},
            },
        )
        _, icpus = op.inodes_get_inumas_icpus()
        core_ids = [c['core'] for c in icpus]
        self.assertEqual([32, 32, 48, 48], core_ids)

    def test_thread_id_correct_with_non_consecutive_core_ids(self):
        """thread_id is 0/1 based on sibling position, not core_id value."""
        op = self._make_op(
            numa_nodes=[0],
            cpulist_by_node={0: [0, 1, 2, 3]},
            topology_by_cpu={
                0: {'core_id': 16, 'thread_siblings': [0, 1]},
                1: {'core_id': 16, 'thread_siblings': [0, 1]},
                2: {'core_id': 48, 'thread_siblings': [2, 3]},
                3: {'core_id': 48, 'thread_siblings': [2, 3]},
            },
        )
        _, icpus = op.inodes_get_inumas_icpus()
        by_cpu = {c['cpu']: c for c in icpus}
        self.assertEqual(0, by_cpu[0]['thread'])
        self.assertEqual(1, by_cpu[1]['thread'])
        self.assertEqual(0, by_cpu[2]['thread'])
        self.assertEqual(1, by_cpu[3]['thread'])

    def test_non_consecutive_core_ids_across_numa_nodes(self):
        """Each NUMA node may have its own non-consecutive core_id space."""
        op = self._make_op(
            numa_nodes=[0, 1],
            cpulist_by_node={0: [0, 1], 1: [2, 3]},
            topology_by_cpu={
                # node 0: core_ids 0,1
                0: {'core_id': 0, 'thread_siblings': [0]},
                1: {'core_id': 1, 'thread_siblings': [1]},
                # node 1: core_ids restart at 32 (CCD offset)
                2: {'core_id': 32, 'thread_siblings': [2]},
                3: {'core_id': 33, 'thread_siblings': [3]},
            },
        )
        inumas, icpus = op.inodes_get_inumas_icpus()
        by_cpu = {c['cpu']: c for c in icpus}
        self.assertEqual(2, len(inumas))
        self.assertEqual(0, by_cpu[0]['core'])
        self.assertEqual(1, by_cpu[1]['core'])
        self.assertEqual(32, by_cpu[2]['core'])
        self.assertEqual(33, by_cpu[3]['core'])
        self.assertEqual(1, by_cpu[2]['numa_node'])
        self.assertEqual(1, by_cpu[3]['numa_node'])

    def test_duplicate_core_ids_across_nodes_are_independent(self):
        """Same core_id value on different NUMA nodes is valid and distinct."""
        op = self._make_op(
            numa_nodes=[0, 1],
            cpulist_by_node={0: [0, 1], 1: [2, 3]},
            topology_by_cpu={
                0: {'core_id': 0, 'thread_siblings': [0, 1]},
                1: {'core_id': 0, 'thread_siblings': [0, 1]},
                2: {'core_id': 0, 'thread_siblings': [2, 3]},
                3: {'core_id': 0, 'thread_siblings': [2, 3]},
            },
        )
        _, icpus = op.inodes_get_inumas_icpus()
        node0_cpus = [c for c in icpus if c['numa_node'] == 0]
        node1_cpus = [c for c in icpus if c['numa_node'] == 1]
        self.assertEqual(2, len(node0_cpus))
        self.assertEqual(2, len(node1_cpus))
        self.assertTrue(all(c['core'] == 0 for c in node0_cpus))
        self.assertTrue(all(c['core'] == 0 for c in node1_cpus))

    def test_single_thread_per_core_non_consecutive(self):
        """No hyperthreading: each cpu_id is its own sibling, non-consecutive core_ids."""
        op = self._make_op(
            numa_nodes=[0],
            cpulist_by_node={0: [0, 1, 2, 3]},
            topology_by_cpu={
                0: {'core_id': 0, 'thread_siblings': [0]},
                1: {'core_id': 3, 'thread_siblings': [1]},
                2: {'core_id': 7, 'thread_siblings': [2]},
                3: {'core_id': 15, 'thread_siblings': [3]},
            },
        )
        _, icpus = op.inodes_get_inumas_icpus()
        by_cpu = {c['cpu']: c for c in icpus}
        self.assertEqual(4, len(icpus))
        self.assertEqual(0, by_cpu[0]['core'])
        self.assertEqual(3, by_cpu[1]['core'])
        self.assertEqual(7, by_cpu[2]['core'])
        self.assertEqual(15, by_cpu[3]['core'])
        # all thread_ids must be 0 (no siblings)
        self.assertTrue(all(c['thread'] == 0 for c in icpus))

    def test_numa_node_assigned_correctly_with_non_consecutive_core_ids(self):
        """numa_node on each icpu reflects the node it was enumerated under."""
        op = self._make_op(
            numa_nodes=[0, 1, 2, 3],
            cpulist_by_node={0: [0], 1: [1], 2: [2], 3: [3]},
            topology_by_cpu={
                0: {'core_id': 100, 'thread_siblings': [0]},
                1: {'core_id': 100, 'thread_siblings': [1]},
                2: {'core_id': 100, 'thread_siblings': [2]},
                3: {'core_id': 100, 'thread_siblings': [3]},
            },
        )
        _, icpus = op.inodes_get_inumas_icpus()
        by_cpu = {c['cpu']: c for c in icpus}
        self.assertEqual(0, by_cpu[0]['numa_node'])
        self.assertEqual(1, by_cpu[1]['numa_node'])
        self.assertEqual(2, by_cpu[2]['numa_node'])
        self.assertEqual(3, by_cpu[3]['numa_node'])
