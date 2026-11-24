#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the manage-partitions script.
"""

import importlib.machinery
import importlib.util
import json
import os

import mock
from oslo_config import cfg

from sysinv.common import constants
from sysinv.tests import base

SCRIPT_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'scripts',
    'manage-partitions'))


def _load_manage_partitions():
    # The script has no .py extension and registers a CLI option at import
    # time, which would clash with the already parsed global CONF.
    loader = importlib.machinery.SourceFileLoader('manage_partitions',
                                                  SCRIPT_PATH)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.object(cfg.CONF, 'register_cli_opt'):
        loader.exec_module(module)
    return module


manage_partitions = None


def setUpModule():
    # Load here, not at import, so a script load failure is reported as a
    # module setup error instead of breaking test collection.
    global manage_partitions
    manage_partitions = _load_manage_partitions()


class TestMiBToSectors(base.TestCase):

    def test_returns_int(self):
        sectors = manage_partitions._MiB_to_sectors(1, 512)
        self.assertIsInstance(sectors, int)
        self.assertEqual(2048, sectors)

    def test_4k_sectors(self):
        sectors = manage_partitions._MiB_to_sectors(102401, 4096)
        self.assertIsInstance(sectors, int)
        self.assertEqual(102401 * 256, sectors)

    def test_float_input_returns_int(self):
        sectors = manage_partitions._MiB_to_sectors(1025.0, 512)
        self.assertIsInstance(sectors, int)
        self.assertEqual(1025 * 2048, sectors)


PARTED_FREE_OUTPUT = """BYT;
/dev/sdb:937703088s:scsi:512:512:gpt:DELL PERC H730P Mini:;
1:34s:2047s:2014s:free;
1:2048s:2099199s:2097152s::LVM Physical Volume:lvm;
2:2099200s:4196351s:2097152s::LVM Physical Volume:lvm;
1:4196352s:937703054s:933506703s:free;
"""


class TestParseFreeSectors(base.TestCase):

    def test_parse(self):
        self.assertEqual(
            [(34, 2047), (4196352, 937703054)],
            manage_partitions._parse_free_sectors(PARTED_FREE_OUTPUT))

    def test_no_free_space(self):
        output = ("BYT;\n"
                  "/dev/sdb:4196352s:scsi:512:512:gpt:disk:;\n"
                  "1:2048s:4196351s:4194304s::LVM Physical Volume:lvm;\n")
        self.assertEqual([], manage_partitions._parse_free_sectors(output))


class TestGetFreeSectors(base.TestCase):

    def test_parted_error_raises(self):
        with mock.patch.object(manage_partitions, '_command',
                               return_value=('', 'unrecognised disk label', 1)):
            self.assertRaisesRegex(
                IOError, 'Could not read free space on disk /dev/sdb: '
                         'unrecognised disk label',
                manage_partitions._get_free_sectors, '/dev/sdb')


class TestRangeInFreeSpace(base.TestCase):

    free = [(34, 2047), (4196352, 937703054)]

    def test_inside(self):
        self.assertTrue(manage_partitions._range_in_free_space(
            self.free, 4196352, 2097152))

    def test_exactly_fills_region(self):
        self.assertTrue(manage_partitions._range_in_free_space(
            self.free, 4196352, 937703054 - 4196352 + 1))

    def test_overlaps_previous_partition(self):
        self.assertFalse(manage_partitions._range_in_free_space(
            self.free, 4196351, 2097152))

    def test_past_end_of_region(self):
        self.assertFalse(manage_partitions._range_in_free_space(
            self.free, 4196352, 937703054 - 4196352 + 2))

    def test_spans_two_regions(self):
        self.assertFalse(manage_partitions._range_in_free_space(
            self.free, 34, 4196352))

    def test_no_free_regions(self):
        self.assertFalse(manage_partitions._range_in_free_space(
            [], 2048, 2048))


class TestCreatePartitionFreeSpaceCheck(base.TestCase):

    def setUp(self):
        super(TestCreatePartitionFreeSpaceCheck, self).setUp()
        patcher = mock.patch.object(manage_partitions,
                                    '_get_disk_sector_size',
                                    return_value=512)
        self.mock_sector_size = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(manage_partitions, '_get_free_sectors',
                                    return_value=[(4196352, 937703054)])
        self.mock_get_free = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(manage_partitions, '_wipe_partition')
        self.mock_wipe = patcher.start()
        self.addCleanup(patcher.stop)

    def test_overlap_raises_before_wipe(self):
        # 2048 MiB = sector 4194304, inside partition 2
        self.assertRaisesRegex(IOError,
                               r'\(start sector 4194304, 2097152 sectors\)',
                               manage_partitions._create_partition,
                               '/dev/sdb', 3, 2048, 1024, 'guid')
        self.mock_wipe.assert_not_called()

    def test_free_range_wipes(self):
        # 2049 MiB start, 1024 MiB size, at the start of the free region
        for sector_size, start, size in ((512, 4196352, 2097152),
                                         (4096, 524544, 262144)):
            with self.subTest(sector_size=sector_size):
                self.mock_sector_size.return_value = sector_size
                self.mock_get_free.return_value = [(start, start + size)]
                self.mock_wipe.reset_mock()
                with mock.patch.object(manage_partitions, '_command',
                                       side_effect=Exception('stop')):
                    self.assertRaisesRegex(
                        Exception, 'stop',
                        manage_partitions._create_partition,
                        '/dev/sdb', 3, 2049, 1024, 'guid')
                self.mock_wipe.assert_called_once_with('/dev/sdb', start,
                                                       size, sector_size)

    def test_skip_wipe_skips_check(self):
        with mock.patch.object(manage_partitions, '_command',
                               side_effect=Exception('stop')):
            self.assertRaisesRegex(Exception, 'stop',
                                   manage_partitions._create_partition,
                                   '/dev/sdb', 3, 2048, 1024, 'guid',
                                   skip_wipe=True)
        self.mock_get_free.assert_not_called()
        self.mock_wipe.assert_not_called()


class TestErrorHandlers(base.TestCase):
    """Errors must be logged and reported."""

    def setUp(self):
        super(TestErrorHandlers, self).setUp()
        self.mp = manage_partitions
        patcher = mock.patch.object(self.mp, 'LOG')
        self.mock_log = patcher.start()
        self.addCleanup(patcher.stop)

    def _patch(self, name, **kwargs):
        patcher = mock.patch.object(self.mp, name, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def _assert_logged(self, text):
        self.assertIn(text, str(self.mock_log.error.call_args))

    def test_create_error_sets_error_status(self):
        self._patch('_gpt_table_present', return_value=True)
        self._patch('_partition_exists', return_value=False)
        self._patch('_get_free_space', return_value=[{'start_mib': '1'}])
        self._patch('_get_no_of_partitions', return_value=0)
        self._patch('_create_partition', side_effect=IOError('boom'))
        send = self._patch('_send_inventory_update')
        data = json.dumps([{
            'disk_device_path': '/dev/sdb',
            'part_device_path': '/dev/sdb-part1',
            'req_size_mib': 1024, 'req_guid': 'guid',
            'req_uuid': 'uuid', 'ihost_uuid': 'host'}])

        self.mp.create_partitions(data, 'send', None)

        send.assert_called_once_with({
            'uuid': 'uuid', 'ihost_uuid': 'host',
            'status': constants.PARTITION_ERROR_STATUS})
        self._assert_logged('boom')

    def test_delete_error_sets_error_status(self):
        self._patch('_gpt_table_present', return_value=True)
        self._patch('_delete_partition', side_effect=IOError('boom'))
        self._patch('_command', return_value=('', '', 0))
        send = self._patch('_send_inventory_update')
        data = json.dumps([{
            'part_device_path': '/dev/disk/by-path/pci-0:1:0-part1',
            'current_uuid': 'uuid', 'ihost_uuid': 'host'}])

        self.mp.delete_partitions(data, 'send', None)

        send.assert_called_once_with({
            'uuid': 'uuid', 'ihost_uuid': 'host',
            'status': constants.PARTITION_ERROR_STATUS})
        self._assert_logged('boom')

    def test_resize_error_reraises_original(self):
        self._patch('_delete_partition')
        self._patch('_create_partition', side_effect=IOError('boom'))

        self.assertRaisesRegex(IOError, 'boom',
                               self.mp._resize_partition,
                               '/dev/sdb', 1, 2048, 1, 'guid')
        self._assert_logged('boom')
