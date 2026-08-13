#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for scripts/upgrade_swact_migration.py."""

import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock

_script = os.path.join(os.path.dirname(__file__), '..', '..', 'scripts',
                       'upgrade_swact_migration.py')
_spec = (
    importlib.util.spec_from_file_location('upgrade_swact_migration',
                                           os.path.abspath(_script))
)
usm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(usm)


class TestMain(unittest.TestCase):
    """Tests for main function."""

    @mock.patch.object(usm, 'migrate_etcd_on_swact')
    @mock.patch.object(usm.log, 'configure')
    def test_main_migrate_etcd(self, _log, mock_migrate):
        with mock.patch.object(
                sys,
                'argv',
                ['prog', 'migrate_etcd', '1.0', '2.0']
        ):
            self.assertEqual(usm.main(), 0)
        mock_migrate.assert_called_once()

    @mock.patch.object(usm, 'upgrade_prepare_swact')
    @mock.patch.object(usm.log, 'configure')
    def test_main_prepare_swact(self, _log, mock_prep):
        with mock.patch.object(
                sys,
                'argv',
                ['prog', 'prepare_swact', '1.0', '2.0']
        ):
            self.assertEqual(usm.main(), 0)
        mock_prep.assert_called_once_with('1.0', '2.0')

    @mock.patch.object(
        usm,
        'migrate_etcd_on_swact',
        side_effect=Exception("fail")
    )
    @mock.patch.object(usm.log, 'configure')
    def test_main_migrate_exception(self, _log, _migrate):
        with mock.patch.object(sys, 'argv', ['prog', 'migrate_etcd']):
            self.assertEqual(usm.main(), 1)

    @mock.patch.object(usm.log, 'configure')
    def test_main_invalid_arg(self, _log):
        with mock.patch.object(
                sys,
                'argv',
                ['prog', 'a', 'b', 'c', 'extra']
        ):
            self.assertEqual(usm.main(), 1)


class TestUpgradePrepareSwact(unittest.TestCase):
    """Tests for upgrade_prepare_swact."""

    def test_writes_yaml(self):
        with tempfile.NamedTemporaryFile(mode='r', suffix='.yaml',
                                         delete=False) as f:
            fname = f.name
        try:
            with mock.patch.object(usm, 'UPGRADE_ETCD_FILE', fname):
                usm.upgrade_prepare_swact('1.0', '2.0')
            with open(fname) as f:
                content = f.read()
            self.assertIn('from_release', content)
        finally:
            os.unlink(fname)


class TestMigrateEtcdOnSwact(unittest.TestCase):
    """Tests for migrate_etcd_on_swact."""

    @mock.patch('shutil.copytree')
    @mock.patch('socket.gethostname', return_value='controller-0')
    def test_successful_migration(self, _host, _copy):
        with tempfile.TemporaryDirectory() as tmpdir:
            upgrade_file = os.path.join(tmpdir, '.upgrade_etcd')
            with open(upgrade_file, 'w') as f:
                f.write('from_release: "1.0"\nto_release: "2.0"\n')
            os.makedirs(os.path.join(tmpdir, '1.0'))
            with mock.patch.object(
                    usm,
                    'UPGRADE_ETCD_FILE',
                    upgrade_file
            ):
                with mock.patch.object(usm, 'ETCD_PATH', tmpdir):
                    usm.migrate_etcd_on_swact()
            self.assertFalse(os.path.exists(upgrade_file))

    @mock.patch('socket.gethostname', return_value='controller-0')
    def test_dest_already_exists(self, _host):
        with tempfile.TemporaryDirectory() as tmpdir:
            upgrade_file = os.path.join(tmpdir, '.upgrade_etcd')
            with open(upgrade_file, 'w') as f:
                f.write('from_release: "1.0"\nto_release: "2.0"\n')
            os.makedirs(os.path.join(tmpdir, '2.0'))
            with mock.patch.object(
                    usm,
                    'UPGRADE_ETCD_FILE',
                    upgrade_file
            ):
                with mock.patch.object(usm, 'ETCD_PATH', tmpdir):
                    usm.migrate_etcd_on_swact()
            self.assertFalse(os.path.exists(upgrade_file))


if __name__ == '__main__':
    unittest.main()
