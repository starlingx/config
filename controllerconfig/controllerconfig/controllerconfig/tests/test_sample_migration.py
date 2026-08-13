#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for scripts/00-sample-migration.py."""

import importlib.util
import os
import sys
import unittest
from unittest import mock

sys.modules.setdefault('psycopg2', mock.MagicMock())
sys.modules.setdefault('psycopg2.extras', mock.MagicMock())

_script = os.path.join(os.path.dirname(__file__), '..', '..', 'scripts',
                       '00-sample-migration.py')
_spec = importlib.util.spec_from_file_location('sample_migration',
                                               os.path.abspath(_script))
sample_migration = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sample_migration)


class TestMain(unittest.TestCase):
    """Tests for main function."""

    @mock.patch.object(sample_migration.log, 'configure')
    def test_main_no_action(self, _log):
        with mock.patch.object(sys, 'argv', ['prog', '17.06', '18.03']):
            result = sample_migration.main()
        self.assertIsNone(result)

    @mock.patch.object(sample_migration, 'do_migration_work',
                       side_effect=Exception("db error"))
    @mock.patch.object(sample_migration.log, 'configure')
    def test_main_migrate_exception(self, _log, _work):
        with mock.patch.object(
                sys,
                'argv',
                ['prog', '17.06', '18.03', 'migrate']
        ):
            self.assertEqual(sample_migration.main(), 1)

    @mock.patch.object(sample_migration.log, 'configure')
    def test_main_wrong_release(self, _log):
        with mock.patch.object(
                sys,
                'argv',
                ['prog', '20.06', '21.06', 'migrate']
        ):
            result = sample_migration.main()
        self.assertIsNone(result)

    @mock.patch.object(sample_migration.log, 'configure')
    def test_main_invalid_arg(self, _log):
        with mock.patch.object(
                sys,
                'argv',
                ['prog', 'a', 'b', 'c', 'extra']
        ):
            self.assertEqual(sample_migration.main(), 1)


if __name__ == '__main__':
    unittest.main()
