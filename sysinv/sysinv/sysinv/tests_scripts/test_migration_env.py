#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for sysinv/db/sqlalchemy/migrations/env.py."""

import importlib.util
import os
import unittest
from unittest import mock

ENV_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', 'sysinv',
    'db', 'sqlalchemy', 'migrations', 'env.py'))


class TestMigrationEnv(unittest.TestCase):
    """Tests for alembic env.py."""

    @mock.patch('alembic.context')
    @mock.patch('oslo_config.cfg.CONF')
    @mock.patch('oslo_db.options.set_defaults')
    @mock.patch('logging.config.fileConfig')
    def test_env_loads_offline(self,
                               _filecfg,
                               _set_defaults,
                               mock_conf,
                               mock_ctx
                               ):
        mock_ctx.config = mock.MagicMock()
        mock_ctx.config.config_file_name = None
        mock_ctx.is_offline_mode.return_value = True
        mock_ctx.get_main_option.return_value = 'sqlite://'
        mock_conf.database.connection = 'sqlite://'

        spec = importlib.util.spec_from_file_location(
            'env_test',
            ENV_PATH
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        self.assertTrue(hasattr(mod, 'run_migrations_offline'))
        self.assertTrue(hasattr(mod, 'run_migrations_online'))


if __name__ == '__main__':
    unittest.main()
