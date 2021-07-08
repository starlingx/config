# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Base classes for our unit tests.

Allows overriding of config for use of fakes, and some black magic for
inline callbacks.

"""
import sys
import eventlet
eventlet.monkey_patch(os=False)

import copy
import fixtures
import mock
import os
import testtools

from oslo_config import cfg
from oslo_db.sqlalchemy import enginefacade
from oslo_log import log as logging
from oslo_utils import timeutils

from sysinv.db import api as dbapi
from sysinv.db import migration as db_migration
from sysinv.db.sqlalchemy import migration

import sysinv.helm.utils
from sysinv.objects import base as objects_base
from sysinv.tests import conf_fixture
from sysinv.tests import policy_fixture

sys.modules['fm_core'] = mock.Mock()
sys.modules['rpm'] = mock.Mock()

CONF = cfg.CONF
_DB_CACHE = None


class Database(fixtures.Fixture):

    def __init__(self, engine, db_migrate, sql_connection):
        self.sql_connection = sql_connection

        self.engine = engine
        self.engine.dispose()
        conn = self.engine.connect()
        self.setup_sqlite(db_migrate)

        self.post_migrations()
        self._DB = "".join(line for line in conn.connection.iterdump())
        self.engine.dispose()

    def setup_sqlite(self, db_migrate):
        if db_migrate.db_version() > db_migration.INIT_VERSION:
            return
        db_migrate.db_sync()

    def setUp(self):
        super(Database, self).setUp()

        conn = self.engine.connect()
        conn.connection.executescript(self._DB)
        self.addCleanup(self.engine.dispose)

    def post_migrations(self):
        """Any addition steps that are needed outside of the migrations."""
        # This is a workaround for unit test only.
        # The migration of adding edgeworker personality works with postgres
        # db. But sqlite db which is used by unit test neither supports
        # ALTER TYPE to introduce a new personality, nor supports adding
        # a new CHECK contraint to an existing table. This implements the
        # migration of version 109 to add an edgeworker personality enum
        # to i_host table.
        personality_check_old = "CHECK (personality IN ('controller', " + \
            "'worker', 'network', 'storage', 'profile', 'reserve1', " + \
            "'reserve2'))"
        personality_check_new = "CHECK (personality IN ('controller', " + \
            "'worker', 'network', 'storage', 'profile', 'reserve1', " + \
            "'reserve2', 'edgeworker'))"
        results = self.engine.execute("SELECT sql FROM sqlite_master \
            WHERE type='table' AND name='i_host'")
        create_i_host = list(results.first().values())[0]
        create_i_host = create_i_host.replace(personality_check_old,
                                               personality_check_new)
        self.engine.execute("ALTER TABLE i_host RENAME TO i_host_bak")
        self.engine.execute(create_i_host)


class ReplaceModule(fixtures.Fixture):
    """Replace a module with a fake module."""

    def __init__(self, name, new_value):
        self.name = name
        self.new_value = new_value

    def _restore(self, old_value):
        sys.modules[self.name] = old_value

    def setUp(self):
        super(ReplaceModule, self).setUp()
        old_value = sys.modules.get(self.name)
        sys.modules[self.name] = self.new_value
        self.addCleanup(self._restore, old_value)


class TestingException(Exception):
    pass


class TestCase(testtools.TestCase):
    """Test case base class for all unit tests."""

    helm_refresh_patcher = mock.patch.object(sysinv.helm.utils, 'refresh_helm_repo_information')

    def setUp(self):
        """Run before each test method to initialize test environment."""
        super(TestCase, self).setUp()
        self.mock_helm_refresh = self.helm_refresh_patcher.start()

        self.dbapi = dbapi.get_instance()

        test_timeout = os.environ.get('OS_TEST_TIMEOUT', 0)
        try:
            test_timeout = int(test_timeout)
        except ValueError:
            # If timeout value is invalid do not set a timeout.
            test_timeout = 0
        if test_timeout > 0:
            self.useFixture(fixtures.Timeout(test_timeout, gentle=True))
        self.useFixture(fixtures.NestedTempfile())
        self.useFixture(fixtures.TempHomeDir())

        if (os.environ.get('OS_STDOUT_CAPTURE') == 'True' or
                os.environ.get('OS_STDOUT_CAPTURE') == '1'):
            stdout = self.useFixture(fixtures.StringStream('stdout')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stdout', stdout))
        if (os.environ.get('OS_STDERR_CAPTURE') == 'True' or
                os.environ.get('OS_STDERR_CAPTURE') == '1'):
            stderr = self.useFixture(fixtures.StringStream('stderr')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stderr', stderr))

        self.log_fixture = self.useFixture(fixtures.FakeLogger())

        def fake_logging_setup(*args):
            pass

        self.useFixture(
            fixtures.MonkeyPatch('oslo_log.log.setup', fake_logging_setup))
        logging.register_options(CONF)

        self.useFixture(conf_fixture.ConfFixture(CONF))
        # The fixture config is not setup when the DB_CACHE below is being constructed
        self.config(connection="sqlite://",
                    sqlite_synchronous=False,
                    group='database')

        # NOTE(danms): Make sure to reset us back to non-remote objects
        # for each test to avoid interactions. Also, backup the object
        # registry
        objects_base.SysinvObject.indirection_api = None
        self._base_test_obj_backup = copy.copy(
                objects_base.SysinvObject._obj_classes)
        self.addCleanup(self._restore_obj_registry)

        self.addCleanup(self._clear_attrs)
        self.useFixture(fixtures.EnvironmentVariable('http_proxy'))
        self.policy = self.useFixture(policy_fixture.PolicyFixture())
        CONF.set_override('fatal_exception_format_errors', True)

        global _DB_CACHE
        if not _DB_CACHE:
            engine = enginefacade.get_legacy_facade().get_engine()
            _DB_CACHE = Database(engine, migration,
                                 sql_connection=CONF.database.connection)
        self.useFixture(_DB_CACHE)

    def tearDown(self):
        super(TestCase, self).tearDown()
        self.helm_refresh_patcher.stop()

    def _restore_obj_registry(self):
        objects_base.SysinvObject._obj_classes = self._base_test_obj_backup

    def _clear_attrs(self):
        # Delete attributes that don't start with _ so they don't pin
        # memory around unnecessarily for the duration of the test
        # suite
        for key in [k for k in self.__dict__.keys() if k[0] != '_']:
            del self.__dict__[key]

    def config(self, **kw):
        """Override config options for a test."""
        group = kw.pop('group', None)
        for k, v in kw.items():
            CONF.set_override(k, v, group)

    def path_get(self, project_file=None):
        """Get the absolute path to a file. Used for testing the API.

        :param project_file: File whose path to return. Default: None.
        :returns: path to the specified file, or path to project root.
        """
        root = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                            '..',
                                            '..',
                                            )
                               )
        if project_file:
            return os.path.join(root, project_file)
        else:
            return root

    def stub_out(self, old, new):
        """Replace a function for the duration of the test.

        Use the monkey patch fixture to replace a function for the
        duration of a test. Useful when you want to provide fake
        methods instead of mocks during testing.
        """
        self.useFixture(fixtures.MonkeyPatch(old, new))


class TimeOverride(fixtures.Fixture):
    """Fixture to start and remove time override."""

    def setUp(self):
        super(TimeOverride, self).setUp()
        timeutils.set_time_override()
        self.addCleanup(timeutils.clear_time_override)
