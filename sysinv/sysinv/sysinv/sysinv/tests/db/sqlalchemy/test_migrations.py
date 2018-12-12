# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2016 Wind River Systems, Inc.
# Copyright 2010-2011 OpenStack Foundation
# Copyright 2012-2013 IBM Corp.
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

"""
Tests for database migrations. This test case reads the configuration
file test_migrations.conf for database connection settings
to use in the tests. For each connection found in the config file,
the test case runs a series of test cases to ensure that migrations work
properly.

There are also "opportunistic" tests for both mysql and postgresql in here,
which allows testing against all 3 databases (sqlite in memory, mysql, pg) in
a properly configured unit test environment.

For the opportunistic testing you need to set up a db named 'openstack_citest'
with user 'openstack_citest' and password 'openstack_citest' on localhost.
The test will then use that db and u/p combo to run the tests.

For postgres on Ubuntu this can be done with the following commands:

sudo -u postgres psql
postgres=# create user openstack_citest with createdb login password
      'openstack_citest';
postgres=# create database openstack_citest with owner openstack_citest;

"""

import commands
from six.moves import configparser
import os
from six.moves.urllib.parse import urlparse

import mock
import sqlalchemy
import sqlalchemy.exc

from migrate.versioning import repository
from oslo_db.sqlalchemy import utils as db_utils
from sqlalchemy import MetaData, Table
from sysinv.openstack.common import lockutils
from sysinv.openstack.common import log as logging

import sysinv.db.sqlalchemy.migrate_repo
from sysinv.tests import utils as test_utils

LOG = logging.getLogger(__name__)


def _get_connect_string(backend, user, passwd, database):
    """Get database connection

    Try to get a connection with a very specific set of values, if we get
    these then we'll run the tests, otherwise they are skipped
    """
    if backend == "postgres":
        backend = "postgresql+psycopg2"
    elif backend == "mysql":
        backend = "mysql+mysqldb"
    # Presently returns a connection string to set up an sqlite db in memory
    # if user, passwd, and databse are not empty strings, the connection string
    # will be invalid. Can change string format to make db on disk, but no
    # user/pass is directly supported by sqlite.
    elif backend == "sqlite":
        backend = "sqlite"
        return ("%(backend)s://%(user)s%(passwd)s%(database)s"
                % {'backend': backend, 'user': user, 'passwd': passwd,
                    'database': database})
    else:
        raise Exception("Unrecognized backend: '%s'" % backend)

    return ("%(backend)s://%(user)s:%(passwd)s@localhost/%(database)s"
            % {'backend': backend, 'user': user, 'passwd': passwd,
                'database': database})


def _is_backend_avail(backend, user, passwd, database):
    try:
        connect_uri = _get_connect_string(backend, user, passwd, database)
        engine = sqlalchemy.create_engine(connect_uri)
        connection = engine.connect()
    except Exception:
        # intentionally catch all to handle exceptions even if we don't
        # have any backend code loaded.
        return False
    else:
        connection.close()
        engine.dispose()
        return True


def _have_sqlite(user, passwd, database):
    present = os.environ.get('TEST_SQLITE_PRESENT')
    if present is None:
        # If using in-memory db for sqlite, no database should be specified
        # and user/passwd aren't directly supported by sqlite, thus we send
        # empty strings so we can connect with 'sqlite://'. If you decide to
        # use an on-disk sqlite db, replace the empty strings below.
        return _is_backend_avail('sqlite', '', '', '')
    return present.lower() in ('', 'true')


def _have_mysql(user, passwd, database):
    present = os.environ.get('TEST_MYSQL_PRESENT')
    if present is None:
        return _is_backend_avail('mysql', user, passwd, database)
    return present.lower() in ('', 'true')


def _have_postgresql(user, passwd, database):
    present = os.environ.get('TEST_POSTGRESQL_PRESENT')
    if present is None:
        return _is_backend_avail('postgres', user, passwd, database)
    return present.lower() in ('', 'true')


def get_db_connection_info(conn_pieces):
    """Gets user, pass, db, and host for each dialect

       Strips connection strings in test_migrations.conf for each corresponding
       dialect in the file to get values for each component in the connection
       string.
    """
    database = conn_pieces.path.strip('/')
    loc_pieces = conn_pieces.netloc.split('@')
    host = loc_pieces[1]

    auth_pieces = loc_pieces[0].split(':')
    user = auth_pieces[0]
    password = ""
    if len(auth_pieces) > 1:
        password = auth_pieces[1].strip()

    return (user, password, database, host)


class BaseMigrationTestCase(test_utils.BaseTestCase):
    """Base class for testing of migration utils."""

    def __init__(self, *args, **kwargs):
        super(BaseMigrationTestCase, self).__init__(*args, **kwargs)

        self.DEFAULT_CONFIG_FILE = os.path.join(os.path.dirname(__file__),
                                                'test_migrations.conf')
        # Test machines can set the TEST_MIGRATIONS_CONF variable
        # to override the location of the config file for migration testing
        self.CONFIG_FILE_PATH = os.environ.get('TEST_MIGRATIONS_CONF',
                                               self.DEFAULT_CONFIG_FILE)
        self.test_databases = {}
        self.migration_api = None

    def setUp(self):
        super(BaseMigrationTestCase, self).setUp()

        # Load test databases from the config file. Only do this
        # once. No need to re-run this on each test...
        LOG.debug('config_path is %s' % self.CONFIG_FILE_PATH)
        if os.path.exists(self.CONFIG_FILE_PATH):
            cp = configparser.RawConfigParser()
            try:
                cp.read(self.CONFIG_FILE_PATH)
                defaults = cp.defaults()
                for key, value in defaults.items():
                    self.test_databases[key] = value
            except configparser.ParsingError as e:
                self.fail("Failed to read test_migrations.conf config "
                          "file. Got error: %s" % e)
        else:
            self.fail("Failed to find test_migrations.conf config "
                      "file.")

        self.engines = {}
        for key, value in self.test_databases.items():
            self.engines[key] = sqlalchemy.create_engine(value)

        # We start each test case with a completely blank slate.
        self._reset_databases()

    def tearDown(self):
        # We destroy the test data store between each test case,
        # and recreate it, which ensures that we have no side-effects
        # from the tests
        self._reset_databases()
        super(BaseMigrationTestCase, self).tearDown()

    def execute_cmd(self, cmd=None):
        status, output = commands.getstatusoutput(cmd)
        LOG.debug(output)
        self.assertEqual(0, status,
                         "Failed to run: %s\n%s" % (cmd, output))

    @lockutils.synchronized('pgadmin', 'tests-', external=True)
    def _reset_pg(self, conn_pieces):
        """Resets postgresql db
        """
        (user, password, database, host) = get_db_connection_info(conn_pieces)
        # If the user and pass in your connection strings in
        # test_migrations.conf don't match the user and pass of a pre-existing
        # psql db on your host machine, you either need to create a psql role
        # (user) to match, or must change the values in your conf file.
        os.environ['PGPASSWORD'] = password
        os.environ['PGUSER'] = user
        # note(boris-42): We must create and drop database, we can't
        # drop database which we have connected to, so for such
        # operations there is a special database template1.
        sqlcmd = ("psql -w -U %(user)s -h %(host)s -c"
                  " '%(sql)s' -d template1")

        sql = ("drop database if exists %s;") % database
        droptable = sqlcmd % {'user': user, 'host': host, 'sql': sql}
        self.execute_cmd(droptable)

        sql = ("create database %s;") % database
        createtable = sqlcmd % {'user': user, 'host': host, 'sql': sql}
        self.execute_cmd(createtable)

        os.unsetenv('PGPASSWORD')
        os.unsetenv('PGUSER')

    def _reset_databases(self):
        for key, engine in self.engines.items():
            conn_string = self.test_databases[key]
            conn_pieces = urlparse(conn_string)

            engine.dispose()
            if conn_string.startswith('sqlite'):
                # We can just delete the SQLite database, which is
                # the easiest and cleanest solution
                db_path = conn_pieces.path.strip('/')
                if os.path.exists(db_path):
                    os.unlink(db_path)
                # No need to recreate the SQLite DB. SQLite will
                # create it for us if it's not there...
            elif conn_string.startswith('mysql'):
                # We can execute the MySQL client to destroy and re-create
                # the MYSQL database, which is easier and less error-prone
                # than using SQLAlchemy to do this via MetaData...trust me.

                (user, password, database, host) = \
                    get_db_connection_info(conn_pieces)
                sql = ("drop database if exists %(database)s; "
                        "create database %(database)s;") % {'database': database}
                cmd = ("mysql -u \"%(user)s\" -p\"%(password)s\" -h %(host)s "
                        "-e \"%(sql)s\"") % {'user': user, 'password': password,
                                            'host': host, 'sql': sql}

                self.execute_cmd(cmd)
            elif conn_string.startswith('postgresql'):
                pass
                """
                The below code has been commented out because the above for-loop
                cycles through all backend types (sqlite, mysql, postgresql) and
                postgres is not set up on the build/jenkins servers and will cause
                errors when _reset_pg tries to run psql commands. This pass allows
                non-postgresql tests to run because all tests call setup which
                calls _reset_databases.

                self._reset_pg(conn_pieces)
                """


class WalkVersionsMixin(object):
    def _walk_versions(self, engine=None, snake_walk=False, downgrade=True):
        # Determine latest version script from the repo, then
        # upgrade from 1 through to the latest, with no data
        # in the databases. This just checks that the schema itself
        # upgrades successfully.

        # Place the database under version control

        self.migration_api.version_control(engine, self.REPOSITORY,
                                           self.INIT_VERSION)
        self.assertEqual(self.INIT_VERSION,
                         self.migration_api.db_version(engine,
                                                       self.REPOSITORY))
        # downgrade=False  # JKUNG so we can examing the db

        LOG.debug('latest version is %s' % self.REPOSITORY.latest)
        versions = range(self.INIT_VERSION + 1, self.REPOSITORY.latest + 1)

        for version in versions:
            # upgrade -> downgrade -> upgrade
            self._migrate_up(engine, version, with_data=True)
            if snake_walk:
                downgraded = self._migrate_down(
                    engine, version - 1, with_data=True)
                if downgraded:
                    self._migrate_up(engine, version)
        if downgrade:
            # Now walk it back down to 0 from the latest, testing
            # the downgrade paths.
            for version in reversed(versions):
                # downgrade -> upgrade -> downgrade
                downgraded = self._migrate_down(engine, version - 1)

                if snake_walk and downgraded:
                    self._migrate_up(engine, version)
                    self._migrate_down(engine, version - 1)

    def _migrate_down(self, engine, version, with_data=False):
        try:
            self.migration_api.downgrade(engine, self.REPOSITORY, version)
        except NotImplementedError:
            # NOTE(sirp): some migrations, namely release-level
            # migrations, don't support a downgrade.
            return False

        self.assertEqual(
            version, self.migration_api.db_version(engine, self.REPOSITORY))

        # NOTE(sirp): `version` is what we're downgrading to (i.e. the 'target'
        # version). So if we have any downgrade checks, they need to be run for
        # the previous (higher numbered) migration.
        if with_data:
            post_downgrade = getattr(
                self, "_post_downgrade_%03d" % (version + 1), None)
            if post_downgrade:
                post_downgrade(engine)

        return True

    def _migrate_up(self, engine, version, with_data=False):
        """migrate up to a new version of the db.

        We allow for data insertion and post checks at every
        migration version with special _pre_upgrade_### and
        _check_### functions in the main test.
        """
        # NOTE(sdague): try block is here because it's impossible to debug
        # where a failed data migration happens otherwise
        try:
            if with_data:
                data = None
                pre_upgrade = getattr(
                    self, "_pre_upgrade_%03d" % version, None)
                if pre_upgrade:
                    data = pre_upgrade(engine)

            self.migration_api.upgrade(engine, self.REPOSITORY, version)
            self.assertEqual(version,
                             self.migration_api.db_version(engine,
                                                           self.REPOSITORY))
            if with_data:
                check = getattr(self, "_check_%03d" % version, None)
                if check:
                    check(engine, data)
        except Exception:
            LOG.error("Failed to migrate to version %s on engine %s" %
                      (version, engine))
            raise


class TestWalkVersions(test_utils.BaseTestCase, WalkVersionsMixin):
    def setUp(self):
        super(TestWalkVersions, self).setUp()
        self.migration_api = mock.MagicMock()
        self.engine = mock.MagicMock()
        self.REPOSITORY = mock.MagicMock()
        self.INIT_VERSION = 4

    def test_migrate_up(self):
        self.migration_api.db_version.return_value = 141

        self._migrate_up(self.engine, 141)

        self.migration_api.upgrade.assert_called_with(
            self.engine, self.REPOSITORY, 141)
        self.migration_api.db_version.assert_called_with(
            self.engine, self.REPOSITORY)

    def test_migrate_up_with_data(self):
        test_value = {"a": 1, "b": 2}
        self.migration_api.db_version.return_value = 141
        self._pre_upgrade_141 = mock.MagicMock()
        self._pre_upgrade_141.return_value = test_value
        self._check_141 = mock.MagicMock()

        self._migrate_up(self.engine, 141, True)

        self._pre_upgrade_141.assert_called_with(self.engine)
        self._check_141.assert_called_with(self.engine, test_value)

    def test_migrate_down(self):
        self.migration_api.db_version.return_value = 42

        self.assertTrue(self._migrate_down(self.engine, 42))
        self.migration_api.db_version.assert_called_with(
            self.engine, self.REPOSITORY)

    def test_migrate_down_not_implemented(self):
        self.migration_api.downgrade.side_effect = NotImplementedError
        self.assertFalse(self._migrate_down(self.engine, 42))

    def test_migrate_down_with_data(self):
        self._post_downgrade_043 = mock.MagicMock()
        self.migration_api.db_version.return_value = 42

        self._migrate_down(self.engine, 42, True)

        self._post_downgrade_043.assert_called_with(self.engine)

    @mock.patch.object(WalkVersionsMixin, '_migrate_up')
    @mock.patch.object(WalkVersionsMixin, '_migrate_down')
    def test_walk_versions_all_default(self, _migrate_up, _migrate_down):
        self.REPOSITORY.latest = 20
        self.migration_api.db_version.return_value = self.INIT_VERSION

        self._walk_versions()

        self.migration_api.version_control.assert_called_with(
            None, self.REPOSITORY, self.INIT_VERSION)
        self.migration_api.db_version.assert_called_with(
            None, self.REPOSITORY)

        versions = range(self.INIT_VERSION + 1, self.REPOSITORY.latest + 1)
        upgraded = [mock.call(None, v, with_data=True) for v in versions]
        self.assertEqual(self._migrate_up.call_args_list, upgraded)

        downgraded = [mock.call(None, v - 1) for v in reversed(versions)]
        self.assertEqual(self._migrate_down.call_args_list, downgraded)

    @mock.patch.object(WalkVersionsMixin, '_migrate_up')
    @mock.patch.object(WalkVersionsMixin, '_migrate_down')
    def test_walk_versions_all_true(self, _migrate_up, _migrate_down):
        self.REPOSITORY.latest = 20
        self.migration_api.db_version.return_value = self.INIT_VERSION

        self._walk_versions(self.engine, snake_walk=True, downgrade=True)

        versions = range(self.INIT_VERSION + 1, self.REPOSITORY.latest + 1)
        upgraded = []
        for v in versions:
            upgraded.append(mock.call(self.engine, v, with_data=True))
            upgraded.append(mock.call(self.engine, v))
        upgraded.extend(
            [mock.call(self.engine, v) for v in reversed(versions)]
        )
        self.assertEqual(upgraded, self._migrate_up.call_args_list)

        downgraded_1 = [
            mock.call(self.engine, v - 1, with_data=True) for v in versions
        ]
        downgraded_2 = []
        for v in reversed(versions):
            downgraded_2.append(mock.call(self.engine, v - 1))
            downgraded_2.append(mock.call(self.engine, v - 1))
        downgraded = downgraded_1 + downgraded_2
        self.assertEqual(self._migrate_down.call_args_list, downgraded)

    @mock.patch.object(WalkVersionsMixin, '_migrate_up')
    @mock.patch.object(WalkVersionsMixin, '_migrate_down')
    def test_walk_versions_true_false(self, _migrate_up, _migrate_down):
        self.REPOSITORY.latest = 20
        self.migration_api.db_version.return_value = self.INIT_VERSION

        self._walk_versions(self.engine, snake_walk=True, downgrade=False)

        versions = range(self.INIT_VERSION + 1, self.REPOSITORY.latest + 1)

        upgraded = []
        for v in versions:
            upgraded.append(mock.call(self.engine, v, with_data=True))
            upgraded.append(mock.call(self.engine, v))
        self.assertEqual(upgraded, self._migrate_up.call_args_list)

        downgraded = [
            mock.call(self.engine, v - 1, with_data=True) for v in versions
        ]
        self.assertEqual(self._migrate_down.call_args_list, downgraded)

    @mock.patch.object(WalkVersionsMixin, '_migrate_up')
    @mock.patch.object(WalkVersionsMixin, '_migrate_down')
    def test_walk_versions_all_false(self, _migrate_up, _migrate_down):
        self.REPOSITORY.latest = 20
        self.migration_api.db_version.return_value = self.INIT_VERSION

        self._walk_versions(self.engine, snake_walk=False, downgrade=False)

        versions = range(self.INIT_VERSION + 1, self.REPOSITORY.latest + 1)

        upgraded = [
            mock.call(self.engine, v, with_data=True) for v in versions
        ]
        self.assertEqual(upgraded, self._migrate_up.call_args_list)


class TestMigrations(BaseMigrationTestCase, WalkVersionsMixin):
    # openstack_citest is used as the credentials to connect to a pre-existing
    # db that was made using these values (you may have to make this yourself
    # if you've never run these tests before).
    USER = "openstack_citest"
    PASSWD = "openstack_citest"
    DATABASE = "openstack_citest"

    def __init__(self, *args, **kwargs):
        super(TestMigrations, self).__init__(*args, **kwargs)

        self.MIGRATE_FILE = sysinv.db.sqlalchemy.migrate_repo.__file__
        self.REPOSITORY = repository.Repository(
                        os.path.abspath(os.path.dirname(self.MIGRATE_FILE)))

    def setUp(self):
        super(TestMigrations, self).setUp()

        self.migration = __import__('sysinv.db.migration',
                                    globals(), locals(), ['INIT_VERSION'], -1)
        self.INIT_VERSION = self.migration.INIT_VERSION
        if self.migration_api is None:
            temp = __import__('sysinv.db.sqlalchemy.migration',
                                globals(), locals(), ['versioning_api'], -1)
            self.migration_api = temp.versioning_api

    def column_exists(self, engine, table_name, column):
        metadata = MetaData()
        metadata.bind = engine
        table = Table(table_name, metadata, autoload=True)
        return column in table.c

    def assertColumnExists(self, engine, table_name, column):
        self.assertTrue(self.column_exists(engine, table_name, column),
                        'Column %s.%s does not exist' % (table_name, column))

    def assertColumnNotExists(self, engine, table_name, column):
        self.assertFalse(self.column_exists(engine, table_name, column),
                        'Column %s.%s should not exist' % (table_name, column))

    def assertTableNotExists(self, engine, table):
        self.assertRaises(sqlalchemy.exc.NoSuchTableError,
                            db_utils.get_table, engine, table)

    def _test_sqlite_opportunistically(self):
        if not _have_sqlite(self.USER, self.PASSWD, self.DATABASE):
            self.skipTest("sqlite not available")
        # add this to the global lists to make reset work with it, it's removed
        # automatically in tearDown so no need to clean it up here.
        connect_string = _get_connect_string("sqlite", "", "", "")
        engine = sqlalchemy.create_engine(connect_string)
        self.engines['openstack_citest'] = engine
        self.test_databases['openstack_citest'] = connect_string

        self._reset_databases()
        self._walk_versions(engine, False, False)

    def _test_mysql_opportunistically(self):
        # Test that table creation on mysql only builds InnoDB tables
        if not _have_mysql(self.USER, self.PASSWD, self.DATABASE):
            self.skipTest("mysql not available")
        # add this to the global lists to make reset work with it, it's removed
        # automatically in tearDown so no need to clean it up here.
        connect_string = _get_connect_string("mysql", self.USER, self.PASSWD,
                                            self.DATABASE)
        (user, password, database, host) = \
            get_db_connection_info(urlparse(connect_string))
        engine = sqlalchemy.create_engine(connect_string)
        self.engines[database] = engine
        self.test_databases[database] = connect_string

        # build a fully populated mysql database with all the tables
        self._reset_databases()
        self._walk_versions(engine, False, False)

        connection = engine.connect()
        # sanity check
        total = connection.execute("SELECT count(*) "
                                   "from information_schema.TABLES "
                                   "where TABLE_SCHEMA='%s'" % database)
        self.assertTrue(total.scalar() > 0, "No tables found. Wrong schema?")

        noninnodb = connection.execute("SELECT count(*) "
                                       "from information_schema.TABLES "
                                       "where TABLE_SCHEMA='%s' "
                                       "and ENGINE!='InnoDB' "
                                       "and TABLE_NAME!='migrate_version'" %
                                       database)
        count = noninnodb.scalar()
        self.assertEqual(count, 0, "%d non InnoDB tables created" % count)
        connection.close()

    def _test_postgresql_opportunistically(self):
        # Test postgresql database migration walk
        if not _have_postgresql(self.USER, self.PASSWD, self.DATABASE):
            self.skipTest("postgresql not available")
        # add this to the global lists to make reset work with it, it's removed
        # automatically in tearDown so no need to clean it up here.
        connect_string = _get_connect_string("postgres", self.USER,
                                            self.PASSWD, self.DATABASE)
        engine = sqlalchemy.create_engine(connect_string)
        (user, password, database, host) = \
            get_db_connection_info(urlparse(connect_string))
        self.engines[database] = engine
        self.test_databases[database] = connect_string

        # build a fully populated postgresql database with all the tables
        self._reset_databases()
        self._walk_versions(engine, False, False)

    def test_walk_versions(self):
        for engine in self.engines.values():
            if 'sqlite' in str(engine) and _have_sqlite(self.USER,
            self.PASSWD, self.DATABASE):
                self._walk_versions(engine, snake_walk=False,
                                    downgrade=False)
            elif 'postgres' in str(engine) and _have_postgresql(self.USER,
            self.PASSWD, self.DATABASE):
                self._walk_versions(engine, snake_walk=False,
                                    downgrade=False)
            elif 'mysql' in str(engine) and _have_mysql(self.USER,
            self.PASSWD, self.DATABASE):
                self._walk_versions(engine, snake_walk=False,
                                    downgrade=False)

    def test_sqlite_opportunistically(self):
        self._test_sqlite_opportunistically()

    def test_sqlite_connect_fail(self):
        """Test that we can trigger an sqlite connection failure

        Test that we can fail gracefully to ensure we don't break people
        without sqlite
        """
        # At present this auto-fails because _is_backend_avail calls
        # _get_connect_string and having anything follow the double slash in
        # the sqlite connection string is an invalid format
        if _is_backend_avail('sqlite', "openstack_cifail", self.PASSWD,
                             self.DATABASE):
            self.fail("Shouldn't have connected")

    def test_mysql_opportunistically(self):
        self._test_mysql_opportunistically()

    def test_mysql_connect_fail(self):
        """Test that we can trigger a mysql connection failure

        Test that we can fail gracefully to ensure we don't break people
        without mysql
        """
        if _is_backend_avail('mysql', "openstack_cifail", self.PASSWD,
                             self.DATABASE):
            self.fail("Shouldn't have connected")

    def test_postgresql_opportunistically(self):
        # Test is skipped because postgresql isn't present/configured on target
        # server and will cause errors. Skipped to prevent Jenkins notification.
        self.skipTest("Skipping to prevent postgres from throwing error in Jenkins")
        self._test_postgresql_opportunistically()

    def test_postgresql_connect_fail(self):
        # Test is skipped because postgresql isn't present/configured on target
        # server and will cause errors. Skipped to prevent Jenkins notification.
        self.skipTest("Skipping to prevent postgres from throwing error in Jenkins")
        """Test that we can trigger a postgres connection failure

        Test that we can fail gracefully to ensure we don't break people
        without postgres
        """
        if _is_backend_avail('postgres', "openstack_cifail", self.PASSWD,
                             self.DATABASE):
            self.fail("Shouldn't have connected")

    def _check_001(self, engine, data):
        # TODO: Commented out attributes for the following tables are
        # attributes of enumerated types that do not exist by default in
        # SQLAlchemy, and will need to be added as custom sqlalchemy types
        # if you'd like them to be tested in the same for-loop as the other
        # attributes wherein you assert that the attribute is of the specified
        # type
        systems = db_utils.get_table(engine, 'i_system')
        systems_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            'name': 'String', 'description': 'String', 'capabilities': 'Text',
            'contact': 'String', 'location': 'String', 'services': 'Integer',
            'software_version': 'String',
        }
        for col, coltype in systems_col.items():
            self.assertTrue(isinstance(systems.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        servers = db_utils.get_table(engine, 'i_host')
        servers_col = {
            'id': 'Integer', 'uuid': 'String',
            'reserved': 'Boolean', 'hostname': 'String', 'mgmt_mac': 'String',
            'mgmt_ip': 'String', 'bm_ip': 'String', 'bm_mac': 'String',
            'bm_type': 'String', 'bm_username': 'String', 'serialid': 'String',
            # 'invprovision': 'invprovisionStateEnum', 'personality': 'personalityEnum',
            # 'recordtype': 'recordTypeEnum', 'action': 'actionEnum',
            # 'administrative': 'adminEnum', 'operational': 'operationalEnum',
            # 'availability': 'availabilityEnum',
            'deleted_at': 'DateTime', 'task': 'String', 'location': 'Text',
            'created_at': 'DateTime', 'updated_at': 'DateTime', 'uptime': 'Integer',
            'capabilities': 'Text', 'config_status': 'String', 'config_applied': 'String',
            'config_target': 'String', 'forisystemid': 'Integer'
        }
        for col, coltype in servers_col.items():
            self.assertTrue(isinstance(servers.c[col].type,
                            getattr(sqlalchemy.types, coltype)),
                            "migrate to col %s of type  %s of server %s"
                            % (col, getattr(sqlalchemy.types, coltype),
                               servers.c[col].type))
        servers_enums_col = [
            'recordtype', 'personality', 'invprovision', 'personality', 'action',
            'administrative', 'operational', 'availability',
        ]
        for col in servers_enums_col:
            self.assertColumnExists(engine, 'i_host', col)

        nodes = db_utils.get_table(engine, 'i_node')
        nodes_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            'numa_node': 'Integer', 'capabilities': 'Text', 'forihostid': 'Integer',
        }
        for col, coltype in nodes_col.items():
            self.assertTrue(isinstance(nodes.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        cpus = db_utils.get_table(engine, 'i_icpu')
        cpus_col = {
            'id': 'Integer', 'uuid': 'String', 'cpu': 'Integer',
            'forinodeid': 'Integer', 'core': 'Integer', 'thread': 'Integer',
            'cpu_family': 'String', 'cpu_model': 'String', 'allocated_function': 'String',
            'capabilities': 'Text', 'forihostid': 'Integer',  # 'coProcessors': 'String',
            'forinodeid': 'Integer', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime'
        }
        for col, coltype in cpus_col.items():
            self.assertTrue(isinstance(cpus.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        imemory = db_utils.get_table(engine, 'i_imemory')
        imemory_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            'memtotal_mib': 'Integer', 'memavail_mib': 'Integer',
            'platform_reserved_mib': 'Integer', 'hugepages_configured': 'Boolean',
            'avs_hugepages_size_mib': 'Integer', 'avs_hugepages_reqd': 'Integer',
            'avs_hugepages_nr': 'Integer', 'avs_hugepages_avail': 'Integer',
            'vm_hugepages_size_mib': 'Integer', 'vm_hugepages_nr': 'Integer',
            'vm_hugepages_avail': 'Integer', 'capabilities': 'Text',
            'forihostid': 'Integer', 'forinodeid': 'Integer',

        }
        for col, coltype in imemory_col.items():
            self.assertTrue(isinstance(imemory.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        interfaces = db_utils.get_table(engine, 'i_interface')
        interfaces_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            'ifname': 'String', 'iftype': 'String', 'imac': 'String', 'imtu': 'Integer',
            'networktype': 'String', 'aemode': 'String', 'txhashpolicy': 'String',
            'providernetworks': 'String', 'providernetworksdict': 'Text',
            'schedpolicy': 'String', 'ifcapabilities': 'Text', 'farend': 'Text',
            'forihostid': 'Integer',
        }
        for col, coltype in interfaces_col.items():
            self.assertTrue(isinstance(interfaces.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        ports = db_utils.get_table(engine, 'i_port')
        ports_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            'pname': 'String', 'pnamedisplay': 'String', 'pciaddr': 'String',
            'pclass': 'String', 'pvendor': 'String', 'pdevice': 'String', 'psdevice': 'String',
            'psvendor': 'String', 'numa_node': 'Integer', 'mac': 'String', 'mtu': 'Integer',
            'speed': 'Integer', 'link_mode': 'String', 'autoneg': 'String', 'bootp': 'String',
            'capabilities': 'Text', 'forihostid': 'Integer', 'foriinterfaceid': 'Integer',
            'forinodeid': 'Integer',
        }
        for col, coltype in ports_col.items():
            self.assertTrue(isinstance(ports.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        stors = db_utils.get_table(engine, 'i_istor')
        stors_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            'osdid': 'Integer', 'idisk_uuid': 'String', 'state': 'String',
            'function': 'String', 'capabilities': 'Text', 'forihostid': 'Integer',
        }
        for col, coltype in stors_col.items():
            self.assertTrue(isinstance(stors.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        disks = db_utils.get_table(engine, 'i_idisk')
        disks_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            'device_node': 'String', 'device_num': 'Integer', 'device_type': 'String',
            'size_mib': 'Integer', 'serial_id': 'String', 'capabilities': 'Text',
            'forihostid': 'Integer', 'foristorid': 'Integer',
        }
        for col, coltype in disks_col.items():
            self.assertTrue(isinstance(disks.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        serviceGroups = db_utils.get_table(engine, 'i_servicegroup')
        serviceGroups_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            'servicename': 'String', 'state': 'String',
        }
        for col, coltype in serviceGroups_col.items():
            self.assertTrue(isinstance(serviceGroups.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        services = db_utils.get_table(engine, 'i_service')
        services_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            'servicename': 'String', 'hostname': 'String', 'forihostid': 'Integer',
            'activity': 'String', 'state': 'String', 'reason': 'Text',
        }
        for col, coltype in services_col.items():
            self.assertTrue(isinstance(services.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        traps = db_utils.get_table(engine, 'i_trap_destination')
        traps_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',  # 'type': 'typeEnum',
            'ip_address': 'String', 'community': 'String', 'port': 'Integer',
            # 'transport': 'transportEnum',
        }
        for col, coltype in traps_col.items():
            self.assertTrue(isinstance(traps.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        traps_enums_col = [
            'type', 'transport'
        ]
        for col in traps_enums_col:
            self.assertColumnExists(engine, 'i_trap_destination', col)

        communities = db_utils.get_table(engine, 'i_community')
        communities_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',  # 'access': 'accessEnum',
            'community': 'String', 'view': 'String',
        }
        for col, coltype in communities_col.items():
            self.assertTrue(isinstance(communities.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        communities_enums_col = [
            'access'
        ]
        for col in communities_enums_col:
            self.assertColumnExists(engine, 'i_community', col)

        users = db_utils.get_table(engine, 'i_user')
        users_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            'root_sig': 'String', 'reserved_1': 'String', 'reserved_2': 'String',
            'reserved_3': 'String', 'forisystemid': 'Integer',
        }
        for col, coltype in users_col.items():
            self.assertTrue(isinstance(users.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        dnses = db_utils.get_table(engine, 'i_dns')
        dnses_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            'nameservers': 'String', 'forisystemid': 'Integer',
        }
        for col, coltype in dnses_col.items():
            self.assertTrue(isinstance(dnses.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        ntps = db_utils.get_table(engine, 'i_ntp')
        ntps_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            'ntpservers': 'String', 'forisystemid': 'Integer',
        }
        for col, coltype in ntps_col.items():
            self.assertTrue(isinstance(ntps.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        extoams = db_utils.get_table(engine, 'i_extoam')
        extoams_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            'oam_subnet': 'String', 'oam_gateway_ip': 'String', 'oam_floating_ip': 'String',
            'oam_c0_ip': 'String', 'oam_c1_ip': 'String', 'forisystemid': 'Integer',
        }
        for col, coltype in extoams_col.items():
            self.assertTrue(isinstance(extoams.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        pms = db_utils.get_table(engine, 'i_pm')
        pms_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            'retention_secs': 'String', 'reserved_1': 'String', 'reserved_2': 'String',
            'reserved_3': 'String', 'forisystemid': 'Integer',
        }
        for col, coltype in pms_col.items():
            self.assertTrue(isinstance(pms.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        storconfigs = db_utils.get_table(engine, 'i_storconfig')
        storconfigs_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            'cinder_backend': 'String', 'database_gib': 'String', 'image_gib': 'String',
            'backup_gib': 'String', 'cinder_device': 'String', 'cinder_gib': 'String',
            'forisystemid': 'Integer',
        }
        for col, coltype in storconfigs_col.items():
            self.assertTrue(isinstance(storconfigs.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

    def _check_002(self, engine, data):
        servers = db_utils.get_table(engine, 'i_host')
        servers_col = {
            'ihost_action': 'String', 'vim_progress_status': 'String',
            'subfunctions': 'String', 'subfunction_oper': 'String', 'subfunction_avail': 'String',
            'boot_device': 'String', 'rootfs_device': 'String', 'install_output': 'String',
            'console': 'String', 'vsc_controllers': 'String',
            'ttys_dcd': 'Boolean',
        }
        for col, coltype in servers_col.items():
            self.assertTrue(isinstance(servers.c[col].type,
                            getattr(sqlalchemy.types, coltype)),
                            "migrate to col %s of type  %s of server %s"
                            % (col, getattr(sqlalchemy.types, coltype),
                               servers.c[col].type))

        imemories = db_utils.get_table(engine, 'i_imemory')
        imemories_col = {
            'vm_hugepages_nr_2M': 'Integer', 'vm_hugepages_nr_1G': 'Integer',
            'vm_hugepages_use_1G': 'Boolean', 'vm_hugepages_possible_2M': 'Integer',
            'vm_hugepages_possible_1G': 'Integer', 'vm_hugepages_nr_2M_pending': 'Integer',
            'vm_hugepages_nr_1G_pending': 'Integer', 'vm_hugepages_avail_2M': 'Integer',
            'vm_hugepages_avail_1G': 'Integer', 'vm_hugepages_nr_4K': 'Integer',
            'node_memtotal_mib': 'Integer',
        }
        for col, coltype in imemories_col.items():
            self.assertTrue(isinstance(imemories.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        imemories_dropped_col = {
            'vm_hugepages_size_mib', 'vm_hugepages_nr', 'vm_hugepages_avail',
        }
        for col in imemories_dropped_col:
            self.assertColumnNotExists(engine, 'i_imemory', col)

        interfaces = db_utils.get_table(engine, 'i_interface')
        interfaces_col = {
            'sriov_numvfs': 'Integer', 'aedict': 'Text',
        }
        for col, coltype in interfaces_col.items():
            self.assertTrue(isinstance(interfaces.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        interfaces = db_utils.get_table(engine, 'interfaces')
        interfaces_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime', 'forihostid': 'Integer',
            'iftype': 'String', 'ifname': 'String', 'networktype': 'String',
            'sriov_numvfs': 'Integer', 'ifcapabilities': 'Text', 'farend': 'Text',
        }
        for col, coltype in interfaces_col.items():
            self.assertTrue(isinstance(interfaces.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        ports = db_utils.get_table(engine, 'i_port')
        ports_col = {
            'sriov_totalvfs': 'Integer', 'sriov_numvfs': 'Integer',
            'sriov_vfs_pci_address': 'String', 'driver': 'String',
            'dpdksupport': 'Boolean',
        }
        for col, coltype in ports_col.items():
            self.assertTrue(isinstance(ports.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        disks = db_utils.get_table(engine, 'i_idisk')
        disks_col = {
            'foripvid': 'Integer',
        }
        for col, coltype in disks_col.items():
            self.assertTrue(isinstance(disks.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        interfaces_to_interfaces = db_utils.get_table(engine, 'interfaces_to_interfaces')
        interfaces_to_interfaces_col = {
            'used_by_id': 'Integer', 'uses_id': 'Integer',
        }
        for col, coltype in interfaces_to_interfaces_col.items():
            self.assertTrue(isinstance(interfaces_to_interfaces.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        ethernet_interfaces = db_utils.get_table(engine, 'ethernet_interfaces')
        ethernet_interfaces_col = {
            'id': 'Integer', 'deleted_at': 'DateTime', 'created_at': 'DateTime',
            'updated_at': 'DateTime', 'imac': 'String', 'imtu': 'Integer',
            'providernetworks': 'String', 'providernetworksdict': 'Text',
        }
        for col, coltype in ethernet_interfaces_col.items():
            self.assertTrue(isinstance(ethernet_interfaces.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        ae_interfaces = db_utils.get_table(engine, 'ae_interfaces')
        ae_interfaces_col = {
            'id': 'Integer', 'deleted_at': 'DateTime', 'created_at': 'DateTime',
            'updated_at': 'DateTime', 'aemode': 'String', 'aedict': 'Text',
            'txhashpolicy': 'String', 'schedpolicy': 'String', 'imac': 'String',
            'imtu': 'Integer', 'providernetworks': 'String', 'providernetworksdict': 'Text',
        }
        for col, coltype in ae_interfaces_col.items():
            self.assertTrue(isinstance(ae_interfaces.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        vlan_interfaces = db_utils.get_table(engine, 'vlan_interfaces')
        vlan_interfaces_col = {
            'id': 'Integer', 'deleted_at': 'DateTime', 'created_at': 'DateTime',
            'updated_at': 'DateTime', 'vlan_id': 'String', 'vlan_type': 'String',
            'imac': 'String', 'imtu': 'Integer', 'providernetworks': 'String',
            'providernetworksdict': 'Text',
        }
        for col, coltype in vlan_interfaces_col.items():
            self.assertTrue(isinstance(vlan_interfaces.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        ports = db_utils.get_table(engine, 'ports')
        ports_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime', 'host_id': 'Integer',
            'node_id': 'Integer', 'interface_id': 'Integer', 'type': 'String', 'name': 'String',
            'namedisplay': 'String', 'pciaddr': 'String', 'dev_id': 'Integer',
            'sriov_totalvfs': 'Integer', 'sriov_numvfs': 'Integer',
            'sriov_vfs_pci_address': 'String', 'driver': 'String', 'pclass': 'String',
            'pvendor': 'String', 'pdevice': 'String', 'psvendor': 'String', 'psdevice': 'String',
            'dpdksupport': 'Boolean', 'numa_node': 'Integer', 'capabilities': 'Text',
        }
        for col, coltype in ports_col.items():
            self.assertTrue(isinstance(ports.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        ethernet_ports = db_utils.get_table(engine, 'ethernet_ports')
        ethernet_ports_col = {
            'id': 'Integer', 'deleted_at': 'DateTime', 'created_at': 'DateTime',
            'updated_at': 'DateTime', 'mac': 'String', 'mtu': 'Integer', 'speed': 'Integer',
            'link_mode': 'String', 'duplex': 'String', 'autoneg': 'String', 'bootp': 'String',
            'capabilities': 'Text',
        }
        for col, coltype in ethernet_ports_col.items():
            self.assertTrue(isinstance(ethernet_ports.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        address_pools = db_utils.get_table(engine, 'address_pools')
        address_pools_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime', 'name': 'String',
            'family': 'Integer', 'network': 'String', 'prefix': 'Integer', 'order': 'String',
        }
        for col, coltype in address_pools_col.items():
            self.assertTrue(isinstance(address_pools.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        address_pool_ranges = db_utils.get_table(engine, 'address_pool_ranges')
        address_pool_ranges_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime', 'start': 'String',
            'end': 'String', 'address_pool_id': 'Integer',
        }
        for col, coltype in address_pool_ranges_col.items():
            self.assertTrue(isinstance(address_pool_ranges.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        addresses = db_utils.get_table(engine, 'addresses')
        addresses_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime', 'family': 'Integer',
            'address': 'String', 'prefix': 'Integer', 'enable_dad': 'Boolean',
            'name': 'String', 'interface_id': 'Integer', 'address_pool_id': 'Integer',
        }
        for col, coltype in addresses_col.items():
            self.assertTrue(isinstance(addresses.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        address_modes = db_utils.get_table(engine, 'address_modes')
        address_modes_col = {
            'id': 'Integer', 'uuid': 'String', 'family': 'Integer', 'mode': 'String',
            'interface_id': 'Integer', 'address_pool_id': 'Integer',
        }
        for col, coltype in address_modes_col.items():
            self.assertTrue(isinstance(address_modes.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        routes = db_utils.get_table(engine, 'routes')
        routes_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime', 'family': 'Integer',
            'network': 'String', 'prefix': 'Integer', 'gateway': 'String', 'metric': 'Integer',
            'interface_id': 'Integer'
        }
        for col, coltype in routes_col.items():
            self.assertTrue(isinstance(routes.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        networks = db_utils.get_table(engine, 'networks')
        networks_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime', 'type': 'String', 'mtu': 'Integer',
            'link_capacity': 'Integer', 'dynamic': 'Boolean', 'vlan_id': 'Integer',
            'address_pool_id': 'Integer',
        }
        for col, coltype in networks_col.items():
            self.assertTrue(isinstance(networks.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        i_lvgs = db_utils.get_table(engine, 'i_lvg')
        i_lvgs_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',  # 'vg_state': 'vgStateEnum',
            'lvm_vg_name': 'String', 'lvm_vg_uuid': 'String', 'lvm_vg_access': 'String',
            'lvm_max_lv': 'Integer', 'lvm_cur_lv': 'Integer', 'lvm_max_pv': 'Integer',
            'lvm_cur_pv': 'Integer', 'lvm_vg_size': 'BigInteger', 'lvm_vg_total_pe': 'Integer',
            'lvm_vg_free_pe': 'Integer', 'capabilities': 'Text', 'forihostid': 'Integer',
        }
        for col, coltype in i_lvgs_col.items():
            self.assertTrue(isinstance(i_lvgs.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        i_lvgs_enums_col = [
            'vg_state'
        ]
        for col in i_lvgs_enums_col:
            self.assertColumnExists(engine, 'i_lvg', col)

        i_pvs = db_utils.get_table(engine, 'i_pv')
        i_pvs_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
            # 'pv_state': 'pvStateEnum', 'pv_type': 'pvTypeEnum',
            'idisk_uuid': 'String', 'idisk_device_node': 'String', 'lvm_pv_name': 'String',
            'lvm_vg_name': 'String', 'lvm_pv_uuid': 'String', 'lvm_pv_size': 'BigInteger',
            'lvm_pe_total': 'Integer', 'lvm_pe_alloced': 'Integer', 'capabilities': 'Text',
            'forihostid': 'Integer', 'forilvgid': 'Integer',
        }
        for col, coltype in i_pvs_col.items():
            self.assertTrue(isinstance(i_pvs.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        i_pvs_enums_col = [
            'pv_type', 'pv_state'
        ]
        for col in i_pvs_enums_col:
            self.assertColumnExists(engine, 'i_pv', col)

        sensorGroups = db_utils.get_table(engine, 'i_sensorgroups')
        sensorGroups_col = {
            'id': 'Integer', 'uuid': 'String', 'host_id': 'Integer',
            'sensortype': 'String', 'datatype': 'String', 'sensorgroupname': 'String',
            'path': 'String', 'description': 'String', 'state': 'String',
            'possible_states': 'String', 'algorithm': 'String', 'audit_interval_group': 'Integer',
            'record_ttl': 'Integer', 'actions_minor_group': 'String', 'actions_major_group': 'String',
            'actions_critical_group': 'String', 'suppress': 'Boolean', 'capabilities': 'Text',
            'actions_critical_choices': 'String', 'actions_major_choices': 'String',
            'actions_minor_choices': 'String',
        }
        for col, coltype in sensorGroups_col.items():
            self.assertTrue(isinstance(sensorGroups.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        sensorgroups_discrete = db_utils.get_table(engine, 'i_sensorgroups_discrete')
        sensorgroups_discrete_col = {
            'id': 'Integer', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
        }
        for col, coltype in sensorgroups_discrete_col.items():
            self.assertTrue(isinstance(sensorgroups_discrete.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        sensorGroup_analogs = db_utils.get_table(engine, 'i_sensorgroups_analog')
        sensorGroup_analogs_col = {
            'unit_base_group': 'String', 'unit_modifier_group': 'String',
            'unit_rate_group': 'String', 't_minor_lower_group': 'String',
            't_minor_upper_group': 'String', 't_major_lower_group': 'String',
            't_major_upper_group': 'String', 't_critical_lower_group': 'String',
            't_critical_upper_group': 'String',
        }
        for col, coltype in sensorGroup_analogs_col.items():
            self.assertTrue(isinstance(sensorGroup_analogs.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        sensors = db_utils.get_table(engine, 'i_sensors')
        sensors_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime', 'host_id': 'Integer',
            'sensorgroup_id': 'Integer', 'sensorname': 'String',
            'path': 'String', 'datatype': 'String', 'sensortype': 'String',
            'status': 'String', 'state': 'String', 'state_requested': 'String',
            'sensor_action_requested': 'String', 'audit_interval': 'Integer', 'algorithm': 'String',
            'actions_minor': 'String', 'actions_major': 'String', 'actions_critical': 'String',
            'suppress': 'Boolean', 'capabilities': 'Text',
        }
        for col, coltype in sensors_col.items():
            self.assertTrue(isinstance(sensors.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        sensors_discrete = db_utils.get_table(engine, 'i_sensors_discrete')
        sensors_discrete_col = {
            'id': 'Integer', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime',
        }
        for col, coltype in sensors_discrete_col.items():
            self.assertTrue(isinstance(sensors_discrete.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        sensors_analog = db_utils.get_table(engine, 'i_sensors_analog')
        sensors_analog_col = {
            'id': 'Integer', 'deleted_at': 'DateTime', 'created_at': 'DateTime',
            'updated_at': 'DateTime', 'unit_base': 'String', 'unit_modifier': 'String',
            'unit_rate': 'String', 't_minor_lower': 'String', 't_minor_upper': 'String',
            't_major_lower': 'String', 't_major_upper': 'String', 't_critical_lower': 'String',
            't_critical_upper': 'String',
        }
        for col, coltype in sensors_analog_col.items():
            self.assertTrue(isinstance(sensors_analog.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        pci_devices = db_utils.get_table(engine, 'pci_devices')
        pci_devices_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime', 'host_id': 'Integer',
            'name': 'String', 'pciaddr': 'String', 'pclass_id': 'String',
            'pvendor_id': 'String', 'pdevice_id': 'String', 'pclass': 'String', 'pvendor': 'String',
            'pdevice': 'String', 'psvendor': 'String', 'psdevice': 'String', 'numa_node': 'Integer',
            'sriov_totalvfs': 'Integer', 'sriov_numvfs': 'Integer', 'sriov_vfs_pci_address': 'String',
            'driver': 'String', 'enabled': 'Boolean', 'extra_info': 'Text',
        }
        for col, coltype in pci_devices_col.items():
            self.assertTrue(isinstance(pci_devices.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        loads = db_utils.get_table(engine, 'loads')
        loads_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime', 'state': 'String',
            'software_version': 'String', 'compatible_version': 'String',
            'required_patches': 'String',
        }
        for col, coltype in loads_col.items():
            self.assertTrue(isinstance(loads.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        software_upgrade = db_utils.get_table(engine, 'software_upgrade')
        software_upgrade_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime', 'state': 'String',
            'from_load': 'Integer', 'to_load': 'Integer',
        }
        for col, coltype in software_upgrade_col.items():
            self.assertTrue(isinstance(software_upgrade.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        host_upgrades = db_utils.get_table(engine, 'host_upgrade')
        host_upgrades_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime', 'forihostid': 'Integer',
            'software_load': 'Integer', 'target_load': 'Integer',
        }
        for col, coltype in host_upgrades_col.items():
            self.assertTrue(isinstance(host_upgrades.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        drbdconfigs = db_utils.get_table(engine, 'drbdconfig')
        drbdconfigs_col = {
            'id': 'Integer', 'uuid': 'String', 'deleted_at': 'DateTime',
            'created_at': 'DateTime', 'updated_at': 'DateTime', 'link_util': 'Integer',
            'num_parallel': 'Integer', 'rtt_ms': 'Float', 'forisystemid': 'Integer'
        }
        for col, coltype in drbdconfigs_col.items():
            self.assertTrue(isinstance(drbdconfigs.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        service_parameters = db_utils.get_table(engine, 'service_parameter')
        service_parameters_col = {
            'id': 'Integer', 'uuid': 'String',  # 'service': 'serviceEnum',
            'deleted_at': 'DateTime', 'created_at': 'DateTime', 'updated_at': 'DateTime',
            'section': 'String', 'name': 'String', 'value': 'String',
        }
        for col, coltype in service_parameters_col.items():
            self.assertTrue(isinstance(service_parameters.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        service_parameters_enums_col = [
            'service'
        ]
        for col in service_parameters_enums_col:
            self.assertColumnExists(engine, 'service_parameter', col)

        storconfigs = db_utils.get_table(engine, 'i_storconfig')
        storconfigs_col = {
            'glance_backend': 'String', 'glance_gib': 'Integer',
            'img_conversions_gib': 'String',
        }
        for col, coltype in storconfigs_col.items():
            self.assertTrue(isinstance(storconfigs.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        self.assertTableNotExists(engine, 'i_extoam')
        self.assertTableNotExists(engine, 'i_infra')

    def _check_031(self, engine, data):
        # Assert data types for 2 new columns in table "i_storconfig"
        storconfigs = db_utils.get_table(engine, 'i_storconfig')
        storconfigs_col = {
            'cinder_pool_gib': 'Integer',
            'ephemeral_pool_gib': 'Integer',
        }
        for col, coltype in storconfigs_col.items():
            self.assertTrue(isinstance(storconfigs.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        # make sure the rename worked properly
        self.assertColumnNotExists(engine, 'i_storconfig', 'glance_gib')
        self.assertColumnExists(engine, 'i_storconfig', 'glance_pool_gib')

    def _check_032(self, engine, data):
        # The 32 script only updates some rows in table "i_system"
        pass

    def _check_033(self, engine, data):
        # Assert data types for 2 new columns in table "i_user"
        users = db_utils.get_table(engine, 'i_user')
        user_cols = {
            'passwd_hash': 'String',
            'passwd_expiry_days': 'Integer',
        }
        for col, coltype in user_cols.items():
            self.assertTrue(isinstance(users.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

    def _check_034(self, engine, data):
        # Assert data types for all columns in new table "clusters"
        clusters = db_utils.get_table(engine, 'clusters')
        clusters_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'uuid': 'String',
            'cluster_uuid': 'String',
            'type': 'String',
            'name': 'String',
            'capabilities': 'Text',
            'system_id': 'Integer',
        }
        for col, coltype in clusters_cols.items():
            self.assertTrue(isinstance(clusters.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        # Assert data types for all columns in new table "peers"
        peers = db_utils.get_table(engine, 'peers')
        peers_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'uuid': 'String',
            'name': 'String',
            'status': 'String',
            'info': 'Text',
            'capabilities': 'Text',
            'cluster_id': 'Integer',
        }

        for col, coltype in peers_cols.items():
            self.assertTrue(isinstance(peers.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        # Assert data types for 1 new column in table "i_host"
        hosts = db_utils.get_table(engine, 'i_host')
        hosts_cols = {
            'peer_id': 'Integer',
        }
        for col, coltype in hosts_cols.items():
            self.assertTrue(isinstance(hosts.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

    def _check_035(self, engine, data):
        # Assert data types for 1 new column in table "i_system"
        systems = db_utils.get_table(engine, 'i_system')
        systems_cols = {
            'system_type': 'String',
        }
        for col, coltype in systems_cols.items():
            self.assertTrue(isinstance(systems.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

    def _check_036(self, engine, data):
        # Assert data types for all columns in new table "lldp_agents"
        lldp_agents = db_utils.get_table(engine, 'lldp_agents')
        lldp_agents_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'uuid': 'String',
            'host_id': 'Integer',
            'port_id': 'Integer',
            'status': 'String',
        }
        for col, coltype in lldp_agents_cols.items():
            self.assertTrue(isinstance(lldp_agents.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        # Assert data types for all columns in new table "lldp_neighbours"
        lldp_neighbours = db_utils.get_table(engine, 'lldp_neighbours')
        lldp_neighbours_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'uuid': 'String',
            'host_id': 'Integer',
            'port_id': 'Integer',
            'msap': 'String',
        }
        for col, coltype in lldp_neighbours_cols.items():
            self.assertTrue(isinstance(lldp_neighbours.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        # Assert data types for all columns in new table "lldp_tlvs"
        lldp_tlvs = db_utils.get_table(engine, 'lldp_tlvs')
        lldp_tlvs_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'agent_id': 'Integer',
            'neighbour_id': 'Integer',
            'type': 'String',
            'value': 'String',
        }
        for col, coltype in lldp_tlvs_cols.items():
            self.assertTrue(isinstance(lldp_tlvs.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

    def _check_037(self, engine, data):
        # Assert data types for 5 new columns in table "i_storconfig"
        storconfigs = db_utils.get_table(engine, 'i_storconfig')
        storconfigs_cols = {
            'state': 'String',
            'task': 'String',
            'ceph_mon_gib': 'Integer',
            'ceph_mon_dev_ctrl0': 'String',
            'ceph_mon_dev_ctrl1': 'String',
        }
        for col, coltype in storconfigs_cols.items():
            self.assertTrue(isinstance(storconfigs.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

    def _check_038(self, engine, data):
        # Assert data types for all columns in new table "journal"
        journals = db_utils.get_table(engine, 'journal')
        journals_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'uuid': 'String',
            'device_node': 'String',
            'size_mib': 'Integer',
            'onistor_uuid': 'String',
            'foristorid': 'Integer',
        }
        for col, coltype in journals_cols.items():
            self.assertTrue(isinstance(journals.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

    def _check_039(self, engine, data):
        # Assert data types for 1 new column in table "i_idisk"
        idisk = db_utils.get_table(engine, 'i_idisk')
        idisk_cols = {
            'rpm': 'String',
        }
        for col, coltype in idisk_cols.items():
            self.assertTrue(isinstance(idisk.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

    def _check_040(self, engine, data):
        # Assert data types for all columns in new table "remotelogging"
        rlogging = db_utils.get_table(engine, 'remotelogging')
        rlogging_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'uuid': 'String',
            'enabled': 'Boolean',
            # 'transport': 'logTransportEnum',  # enum types cannot be checked, can only check if they exist or not
            'ip_address': 'String',
            'port': 'Integer',
            'key_file': 'String',
            'system_id': 'Integer',
        }
        for col, coltype in rlogging_cols.items():
            self.assertTrue(isinstance(rlogging.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        # Assert that the enum column "transport" exists
        self.assertColumnExists(engine, 'remotelogging', 'transport')

    def _check_041(self, engine, data):
        # Assert data types for all columns in new table "i_horizon_lockout"
        horizon_lockout = db_utils.get_table(engine, 'i_horizon_lockout')
        horizon_lockout_cols = {
            'lockout_time': 'Integer',
            'lockout_retries': 'Integer',
        }
        for col, coltype in horizon_lockout_cols.items():
            self.assertTrue(isinstance(horizon_lockout.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

    def _check_042(self, engine, data):
        # Assert the "service" column became a string instead of an enum
        service_parameter = db_utils.get_table(engine, 'service_parameter')
        service_parameter_cols = {
            'service': 'String',
        }
        for col, coltype in service_parameter_cols.items():
            self.assertTrue(isinstance(service_parameter.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

    def _check_043(self, engine, data):
        # Assert data types for all columns in new table "sdn_controller"
        sdn_controller = db_utils.get_table(engine, 'sdn_controller')
        sdn_controller_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'uuid': 'String',
            'ip_address': 'String',
            'port': 'Integer',
            'transport': 'String',
            'state': 'String',
        }
        for col, coltype in sdn_controller_cols.items():
            self.assertTrue(isinstance(sdn_controller.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

    def _check_044(self, engine, data):
        # Assert data types for all columns in new table "controller_fs"
        controller_fs = db_utils.get_table(engine, 'controller_fs')
        controller_fs_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'uuid': 'String',
            'database_gib': 'Integer',
            'cgcs_gib': 'Integer',
            'img_conversions_gib': 'Integer',
            'backup_gib': 'Integer',
            'forisystemid': 'Integer',
        }
        for col, coltype in controller_fs_cols.items():
            self.assertTrue(isinstance(controller_fs.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        # Assert data types for all columns in new table "storage_backend"
        storage_backend = db_utils.get_table(engine, 'storage_backend')
        storage_backend_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'uuid': 'String',
            'backend': 'String',
            'state': 'String',
            'task': 'String',
            'forisystemid': 'Integer',
        }
        for col, coltype in storage_backend_cols.items():
            self.assertTrue(isinstance(storage_backend.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        # Assert data types for all columns in new table "storage_lvm"
        storage_lvm = db_utils.get_table(engine, 'storage_lvm')
        storage_lvm_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'cinder_device': 'String',
        }
        for col, coltype in storage_lvm_cols.items():
            self.assertTrue(isinstance(storage_lvm.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        # Assert data types for all columns in new table "storage_ceph"
        storage_ceph = db_utils.get_table(engine, 'storage_ceph')
        storage_ceph_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'cinder_pool_gib': 'Integer',
            'glance_pool_gib': 'Integer',
            'ephemeral_pool_gib': 'Integer',
            'object_pool_gib': 'Integer',
            'object_gateway': 'Boolean',
        }
        for col, coltype in storage_ceph_cols.items():
            self.assertTrue(isinstance(storage_ceph.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        # Assert data types for all columns in new table "ceph_mon"
        ceph_mon = db_utils.get_table(engine, 'ceph_mon')
        ceph_mon_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'uuid': 'String',
            'device_node': 'String',
            'ceph_mon_gib': 'Integer',
            'forihostid': 'Integer',
        }
        for col, coltype in ceph_mon_cols.items():
            self.assertTrue(isinstance(ceph_mon.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        # Assert deletion of the i_storconfig table
        self.assertTableNotExists(engine, 'i_storconfig')

    def _check_045(self, engine, data):
        # Assert data types for 2 new column in table "i_host"
        host = db_utils.get_table(engine, 'i_host')
        host_cols = {
            'action_state': 'String',
            'mtce_info': 'String',
        }
        for col, coltype in host_cols.items():
            self.assertTrue(isinstance(host.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

    def _check_050(self, engine, data):
        # 46 --> Drop table i_port
        self.assertTableNotExists(engine, 'i_port')
        # 47 --> add 2 columns to i_host
        host = db_utils.get_table(engine, 'i_host')
        host_col = {
            'install_state': 'String',
            'install_state_info': 'String',
        }
        for col, coltype in host_col.items():
            self.assertTrue(isinstance(host.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        # 48 --> Change column type of "service" in table "service_parameter" to be string instead of enum
        service_parameter = db_utils.get_table(engine, 'service_parameter')
        service_parameter_col = {
            'service': 'String',
        }
        for col, coltype in service_parameter_col.items():
            self.assertTrue(isinstance(service_parameter.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        # 49, 52 --> Add 2 new columns to table "controller_fs"
        controller_fs = db_utils.get_table(engine, 'controller_fs')
        controller_fs_col = {
            'scratch_gib': 'Integer',
            'state': 'String',
        }
        for col, coltype in controller_fs_col.items():
            self.assertTrue(isinstance(controller_fs.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        # 50 --> Create table "services"; Drop table i_servicegroup
        services = db_utils.get_table(engine, 'services')
        services_col = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'name': 'String',
            'enabled': 'Boolean',
        }
        for col, coltype in services_col.items():
            self.assertTrue(isinstance(services.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        self.assertTableNotExists(engine, 'i_servicegroup')

        # 53 --> Create table "virtual_interfaces"
        virtual_interfaces = db_utils.get_table(engine, 'virtual_interfaces')
        virtual_interfaces_col = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'imac': 'String',
            'imtu': 'Integer',
            'providernetworks': 'String',
            'providernetworksdict': 'Text',
        }
        for col, coltype in virtual_interfaces_col.items():
            self.assertTrue(isinstance(virtual_interfaces.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        # 54 --> Add a column to table "i_system"
        systems = db_utils.get_table(engine, 'i_system')
        systems_col = {
            'system_mode': 'String',
        }
        for col, coltype in systems_col.items():
            self.assertTrue(isinstance(systems.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        # 55 --> Create table "tpmconfig"; Create table "tpmdevice"
        tpmconfig = db_utils.get_table(engine, 'tpmconfig')
        tpmconfig_col = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'uuid': 'String',
            'tpm_path': 'String',
        }
        for col, coltype in tpmconfig_col.items():
            self.assertTrue(isinstance(tpmconfig.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        tpmdevice = db_utils.get_table(engine, 'tpmdevice')
        tpmdevice_col = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'uuid': 'String',
            'state': 'String',
            'host_id': 'Integer',
        }
        for col, coltype in tpmdevice_col.items():
            self.assertTrue(isinstance(tpmdevice.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        # 56 --> pv_state gets modified to String type
        ipv = db_utils.get_table(engine, 'i_pv')
        ipv_col = {
            'pv_state': 'String',
        }
        for col, coltype in ipv_col.items():
            self.assertTrue(isinstance(ipv.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        # 57 --> Add 3 columns to table "i_idisk"
        idisk = db_utils.get_table(engine, 'i_idisk')
        idisk_col = {
            'device_id': 'String',
            'device_path': 'String',
            'device_wwn': 'String',
        }
        for col, coltype in idisk_col.items():
            self.assertTrue(isinstance(idisk.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        # 58 --> add another column to i_system
        systems = db_utils.get_table(engine, 'i_system')
        systems_col = {
            'timezone': 'String',
        }
        for col, coltype in systems_col.items():
            self.assertTrue(isinstance(systems.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
        # 60 --> Add a column to table "i_pv"
        ipv = db_utils.get_table(engine, 'i_pv')
        ipv_col = {
            'idisk_device_path': 'String',
        }
        for col, coltype in ipv_col.items():
            self.assertTrue(isinstance(ipv.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

        # "device_node" column renamed to "device_path" in the ceph_mon table
        self.assertColumnNotExists(engine, 'ceph_mon', 'device_node')
        self.assertColumnExists(engine, 'ceph_mon', 'device_path')

        # "device_node" column renamed to "device_path" in the ceph_mon table
        self.assertColumnNotExists(engine, 'journal', 'device_node')
        self.assertColumnExists(engine, 'journal', 'device_path')

        # 61 --> Add a column to table "i_host"
        host = db_utils.get_table(engine, 'i_host')
        host_col = {
            'iscsi_initiator_name': 'String',
        }
        for col, coltype in host_col.items():
            self.assertTrue(isinstance(host.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))

    def _check_067(self, engine, data):
        servers = db_utils.get_table(engine, 'i_host')
        servers_col = {
            'tboot': 'String',
        }
        for col, coltype in servers_col.items():
            self.assertTrue(isinstance(servers.c[col].type,
                            getattr(sqlalchemy.types, coltype)),
                            "migrate to col %s of type  %s of server %s"
                            % (col, getattr(sqlalchemy.types, coltype),
                               servers.c[col].type))

    # TODO (rchurch): Change this name after consolidating all the DB migrations
    def _check_cinder(self, engine, data):
        # 055_cinder_gib_removal.py

        # Assert data types for all columns in table "storage_lvm"
        storage_lvm = db_utils.get_table(engine, 'storage_lvm')
        storage_lvm_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
        }
        for col, coltype in storage_lvm_cols.items():
            self.assertTrue(isinstance(storage_lvm.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
            # Assert deletion of the i_storconfig table
        self.assertTableNotExists(engine, 'storage_lvm')

        # 056_backend_services.py

        # Assert data types for all columns in  "storage_backend"
        storage_backend = db_utils.get_table(engine, 'storage_backend')
        storage_backend_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'uuid': 'String',
            'backend': 'String',
            'state': 'String',
            'task': 'String',
            'forisystemid': 'Integer',
            'services': 'Text',
            'capabilities': 'Text',
        }
        for col, coltype in storage_backend_cols.items():
            self.assertTrue(isinstance(storage_backend.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
            # Assert deletion of the i_storconfig table
        self.assertTableNotExists(engine, 'storage_lvm')

        # 057_storage_file.py

        # Assert data types for all columns in new table "storage_file"
        storage_file = db_utils.get_table(engine, 'storage_file')
        storage_file_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
        }
        for col, coltype in storage_file_cols.items():
            self.assertTrue(isinstance(storage_file.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
            # Assert deletion of the i_storconfig table
        self.assertTableNotExists(engine, 'storage_file')

    def _check_074(self, engine, data):
        ntps = db_utils.get_table(engine, 'i_ntp')
        ntps_col = {
            'enabled': 'Boolean',
        }
        for col, coltype in ntps_col.items():
            self.assertTrue(isinstance(ntps.c[col].type,
                            getattr(sqlalchemy.types, coltype)))

    def _check_075(self, engine, data):
        # Assert data types for all columns in new table "ptp"
        ptp = db_utils.get_table(engine, 'ptp')
        ptp_cols = {
            'created_at': 'DateTime',
            'updated_at': 'DateTime',
            'deleted_at': 'DateTime',
            'id': 'Integer',
            'uuid': 'String',
            'enabled': 'Boolean',
            'mode': 'String',
            'transport': 'String',
            'mechanism': 'String',
            'system_id': 'Integer',
        }
        for col, coltype in ptp_cols.items():
            self.assertTrue(isinstance(ptp.c[col].type,
                                       getattr(sqlalchemy.types, coltype)))
