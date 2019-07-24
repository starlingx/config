This file discusses the current status of sysinv tests and areas where issues
still exist and what to do in order to test them.

--------------------------------------------------------------------------------
RUNNING TESTS:

To actually run the tests, in console navigate to
$MY_REPO/stx/stx-config/sysinv/sysinv/sysinv

On your first ever run of tox tests enter:
tox --recreate -e py27
This will make sure tox's environment is fresh and fully built.

To test both py27 (the actual unit tests), and check the flake8 formatting:
tox

You can also run both py27 and flake8 by entering the following instead:
tox -e flake8,py27
The above order of environments matters. If py27 comes first, flake8 won't run.

To run either individually enter:
tox -e py27
tox -e flake8

--------------------------------------------------------------------------------
RUNNING TESTS WITH POSTGRESQL:

The default behaviour is to run the sysinv tests with the mySQL database. This
should be fine in most cases.

If you really want to test with postgreSQL, in a local Ubuntu VM or similar:
- go to test_migrations.py and in the function
  test_postgresql_opportunistically, comment out the self.skipTest line to
  enable the test to be run.
- Also go to the function test_postgresql_connect_fail and comment out the
  self.skipTest line so that test can be run as well.
- Lastly, in the function _reset_databases, go to the bottom and uncomment
  self._reset_pg(conn_pieces) so the postgres DB can be reset between runs.
  If this last line is not uncommented, your first run of the py27 tests will
  work, but after that you will get
  migrate.exceptions.DatabaseAlreadyControlledError

Do not push these lines uncommented upstream to the repo.

To set up the postgres db for the first time enter the following in console:
sudo apt-get install postgresql postgresql-contrib
pip install psycopg2

sudo -u postgres psql
CREATE USER openstack_citest WITH CREATEDB LOGIN PASSWORD 'openstack_citest';
CREATE DATABASE openstack_citest WITH OWNER openstack_citest;
\q

--------------------------------------------------------------------------------
OUTSTANDING ISSUES:

tests/api/test_acl.py
    test_authenticated
        Fails due HTTPS connection failure as a result of an invalid user token
        which causes webtest.app.AppError:
        Bad response: 401 Unauthorized 'Authentication required'

    test_non_admin
        Fails due to invalid user token resulting in
        raise mismatch_error testtools.matchers._impl.MismatchError: 401 != 403
        Occurs against Www-Authenticate: Keystone uri='https://127.0.0.1:5000'

    test_non_admin_with_admin_header
        Fails due to invalid user token resulting in
        raise mismatch_error testtools.matchers._impl.MismatchError: 401 != 403

tests/conductor/test_manager.py
    test_configure_ihost_new
        IOError: [Errno 13] Permission denied: '/tmp/dnsmasq.hosts'
        This directory does not exist. I am not sure if this directory is
        still supposed to exist, if it has moved, or if this entire test is
        based on deprecated/replaced functionality.

    test_configure_ihost_no_hostname
        os.rename(temp_dnsmasq_hosts_file, dnsmasq_hosts_file)
        OSError: [Errno 1] Operation not permitted
        Fails because the dnsmasq files don't exist.

    test_configure_ihost_replace
        IOError: [Errno 13] Permission denied: '/tmp/dnsmasq.hosts'
        This dnsmasq file doesn't exist. Same issue as in the first test.

There also exists the issue of using postgres for db migrations in
tests/db/sqlalchemy/test_migrations.py. The issue with this is that these
migrations can only be run on local VMs such as Ubuntu, and not on the build
servers or on Jenkins because it would require that someone manually set up
the database on those systems, and the issue with putting it on the build server
is that because there presently exist no ways of getting postgres running in a
virtual environment (e.g. tox's), it must be set up on the actual system. This
means that multiple people running these tests at the same time would interact
with the same db and could run into issues. The reason postgres is being used
is because between versions, some columns of enumerated types are being altered
and SQLite doesn't support ALTER COLUMN or ALTER TABLE functionality. Alembic
and sqlalchemy-migrate offer solutions to this, but presently there is no
intention to incorporate either of these packages.

--------------------------------------------------------------------------------
TESTING DECISIONS:

We've chosen to use flake8 instead of PEP8 because PEP8 results in a lot more
insignificant issues being found, and flake8 combines PEP8 with PyFlakes which
combines code formatting with syntax and import checking, additionally, flake8
provides the option to test code complexity and return warnings if the
complexity exceeds whatever limit you've set.

--------------------------------------------------------------------------------
