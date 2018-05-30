This file discusses the current status of sysinv tests and areas where issues
still exist and what to do in order to test them.

At present, in it's current state, a py27 tox test will result in 18 tests being
skipped. If testing in a VM e.g. Ubuntu, it can be reduced to 16 skipped tests,
where one of those tests only exists for legacy reasons: MYSQL used to be used,
however now we only use SQLite and PostgreSQL, so _test_mysql_opportunistically
in db/sqlalchemy/test_migrations.py results in a skipped test on account that it
is no longer supported but is being kept in the codebase in the event that MYSQL
is ever used again.
One of those skips is also not actually a test, but is test-requirements.txt
which gets skipped because the filename is prefaced with 'test' so tox assumes
it's a test file, but because it doesn't contain any tests there are no tests to
pass or fail.
Two of the skips are in sysinv/tests/test_sysinv_deploy_helper.py where they're
hard-coded to skip because the tests are incompatible with the current Sysinv
db.

Thus the number of tests being skipped that need to be investigated/fixed is 12.

--------------------------------------------------------------------------------
RUNNING TESTS:

To fully test Sysinv in a local Ubuntu VM or similar, go to test_migrations.py
and in the function test_postgresql_opportunistically, comment out the
self.skipTest line to enable the test to be run.
Also go to the function test_postgresql_connect_fail and comment out the
self.skipTest line so that test can be run as well.
Lastly, in the function _reset_databases, go to the bottom and uncomment
self._reset_pg(conn_pieces) so the postgres DB can be reset between runs.
If this last line is not uncommented, your first run of the py27 tests will
work, but after that you will get
migrate.exceptions.DatabaseAlreadyControlledError

Do not push these lines uncommented upstream to the repo as Jenkins does not
have postgres set up and will throw errors which will send e-mails out to the
team.

If you've never run sysinv tests on your system before see
http://wiki.wrs.com/PBUeng/ToxUnitTesting#Sysinv
The above link contains information on setting up the postgres database used by
tests under TestMigrations.

The following has been pasted from the above link just to keep this file
self-contained:

Prior to running tests you will need certain packages installed:
sudo apt-get install sqlite3 libsqlite3-dev libvirt-dev libsasl2-dev libldap2-dev

To set up the postgres db for the first time enter the following in console:
sudo apt-get install postgresql postgresql-contrib
pip install psycopg2

sudo -u postgres psql
CREATE USER openstack_citest WITH CREATEDB LOGIN PASSWORD 'openstack_citest';
CREATE DATABASE openstack_citest WITH OWNER openstack_citest;
\q


To actually run the tests, in console navigate to
wrlinux-x/addons/wr-cgcs/layers/cgcs/middleware/sysinv/recipes-common/sysinv/sysinv

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

tests/api/test_invservers.py
    test_create_ihost
        Issues may be related to keyring.
        Fails with
        webtest.app.AppError: Bad response: 400 Bad Request (not 200 OK or 3xx
        redirect for http://localhost/v1/ihosts)
        '{"error_message": "{\\"debuginfo\\": null, \\"faultcode\\": \\"Client\\",
         \\"faultstring\\": \\"Unknown attribute for argument host: recordtype\\"}"}'

    test_create_ihost_valid_extra
        Fails for the same reason as the above test.

    test_post_ports_subresource
        Fails for the same reason as the above test.

    test_delete_iHost
        Fails for the same reason as the above test.

    test_delete_ports_subresource
        Fails for the same reason as the above test.

    test_one
        Fails due to mismatch error: matches Contains('serialid')
        Looks like /v1/ihosts populates from tests/db/utils.py so serialid
        is included. In this test there's an
        assertNotIn('serialid', data['ihosts'][0]), not sure if this is what
        we're intending to check for or not.

tests/conductor/test_manager.py
    test_configure_ihost_new
        IOError: [Errno 13] Permission denied: '/tmp/dnsmasq.hosts'
        This directory does not exist. I am not sure if this this directory is
        still supposed to exist, if it has moved, or if this entire test is
        based on deprecated/replaced functionality.

    test_configure_ihost_no_hostname
        os.rename(temp_dnsmasq_hosts_file, dnsmasq_hosts_file)
        OSError: [Errno 1] Operation not permitted
        Fails because the dnsmasq files don't exist.

    test_configure_ihost_replace
        IOError: [Errno 13] Permission denied: '/tmp/dnsmasq.hosts'
        This dnsmasq file doesn't exist. Same issue as in the first test.


As far as tests go, the tests in sysinv/tests/api above have the highest
priority of the remaining tests to be fixed.

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

The following flake8 Errors and Failures are ignored in tox.ini in sysinv/sysinv
because they were found to be insignificant and too tedious to correct, or were
found to be non-issues.

The list and explanations follow:

F403: 'from <module> import *' used; unable to detect undefined names
    Replacing the above with 'import <module>' requires one to go to all
    instances where the module was used, and to prefix the use of that module's
    function or variable with the name of the module.

F401: '<module> imported but unused'
    Some instances where the issue is reported have the indicated module used
    by other files making calls to the file where this is reported. Attempts to
    reduce the number of occurences of this issue were made, but errors popped
    up eratically due to missing imports and 69 instances were too many to test
    one-by-one.

F821: 'undefined name <var>'
    There were 124 instances, almost all of which complained about '_' not being
    defined, but '_' is something that is actually used and is from
    sysinv.openstack.common.gettextutils import _
    These are usually defined in the file containing the function call
    containing the "undefined name" as a parameter.
    It may however be worth looking through this list occasionally to make sure
    no orphaned variables are making their way into the code.

F841: 'local variable <var> is assigned to but never used'
    Some instances had the variable used by external file calls and there were
    69 instances to manually sort through.

E501: 'line too long (<length> > 79 characters)'
    There are 580 instances, and besides this being a non-issue, attempting to
    fix this may make the code horribly unreadable, or result in indentation
    errors being caused which can themselves be impossible to fix (the reason
    will be discussed below).

E127: 'continuation line over-indented for visual indent'
    There are 231 instances, and this issue can be impossible to fix: attempting
    to fix indentation can result in you either getting an over-indented or
    under-indented error no matter what you do.

E128: 'continuation line under-indented for visual indent'
    There are 455 instances, see above for reason why they remain. These
    visual indent issues also do not affect the code and are therefore
    non-issues.

E231: 'missing whitepace after ',''
    Does not affect code operation, and fixing this issue reduces code
    readability and will cause 'line too long' error.

E266: 'too many leading '#' for block comment'
    Double # are usually used to indicate TODO. Reducing this to a single #
    will make these messages look like comments and may confuse or mislead
    readers.

E402: 'module level import not at top of file'
    Every instance of this module is intentionally imported after patching.

E711: 'comparison to None should be 'if cond is not None:''
    'if != None' and 'if not None' are not precisely equivalent in python.
    This error has been ignored under the assumption that the designer was
    aware of this and wrote it this way intentionally.

E116: 'unexpected indentation (comment)'
    Changing the indentation to be at the outermost level reduces readability
    and thus this error is ignored.

E203: 'whitespace before ':''
    The current spacing was used to allign dictionary values for readability.
    Changing spacing to clear this error will reduce readability.

E731: 'do not assign a lambda expression, use a def'
    PEP8 doesn't like lambdas in assignmments because it isn't as useful
    for tracebacks and duplicates the functionality of using def. However,
    this isn't an actual issue and has been used to one-line very simple
    functionality.

E712: 'comparison to True should be 'if cond is True:' or 'if cond:''
    'if <var> == True' and 'if <var>' or 'if <var> is True' are not precisely
    equivalent in python. This error has been ignored under the assumption that
    the designer was aware of this and wrote it this way intentionally.

E713: 'test for membership should be 'not in''
    'not <x> in' and '<x> not in' are translated by the compiler to be the same
    thing. Should probably be changed to make it more pythonic.

E702: 'multiple statements on one line (semicolon)'
    Short statements were put on one line to save space and for readability.

E714: 'test for object identity should be 'is not'
    Translates in the compiler to be the same thing. Should be changed.

E126: 'continuation line over-indented for hanging indent'
    Doesn't affect functionality, and following this rule can reduce
    readability. Also is not enforced by PEP8 or unanimously accepted.

E121: 'continuation line under-indented for hanging indent'
    Doesn't affect functionality, and following this rule can reduce
    readability. Also is not enforced by PEP8 or unanimously accepted.

--------------------------------------------------------------------------------
