#!/usr/bin/env python
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Sample upgrade migration script. Important notes:
# - The script should exit 0 on success and exit non-0 on fail. Note that
#   failing will result in the upgrade of controller-1 failing, so don't fail
#   unless it is a real failure.
# - Your logic should only check the FROM_RELEASE to determine if migration is
#   required. Checking the TO_RELEASE is dangerous because we do not know
#   the exact value the TO_RELEASE will hold until we reach final compile.
#   The TO_RELEASE is here for logging reasons and in case of some unexpected
#   emergency where we may need it.
# - The script will be passed one of the following actions:
#     start: Prepare for upgrade on release N side. Called during
#            "system upgrade-start".
#     migrate: Perform data migration on release N+1 side. Called while
#              controller-1 is performing its upgrade. At this point in the
#              upgrade of controller-1, the databases have been migrated from
#              release N to release N+1 (data migration scripts have been
#              run). Postgres is running and is using the release N+1
#              databases. The platform filesystem is mounted at /opt/platform
#              and has data populated for both release N and release N+1.
# - We do the migration work here in the python script. This is the format we
#   use when we need to connect to the postgres database. This format makes
#   manipulating the data easier and gives more details when error handling.
# - The migration scripts are executed in alphabetical order. Please prefix
#   your script name with a two digit number (e.g. 01-my-script-name.sh). The
#   order of migrations usually shouldn't matter, so pick an unused number
#   near the middle of the range.

import sys

import psycopg2
from controllerconfig.common import log
from psycopg2.extras import RealDictCursor

LOG = log.get_logger(__name__)


def main():
    action = None
    from_release = None
    to_release = None  # noqa
    arg = 1
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]  # noqa
        elif arg == 3:
            action = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    if from_release == "17.06" and action == "migrate":
        try:
            LOG.info("performing sample migration from release %s to %s with "
                     "action: %s" % (from_release, to_release, action))
            do_migration_work()
        except Exception as ex:
            LOG.exception(ex)
            print(ex)
            return 1


# Rename this function to something relevant
def do_migration_work():
    """ This is a sample upgrade action."""
    conn = psycopg2.connect("dbname='sysinv' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("select * from i_system;")
            row = cur.fetchone()
            if row is None:
                LOG.exception("Failed to fetch i_system data")
                raise
            LOG.info("Got system version: %s during sample migration script"
                     % row.get('software_version'))


if __name__ == "__main__":
    sys.exit(main())
