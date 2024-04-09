#!/usr/bin/env python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# The purpose of this script is to populate the sw_version
# field on i_host table.

import sys
import psycopg2
from controllerconfig.common import log

LOG = log.get_logger(__name__)
CONTROLLER_1_HOSTNAME = "controller-1"
DEFAULT_POSTGRES_PORT = 5432


def main():
    action = None
    from_release = None
    to_release = None
    postgres_port = DEFAULT_POSTGRES_PORT
    arg = 1
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            postgres_port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1
    log.configure()
    LOG.info(
        "%s invoked from_release = %s to_release = %s action = %s"
        % (sys.argv[0], from_release, to_release, action)
    )
    res = 0
    if action == 'migrate' and from_release == '22.12':
        try:
            conn = psycopg2.connect("dbname=sysinv user=postgres port=%s"
                                    % postgres_port)
            populate_ihost_sw_version(conn, to_release, from_release)
            conn.close()
        except Exception as e:
            LOG.exception("Error: {}".format(e))
            res = 1
    return res


def populate_ihost_sw_version(conn, to_release, from_release):
    """
    Populate with the to_release/from_release sw_version field of i_host table
    """
    hostname_query = "SELECT hostname from i_host"
    res = db_query(conn, hostname_query)
    for hostname in res:
        # if len == 1 is SX.
        if len(res) == 1 or hostname[0] == CONTROLLER_1_HOSTNAME:
            update_query = ("UPDATE i_host set sw_version = %s WHERE "
                            "hostname = '%s'" % (to_release, hostname[0]))
            db_update(conn, update_query)
            LOG.info("Updated sw_version to %s on %s" %
                     (to_release, hostname[0]))
        else:
            update_query = ("UPDATE i_host set sw_version = %s WHERE "
                            "hostname = '%s'" % (from_release, hostname[0]))
            db_update(conn, update_query)
            LOG.info("Updated sw_version to %s on %s" %
                     (from_release, hostname[0]))


def db_update(conn, query):
    with conn.cursor() as cur:
        cur.execute(query)
    conn.commit()


def db_query(conn, query):
    result = []
    with conn.cursor() as cur:
        cur.execute(query)
        for rec in cur:
            result.append(rec)
    return result


if __name__ == "__main__":
    sys.exit(main())
