#!/usr/bin/env python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will remove load, host_upgrade and software_upgrade
# database table
#

import logging
import sys

from packaging import version
import psycopg2

from controllerconfig.common.usm_log import configure_logging

DEFAULT_POSTGRES_PORT = 5432

LOG = logging.getLogger('main_logger')


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
    configure_logging()
    LOG.info(
        "%s invoked from_release = %s to_release = %s action = %s"
        % (sys.argv[0], from_release, to_release, action)
    )
    res = 0
    to_release_version = version.Version(to_release)
    minimum_version = version.Version("25.09")
    if action == 'migrate' and to_release_version == minimum_version:
        try:
            conn = psycopg2.connect("dbname=sysinv user=postgres port=%s"
                                    % postgres_port)
            delete_software_upgrade_database(conn)
            delete_host_upgrade_database(conn)
            delete_load_database(conn)
            conn.close()
        except Exception as e:
            LOG.exception("Error: {}".format(e))
            res = 1
    return res


def delete_load_database(conn):
    delete_cmd = "drop table if exists loads;"
    db_update(conn, delete_cmd)
    LOG.info("Loads table removed with success")


def delete_host_upgrade_database(conn):
    delete_cmd = "drop table if exists host_upgrade;"
    db_update(conn, delete_cmd)
    LOG.info("Host_upgrade table removed with success")


def delete_software_upgrade_database(conn):
    delete_cmd = "drop table if exists software_upgrade;"
    db_update(conn, delete_cmd)
    LOG.info("Software_upgrade table removed with success")


def db_update(conn, query):
    with conn.cursor() as cur:
        cur.execute(query)
    conn.commit()


if __name__ == "__main__":
    sys.exit(main())
