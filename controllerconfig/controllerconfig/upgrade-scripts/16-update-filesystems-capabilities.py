#!/usr/bin/env python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will update the capabilities
# field in the controller_fs and host_fs
# tables to the default configuration
# '{"functions": []}' when performing
# version migration.
#

import logging as LOG
import sys

import psycopg2

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
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=LOG.INFO, datefmt="%FT%T")
    LOG.info(
        "%s invoked from_release = %s to_release = %s action = %s"
        % (sys.argv[0], from_release, to_release, action)
    )
    res = 0

    if action == 'migrate' and from_release == '22.12':
        try:
            conn = psycopg2.connect("dbname=sysinv user=postgres port=%s"
                                    % postgres_port)
            update_controller_fs_capabilities(conn)
            update_host_fs_capabilities(conn)
            conn.close()
        except Exception as e:
            LOG.exception("Error: {}".format(e))
            res = 1

    return res


def update_controller_fs_capabilities(conn):
    update_query = """UPDATE controller_fs
                      SET capabilities = '{"functions": []}';
                    """
    db_update(conn, update_query)
    LOG.info("Updated controller_fs capabilities.")


def update_host_fs_capabilities(conn):
    update_query = """UPDATE host_fs
                      SET capabilities = '{"functions": []}';
                    """
    db_update(conn, update_query)
    LOG.info("Updated host_fs capabilities.")


def db_update(conn, query):
    with conn.cursor() as cur:
        cur.execute(query)
    conn.commit()


if __name__ == "__main__":
    sys.exit(main())
