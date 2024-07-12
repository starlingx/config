#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script is responsible for updating the software_version
# in i_system table during the USM upgrade


import logging as LOG
import psycopg2
import sys


DEFAULT_POSTGRES_PORT = 5432


def main():
    action = None
    from_release = None
    to_release = None  # noqa
    postgres_port = DEFAULT_POSTGRES_PORT
    arg = 1
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]  # noqa
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            # optional port parameter for USM upgrade
            postgres_port = sys.argv[arg]
            pass
        else:
            print(f"Invalid option {sys.argv[arg]}.")
            return 1
        arg += 1

    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=LOG.INFO, datefmt="%FT%T")

    try:
        conn = psycopg2.connect("dbname=sysinv user=postgres port=%s"
                                % postgres_port)
    except Exception as e:
        LOG.exception(f"Error connecting to database: {e}")
        return 1

    if action in ["activate", "activate-rollback"]:
        try:
            LOG.info(f"Updating software_version from {from_release} \
                     to {to_release}\n")
            update_isystem_software_version(conn, to_release)
        except Exception as ex:
            LOG.exception(ex)
            return 1
        finally:
            conn.close()
        return 0


def update_isystem_software_version(conn, new_sw_version):
    """
    This function updates the software_version in isystem table
    """

    update_isystem_software_version_query = \
        f"UPDATE i_system SET software_version='{new_sw_version}';"
    db_update(conn, update_isystem_software_version_query)
    LOG.info(f"Updated software_version to {new_sw_version}")


def db_query(conn, query):
    result = []
    with conn.cursor() as cur:
        cur.execute(query)
        for rec in cur:
            result.append(rec)
    return result


def db_update(conn, query):
    with conn.cursor() as cur:
        cur.execute(query)
    conn.commit()


if __name__ == "__main__":
    sys.exit(main())
