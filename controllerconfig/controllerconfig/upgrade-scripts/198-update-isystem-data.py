#!/usr/bin/python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script is responsible for updating the software_version
# in i_system table during the USM upgrade


import logging
import psycopg2
import sys

from controllerconfig.common.usm_log import configure_logging

LOG = logging.getLogger('main_logger')

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

    configure_logging()

    if action in ["activate", "activate-rollback"]:
        try:
            # This username/password authentication is required in activate
            # or rollback actions to connect to the database
            # For migration, we don't need username/password and host. Peer
            # authentication is available in the case of migration
            username, password = get_db_credentials()
            conn = psycopg2.connect("dbname=sysinv user=%s password=%s \
                                     host=localhost port=%s"
                                    % (username, password, postgres_port))
        except Exception as e:
            LOG.exception(f"Error connecting to database: {e}")
            return 1
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


def get_db_credentials():
    import re
    import configparser

    configparser = configparser.ConfigParser()
    configparser.read('/etc/sysinv/sysinv.conf')
    conn_string = configparser['database']['connection']
    match = re.match(r'postgresql\+psycopg2://([^:]+):([^@]+)@', conn_string)
    if match:
        username = match.group(1)
        password = match.group(2)
        return username, password
    else:
        raise Exception("Failed to get database credentials from sysinv.conf")


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
