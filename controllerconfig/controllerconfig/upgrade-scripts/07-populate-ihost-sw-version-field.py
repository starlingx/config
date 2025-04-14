#!/usr/bin/env python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# The purpose of this script is to populate the sw_version
# field on i_host table.

import logging
import sys
import psycopg2
from six.moves import configparser

from controllerconfig.common.usm_log import configure_logging

CONTROLLER_0_HOSTNAME = "controller-0"
CONTROLLER_1_HOSTNAME = "controller-1"
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
    if action == 'migrate':
        try:
            conn = psycopg2.connect("dbname=sysinv user=postgres port=%s"
                                    % postgres_port)
            populate_ihost_sw_version(conn, to_release)
            conn.close()
        except Exception as e:
            LOG.exception("Error: {}".format(e))
            res = 1
    return res


def populate_ihost_sw_version(conn, to_release):
    """
    Populate the sw_version field of i_host table for simplex
    """
    hostname = CONTROLLER_1_HOSTNAME
    if get_system_mode() == "simplex":
        hostname = CONTROLLER_0_HOSTNAME
    update_query = ("UPDATE i_host set sw_version = %s WHERE "
                    "hostname = '%s'" % (to_release,
                                         hostname))
    db_update(conn, update_query)
    LOG.info("Updated sw_version to %s on %s" % (to_release, hostname))


def get_system_mode():
    ini_str = '[DEFAULT]\n' + open('/etc/platform/platform.conf', 'r').read()

    config_applied = configparser.RawConfigParser()
    config_applied.read_string(ini_str)

    if config_applied.has_option('DEFAULT', 'system_mode'):
        system_mode = config_applied.get('DEFAULT', 'system_mode')
    else:
        system_mode = None

    return system_mode


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
