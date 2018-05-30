#!/usr/bin/env python
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will add neutron hosts for each controller

import psycopg2
import sys

from sysinv.common import constants

from psycopg2.extras import RealDictCursor

from controllerconfig.common import log

from tsconfig.tsconfig import system_mode

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
            print ("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    if from_release == "17.06" and action == "migrate":
        try:
            neutron_create_controller_hosts()
        except Exception as ex:
            LOG.exception(ex)
            print ex
            return 1


def get_controller(conn, hostname):
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM i_host WHERE hostname=%s;",
                        (hostname,))
            row = cur.fetchone()
            if row is None:
                LOG.exception("Failed to fetch %s host_id" % hostname)
                raise
            return row


def create_neutron_host_if_not_exists(conn, sysinv_host):
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM hosts WHERE name=%s;",
                        (sysinv_host['hostname'],))
            row = cur.fetchone()
            if row is None:
                cur.execute("INSERT INTO hosts "
                            "(id, name, availability, created_at) "
                            "VALUES (%s, %s, %s, %s);",
                            (sysinv_host['uuid'], sysinv_host['hostname'],
                             "down", sysinv_host['created_at']))


def neutron_create_controller_hosts():
    simplex = (system_mode == constants.SYSTEM_MODE_SIMPLEX)

    sysinv_conn = psycopg2.connect("dbname=sysinv user=postgres")
    controller_0 = get_controller(sysinv_conn, constants.CONTROLLER_0_HOSTNAME)
    if not simplex:
        controller_1 = get_controller(sysinv_conn,
                                      constants.CONTROLLER_1_HOSTNAME)

    neutron_conn = psycopg2.connect("dbname=neutron user=postgres")
    create_neutron_host_if_not_exists(neutron_conn, controller_0)
    if not simplex:
        create_neutron_host_if_not_exists(neutron_conn, controller_1)


if __name__ == "__main__":
    sys.exit(main())
