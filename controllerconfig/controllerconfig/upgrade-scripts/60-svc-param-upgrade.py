#!/usr/bin/env python
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will add service parameters specific to handling of ghcr.io
# registry into the sysinv database during migration phase of upgrade
# procedure.
# Also, the previous horizon parameters will be removed without necessity
# to keep the old unused values.

import sys
import psycopg2
from datetime import datetime
from oslo_utils import uuidutils
from psycopg2.extras import RealDictCursor
from controllerconfig.common import log

LOG = log.get_logger(__name__)


def main():
    action = None
    from_release = None
    to_release = None
    arg = 1

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    LOG.info("%s invoked with from_release = %s to_release = %s action = %s"
             % (sys.argv[0], from_release, to_release, action))
    if action == "migrate" and from_release == '21.05':
        try:
            conn = psycopg2.connect("dbname=sysinv user=postgres")
            with conn:
                add_ghcr_registry(conn)

                remove_horizon_params(conn)

                return 0
        except Exception as ex:
            LOG.exception(ex)
            return 1


def get_gcr_rows(db_conn):
    with db_conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("select name, value, personality, resource from "
                    "service_parameter where service='docker' and "
                    "section='gcr-registry'")

        return cur.fetchall()


def add_ghcr_registry(db_conn):
    cmd = """
        INSERT INTO service_parameter (created_at, uuid, name,
        value, service, section, personality, resource) VALUES
        (%s, %s, %s, %s, %s, %s, %s, %s);
        """
    rows = get_gcr_rows(db_conn)
    for row in rows:
        timestamp = str(datetime.now())
        uuid = uuidutils.generate_uuid()
        value = row.get('value')

        # There are two names where we expect to need to
        # replace the registry name in the corresponding value.
        for key in ['additional-overrides', 'url']:
            if value and row.get('name') == key:
                value = value.replace('gcr.io', 'ghcr.io')

        LOG.info("Adding %s=%s to db for ghcr-registry"
                 % (row['name'], value))
        with db_conn.cursor() as cur:
            cur.execute(
                cmd,
                (timestamp, uuid, row['name'], value,
                    'docker', 'ghcr-registry', row['personality'],
                    row['resource']))
    LOG.info("ghcr_registry parameters upgrade completed")


def remove_horizon_params(db_conn):
    cmd_delete = "DELETE FROM service_parameter WHERE " \
                 "service='horizon' and section='auth'"
    LOG.info("Removing horizon auth params from db")
    with db_conn.cursor() as cur:
        cur.execute(cmd_delete)
    LOG.info("Horizon auth params removed")


if __name__ == "__main__":
    sys.exit(main())
