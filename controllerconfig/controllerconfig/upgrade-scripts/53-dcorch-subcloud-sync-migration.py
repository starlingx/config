#!/usr/bin/python
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script updates the subcloud_sync table in dcorch database
# in preparation for upgrade from release 20.06.
#
# This script can be removed in the release that follows.
#

import json
import psycopg2
import sys
from controllerconfig.common import log
from psycopg2.extras import RealDictCursor


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

    LOG.debug("%s invoked with from_release = %s to_release = %s action = %s"
              % (sys.argv[0], from_release, to_release, action))
    if from_release == "20.06" and action == "migrate":
        try:
            if is_system_controller():
                LOG.info("Performing dcorch subcloud sync data migration...")
                update_subcloud_sync()
        except Exception as ex:
            LOG.exception(ex)
            print(ex)
            return 1


def is_system_controller():
    conn = psycopg2.connect("dbname='sysinv' user='postgres'")

    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * from i_system")
            system = cur.fetchone()
            return system['distributed_cloud_role'] == 'systemcontroller'


def update_subcloud_sync():
    conn = psycopg2.connect("dbname='dcorch' user='postgres'")

    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check if there are any subclouds
            cur.execute("SELECT * from subcloud")
            subcloud_records = cur.fetchall()
            if not subcloud_records:
                LOG.info("dcorch subcloud_sync data migration not required")
                return

            for record in subcloud_records:
                capabilities = json.loads(record['capabilities'])
                endpoint_types = capabilities.get('endpoint_types')

                for ept in endpoint_types:
                    # Insert a record into subcloud sync for each of the
                    # endpoint types supported for each subcloud
                    cur.execute("INSERT into subcloud_sync (subcloud_id, "
                                "subcloud_name, endpoint_type, "
                                "audit_status, created_at, "
                                "deleted) values (%d, '%s', "
                                "'%s', '%s', '%s', 0)"
                                % (record['id'],
                                   record['region_name'],
                                   ept,
                                   'none',
                                   record['created_at']))

    LOG.info("dcorch subcloud_sync data migration completed.")


if __name__ == "__main__":
    sys.exit(main())
