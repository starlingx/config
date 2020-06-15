#!/usr/bin/python
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will update subcloud_status table in dcmanager database
# in preparation for upgrade to release 20.06.
#
# Subcloud load audit, introduced in release 20.06, entails creating
# load status record when a subcloud is added to the database and
# having the subcloud load status updated by dcmanager audit task.
# The script adds a load status record for each of the existing
# subclouds to ensure successful startup and operation of dcmanager
# when the system controller hosts are upgraded to 20.06.
#
# This script can be removed in the release that follows 20.06.
#

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
            print ("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    LOG.debug("%s invoked with from_release = %s to_release = %s action = %s"
              % (sys.argv[0], from_release, to_release, action))
    if to_release == "20.06" and action == "migrate":
        try:
            if is_system_controller():
                LOG.info("Performing subcloud status data migration...")
                update_subcloud_status()
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


def update_subcloud_status():
    conn = psycopg2.connect("dbname='dcmanager' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check if there are any subclouds
            cur.execute("SELECT * from subclouds")
            subcloud_records = cur.fetchall()
            if not subcloud_records:
                LOG.info("Nothing to do - there are no subclouds.")
                return

            # Check if load status records already exist
            cur.execute("SELECT * from subcloud_status where "
                        "endpoint_type = 'load'")
            load_status_records = cur.fetchall()
            if load_status_records:
                LOG.info("Nothing to do - load status records already exist.")
                return

            cur.execute("SELECT * from subcloud_status where "
                        "endpoint_type = 'patching'")
            patching_status_records = cur.fetchall()
            if not patching_status_records:
                LOG.exception("Failed to fetch subcloud status data.")
                raise

            for record in patching_status_records:
                # Insert a record for load endpoint type for each
                # subcloud based on data of patching record.
                cur.execute("INSERT into subcloud_status (subcloud_id, "
                            "endpoint_type, sync_status, created_at, "
                            "deleted) values (%d, 'load', "
                            "'%s', '%s', 0)"
                            % (record['subcloud_id'],
                               record['sync_status'],
                               record['created_at']))

    LOG.info("Subcloud status data migration completed.")


if __name__ == "__main__":
    sys.exit(main())
