#!/usr/bin/env python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script synchronizes the newly introduced 'management_ip'
# field (24.09) in the dcorch subcloud table with the corresponding
# field in the dcmanager subclouds table for all existing subclouds.

import logging as LOG
import sys

import psycopg2
from psycopg2.extras import DictCursor
from psycopg2.extras import execute_batch

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

    if (
        from_release == "22.12" and
        action == "migrate" and
        is_system_controller()
    ):
        try:
            sync_dcorch_subcloud_management_ips(postgres_port)
        except Exception as e:
            LOG.exception("Error: %s", e)
            return 1
    return 0


def read_config_file(filename):
    config = {}
    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if line and "=" in line:
                key, value = line.split("=", 1)
                config[key.strip()] = value.strip()
    return config


def is_system_controller():
    platform_conf = read_config_file("/etc/platform/platform.conf")
    return "systemcontroller" in platform_conf.get(
        "distributed_cloud_role", ""
    )


def fetch_subclouds_columns(db_connection, columns: list):
    LOG.info(
        f"Fetching specified columns ({columns}) from the subclouds table"
    )
    with db_connection.cursor(cursor_factory=DictCursor) as cur:
        query = f"SELECT {', '.join(columns)} FROM subclouds;"
        cur.execute(query)
        results = cur.fetchall()
    return results


def update_dcorch_ips(db_connection, subclouds):
    LOG.info("Updating dcorch subcloud management IPs...")
    update_query = (
        "UPDATE subcloud SET management_ip = %s WHERE region_name = %s;"
    )
    update_data = [
        (row["management_start_ip"], row["region_name"]) for row in subclouds
    ]
    with db_connection.cursor(cursor_factory=DictCursor) as cur:
        execute_batch(cur, update_query, update_data)
    db_connection.commit()
    LOG.info(f"Updated {len(update_data)} subcloud rows")


def get_db_connection(dbname, postgres_port):
    conn = psycopg2.connect(
        f"dbname={dbname} user=postgres port={postgres_port}"
    )
    return conn


def sync_dcorch_subcloud_management_ips(postgres_port):
    # Get the region name and management IP of all subclouds
    dcmanager_db = get_db_connection("dcmanager", postgres_port)
    try:
        fields = ["region_name", "management_start_ip"]
        subclouds = fetch_subclouds_columns(dcmanager_db, fields)
    finally:
        dcmanager_db.close()

    # If there are no subclouds, there's nothing to be done
    if not subclouds:
        LOG.info("No subclouds found, no need to sync dcorch DB")
        return

    # Sync the management IPs
    dcorch_db = get_db_connection("dcorch", postgres_port)
    try:
        update_dcorch_ips(dcorch_db, subclouds)
    finally:
        dcorch_db.close()


if __name__ == "__main__":
    sys.exit(main())
