#!/usr/bin/env python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script deletes all endpoints and regions for all subclouds from
# the Keystone database. In case of an upgrade rollback, these
# endpoints and regions are recreated.

import configparser
import logging as LOG
import re
import sys
import uuid

import netaddr
import psycopg2
from psycopg2.extras import DictCursor
from psycopg2.extras import execute_batch

ENDPOINT_URLS = {
    "platform": "https://{}:6386/v1",
    "identity": "https://{}:5001/v3",
    "patching": "https://{}:5492",
    "faultmanagement": "https://{}:18003",
    "nfv": "https://{}:4546",
    "usm": "https://{}:5498",
    "dcagent": "https://{}:8326",
}

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

    if is_system_controller():
        try:
            if (
                from_release == "22.12" and
                to_release == "24.09" and
                action == "activate"
            ):
                remove_subcloud_endpoints(postgres_port)
            elif (
                from_release == "24.09" and
                to_release == "22.12" and
                action == "activate-rollback"
            ):
                # We first remove any existing endpoints to avoid
                # duplicates when creating them
                remove_subcloud_endpoints(postgres_port)
                create_subcloud_endpoints_and_regions(postgres_port)
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


def get_services(db_connection):
    LOG.info("Getting service list")
    with db_connection.cursor(cursor_factory=DictCursor) as cur:
        cur.execute("SELECT * from service;")
        results = cur.fetchall()
    return results


def fetch_subclouds_columns(db_connection, columns: list):
    LOG.info(
        f"Fetching specified columns ({columns}) from the subclouds table"
    )
    with db_connection.cursor(cursor_factory=DictCursor) as cur:
        query = f"SELECT {', '.join(columns)} FROM subclouds;"
        cur.execute(query)
        results = cur.fetchall()
    return results


def delete_endpoints(db_connection, region_names):
    LOG.info("Deleting subcloud endpoints from keystone DB...")
    with db_connection.cursor(cursor_factory=DictCursor) as cur:
        query_str = "DELETE FROM endpoint WHERE region_id IN %s;"
        cur.execute(query_str, (region_names,))
        deleted_count = cur.rowcount
    db_connection.commit()
    LOG.info(f"Deleted {deleted_count} subcloud endpoints")


def delete_regions(db_connection, region_names):
    LOG.info("Deleting subcloud regions from keystone DB")
    with db_connection.cursor(cursor_factory=DictCursor) as cur:
        query_str = "DELETE FROM region WHERE id IN %s;"
        cur.execute(query_str, (region_names,))
        deleted_count = cur.rowcount
    db_connection.commit()
    LOG.info(f"Deleted {deleted_count} subcloud regions")


def remove_subcloud_endpoints(postgres_port):
    # Get the region names of all subclouds
    dcmanager_db = get_db_connection("dcmanager", postgres_port)
    try:
        subclouds = fetch_subclouds_columns(dcmanager_db, ["region_name"])
        subcloud_region_names = tuple(
            [row["region_name"] for row in subclouds]
        )
    finally:
        dcmanager_db.close()

    # If there are no subclouds, there's nothing to do
    if not subcloud_region_names:
        LOG.info("No subclouds found, no endpoints to delete")
        return

    # Delete all endpoints and regions for all subclouds
    keystone_db = get_db_connection("keystone", postgres_port)
    try:
        delete_endpoints(keystone_db, subcloud_region_names)
        delete_regions(keystone_db, subcloud_region_names)
    finally:
        keystone_db.close()


def build_regions(subclouds):
    regions = []
    for subcloud in subclouds:
        region_name = subcloud["region_name"]
        region = (region_name, "", None, "{}")
        regions.append(region)
    return regions


def build_endpoints(services, subclouds):
    endpoints = []
    for subcloud in subclouds:
        for service in services:
            # Skip usm and dcagent endpoint during rollback
            if (service["type"] not in ["usm", "dcagent"]) and (
                url := ENDPOINT_URLS.get(service["type"], None)
            ):
                uid = uuid.uuid4().hex
                sid = service["id"]
                region = subcloud["region_name"]
                ip = subcloud["management_start_ip"]
                formatted_ip = (
                    f"[{ip}]" if netaddr.IPAddress(ip).version == 6 else ip
                )
                formatted_url = url.format(formatted_ip)
                endpoint = (
                    uid,
                    None,
                    "admin",
                    sid,
                    formatted_url,
                    "{}",
                    True,
                    region,
                )
                endpoints.append(endpoint)
    return endpoints


def insert_regions(db_connection, regions):
    LOG.info("Creating subcloud regions...")
    insert_query = """
    INSERT INTO region (id, description, parent_region_id, extra)
    VALUES (%s, %s, %s, %s);
    """
    with db_connection.cursor(cursor_factory=DictCursor) as cur:
        execute_batch(cur, insert_query, regions)
    db_connection.commit()
    LOG.info(f"Created {len(regions)} subcloud regions")


def insert_endpoints(db_connection, endpoints):
    LOG.info("Creating subcloud endpoints...")
    insert_query = (
        "INSERT INTO endpoint (id, legacy_endpoint_id, interface, service_id, "
        "url, extra, enabled, region_id) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s);"
    )
    with db_connection.cursor(cursor_factory=DictCursor) as cur:
        execute_batch(cur, insert_query, endpoints)
    db_connection.commit()
    LOG.info(f"Created {len(endpoints)} subcloud endpoints")


def get_db_credentials(config_path):
    config = configparser.ConfigParser()
    with open(config_path, "r", encoding="utf-8") as config_file:
        config.read_file(config_file)
    conn_string = config["database"]["connection"]
    match = re.match(r"postgresql\+psycopg2://([^:]+):([^@]+)@", conn_string)
    if match:
        username = match.group(1)
        password = match.group(2)
        return username, password

    raise Exception(f"Failed to get database credentials from {config_file}")


def get_db_connection(dbname, postgres_port):
    config_path = f"/etc/{dbname}/{dbname}.conf"
    user, passwd = get_db_credentials(config_path)
    conn = psycopg2.connect(
        f"dbname={dbname} user={user} password={passwd}"
        f" host=localhost port={postgres_port}"
    )
    return conn


def create_subcloud_endpoints_and_regions(postgres_port):
    # Get the region names and management IPs of all subclouds
    dcmanager_db = get_db_connection("dcmanager", postgres_port)
    try:
        fields = ["region_name", "management_start_ip"]
        subclouds = fetch_subclouds_columns(dcmanager_db, fields)
    finally:
        dcmanager_db.close()

    # If there are no subclouds, there's nothing to be done
    if not subclouds:
        LOG.info("No subclouds found, no endpoints to create")
        return

    # Create the endpoints and regions
    keystone_db = get_db_connection("keystone", postgres_port)
    try:
        services = get_services(keystone_db)
        endpoints = build_endpoints(services, subclouds)
        regions = build_regions(subclouds)
        insert_regions(keystone_db, regions)
        insert_endpoints(keystone_db, endpoints)
    finally:
        keystone_db.close()


if __name__ == "__main__":
    sys.exit(main())
