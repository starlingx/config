#!/usr/bin/env python3
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0


# This script performs database updation and rollback operations
# for the `interfaces` table in the `sysinv` PostgreSQL database,
# specifically targeting VF interfaces with PCI SR-IOV class.


import sys
import psycopg2
import logging as LOG
from psycopg2 import sql
import json
import re
import configparser
import subprocess
import time

DB_NAME = "sysinv"
DB_HOST = "localhost"
TABLE_NAME = "interfaces"
MAX_TX_RATE = "max_tx_rate"
MAX_RX_RATE = "max_rx_rate"
IFCAPABILITIES = "ifcapabilities"
VF_TYPE = "vf"
PCI_CLASS = "pci-sriov"
DEFAULT_POSTGRES_PORT = "5432"

LOG.basicConfig(
    filename="/var/log/software.log",
    format='%(asctime)s: [%(process)s]: %(filename)s(%(lineno)s): '
           '%(levelname)s: %(message)s',
    level=LOG.INFO,
    datefmt="%FT%T"
)


def get_db_credentials():
    """ Retrieve DB credentials from sysinv.conf """
    try:
        config = configparser.ConfigParser()
        config.read('/etc/sysinv/sysinv.conf')

        conn_string = config['database']['connection']
        match = re.match(r'postgresql\+psycopg2://([^:]+):([^@]+)@',
                         conn_string)

        if match:
            username = match.group(1)
            password = match.group(2)
            return username, password
        else:
            raise Exception("Failed to parse DB credentials from sysinv.conf")
    except Exception as e:
        LOG.error(f"Error getting DB credentials: {e}")
        sys.exit(1)


def connect_to_db(port):
    """ Establish DB connection """
    username, password = get_db_credentials()

    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=username,
            password=password,
            host=DB_HOST,
            port=port
        )
        return conn
    except Exception as e:
        LOG.error(f"Database connection failed: {e}")
        sys.exit(1)


def db_query(conn, query, params=()):
    """ Execute SELECT query and return results """
    with conn.cursor() as cur:
        cur.execute(query, params)
        return cur.fetchall()


def db_update(conn, query, params=(), autocommit=True):
    """ Execute UPDATE query """
    with conn.cursor() as cur:
        cur.execute(query, params)
    if autocommit:
        conn.commit()


def columns_exist(conn):
    """ Verify required columns exist in the table """
    query = f"""
    SELECT column_name
    FROM information_schema.columns
    WHERE table_name = '{TABLE_NAME}'
      AND column_name IN ('{MAX_TX_RATE}', '{MAX_RX_RATE}',
                          '{IFCAPABILITIES}');
    """

    cols = db_query(conn, query)
    existing_cols = {col[0] for col in cols}

    if {MAX_TX_RATE, MAX_RX_RATE, IFCAPABILITIES}.issubset(existing_cols):
        return True
    else:
        missing_cols = (
            {MAX_TX_RATE, MAX_RX_RATE, IFCAPABILITIES} - existing_cols
        )
        LOG.error(f"Missing columns: {', '.join(missing_cols)}")
        sys.exit(1)


def update_data(conn):
    LOG.info("Starting data updation...")

    select_query = sql.SQL(f"""
        SELECT id, uuid, {IFCAPABILITIES}
        FROM {TABLE_NAME}
        WHERE iftype = %s AND ifclass = %s;
    """)

    vf_interfaces = []

    vf_interfaces = db_query(
        conn, select_query, (VF_TYPE, PCI_CLASS)
    )
    LOG.info(f"Found {len(vf_interfaces)} VF interfaces to update.")
    if len(vf_interfaces) == 0:
        LOG.info("No VF interfaces found to update. No changes required")
        return

    updated = False

    for iface_id, iface_uuid, ifcapabilities in vf_interfaces:
        if ifcapabilities:
            try:
                capabilities_dict = json.loads(ifcapabilities)
            except(json.JSONDecodeError, TypeError) as e:
                raise ValueError(
                    f"Malformed ifcapabilities for UUID {iface_uuid}: {e}"
                )

            tx_rate = capabilities_dict.get("max_tx_rate", None)

            if "max_tx_rate" in capabilities_dict:
                del capabilities_dict["max_tx_rate"]

            cleaned_ifcapabilities = json.dumps(capabilities_dict) if \
                capabilities_dict else None

            # Only update the database if either tx_rate or
            # cleaned_ifcapabilities has a value
            if tx_rate is not None or cleaned_ifcapabilities is not None:
                update_query = sql.SQL(f"""
                    UPDATE {TABLE_NAME}
                    SET {MAX_TX_RATE} = %s, {IFCAPABILITIES} = %s
                    WHERE id = %s;
                """)

                db_update(
                    conn,
                    update_query,
                    (tx_rate, cleaned_ifcapabilities, iface_id),
                    autocommit=False
                )
                updated = True

                LOG.info(f"Updated {TABLE_NAME} for UUID: {iface_uuid} "
                         f"with max_tx_rate: {tx_rate}")

    if updated:
        conn.commit()
        LOG.info("All applicable records updated successfully.")
    else:
        LOG.info("No changes were made to the database.")


def rollback_data(conn):
    """Rollback migration by moving data back to ifcapabilities"""
    LOG.info("Starting data rollback...")

    select_query = sql.SQL(f"""
        SELECT id, uuid, {MAX_TX_RATE}, {IFCAPABILITIES}
        FROM {TABLE_NAME}
        WHERE iftype = %s AND ifclass = %s;
    """)

    vf_interfaces = []

    vf_interfaces = db_query(
        conn, select_query, (VF_TYPE, PCI_CLASS)
    )
    LOG.info(f"Found {len(vf_interfaces)} VF interfaces to rollback.")
    if len(vf_interfaces) == 0:
        LOG.info("No VF interfaces found to rollback. No changes required")
        return

    updated = False

    for iface_id, iface_uuid, max_tx_rate, ifcapabilities in vf_interfaces:
        capabilities = {}

        if max_tx_rate is not None:
            capabilities["max_tx_rate"] = max_tx_rate

        if ifcapabilities:
            try:
                existing = json.loads(ifcapabilities)
                capabilities.update(existing)
            except (json.JSONDecodeError, TypeError) as e:
                raise ValueError(
                    f"Malformed ifcapabilities for UUID {iface_uuid}: {e}"
                )

        if not capabilities:
            continue

        new_ifcap = json.dumps(capabilities) if capabilities else None

        if new_ifcap or max_tx_rate is not None:
            update_query = sql.SQL(f"""
                UPDATE {TABLE_NAME}
                SET {IFCAPABILITIES} = %s, {MAX_TX_RATE} = NULL
                WHERE id = %s;
            """)

            db_update(
                conn, update_query, (new_ifcap, iface_id), autocommit=False
            )
            updated = True

            LOG.info(
                f"Rolled back {TABLE_NAME} for UUID: {iface_uuid} "
                f"with ifcapabilities: {new_ifcap}"
            )

    if updated:
        conn.commit()
        LOG.info("All applicable records rolled back successfully.")
    else:
        LOG.info("No changes were made to the database.")


def patch_felix_configuration():
    """Ensure FelixConfiguration chainInsertMode is set to Append."""
    LOG.info("Patching FelixConfiguration to Append...")

    cmd = [
        "kubectl", "--kubeconfig=/etc/kubernetes/admin.conf",
        "patch", "felixconfiguration", "default", "--type=merge",
        "-p", '{"spec":{"chainInsertMode":"Append"}}'
    ]

    retries, delay = 3, 5
    timeout = 15

    for attempt in range(retries):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout
            )
            LOG.info(f"Patch applied successfully: {result.stdout}")
            return
        except subprocess.TimeoutExpired:
            LOG.warning(f"Attempt {attempt + 1} timed out after {timeout}s.")
        except subprocess.CalledProcessError as e:
            LOG.warning(f"Attempt {attempt + 1} failed: {e.stderr}")

        if attempt < retries - 1:
            time.sleep(delay)
        else:
            LOG.error("FelixConfiguration patch failed after retries.")


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
            LOG.error(f"Invalid option {sys.argv[arg]}.")
            return 1
        arg += 1

    if action not in ["activate", "activate-rollback"]:
        LOG.warning(f"Action '{action}' is not valid. Skipping...")
        return 0

    try:
        conn = connect_to_db(postgres_port)

        columns_exist(conn)

        if to_release == "25.09" and action == "activate":
            update_data(conn)
            patch_felix_configuration()
        elif from_release == "25.09" and action == "activate-rollback":
            rollback_data(conn)
        else:
            LOG.error(f"Unknown action: {action}")
            return 1

    except Exception as e:
        LOG.error(f"Exception during {action}: {e}", exc_info=True)
        return 1
    finally:
        if 'conn' in locals():
            conn.close()


if __name__ == "__main__":
    main()
