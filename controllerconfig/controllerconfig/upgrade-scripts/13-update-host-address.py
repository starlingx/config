#!/usr/bin/python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import logging as LOG
import psycopg2
import sys

DEFAULT_POSTGRES_PORT = 5432
LOG_FILE = "/var/log/software.log"
DB_NAME = "sysinv"
DB_USER = "postgres"


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
            # optional port parameter for USM upgrade
            postgres_port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename=LOG_FILE, format=log_format, level=LOG.INFO,
                    datefmt="%FT%T")

    res = 0
    LOG.info("%s invoked from_release = %s to_release = %s action = %s"
             % (sys.argv[0], from_release, to_release, action))

    if action == "migrate" and from_release == "24.09":
        LOG.info("Updating addresses table entries.")

        try:
            update_address_name_from_db(postgres_port)
        except Exception as ex:
            LOG.exception("Error: {}".format(ex))
            print(ex)
            res = 1

    return res


def update_address_name_from_db(postgres_port):
    query = """
        UPDATE addresses
        SET name = REGEXP_REPLACE(
            name, '^system-controller-gateway-ip-', 'controller-gateway-')
        WHERE name LIKE 'system-controller-gateway-ip-%';
    """
    try:
        with psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            port=postgres_port
        ) as conn:
            with conn.cursor() as cursor:
                cursor.execute(query)
                rows_updated = cursor.rowcount
                conn.commit()

                if rows_updated:
                    LOG.info(
                        "Updated %d entries in addresses table.", rows_updated)
                else:
                    LOG.info("No entries updated in addresses table.")
    except Exception as e:
        LOG.error(f"Failed to update IP addresses in the "
                  f"database: {e}")
        raise


if __name__ == "__main__":
    sys.exit(main())
