#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Script to Add Service Parameter during Upgrade

import logging as LOG
import sys
import psycopg2
import uuid

SUCCESS = 0
ERROR = 1
RELEASE_22_12 = "22.12"
RELEASE_24_09 = "24.09"

DEFAULT_POSTGRES_PORT = 5432


class PostgresManager(object):
    """
    Handles PostgreSQL operations to add service parameters during an upgrade.
    """
    def __init__(self, port: int = DEFAULT_POSTGRES_PORT) -> None:
        self.dbname = "sysinv"
        self.user = "postgres"
        self.port = port
        self.conn = psycopg2.connect(
            dbname=self.dbname, user=self.user, port=self.port
        )

    def query(self, query: str) -> list:
        """
        Execute a SELECT query and return the results.
        """
        result = []
        with self.conn.cursor() as cur:
            cur.execute(query)
            result = cur.fetchall()
        return result

    def update(self, query: str) -> None:
        """
        Execute an UPDATE or INSERT query.
        """
        with self.conn.cursor() as cur:
            cur.execute(query)
        self.conn.commit()

    def add_out_of_tree_driver(self) -> None:
        """
        Adds the 'out_of_tree_drivers' service parameter during the upgrade
        from 22.12 to 24.09. Skips if the parameter already exists.
        """
        name = "out_of_tree_drivers"
        value = "ice,i40e,iavf"
        service = "platform"
        section = "kernel"

        fetch_query = f"SELECT * FROM service_parameter WHERE name='{name}'"
        result = self.query(fetch_query)

        if not result:
            LOG.info(f"'{name}' service parameter not found. Adding it.")
            insert_query = (
                "INSERT INTO service_parameter(uuid, name, service, "
                f"section, value, id) VALUES ('{uuid.uuid4()}', "
                f"'{name}', '{service}', '{section}', '{value}',"
                "nextval('service_parameter_id_seq'))"
            )
            LOG.info(insert_query)
            self.update(insert_query)

            # Log the newly added service parameter
            new_result = self.query(fetch_query)
            LOG.info(f"Added '{name}' service parameter: {new_result}")
        else:
            LOG.info(f"'{name}' service parameter already exists:\n{result}")


def main() -> int:
    """
    Main function to parse arguments and trigger service parameter addition.
    """
    # Configure logging
    log_format = ('%(asctime)s: [%(process)s]: %(filename)s(%(lineno)s): '
                  '%(levelname)s: %(message)s')
    LOG.basicConfig(
        filename="/var/log/software.log",
        format=log_format, level=LOG.INFO, datefmt="%FT%T"
    )

    if len(sys.argv) < 4:
        LOG.error(
            "Missing arguments! \n Usage: migration.py <from-release> "
            "<to-release> <action>"
        )
        return ERROR

    script, from_release, to_release, action = sys.argv[0:4]
    postgres_port = DEFAULT_POSTGRES_PORT

    if action == "migrate" and \
            (from_release == RELEASE_22_12 and to_release == RELEASE_24_09):
        LOG.info(
            f"{script} invoked with from_release={from_release}, "
            f"to_release={to_release}, action={action}"
        )
        PostgresManager(postgres_port).add_out_of_tree_driver()
    else:
        LOG.info("No action required for the specified upgrade path.")

    return SUCCESS


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        LOG.error(f"An error occurred: {e}")
        raise
