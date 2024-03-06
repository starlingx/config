#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script is responsible for cleaning the capabilities column of i_host
# sysinv table, removing information used on old audit report of cstates
# min and max frequency.

import json
import sys

from psycopg2.extras import RealDictCursor
import psycopg2

from controllerconfig.common import log
from sysinv.common import constants

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
        elif arg == 4:
            # optional port parameter for USM upgrade
            # port = sys.argv[arg]
            pass
        else:
            print(f"Invalid option {sys.argv[arg]}.")
            return 1
        arg += 1

    log.configure()

    if from_release == "22.12" and action == "migrate":
        try:
            LOG.info("removing min_cpu_mhz_allowed, max_cpu_mhz_allowed, and "
                     "cstates_available information from capabilities column, "
                     f"from the release {from_release} to {to_release} with "
                     f"action: {action}")
            remove_cstates_and_frequency_info()
        except Exception as ex:
            LOG.exception(ex)
            print(ex)
            return 1


def remove_cstates_and_frequency_info():
    """This function removes the information of cstates, min and max frequency
    from the capabilities column.
    """

    conn = psycopg2.connect("dbname='sysinv' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("select uuid, capabilities from i_host;")
            row = cur.fetchall()
            if row is None:
                LOG.exception("Failed to fetch i_host data")
                raise

            for record in row:
                capabilities = json.loads(record['capabilities'])
                # removing min, max and cstates information
                capabilities.pop(constants.IHOST_CSTATES_AVAILABLE, None)
                capabilities.pop(constants.IHOST_MAX_CPU_MHZ_ALLOWED, None)
                capabilities.pop(constants.IHOST_MIN_CPU_MHZ_ALLOWED, None)

                sqlcom = ("update i_host set "
                          f"capabilities='{json.dumps(capabilities)}' "
                          f"where uuid='{record['uuid']}'")
                cur.execute(sqlcom)
        conn.commit()


if __name__ == "__main__":
    sys.exit(main())
