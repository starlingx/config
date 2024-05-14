#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script is to update the "mgmt_ipsec" flag in capabilities of
# sysinv i_host table to "upgrading". This flag will be checked by
# ipsec-server when it receives IPsec config request from ipsec-client.
# It will refuse the request if this flag is "upgrading", meaning
# during upgrade, IPsec won't be configured/enabled.

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
        else:
            print(f"Invalid option {sys.argv[arg]}.")
            return 1
        arg += 1

    log.configure()

    if from_release == "22.12" and action == "migrate":
        try:
            LOG.info("Update mgmt_ipsec in capabilities of "
                     "sysinv i_host table,"
                     f"from the release {from_release} to {to_release} with "
                     f"action: {action}")
            update_mgmt_ipsec(constants.MGMT_IPSEC_UPGRADING)
        except Exception as ex:
            LOG.exception(ex)
            print(ex)
            return 1


def update_mgmt_ipsec(value):
    """This function update mgmt_ipsec in in capabilities of sysinv
       i_host table to the value.
    """

    conn = psycopg2.connect("dbname='sysinv' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("select uuid, capabilities from i_host;")
            rows = cur.fetchall()
            if rows is None:
                LOG.exception("Failed to fetch i_host data")
                raise

            for record in rows:
                capabilities = json.loads(record['capabilities'])

                capabilities.update({constants.MGMT_IPSEC_FLAG: value})

                sqlcom = ("update i_host set "
                          f"capabilities='{json.dumps(capabilities)}' "
                          f"where uuid='{record['uuid']}'")
                cur.execute(sqlcom)
        conn.commit()


if __name__ == "__main__":
    sys.exit(main())
