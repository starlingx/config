#!/usr/bin/env python
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will add service parameters into sysinv database
# during migration phase of upgrade procedure.

import sys
import psycopg2
from datetime import datetime
from oslo_utils import uuidutils
from psycopg2.extras import RealDictCursor
from controllerconfig.common import log
from sysinv.common import constants as sysinv_constants

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

    if action == "migrate":
        if from_release == '21.05':
            try:
                conn = psycopg2.connect("dbname=sysinv user=postgres")
                with conn:
                    timestamp = str(datetime.now())
                    uuid = uuidutils.generate_uuid()
                    role = get_system_role(conn)
                    if (role ==
                            sysinv_constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
                        ghcr_url = 'registry.central:9001/ghcr.io'
                    else:
                        ghcr_url = 'ghcr.io'
                    cmd = "INSERT INTO service_parameter (created_at, uuid, "\
                        "service, section, name, value, personality, "\
                        "resource) VALUES ('{}', '{}', 'docker', "\
                        "'ghcr-registry', 'url', '{}', NULL, NULL)".format(
                            timestamp, uuid, ghcr_url)
                    LOG.info("Adding to db: '%s'" % cmd)
                    with conn.cursor(cursor_factory=RealDictCursor) as cur:
                        cur.execute(cmd,)

                    LOG.info("%s: Upgrade of service parameters completed "
                             "from release %s to %s"
                             % (sys.argv[0], from_release, to_release))

            except Exception as ex:
                LOG.exception(ex)
                return 1


def get_system_role(db_conn):
    cur = db_conn.cursor()

    cur.execute("SELECT distributed_cloud_role FROM i_system")
    row = cur.fetchone()

    role = row[0]
    LOG.debug("System role is %s" % role)

    return role


if __name__ == "__main__":
    sys.exit(main())
