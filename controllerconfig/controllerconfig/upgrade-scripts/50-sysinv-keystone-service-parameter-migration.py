#!/usr/bin/env python
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This migration script converts the identity and assignment driver
# values in the service parameter table from their fully qualified
# paths to a relative path as required by Pike

import sys

import psycopg2
from controllerconfig.common import log
from psycopg2.extras import RealDictCursor

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
            print ("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    if from_release == "17.06" and action == "migrate":
        try:
            LOG.info("performing system migration from release %s to %s with "
                     "action: %s" % (from_release, to_release, action))
            update_identity_service_parameters()
        except Exception as ex:
            LOG.exception(ex)
            print ex
            return 1


def update_identity_service_parameters():
    conn = psycopg2.connect("dbname='sysinv' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("select * from service_parameter "
                        "where service='identity' and name='driver';")
            parameters = cur.fetchall()
            if parameters is None or len(parameters) == 0:
                LOG.exception(
                    "Failed to fetch identity service_parameter data")
                raise

            LOG.info("Updating identity service parameters to 'sql'")
            cur.execute("update service_parameter set value='sql' "
                        "where service='identity' and name='driver';")


if __name__ == "__main__":
    sys.exit(main())
