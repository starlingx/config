#!/usr/bin/env python
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will clear the host config target.
# This is required in order to ensure tracking is aligned with config
# requests in N+1 release and not due to potential stale configuration
# from N release.

import psycopg2
import sys

from psycopg2.extras import RealDictCursor
from controllerconfig.common import log

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
            to_release = sys.argv[arg]  # noqa
        elif arg == 3:
            action = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    LOG.debug("%s invoked with from_release = %s to_release = %s action = %s"
              % (sys.argv[0], from_release, to_release, action))

    # This host table data migration will likely be required for each release
    if action == "migrate":
        try:
            reset_config_target()
        except Exception as ex:
            LOG.exception(ex)
            return 1


def reset_config_target():

    conn = psycopg2.connect("dbname=sysinv user=postgres")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("update i_host set config_target=NULL",)

    LOG.info("Reset host config_target completed")


if __name__ == "__main__":
    sys.exit(main())
