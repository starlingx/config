#!/usr/bin/env python
# Copyright (c) 2021-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will clear the host config target.
# This is required in order to ensure tracking is aligned with config
# requests in N+1 release and not due to potential stale configuration
# from N release.

import logging
import sys

from psycopg2.extras import RealDictCursor
from controllerconfig import utils
from controllerconfig.common import constants
from controllerconfig.common.usm_log import configure_logging

LOG = logging.getLogger('main_logger')


def main():
    action = None
    from_release = None
    to_release = None
    postgres_port = constants.POSTGRESQL_DEFAULT_PORT
    arg = 1

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]  # noqa
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            postgres_port = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    configure_logging()

    LOG.debug("%s invoked with from_release = %s to_release = %s action = %s"
              % (sys.argv[0], from_release, to_release, action))

    # This host table data migration will likely be required for each release
    if action == "migrate":
        try:
            reset_config_target(postgres_port)
        except Exception as ex:
            LOG.exception(ex)
            return 1


def reset_config_target(port):

    conn = utils.connect_to_postgresql(port)
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("update i_host set config_target=NULL",)

    LOG.info("Reset host config_target completed")


if __name__ == "__main__":
    sys.exit(main())
