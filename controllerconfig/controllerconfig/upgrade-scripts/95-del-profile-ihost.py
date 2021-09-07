#!/usr/bin/env python
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will delete hosts which recordtype is a profile.
# This is required because host hardware profiles
# for creating re-usable configuration had been removed from GUI, CLI and
# API endpoinds. Profiles created prior the upgrade should be deleted.

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

    if action == "migrate":
        if from_release == '21.05':
            try:
                delete_profile_host()
            except Exception as ex:
                LOG.exception(ex)
                return 1


def delete_profile_host():
    conn = psycopg2.connect("dbname=sysinv user=postgres")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("delete from i_host where recordtype='profile'")

    LOG.info("Delete profile hosts completed")


if __name__ == "__main__":
    sys.exit(main())
