#!/usr/bin/env python
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This migration script converts the sdn_enabled field in the system table
# from y/n to True/False

import json
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
            update_system_capabilities()
        except Exception as ex:
            LOG.exception(ex)
            print ex
            return 1


def update_system_capabilities():
    conn = psycopg2.connect("dbname='sysinv' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("select capabilities from i_system WHERE id = 1;")
            capabilities = cur.fetchone()
            if capabilities is None:
                LOG.exception("Failed to fetch i_system data")
                raise

            fields_str = capabilities.get('capabilities')
            fields_dict = json.loads(fields_str)

            if fields_dict.get('sdn_enabled') == 'y':
                new_vals = {'sdn_enabled': True}
            else:
                new_vals = {'sdn_enabled': False}
            fields_dict.update(new_vals)

            new_cap = json.dumps(fields_dict)

            LOG.info("Updating system capabilities %s to %s" %
                     (capabilities, new_cap))
            upgrade_vals = {'C': new_cap}
            cur.execute("update i_system set capabilities=%(C)s WHERE id=1",
                        upgrade_vals)


if __name__ == "__main__":
    sys.exit(main())
