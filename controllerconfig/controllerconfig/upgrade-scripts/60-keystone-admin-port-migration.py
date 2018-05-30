#!/usr/bin/env python
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This migration script converts the admin URL in the Keystone
# service catalog to be equivalent to the internal URL

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
            LOG.info("performing keystone migration from release %s to %s "
                     "with action: %s" % (from_release, to_release, action))
            update_identity_admin_url()
        except Exception as ex:
            LOG.exception(ex)
            print ex
            return 1


# We will update for all Regions and not just the primary Region,
# otherwise we'd break non-Primary Regions once Primary Region
# gets upgraded
def update_identity_admin_url():
    conn = psycopg2.connect("dbname='keystone' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT service_id, url, region_id FROM "
                        "endpoint INNER JOIN service "
                        "ON endpoint.service_id = service.id WHERE "
                        "type='identity' and interface='internal';")
            records = cur.fetchall()
            if records is None or len(records) == 0:
                LOG.exception(
                    "Failed to fetch identity endpoint and servic data")
                raise
            for record in records:
                service_id = record['service_id']
                internal_url = record['url']
                region_id = record['region_id']
                if not service_id or not internal_url or not region_id:
                    LOG.exception(
                        "Fetched an entry %s with essential data missing" %
                        record)
                    raise
                LOG.info("Updating identity admin URL to '%s' for "
                         "service_id '%s' and region '%s'" %
                         (internal_url, service_id, region_id))
                cur.execute("UPDATE endpoint SET url='%s' "
                            "WHERE interface='admin' and service_id='%s' "
                            "and region_id='%s' ;" %
                            (internal_url, service_id, region_id))


if __name__ == "__main__":
    sys.exit(main())
