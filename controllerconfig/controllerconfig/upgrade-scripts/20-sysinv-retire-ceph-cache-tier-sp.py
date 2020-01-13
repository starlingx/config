#!/usr/bin/python3
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will update the storage backends for controller-1.
#

import json
import psycopg2
import sys

from sysinv.common import constants
from psycopg2.extras import RealDictCursor
from controllerconfig.common import log

LOG = log.get_logger(__name__)

# Sections that need to be removed from retired Ceph cache tiering feature
SERVICE_PARAM_SECTION_CEPH_CACHE_TIER = 'cache_tiering'
SERVICE_PARAM_SECTION_CEPH_CACHE_TIER_DESIRED = 'cache_tiering.desired'
SERVICE_PARAM_SECTION_CEPH_CACHE_TIER_APPLIED = 'cache_tiering.applied'


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
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    if from_release == "18.03" and action == "migrate":
        try:
            cleanup_ceph_cache_tiering_service_parameters(from_release)
            cleanup_ceph_personality_subtype(from_release)
        except Exception as ex:
            LOG.exception(ex)
            return 1


def cleanup_ceph_cache_tiering_service_parameters(from_release):
    conn = psycopg2.connect("dbname=sysinv user=postgres")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for s in [SERVICE_PARAM_SECTION_CEPH_CACHE_TIER,
                      SERVICE_PARAM_SECTION_CEPH_CACHE_TIER_DESIRED,
                      SERVICE_PARAM_SECTION_CEPH_CACHE_TIER_APPLIED]:
                cur.execute("select * from service_parameter where service=%s "
                            "and section=%s", (constants.SERVICE_TYPE_CEPH,
                                               s,))
                parameters = cur.fetchall()
                if not parameters:
                    LOG.info("No service_parameter data for section %s "
                             "found." % s)
                    continue

                for p in parameters:
                    LOG.debug("Found %s/%s" % (p['section'], p['name']))

                LOG.info("Removing ceph service parameters from section "
                         "%s" % s)
                cur.execute("delete from service_parameter where service=%s "
                            "and section=%s", (constants.SERVICE_TYPE_CEPH,
                                               s,))


def cleanup_ceph_personality_subtype(from_release):
    conn = psycopg2.connect("dbname=sysinv user=postgres")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("select hostname, capabilities from i_host")
            parameters = cur.fetchall()
            if not parameters:
                LOG.info("No capabilities data found ")
                return

            for p in parameters:
                LOG.debug("Found host capabilities %s/%s" %
                          (p['hostname'], p['capabilities']))
                json_dict = json.loads(p['capabilities'])
                if 'pers_subtype' in json_dict:
                    del json_dict['pers_subtype']

                    LOG.info("Removing ceph pers_subtype from capabilities")
                    cur.execute("update i_host set capabilities='%s';" %
                                json.dumps(json_dict))


if __name__ == "__main__":
    sys.exit(main())
