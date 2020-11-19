#!/usr/bin/python
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will update i_system table in sysinv database
# in preparation for upgrade.
#
# The 'i_system' table in sysinv DB has capabilities attribute
# which lists 'identity' as a shared service. However, identity
# is no longer a shared service in DC. The script takes care of
# this by removing identity entry on upgrade.
#
# This script can be removed in the release that follows stx.5.0.
#
import json
import psycopg2
import sys
from controllerconfig.common import log
from psycopg2.extras import RealDictCursor

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
            print ("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    LOG.debug("%s invoked with from_release = %s to_release = %s action = %s"
              % (sys.argv[0], from_release, to_release, action))
    if from_release == "20.06" and action == "migrate":
        try:
            if is_subcloud():
                LOG.info("Removing identity shared service...")
                remove_identity_shared_service()
        except Exception:
            LOG.exception("Failed to remove identity entry during upgrade.")
            return 1


def is_subcloud():
    conn = psycopg2.connect("dbname='sysinv' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * from i_system")
            system = cur.fetchone()
            return system['distributed_cloud_role'] == 'subcloud'


def remove_identity_shared_service():
    conn = psycopg2.connect("dbname='sysinv' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * from i_system")
            system = cur.fetchone()

            # Fetch the capabilities attribute and convert it into a dict
            capabilities = json.loads(system['capabilities'])

            # Fetch shared services
            # It is of type unicode initially
            # and we convert it into a list for further processing
            shared_services = str(capabilities["shared_services"])
            shared_service_list = shared_services.strip('][').split(', ')

            # Create a new list which removes 'identity' shared service
            # and any empty string elements from list
            new_shared_services = [item.strip("'")
                                   for item in shared_service_list
                                   if "identity" not in item and item != '']

            if len(shared_service_list) != len(new_shared_services):
                capabilities["shared_services"] = str(new_shared_services)
                LOG.info("Old shared service list: %s, "
                         "New shared service list: %s"
                         % (shared_services, new_shared_services))
                cur.execute("UPDATE i_system SET capabilities='%s' where id=%s"
                            % (json.dumps(capabilities), system["id"]))

    LOG.info("Removed identity from shared service list on subcloud.")


if __name__ == "__main__":
    sys.exit(main())
