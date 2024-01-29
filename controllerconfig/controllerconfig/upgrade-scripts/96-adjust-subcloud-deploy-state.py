#!/usr/bin/env python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will update the deploy status of subclouds
# from 'deploy-prep-failed' to 'pre-config-failed'
# and 'deploy-failed' to 'config-failed', allowing the
# user to run deploy config step of subcloud deployment
# after the deprecation of subcloud reconfig and the old
# deploy status.

import sys

from dcmanager.common import consts as dcmanager_consts
import psycopg2

from controllerconfig.common import log


LOG = log.get_logger(__name__)

DEPLOY_STATUS_MAP = {
    dcmanager_consts.DEPLOY_STATE_DEPLOY_PREP_FAILED:
        dcmanager_consts.DEPLOY_STATE_PRE_CONFIG_FAILED,
    dcmanager_consts.DEPLOY_STATE_DEPLOY_FAILED:
        dcmanager_consts.DEPLOY_STATE_CONFIG_FAILED
}


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
        elif arg == 4:
            # postgres_port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1
    log.configure()
    LOG.info(
        "%s invoked from_release = %s to_release = %s action = %s"
        % (sys.argv[0], from_release, to_release, action)
    )
    res = 0
    if action == 'migrate' and from_release == '22.12':
        try:
            conn = psycopg2.connect("dbname=dcmanager user=postgres")
            do_update_deploy_status(conn)
        except psycopg2.OperationalError:
            # Since neither tsconfig or /etc/platform/platform.conf have
            # the distributedcloud role at this stage, try to connect to
            # the dcmanager db, and consider to not be a systemcontroller
            # if the database doesn't exist
            LOG.info("Not a systemcontroller, nothing to do")
            res = 0
        except Exception as e:
            LOG.exception("Error: {}".format(e))
            res = 1
    return res


def do_update_deploy_status(conn):
    for old_deploy_status, new_deploy_status in DEPLOY_STATUS_MAP.items():
        query = (
            f"UPDATE subclouds SET deploy_status='{new_deploy_status}'"
            f"WHERE deploy_status='{old_deploy_status}';"
        )
        LOG.info(
            f"Update deploy_status from {old_deploy_status} to "
            f"{new_deploy_status}"
        )
        do_update_query(conn, query)


def do_update_query(conn, query):
    with conn.cursor() as cur:
        cur.execute(query)
    conn.commit()


if __name__ == "__main__":
    sys.exit(main())
