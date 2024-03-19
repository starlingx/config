#!/usr/bin/env python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will set upgrade entries on sysinv
# database tables to support USM major release upgrade,
# the affected tables are loads and host_upgrades.
# TODO(heitormatsui): delete this script once sysinv
#                     upgrade tables are deprecated
#

import sys
import psycopg2
import uuid
from controllerconfig.common import log

LOG = log.get_logger(__name__)
CONTROLLER_0_HOSTNAME = "controller-0"
CONTROLLER_1_HOSTNAME = "controller-1"
DEFAULT_POSTGRES_PORT = 5432


def main():
    action = None
    from_release = None
    to_release = None
    postgres_port = DEFAULT_POSTGRES_PORT
    arg = 1
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            postgres_port = sys.argv[arg]
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
    if action == 'migrate' and to_release == '24.09':
        try:
            conn = psycopg2.connect("dbname=sysinv user=postgres port=%s"
                                    % postgres_port)
            load_id = create_load(conn, to_release)
            update_host_load(conn, load_id)
            conn.close()
        except Exception as e:
            LOG.exception("Error: {}".format(e))
            res = 1
    return res


def create_load(conn, to_release):
    load_id_query = ("select id from loads where software_version = '%s'" %
                     to_release)
    res = db_query(conn, load_id_query)
    if not res:
        load_insert_query = (
            "insert into loads(id, uuid, state, software_version) "
            "values (nextval('loads_id_seq'), '%s', 'available', '%s')"
            % (uuid.uuid4(), to_release)
        )
        db_update(conn, load_insert_query)
        LOG.info("Created %s load entry." % to_release)
        res = db_query(conn, load_id_query)
    return res[0][0]


def update_host_load(conn, load_id, hostname=CONTROLLER_1_HOSTNAME):
    host_id_query = "select id from i_host where hostname = '%s'"

    # get id for hostname passed as parameter
    res = db_query(conn, host_id_query % hostname)
    if not res:
        # if don't find hostname in db, get controller-0 id by default
        res = db_query(conn, host_id_query % CONTROLLER_0_HOSTNAME)
    host_id = res[0][0]

    update_query = ("update host_upgrade set software_load = %s,"
                    "target_load = %s where forihostid = %s" %
                    (load_id, load_id, host_id))
    db_update(conn, update_query)
    LOG.info("Updated host %s load." % host_id)


def db_update(conn, query):
    with conn.cursor() as cur:
        cur.execute(query)
    conn.commit()


def db_query(conn, query):
    result = []
    with conn.cursor() as cur:
        cur.execute(query)
        for rec in cur:
            result.append(rec)
    return result


if __name__ == "__main__":
    sys.exit(main())
