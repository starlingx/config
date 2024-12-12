#!/usr/bin/env python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will update the value of external_oam_subnet_ip_family
# of subclouds from '' to '4' or '6' based upon systemcontroller's
# primary OAM IP family. This is based on assumption both subcloud and
# systemcontroller's single-stack oam_network is of same IP family.

import logging as LOG
import sys

import psycopg2


DEFAULT_POSTGRES_PORT = 5432
NETWORK_TYPE_OAM = "oam"


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
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1
    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=LOG.INFO, datefmt="%FT%T")
    LOG.info(
        "%s invoked from_release = %s to_release = %s action = %s"
        % (sys.argv[0], from_release, to_release, action)
    )
    res = 0
    if action == 'migrate' and from_release == '22.12':
        try:
            conn_dcmanager = psycopg2.connect(
                "dbname=dcmanager user=postgres port=%s" % postgres_port
            )
            conn_sysinv = psycopg2.connect(
                "dbname='sysinv' user='postgres' port=%s" % postgres_port
            )
            do_subclouds_migration_work(conn_dcmanager, conn_sysinv)
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


def network_get_by_type(conn, type):
    # 0            1            2            3    4      5      6
    # created_at | updated_at | deleted_at | id | uuid | type | dynamic
    #   7                 8      9
    # | address_pool_id | name | primary_pool_family
    query_net = "select * from networks;"

    values = db_query(conn, query_net)
    for value in values:
        if value[5] == type:
            return {'created_at': value[0],
                    'updated_at': value[1],
                    'deleted_at': value[2],
                    'id': value[3],
                    'uuid': value[4],
                    'type': value[5],
                    'dynamic': value[6],
                    'address_pool_id': value[7],
                    'name': value[8],
                    'primary_pool_family': value[9]}
    return None


def do_subclouds_migration_work(conn_dcmanager, conn_sysinv):
    oam_network = network_get_by_type(conn_sysinv, NETWORK_TYPE_OAM)
    if oam_network is not None:
        ip_family = 4 if oam_network['primary_pool_family'] == 'IPv4' else 6
        query = (
            f"UPDATE subclouds SET external_oam_subnet_ip_family='{ip_family}'"
            f"WHERE external_oam_subnet_ip_family is NULL;"
        )
        LOG.info(
            f"Update external_oam_subnet_ip_family from '' to "
            f"'{ip_family}'"
        )
        do_update_query(conn_dcmanager, query)


def do_update_query(conn, query):
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
