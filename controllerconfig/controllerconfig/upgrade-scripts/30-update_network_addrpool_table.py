#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import datetime
import logging as LOG
import psycopg2
import sys
from oslo_utils import uuidutils


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
        elif arg == 4:
            # optional port parameter for USM upgrade
            # port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=LOG.INFO, datefmt="%FT%T")

    if from_release == "22.12" and action == "migrate":
        try:
            LOG.info("network-addrpool table migration from release %s to %s"
                     " with action: %s" % (from_release, to_release, action))
            do_network_addrpool_migration_work()
        except Exception as ex:
            LOG.exception(ex)
            print(ex)
            return 1


def do_network_addrpool_migration_work():

    conn = psycopg2.connect("dbname='sysinv' user='postgres'")
    with conn:
        net_dict = get_networks(conn)

        pool_dict = get_address_pools(conn)

        for net_id in net_dict:
            pool_id = net_dict[net_id]['address_pool_id']
            if pool_dict[pool_id]['family'] == 4:
                update = "update networks set primary_pool_family = 'IPv4'"\
                         f" where id = {net_id}"
                LOG.info(f"execute: '{update}")
                db_update(conn, update)
            elif pool_dict[pool_id]['family'] == 6:
                update = "update networks set primary_pool_family = 'IPv6'"\
                         f" where id = {net_id}"
                LOG.info(f"execute: '{update}")
                db_update(conn, update)

        for net_id in net_dict:
            address_pool_id = net_dict[net_id]['address_pool_id']
            srch = f"network_id={net_id} and address_pool_id={address_pool_id}"
            query = f"select * from network_addresspools where {srch};"
            rec = db_query(conn, query)
            if not rec:
                now = datetime.datetime.now()
                uuid = uuidutils.generate_uuid()
                columns = "(created_at, uuid, address_pool_id, network_id)"
                values = f"('{now}','{uuid}','{address_pool_id}','{net_id}')"
                create = f"insert into network_addresspools {columns}"\
                         f" values {values}"
                LOG.info(f"execute: '{create}")
                db_update(conn, create)


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


def get_networks(conn):
    # 0            1            2            3    4      5      6
    # created_at | updated_at | deleted_at | id | uuid | type | dynamic
    #   7                 8      9
    # | address_pool_id | name | primary_pool_family
    query_net = "select * from networks;"

    values = db_query(conn, query_net)
    net_dict = dict()
    for value in values:
        net_dict[value[3]] = {'created_at': value[0],
                              'updated_at': value[1],
                              'deleted_at': value[2],
                              'uuid': value[4],
                              'type': value[5],
                              'dynamic': value[6],
                              'address_pool_id': value[7],
                              'name': value[8],
                              'primary_pool_family': value[9]}
    return net_dict


def get_address_pools(conn):
    #    0            1            2         3     4      5       6
    # created_at | updated_at | deleted_at | id | uuid | name | family
    #     7          8       9     10
    # | network | prefix | order | controller0_address_id
    #   11                       12                    13
    # | controller1_address_id | floating_address_id | gateway_address_id
    query_pool = "select * from address_pools;"
    values = db_query(conn, query_pool)
    pool_dict = dict()
    for value in values:
        pool_dict[value[3]] = {'created_at': value[0],
                               'updated_at': value[1],
                               'deleted_at': value[2],
                               'uuid': value[4],
                               'name': value[5],
                               'family': value[6],
                               'network': value[7],
                               'prefix': value[8],
                               'order': value[9],
                               'controller0_address_id': value[10],
                               'controller1_address_id': value[11],
                               'floating_address_id': value[12],
                               'gateway_address_id': value[13]}
    return pool_dict


if __name__ == "__main__":
    sys.exit(main())
