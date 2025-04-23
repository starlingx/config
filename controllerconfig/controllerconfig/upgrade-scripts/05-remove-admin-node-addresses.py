#!/usr/bin/env python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script updates the node IP addresses in sysinv DB tables. Only admin
# network entries and only AIO-SX systems will be updated with the following
# actions:
# - address_pools: update controller0_address_id and controller1_address_id
#                  to None
# - addresses: update floating address IPv4 and IPv6 entries' interface_id
#              with controller-0's entries' interface_id
# - addresses: delete IPv4 and IPv6 controller-0 and controller-1 entries'
#              interface_id
#

import logging as LOG
import sys

from packaging import version
import psycopg2
from six.moves import configparser

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
    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=LOG.INFO, datefmt="%FT%T")
    LOG.info(
        "%s invoked from_release = %s to_release = %s action = %s"
        % (sys.argv[0], from_release, to_release, action)
    )
    res = 0
    to_release_version = version.Version(to_release)
    target_version = version.Version("25.09")
    if action == 'migrate' and to_release_version == target_version:
        if get_system_mode() == "simplex":
            try:
                conn = psycopg2.connect("dbname=sysinv user=postgres port=%s"
                                        % postgres_port)
                del_admin_node_addresses(conn)
                conn.close()
            except Exception as e:
                LOG.exception("Error: {}".format(e))
                res = 1
    return res


def del_admin_node_addresses(conn):
    query = (
        "SELECT address_pools.id,controller0_address_id,controller1_address_id"
        ",floating_address_id "
        "FROM address_pools "
        "JOIN network_addresspools ON address_pools.id "
        "= network_addresspools.address_pool_id "
        "JOIN networks ON network_addresspools.network_id = networks.id "
        "WHERE networks.type = 'admin';"
    )
    res1 = db_query(conn, query)
    LOG.info("Number of address_pools entries found: %s" % len(res1))

    controller0_ids = ",".join([str(e[1]) for e in res1 if e[1]])
    if not controller0_ids:
        LOG.info("Nothing to change")
        return

    query = (
        "SELECT interface_id "
        "FROM addresses "
        "WHERE id IN (%s);" % controller0_ids
    )
    res2 = db_query(conn, query)
    c0_interface_ids = tuple([e[0] for e in res2])
    LOG.info("interface_id found in addresses: %s" % (c0_interface_ids,))

    idx = 0
    for entry in res1:
        address_pools_id = entry[0]
        node_ids = entry[1:3]
        floating_id = entry[3]
        LOG.info("Found admin controller-0 and controller-1 IDs = %s"
                 % (node_ids,))
        query = (
            "UPDATE address_pools "
            "SET controller0_address_id = NULL, controller1_address_id = NULL "
            "WHERE id = %s;" % address_pools_id
        )
        db_update(conn, query)
        query = (
            "UPDATE addresses "
            "SET interface_id = %s "
            "WHERE id = %s;" % (c0_interface_ids[idx], floating_id)
        )
        db_update(conn, query)
        query = (
            "DELETE FROM addresses "
            "WHERE id IN %s;" % (node_ids,)
        )
        db_update(conn, query)
        idx += 1

    LOG.info("Admin addresses deleted from address_pools and addresses tables "
             "with success")


def db_query(conn, query):
    result = []
    with conn.cursor() as cur:
        cur.execute(query)
        for rec in cur:
            result.append(rec)
    return result


def db_update(conn, query):
    with conn.cursor() as cur:
        cur.execute(query)
    conn.commit()


def get_system_mode():
    ini_str = '[DEFAULT]\n' + open('/etc/platform/platform.conf', 'r').read()

    config_applied = configparser.RawConfigParser()
    config_applied.read_string(ini_str)

    if config_applied.has_option('DEFAULT', 'system_mode'):
        system_mode = config_applied.get('DEFAULT', 'system_mode')
    else:
        system_mode = None

    return system_mode


if __name__ == "__main__":
    sys.exit(main())
