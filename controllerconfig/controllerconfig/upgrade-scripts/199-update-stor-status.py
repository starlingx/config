#!/usr/bin/env python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will check the stor osd status and
# compare it with deployed OSDs when the storage
# backend is Ceph (Bare Metal), ensuring inventory consistency
# and avoiding an intermittent known issue from older releases,
# where adding more than one OSD at a time on the same host
# could keep the last one in configuring state even if
# it's already configured.
#

import json
import logging as LOG
import psycopg2
import subprocess
import sys


DEFAULT_POSTGRES_PORT = 5432
CEPH_CLUSTER = "ceph"
CEPH_CONF_FILE = "/etc/ceph/ceph.conf"


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
            # In this case, we need to change the main database
            # using the default PostgresSQL port
            # postgres_port = sys.argv[arg]
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

    if action == 'migrate' and from_release == '22.12':
        try:
            username, password = get_db_credentials()
            conn = psycopg2.connect(
                "dbname=sysinv user=%s password=%s host=localhost port=%s"
                % (username, password, DEFAULT_POSTGRES_PORT)
            )

            update_stor_status(conn)
            conn.close()
        except Exception as e:
            LOG.exception("Error: {}".format(e))
            res = 1

    return res


def update_stor_status(conn):
    stor_configuring = get_stor_configuring(conn)
    if not stor_configuring:
        # Nothing to do
        return

    osd_tree = get_osd_tree()
    if not osd_tree or 'nodes' not in osd_tree:
        LOG.error(f"ceph-osd-tree cmd not collected. Output: {osd_tree}")
        raise Exception(
            "The ceph-osd-tree cmd was not collected. Check the Ceph status."
        )

    count_found = 0
    for node in osd_tree['nodes']:
        if node['type'] == 'osd' and \
                node['id'] in stor_configuring:
            count_found += 1

    if len(stor_configuring) != count_found:
        # We should not accept to upgrade the system if some OSD is marked
        # as configuring and it is not up in the ceph cluster.
        LOG.error(
            f"Some OSD ({stor_configuring}) in configuring "
            "state was not found in ceph-osd-tree cmd output."
        )
        LOG.error(f"ceph-osd-tree cmd output: {osd_tree['nodes']}")
        raise Exception(f"OSDs {stor_configuring} not found.")

    for osdid in stor_configuring:
        query = f"""UPDATE public.i_istor
                    SET state='configured'
                    WHERE osdid={osdid};"""
        db_update(conn, query)
        LOG.info(
            f"Stor osd.{osdid} updated from configuring to configured."
        )


def get_stor_configuring(conn):
    # getting stor (osdid) filtering by:
    #  - stor in configuring state and osd function
    #  - ceph storage backend configured
    # NOTE: if not match any filter it will return an empty array
    query = """
        SELECT osdid
        FROM public.i_istor
        WHERE
            state='configuring'
            and function='osd'
            -- looking for ceph storage backend
            and 'ceph'=(
                SELECT backend
                FROM public.storage_backend
                WHERE state='configured');"""
    response = db_query(conn, query)
    if response:
        return [osd[0] for osd in response
                if osd and type(osd) is tuple]


def get_osd_tree():
    cmd = (
        f"ceph --conf {CEPH_CONF_FILE} --cluster {CEPH_CLUSTER} "
        "osd tree -f json --connect-timeout 10;"
    )
    stdout, _ = execute_cmd(cmd)
    return json.loads(stdout)


def get_db_credentials():
    import re
    import configparser

    configparser = configparser.ConfigParser()
    configparser.read('/etc/sysinv/sysinv.conf')
    conn_string = configparser['DEFAULT']['sql_connection']
    match = re.match(r'postgresql://([^:]+):([^@]+)@', conn_string)
    if match:
        username = match.group(1)
        password = match.group(2)
        return username, password
    else:
        raise Exception("Failed to get database credentials, sysinv.conf")


def execute_cmd(cmd):
    sub = subprocess.Popen(cmd, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        LOG.error('Command failed:\n %s\n. %s\n%s\n'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception(f'Cannot run cmd: "{cmd}"')
    return stdout.decode('utf-8'), stderr.decode('utf-8')


def db_query(conn, query, fetchall=True):
    result = []
    with conn.cursor() as cur:
        cur.execute(query)
        result = cur.fetchall() if fetchall else cur.fetchone()
    return result


def db_update(conn, query):
    with conn.cursor() as cur:
        cur.execute(query)
    conn.commit()


if __name__ == "__main__":
    sys.exit(main())
