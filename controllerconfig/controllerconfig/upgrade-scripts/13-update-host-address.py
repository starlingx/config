#!/usr/bin/python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import logging as LOG
import sys
import os
import subprocess


DEFAULT_POSTGRES_PORT = 5432
LOG_FILE = "/var/log/software.log"


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
            # optional port parameter for USM upgrade
            postgres_port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename=LOG_FILE, format=log_format, level=LOG.INFO,
                    datefmt="%FT%T")

    res = 0
    LOG.info("%s invoked from_release = %s to_release = %s action = %s"
             % (sys.argv[0], from_release, to_release, action))

    if action == "activate" and from_release == "24.09":
        LOG.info("Updating addresses table entries.")

        try:
            update_address_name_from_db(postgres_port)
        except Exception as ex:
            LOG.exception("Error: {}".format(ex))
            print(ex)
            res = 1
    return res


def update_address_name_from_db(postgres_port):
    query = """
        UPDATE addresses
        SET name = REGEXP_REPLACE(name,
                                '^system-controller-gateway-ip-',
                                'controller-gateway-')
        WHERE name LIKE 'system-controller-gateway-ip-%';
        """
    try:
        res = db_query(postgres_port, query)
        if res:
            LOG.info("Addresses table entries updated to use new "
                     "controller gateway name")
        else:
            LOG.info("No entries updated at addresses table")
    except Exception as e:
        LOG.error(f"Failed to update IP addresses in the "
                  f"database: {e}")
        raise


def db_query(postgres_port, query):
    env = os.environ.copy()
    sub_sel = subprocess.Popen(
        ['sudo', '-u', 'postgres',
         'psql', '-p', f'{postgres_port}',
         '-d', 'sysinv', '-c', query],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True)
    stdout, stderr = sub_sel.communicate()
    if sub_sel.returncode == 0:
        return True
    else:
        LOG.error('Failed to connect to sysinv database or execute query:'
                  '\n%s. \n%s.' % (stdout, stderr))
        raise Exception(stderr)


if __name__ == "__main__":
    sys.exit(main())
