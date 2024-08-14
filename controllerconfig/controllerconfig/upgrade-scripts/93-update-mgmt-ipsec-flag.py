#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script is to update the "mgmt_ipsec" flag in capabilities of
# sysinv i_host table to "upgrading". This flag will be checked by
# ipsec-server when it receives IPsec config request from ipsec-client.
# It will refuse the request if this flag is "upgrading", meaning
# during upgrade, IPsec won't be configured/enabled.

import json
import logging as LOG
import sys

from psycopg2.extras import RealDictCursor
import psycopg2

from six.moves import configparser
from sysinv.common import constants

DEFAULT_POSTGRES_PORT = 5432


def main():
    action = None
    from_release = None
    to_release = None  # noqa
    postgres_port = DEFAULT_POSTGRES_PORT
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
            postgres_port = sys.argv[arg]
            pass
        else:
            print(f"Invalid option {sys.argv[arg]}.")
            return 1
        arg += 1

    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=LOG.INFO, datefmt="%FT%T")

    if get_system_mode() != "simplex":
        if from_release == "22.12" and action == "migrate":
            try:
                LOG.info("Update mgmt_ipsec in capabilities of "
                         "sysinv i_host table,"
                         f"from the release {from_release} to {to_release} "
                         f"with action: {action}")
                update_mgmt_ipsec(constants.MGMT_IPSEC_UPGRADING,
                                  postgres_port)
            except Exception as ex:
                LOG.exception(ex)
                print(ex)
                return 1
            return 0
    LOG.info(f"Nothing to do for action {action}.")


def get_system_mode():
    ini_str = '[DEFAULT]\n' + open('/etc/platform/platform.conf', 'r').read()

    config_applied = configparser.RawConfigParser()
    config_applied.read_string(ini_str)

    if config_applied.has_option('DEFAULT', 'system_mode'):
        system_mode = config_applied.get('DEFAULT', 'system_mode')
    else:
        system_mode = None

    return system_mode


def update_mgmt_ipsec(value, port):
    """This function update mgmt_ipsec in in capabilities of sysinv
       i_host table to the value.
    """

    conn = psycopg2.connect("dbname='sysinv' user='postgres' port=%s" % port)
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("select uuid, capabilities from i_host;")
            rows = cur.fetchall()
            if rows is None:
                LOG.exception("Failed to fetch i_host data")
                raise

            for record in rows:
                capabilities = json.loads(record['capabilities'])

                capabilities.update({constants.MGMT_IPSEC_FLAG: value})

                sqlcom = ("update i_host set "
                          f"capabilities='{json.dumps(capabilities)}' "
                          f"where uuid='{record['uuid']}'")
                cur.execute(sqlcom)
        conn.commit()


if __name__ == "__main__":
    sys.exit(main())
