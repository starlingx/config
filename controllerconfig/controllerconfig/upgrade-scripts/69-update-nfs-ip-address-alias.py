#!/usr/bin/env python
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This migration script is used for update controller-platform-nfs
# during migrate stage of platform upgrade. It will:
# - create controller-platform-nfs alias for controller mgmt IP in
#   /opt/platform/config/<to_release>/hosts file
# - remove the controller-platform-nfs-mgmt IP address from address DB


import sys

import psycopg2
from psycopg2.extras import DictCursor
import subprocess
import os.path

from controllerconfig.common import log

LOG = log.get_logger(__name__)


def _add_nfs_alias_to_hosts_file(connection, to_release):
    with connection.cursor(cursor_factory=DictCursor) as cur:

        # during the upgrade-start the hosts file is copied from:
        # /opt/platform/config/<from_release>/
        # to
        # /opt/platform/config/<to_release>/
        # and /opt/platform/config/<to_release>/host is used to upgrade
        # other controller/storage/worker nodes
        # the host files from this path must be updated
        CONFIG_PERMDIR = "/opt/platform/config/{}".format(to_release)
        host_file = "{}/hosts".format(CONFIG_PERMDIR)
        LOG.info("updating hosts in {}".format(CONFIG_PERMDIR))
        if (not os.path.exists(host_file)):
            LOG.info("Skipping update of {}. File does not exists"
                     .format(host_file))
            return None

        LOG.info("Get controller-mgmt floating ip from 'addresses' table")
        cur.execute("SELECT address FROM addresses WHERE "
                    "name='controller-mgmt';")
        ctrl_mgmt_ip = cur.fetchone()

        # remove the controller-platform-nfs line from ${host_file}
        sed_cmd = "sed -i '/controller\-platform\-nfs/d' {}".format(host_file)

        # Find the controller mgmt floating IP
        # copy entire line and put in ctrl_float
        grep_cmd = "grep -w '{}' {} | xargs -I ctrl_float" \
                   .format(ctrl_mgmt_ip['address'], host_file)

        # Add the alias controller-platform-nfs to controller IP
        # replacing the ${ctrl_float} by
        # "${ctrl_float} controller-platform-nfs"
        sed_concat = "sed -i -e " \
                     "'s|ctrl_float|ctrl_float controller-platform-nfs|' {}" \
                     .format(host_file)

        command = "{} && {} {}".format(sed_cmd, grep_cmd, sed_concat)

        sub = subprocess.Popen(command, shell=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = sub.communicate()

        if sub.returncode != 0:
            LOG.error('Cmd Failed:\n%s\n.%s\n%s' % (command, stdout, stderr))
            raise Exception('Error controller-platform-nfs IP: {} '
                            'in etc/hosts'.format(ctrl_mgmt_ip['address']))
        LOG.info('alias controller-platform-nfs added for IP: {} '
                 'in {}'.format(ctrl_mgmt_ip['address'], host_file))


def _remove_nfs_ip_allocation(connection):
    with connection.cursor(cursor_factory=DictCursor) as cur:
        LOG.info("Del controller-platform-nfs-mgmt from 'addresses' table")
        cur.execute("DELETE FROM addresses WHERE "
                    "name = 'controller-platform-nfs-mgmt';")


def main():
    action = None
    from_release = None
    to_release = None
    arg = 1
    res = 0

    log.configure()

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        else:
            LOG.error("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    LOG.info("%s invoked with from_release = %s to_release = %s action = %s"
             % (sys.argv[0], from_release, to_release, action))

    if action == "migrate" and from_release in ['21.12', '22.06']:

        conn = psycopg2.connect("dbname=sysinv user=postgres")
        try:
            _add_nfs_alias_to_hosts_file(conn, to_release)
            _remove_nfs_ip_allocation(conn)

        except psycopg2.Error as ex:
            LOG.exception(ex)
            LOG.warning("DB Connection error")
            res = 1
        except Exception as ex:
            LOG.exception(ex)
            LOG.warning("Exception")
            res = 1
        else:
            LOG.info("committing changes into database")
            conn.commit()
        finally:
            LOG.info("Closing connection")
            conn.close()

    return res


if __name__ == "__main__":
    sys.exit(main())
