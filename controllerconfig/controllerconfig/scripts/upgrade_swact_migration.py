#!/usr/bin/python3
#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will perform upgrade preparation and migration operations for
# host-swact to controller-0.
#

import os
import shutil
import socket
import subprocess
import sys
import yaml

from controllerconfig.common import log

LOG = log.get_logger(__name__)

ETCD_PATH = "/opt/etcd"
UPGRADE_ETCD_FILE = os.path.join(ETCD_PATH, ".upgrade_etcd")


def main():
    action = None
    from_release = None
    to_release = None
    arg = 1

    while arg < len(sys.argv):
        if arg == 1:
            action = sys.argv[arg]
        elif arg == 2:
            from_release = sys.argv[arg]
        elif arg == 3:
            to_release = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    LOG.info("upgrade_swact_migration called with action: %s from_release: %s "
             "to_release: %s" % (action, from_release, to_release))

    if action == "migrate_etcd":
        try:
            migrate_etcd_on_swact()
        except Exception as ex:
            LOG.exception(ex)
            return 1
    elif action == "prepare_swact":
        upgrade_prepare_swact(from_release, to_release)

    LOG.info("upgrade_swact_migration complete")
    return 0


def upgrade_prepare_swact(from_release, to_release):
    migrate_data = {
        'from_release': from_release,
        'to_release': to_release
    }
    with open(UPGRADE_ETCD_FILE, 'w') as f:
        yaml.dump(migrate_data, f, default_flow_style=False)


def migrate_etcd_on_swact():
    if not os.path.isfile(UPGRADE_ETCD_FILE):
        LOG.info("Skipping etcd migration, no request %s" %
                 UPGRADE_ETCD_FILE)
        return

    if socket.gethostname() != 'controller-0':
        LOG.info("Skipping etcd migration, not running on controller-0")
        return

    with open(UPGRADE_ETCD_FILE, 'r') as f:
        document = yaml.safe_load(f)

    from_release = document.get('from_release')
    to_release = document.get('to_release')

    dest_etcd = os.path.join(ETCD_PATH, to_release)

    if os.path.islink(dest_etcd):
        LOG.info("Unlinking destination etcd directory: %s " % dest_etcd)
        os.unlink(dest_etcd)

    if os.path.exists(dest_etcd):
        # The directory was already copied but somehow the upgrade file exists
        LOG.info("Skipping etcd migration %s already exists" %
                 dest_etcd)
        os.remove(UPGRADE_ETCD_FILE)
        return

    source_etcd = os.path.join(ETCD_PATH, from_release)
    try:
        shutil.copytree(os.path.join(source_etcd),
                        os.path.join(dest_etcd))
        os.remove(UPGRADE_ETCD_FILE)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to migrate %s" % source_etcd)
        raise


if __name__ == "__main__":
    sys.exit(main())
