#!/usr/bin/python
#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will perform upgrade preparation and migration operations for
# host-swact to controller-1.
#

import os
import shutil
import subprocess
import sys
import yaml

from oslo_log import log

LOG = log.getLogger(__name__)

ETCD_PATH = "/opt/etcd"
UPGRADE_CONTROLLER_1_FILE = "/etc/platform/.upgrade_swact_controller_1"


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

    if action == "migrate_etcd":
        try:
            migrate_etcd_on_swact()
        except Exception as ex:
            LOG.exception(ex)
            return 1
    elif action == "prepare_swact":
        upgrade_prepare_swact(from_release, to_release)
    return 0


def upgrade_prepare_swact(from_release, to_release):
    migrate_data = {
        'from_release': from_release,
        'to_release': to_release
    }
    with open(UPGRADE_CONTROLLER_1_FILE, 'w') as f:
        yaml.dump(migrate_data, f, default_flow_style=False)


def migrate_etcd_on_swact():
    with open(UPGRADE_CONTROLLER_1_FILE, 'r') as f:
        document = yaml.safe_load(f)

    from_release = document.get('from_release')
    to_release = document.get('to_release')

    dest_etcd = os.path.join(ETCD_PATH, to_release)

    if os.path.exists(dest_etcd):
        # The dest_etcd must not have already been created,
        # however this can occur on a forced host-swact
        LOG.info("skipping etcd migration %s already exists" %
                 dest_etcd)
        return

    if not os.path.isfile(UPGRADE_CONTROLLER_1_FILE):
        LOG.info("skipping etcd migration, no request %s" %
                 UPGRADE_CONTROLLER_1_FILE)
        return

    source_etcd = os.path.join(ETCD_PATH, from_release)
    try:
        shutil.copytree(os.path.join(source_etcd),
                        os.path.join(dest_etcd))
        os.remove(UPGRADE_CONTROLLER_1_FILE)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to migrate %s" % source_etcd)
        raise


if __name__ == "__main__":
    sys.exit(main())
