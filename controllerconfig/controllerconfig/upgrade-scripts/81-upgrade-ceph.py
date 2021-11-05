#!/usr/bin/env python
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will run during the upgrade activation step after all nodes have
# been upgraded.
#
# This will set the required_osd_release to 'nautilus' and enable the straw2
# bucket algorithm. 'straw2' has improvements over the previous 'straw'
# algorithm. For more information see:
# https://docs.ceph.com/en/latest/rados/operations/crush-map/#hammer-crush-v4
#
# This script can be removed in the release that follows 21.12.

import json
import subprocess
import sys

from controllerconfig.common import log

LOG = log.get_logger(__name__)


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
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    LOG.debug("%s invoked with from_release = %s to_release = %s action = %s"
              % (sys.argv[0], from_release, to_release, action))

    if from_release == "21.05" and action == "activate":
        try:
            upgrade_ceph()
        except Exception as e:
            LOG.exception('Upgrade failed due to the following exception: %s'
                          % e)
            return 1


def upgrade_ceph():
    if not is_ceph_configured():
        LOG.info("Ceph backend absent. "
                 "No further upgrade actions are required."
                 )
        return
    else:
        LOG.info("Ceph backend present. Verifying Ceph upgrade to Nautilus is "
                 "complete.")

    osd_release = get_required_osd_release()
    straw2_enabled = is_straw2_enabled()

    if osd_release != 'nautilus' or not straw2_enabled:
        LOG.info("Completing upgrade to Ceph Nautilus...")

        # Setting to nautilus release first is mandatory
        if osd_release != 'nautilus':
            set_required_osd_release()

        if not straw2_enabled:
            enable_straw2()

        LOG.info("Upgrade complete to Ceph Nautilus")
    else:
        LOG.info("No additional Ceph upgraded actions required")


def is_ceph_configured():
    # This command was used because it was not possible to connect to
    # the sysinv database using the psycopg2 module when in 'activate'
    # action
    command = ("sudo -u postgres psql -U postgres -d sysinv -t -A -q -c "
               "\"SELECT count(*) FROM storage_backend "
               "where backend='ceph' AND name='ceph-store';\"")
    out = exec_command(command)
    return out.strip() == "1"


def get_required_osd_release():
    command = "ceph osd dump -f json"
    out = exec_ceph_command(command)
    json_out = json.loads(out)
    return json_out.get('require_osd_release')


def is_straw2_enabled():
    command = "ceph osd crush dump -f json"
    out = exec_ceph_command(command)
    json_out = json.loads(out)
    algs = [b['alg'] for b in json_out.get('buckets')]
    return algs.count('straw') == 0


def set_required_osd_release():
    LOG.info("Set 'nautilus' for require_osd_release...")
    command = "ceph osd require-osd-release nautilus"
    exec_ceph_command(command)
    release = get_required_osd_release()
    if release != 'nautilus':
        raise Exception("Could not set nautilus release 'require_osd_release'")


def enable_straw2():
    LOG.info("Enabling straw2 bucket algorithm...")
    command = "ceph osd crush set-all-straw-buckets-to-straw2"
    exec_ceph_command(command)
    if not is_straw2_enabled():
        raise Exception("Could not enable straw2 bucket algorithm")


def exec_command(command):
    LOG.debug("Running command: %s" % command)
    process = subprocess.Popen(command,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               shell=True)
    stdout, stderr = process.communicate()
    rc = process.returncode
    if rc != 0:
        raise Exception("Failed to run command: %s | rc=%s | stdout: %s"
                        " | stderr: %s" %
                        (command, rc, stdout, stderr))
    return stdout


def exec_ceph_command(command):
    command = 'timeout 60s %s' % command
    return exec_command(command)


if __name__ == "__main__":
    sys.exit(main())
