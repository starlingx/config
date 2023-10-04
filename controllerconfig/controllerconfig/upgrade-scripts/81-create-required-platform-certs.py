#!/usr/bin/python
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script creates required platform certificates for DX systems.
# SX systems leverage the execution ansible upgrade playbook for this.
#
# Note: A file is used as temporary feature flag for
#       https://storyboard.openstack.org/#!/story/2009811
#       to avoid interfering with current behavior before the feature is
#       completed (see variable 'feature_flag').
#

import subprocess
import sys
import os.path
from controllerconfig.common import log
LOG = log.get_logger(__name__)


def get_system_mode():
    # get system_mode from platform.conf
    lines = [line.rstrip('\n') for line in
             open('/etc/platform/platform.conf')]
    for line in lines:
        values = line.split('=')
        if values[0] == 'system_mode':
            return values[1]
    return None


def create_platform_certificates():
    """Run ansible playbook to create platform certificates
    """
    playbooks_root = '/usr/share/ansible/stx-ansible/playbooks'
    upgrade_script = 'create-platform-certificates-in-upgrade.yml'
    cmd = 'ansible-playbook {}/{}'.format(playbooks_root, upgrade_script)
    sub = subprocess.Popen(cmd, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        LOG.error('Command failed:\n %s\n. %s\n%s' % (cmd, stdout, stderr))
        raise Exception('Cannot create platform certificates.')
    LOG.info('Successfully created platform certificates.')


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

    # Temporary feature flag file
    config_dir = '/opt/platform/config/' + to_release
    feature_flag = config_dir + '/.create_platform_certificates'

    if (action == 'activate' and
            from_release == '22.12' and
            os.path.exists(feature_flag)):
        LOG.info("%s invoked with from_release = %s to_release = %s "
                 "action = %s"
                 % (sys.argv[0], from_release, to_release, action))

        mode = get_system_mode()

        if mode == 'simplex':
            LOG.info("%s: System mode is %s. No actions required."
                     % (sys.argv[0], mode))
            return 0

        create_platform_certificates()


if __name__ == "__main__":
    sys.exit(main())
