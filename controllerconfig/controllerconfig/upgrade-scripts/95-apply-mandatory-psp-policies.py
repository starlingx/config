#!/usr/bin/python3
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script applies mandatory pod security policies to a system
# after upgrades. These are usually applied by ansible, which is
# not run during an upgrade.
#

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

    if from_release == '20.06' and action == 'activate':
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (sys.argv[0], from_release, to_release, action))
        apply_mandatory_psp_policies()


def apply_mandatory_psp_policies():
    cmd = "kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f " \
          "/usr/share/ansible/stx-ansible/playbooks/roles/bootstrap/" \
          "bringup-essential-services/files/psp-policies.yaml"

    sub = subprocess.Popen(cmd, shell=True,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           universal_newlines=True)

    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        LOG.error('Command failed:\n %s\n. %s\n%s' % (cmd, stdout, stderr))
        raise Exception('Cannot apply pod security policies')

    LOG.info('Mandatory pod security policies applied successfully')


if __name__ == "__main__":
    sys.exit(main())
