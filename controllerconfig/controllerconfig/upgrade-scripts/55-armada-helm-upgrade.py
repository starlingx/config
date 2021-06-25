#!/usr/bin/python
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script updates armada to containerized version
# based using Helm v3. This also cleans up previous
# tiller-deployment.
#
# This script can be removed in the release that follows stx5.0

import json
import subprocess
import sys
from sysinv.common.kubernetes import KUBERNETES_ADMIN_CONF
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

    if action == 'activate' and not is_containerized_armada_installed():
        LOG.info("%s invoked with from_release = %s to_release = %s "
                 "action = %s"
                 % (sys.argv[0], from_release, to_release, action))
        update_armada_helmv3()


def is_containerized_armada_installed():
    """Check if containerized armada is installed by helmv3"""
    try:
        cmd = "/usr/sbin/helm list " \
              "--namespace armada --filter armada --output json " \
              "--kubeconfig {} ".format(KUBERNETES_ADMIN_CONF)
        result = subprocess.check_output(cmd, shell=True,
                                         stderr=subprocess.STDOUT,
                                         universal_newlines=True)
        if not json.loads(result):
            return False
        return True
    except subprocess.CalledProcessError as e:
        LOG.exception("Unable to query armada helmv3 release: %s" % e.output)
        raise


def update_armada_helmv3():
    playbooks_root = '/usr/share/ansible/stx-ansible/playbooks'
    upgrade_script = 'upgrade-k8s-armada-helm.yml'
    cmd = 'ansible-playbook {}/{}'.format(playbooks_root, upgrade_script)
    sub = subprocess.Popen(cmd, shell=True,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           universal_newlines=True)

    stdout, stderr = sub.communicate()

    if sub.returncode != 0:
        LOG.error('Command failed:\n %s\n. %s\n%s' % (cmd, stdout, stderr))
        raise Exception('Cannot update armada')

    LOG.info('armada helm v3 updated successfully')


if __name__ == "__main__":
    sys.exit(main())
