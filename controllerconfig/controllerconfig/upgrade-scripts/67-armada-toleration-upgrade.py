#!/usr/bin/python
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script updates armada to add tolerations for the
# node-role.kubernetes.io/master:NoSchedule taint on armada-api pod.
#
# This script can be removed in the release that follows stx6
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

    if action == 'activate' and from_release == '21.05':
        LOG.info("%s invoked with from_release = %s to_release = %s "
                 "action = %s"
                 % (sys.argv[0], from_release, to_release, action))
        update_armada_toleration()


def update_armada_toleration():
    """Run upgrade-k8s-armada-helm.yml to update armada helm chart.

    When this script is run, all hosts have been upgraded and the new helm
    chart and the armada-overrides.yaml.j2 file with the tolerations override
    are available on the active controller.

    This function will run the upgrade-k8s-armada-helm.yml playbook that
    upgrades the armada chart with overrides present on armada-overrides.yaml.
    """

    playbooks_root = '/usr/share/ansible/stx-ansible/playbooks'
    upgrade_script = 'upgrade-k8s-armada-helm.yml'
    cmd = 'ansible-playbook {}/{}'.format(playbooks_root, upgrade_script)
    sub = subprocess.Popen(cmd, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        LOG.error('Command failed:\n %s\n. %s\n%s' % (cmd, stdout, stderr))
        raise Exception('Cannot update armada')
    LOG.info('Toleration applied to armada successfully')


if __name__ == "__main__":
    sys.exit(main())
