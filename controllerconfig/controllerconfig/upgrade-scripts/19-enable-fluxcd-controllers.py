#!/usr/bin/python
# Copyright (c) 2022-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script install fluxcd controllers in the fluxcd-helm namespace
# in kubernetes
#
# This script can be removed in the release that follows stx7
import logging as LOG
import subprocess
import sys

from sysinv.common.kubernetes import test_k8s_health


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
        elif arg == 4:
            # postgres_port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1
    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=LOG.INFO, datefmt="%FT%T")

    if action == 'activate' and from_release >= '21.12':
        LOG.info("%s invoked with from_release = %s to_release = %s "
                 "action = %s"
                 % (sys.argv[0], from_release, to_release, action))
        enable_fluxcd_controllers(from_release)


@test_k8s_health
def enable_fluxcd_controllers(from_release):
    """Run fluxcd_controllers ansible playbook to enable fluxcd controllers

    """

    playbooks_root = '/usr/share/ansible/stx-ansible/playbooks'
    upgrade_script = 'upgrade-fluxcd-controllers.yml'
    cmd = 'ansible-playbook {}/{} -e "upgrade_activate_from_release={}"'\
          ''.format(playbooks_root, upgrade_script, from_release)
    sub = subprocess.Popen(cmd, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        LOG.error('Command failed:\n %s\n. %s\n%s' % (
            cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception('Cannot install fluxcd controllers')
    LOG.info('FluxCD controllers enabled. Output: %s' % stdout.decode('utf-8'))


if __name__ == "__main__":
    sys.exit(main())
