#!/usr/bin/python
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script creates the openldap certificate on kubernetes
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

    if action == 'activate' and to_release == '22.12':
        LOG.info("%s invoked with from_release = %s to_release = %s "
                 "action = %s"
                 % (sys.argv[0], from_release, to_release, action))
        create_openldap_certificate()


def create_openldap_certificate():
    """Run openldap certificate ansible playbook
    """
    playbooks_root = '/usr/share/ansible/stx-ansible/playbooks'
    upgrade_script = 'create-openldap-certificate-for-upgrade.yml'
    cmd = 'ansible-playbook {}/{}'.format(playbooks_root, upgrade_script)
    sub = subprocess.Popen(cmd, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        LOG.error('Command failed:\n %s\n. %s\n%s' % (cmd, stdout, stderr))
        raise Exception('Cannot create openldap certificate')
    LOG.info('Successfully created openldap certificate')


if __name__ == "__main__":
    sys.exit(main())
