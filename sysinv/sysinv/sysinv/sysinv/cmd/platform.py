# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import argparse
import getpass
import subprocess
import sys
from oslo_config import cfg
from oslo_log import log as logging


LOG = logging.getLogger(__name__)
CONF = cfg.CONF
UPGRADE_PLATFORM_FILE = '/usr/share/ansible/stx-ansible/playbooks/upgrade_platform.yml'
BECOME_PASS_KEY = 'ansible_become_pass'
UPGRADE_ACTION = 'upgrade'


def prompt_for_password(pw_type='sysadmin'):
    while True:
        password = getpass.getpass(
            "Enter the " + pw_type + " password for the Ansible Playbooks: ")
        if len(password) < 1:
            print("Password cannot be empty")
            continue
        confirm = getpass.getpass(
            "Re-enter " + pw_type + " password to confirm: ")
        if password != confirm:
            print("Passwords did not match")
            continue
        break
    return password


def upgrade_action(become_pass, extra_vars):
    become_pass_str = '%s=%s' % (BECOME_PASS_KEY, become_pass)

    ansible_options_dict = {'-e': '"%s"' % become_pass_str}
    if extra_vars:
        ansible_options_dict["-e"] = '"%s %s"' % (become_pass_str, extra_vars.replace(",", " "))

    # Build the Ansible options
    ansible_options_str = ' '.join(' '.join((key, val)) for (key, val)
                                   in ansible_options_dict.items())

    upgrade_platform_cmd = ['ansible-playbook', UPGRADE_PLATFORM_FILE, ansible_options_str]
    try:
        proc = subprocess.Popen(upgrade_platform_cmd,
                                stdout=subprocess.PIPE,
                                universal_newlines=True)
        out, _ = proc.communicate()
        # Print the Ansible Playbook output on the CLI
        print(out)
    except Exception as e:
        LOG.info("Running ansible playbook command failed: Error: %s" % str(e))


def main():
    """
    Example:  platform-upgrade --become_pass=mypassword --extra_vars=k1=v1,k2=v2,k3=v3

    """
    parser = argparse.ArgumentParser(prog='platform-upgrade')
    parser.add_argument('-p', '--become_pass',
                            help='Ansible password to execute upgrade platform. '
                        )
    parser.add_argument('-e', '--extra_vars',
                            help='Variables are passed in using key=value format syntax. '
                                 'Use comma to separate multiple variables. '
                        )
    options, _ = parser.parse_known_args(sys.argv[1:])

    common_opts = [
        cfg.StrOpt('become_pass',
                    default=options.become_pass),
        cfg.StrOpt('extra_vars',
                    default=options.extra_vars),
    ]
    CONF.register_cli_opts(common_opts)
    cfg.CONF.log_opt_values(LOG, logging.INFO)

    if not CONF.become_pass:
        CONF.become_pass = prompt_for_password()
    upgrade_action(CONF.become_pass, CONF.extra_vars)
