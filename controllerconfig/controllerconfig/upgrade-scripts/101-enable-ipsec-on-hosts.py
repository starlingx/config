#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script enables IPsec on all hosts and should be executed
# at the end of upgrade-activate stage.

import json
import os
import subprocess
import sys

from controllerconfig.common import log
from six.moves import configparser
from sysinv.common import constants as consts
from sysinv.common import service_parameter as sp_consts
from sysinv.ipsec_auth.common import constants as ips_consts

LOG = log.get_logger(__name__)

DEFAULT_POSTGRES_PORT = 5432


def main():
    action = None
    from_release = None
    to_release = None
    port = DEFAULT_POSTGRES_PORT
    arg = 1
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            # optional port parameter for USM upgrade
            port = sys.argv[arg]
            pass
        else:
            print(f"Invalid option {sys.argv[arg]}.")
            return 1
        arg += 1

    log.configure()

    if get_system_mode() != "simplex":
        if from_release == "22.12" and action == "activate":
            try:
                LOG.info(f"Enable IPsec on system from the release "
                         f"{from_release} to {to_release}")
                LOG.info("Update mtce_heartbeat_failure_action to alarm, "
                         "before IPsec is enabled.")
                update_heartbeat_failure(
                    sp_consts.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_ALARM)
                LOG.info("Remove mgmt_ipsec in capabilities of "
                         "sysinv i_host table")
                remove_mgmt_ipsec(port)
                LOG.info("Start ipsec-server service")
                start_ipsec_server()
                LOG.info("Configure IPsec on each node of the environment")
                configure_ipsec_on_nodes(to_release)
                LOG.info("Update heartbeat_failure_action to default value "
                         "(fail). IPsec is enabled.")
                update_heartbeat_failure(
                    consts.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_DEFAULT)
            except Exception as ex:
                LOG.exception(ex)
                print(ex)
                return 1
            return 0
    LOG.info(f"Nothing to do for action {action}.")


def start_ipsec_server():
    cmd = "systemctl enable ipsec-server.service --now"
    sub = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        return stdout.decode('utf-8').rstrip('\n')
    else:
        LOG.error('Command failed:\n %s\n. %s\n%s\n'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception("Failed to start ipsec-server.")


def remove_mgmt_ipsec(postgres_port):
    """This function removes mgmt_ipsec in capabilities of sysinv
       i_host table.
    """
    env = os.environ.copy()
    sub_sel = subprocess.Popen(
        ['sudo', '-u', 'postgres',
         'psql', '-p', f'{postgres_port}',
         '-d', 'sysinv', '-c',
         'select uuid, capabilities from i_host'],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True)

    stdout, stderr = sub_sel.communicate()
    if sub_sel.returncode == 0 and stdout:
        rows = [item for item in stdout.split('\n') if '|' in item]
        # Remove header from sql stdout
        rows.pop(0)

        for records in rows:
            record = records.split('|')
            host_uuid = record[0].strip()
            capabilities = json.loads(record[1].strip())

            if 'mgmt_ipsec' in capabilities and \
               capabilities['mgmt_ipsec'] != ips_consts.MGMT_IPSEC_ENABLED:
                del capabilities['mgmt_ipsec']

                capabilities = json.dumps(capabilities)
                sqlcom = (f"update i_host set capabilities='{capabilities}'"
                          f"where uuid='{host_uuid}'")
                sub_update = subprocess.Popen(
                    ['sudo', '-u', 'postgres', 'psql',
                     '-p', f'{postgres_port}',
                     '-d', 'sysinv', '-c', sqlcom],
                    env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    universal_newlines=True)

                stdout, stderr = sub_update.communicate()
                if sub_update.returncode != 0:
                    LOG.error('Failed to remove mgmt_ipsec flag:'
                              '\n%s. \n%s' % (stdout, stderr))
                    raise Exception(stderr)
    else:
        LOG.error('Failed to connect to sysinv database:'
                  '\n%s. \n%s.' % (stdout, stderr))
        raise Exception(stderr)


def execute_system_cmd(api_cmd, exc_msg):
    cmd = f'source /etc/platform/openrc && {api_cmd}'

    sub = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        return stdout.decode('utf-8').rstrip('\n')
    else:
        LOG.error('Command failed:\n %s\n. %s\n%s\n'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception(exc_msg)


def update_heartbeat_failure(action):
    cmd = f'system service-parameter-modify platform ' \
          f'maintenance heartbeat_failure_action={action} && ' \
          'system service-parameter-apply platform'

    exc_msg = f'Cannot modify heartbeat_failure_action to {action}.'
    return execute_system_cmd(cmd, exc_msg)


def get_admin_credentials():
    cmd = 'echo $OS_PASSWORD'
    exc_msg = 'Cannot retrieve user credential.'

    passwd = execute_system_cmd(cmd, exc_msg)
    if passwd == '':
        raise Exception('Failed to retrieve sysadmin credentials.')

    credentials = []
    credentials.append('sysadmin')
    credentials.append(passwd)

    return credentials


def configure_ipsec_on_nodes(to_release):
    """Run ansible playbook to enable and configure IPsec on nodes
    """
    playbooks_root = '/usr/share/ansible/stx-ansible/playbooks'
    upgrade_script = 'enable-ipsec-on-nodes-in-upgrade.yml'
    ssh_credentials = get_admin_credentials()

    cmd = 'ansible-playbook {}/{} -e "software_version={} \
        ansible_ssh_user={} ansible_ssh_pass={} \
        ansible_become_pass={}"'.format(
        playbooks_root, upgrade_script, to_release, ssh_credentials[0],
        ssh_credentials[1], ssh_credentials[1])

    sub = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        LOG.error('Command failed:\n %s\n. %s\n%s\n'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception('Failed to enable IPsec on all hosts.')
    LOG.info('Successfully enabled IPsec on all hosts. Output:\n%s\n'
             % stdout.decode('utf-8'))


def get_system_mode():
    ini_str = '[DEFAULT]\n' + open('/etc/platform/platform.conf', 'r').read()

    config_applied = configparser.RawConfigParser()
    config_applied.read_string(ini_str)

    if config_applied.has_option('DEFAULT', 'system_mode'):
        system_mode = config_applied.get('DEFAULT', 'system_mode')
    else:
        system_mode = None

    return system_mode


if __name__ == "__main__":
    sys.exit(main())
