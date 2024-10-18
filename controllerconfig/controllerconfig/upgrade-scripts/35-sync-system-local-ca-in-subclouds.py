#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script syncs the secret system-local-ca in the subclouds
# with the one in the SystemController in DC systems, if
# required.
#

import logging as LOG
import subprocess
import sys
from time import sleep
import yaml

from sysinv.common.kubernetes import test_k8s_health

KUBE_CMD = 'kubectl --kubeconfig=/etc/kubernetes/admin.conf '
KUBE_IGNORE_NOT_FOUND = ' --ignore-not-found=true'
SSH_CMD = 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -q '
SSH_TIMEOUT = "30"

NETWORK_TYPES = ['OAM', 'MGMT']
RETRIES = len(NETWORK_TYPES) * 3


def get_distributed_cloud_role():
    lines = [line.rstrip('\n') for line in
             open('/etc/platform/platform.conf')]
    for line in lines:
        values = line.split('=')
        if values[0] == 'distributed_cloud_role':
            return values[1]
    return None


def execute_system_cmd(api_cmd, exc_msg):
    """Execute command after sourcing admin credentials
    """
    cmd = api_cmd

    sub = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        return stdout.decode('utf-8').rstrip('\n')
    else:
        LOG.error('Command failed:\n %s\n. %s\n%s\n'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception(exc_msg)


def get_admin_credentials():
    """Retrieve admin credentials
    """
    cmd = 'echo $OS_PASSWORD'
    exc_msg = 'Cannot retrieve user credential.'

    passwd = execute_system_cmd(cmd, exc_msg)
    if passwd == '':
        raise Exception('Failed to retrieve sysadmin credentials.')

    credentials = []
    credentials.append('sysadmin')
    credentials.append(passwd)

    return credentials


def get_ldapserver_ip():
    """Get ldapserver ip from hieradata
    """
    cmd = 'puppet lookup platform::ldap::params::ldapserver_host'

    sub = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        return stdout.decode('utf-8').rstrip('\n').lstrip('--- ')
    else:
        LOG.error('Command failed:\n %s\n. %s\n%s\n'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception("Could not retrieve ldapserver ip from hieradata.")


def get_hostname_or_ip(network):
    """Return hostname or IP based on the network type, for SSH usage
    """
    # Retrieved using already stablished configs to increase speed
    # (compared to retrieve w/ 'system' commands)
    if network == 'OAM':
        # registry.central should resolve to SystemController in OAM network
        return 'registry.central'
    if network == 'MGMT':
        # LDAP server is hosted in SystemController, access in MGMT network
        return get_ldapserver_ip()
    else:
        return None


def get_secret_data_ssh(address, credentials, name, namespace):
    """Retrieve a K8s secret data from a remote host using SSH
    """
    ssh_cmd = ('timeout ' + SSH_TIMEOUT + ' sshpass -p ' + credentials[1] +
               ' ' + SSH_CMD + credentials[0] + '@' + address)
    k8s_cmd = (KUBE_CMD + 'get secret -n ' + namespace + ' ' + name +
               ' -o yaml')
    cmd = ssh_cmd + ' ' + k8s_cmd

    sub = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        return stdout.decode('utf-8').rstrip('\n')
    else:
        LOG.error('Command failed:\n %s\n. %s\n%s\n'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception("Could not retrieve secret from remote host %s "
                        "using SSH." % address)


def parse_tls_data(secret_data):
    """Return TLS cert and key data from a secret dumped as YAML
    """
    data = yaml.safe_load(secret_data).get('data', None)
    if data is None:
        error = 'Secret YAML data is incorrect, missing \'spec\' field.'
        LOG.error(error)
        raise Exception(error)

    tls_crt = data.get('tls.crt', None)
    tls_key = data.get('tls.key', None)
    if tls_crt is None or tls_key is None:
        error = 'Secret YAML data is incorrect, missing TLS cert or key field.'
        LOG.error(error)
        raise Exception(error)

    return tls_crt, tls_key


@test_k8s_health
def delete_certificate(certificate, namespace='deployment'):
    """Delete certificate from k8s
    """
    delete_cmd = (KUBE_CMD + 'delete certificate ' + certificate + ' -n ' +
                  namespace + KUBE_IGNORE_NOT_FOUND)

    sub = subprocess.Popen(
        delete_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        return stdout.decode('utf-8')
    else:
        LOG.error('Command failed:\n%s\n%s.\n%s.' % (
            delete_cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception('Cannot delete Certificate %s from namespace %s.'
                        % (certificate, namespace))


@test_k8s_health
def delete_secret(secret, namespace='deployment'):
    """Delete certificate from k8s
    """
    delete_cmd = (KUBE_CMD + 'delete secret ' + secret + ' -n ' +
                  namespace + KUBE_IGNORE_NOT_FOUND)

    sub = subprocess.Popen(
        delete_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        return stdout.decode('utf-8')
    else:
        LOG.error('Command failed:\n%s\n%s.\n%s.' % (
            delete_cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception('Cannot delete secret %s from namespace %s.'
                        % (secret, namespace))


@test_k8s_health
def get_secret_type(secret, namespace):
    """Get secret type
    """
    get_cmd = (KUBE_CMD + 'get secret -n ' + namespace + ' ' + secret +
               ' -o=jsonpath=\'{.type}\'' + KUBE_IGNORE_NOT_FOUND)

    sub = subprocess.Popen(get_cmd, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        return stdout.decode('utf-8')
    else:
        LOG.error('Command failed:\n%s\n%s.\n%s.' % (get_cmd,
                                                     stdout.decode('utf-8'),
                                                     stderr.decode('utf-8')))
        raise Exception('Cannot retrieve secret data for secret %s '
                        'from namespace %s.' % (secret, namespace))


@test_k8s_health
def get_certificate_by_secretName(secret, namespace):
    """Get the name of a Certificate CRD that owns the specified secret
    """
    get_secretNames = (KUBE_CMD + 'get certificates -n ' + namespace +
                       ' -o=jsonpath=\'{.items[*].spec.secretName}\'')
    get_certificateNames = (KUBE_CMD + 'get certificates -n ' + namespace +
                            ' -o=jsonpath=\'{.items[*].metadata.name}\'')

    cmd = get_secretNames
    sub = subprocess.Popen(cmd,
                           shell=True,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        secretList = stdout.decode('utf-8').split()
        if secret in secretList:
            cmd = get_certificateNames
            sub = subprocess.Popen(cmd,
                                   shell=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            stdout, stderr = sub.communicate()
            if sub.returncode == 0:
                certificateList = stdout.decode('utf-8').split()
                return certificateList[secretList.index(secret)]
        else:
            return None

    # Note: using 'sub' twice
    if sub.returncode != 0:
        LOG.error('Command failed:\n%s\n%s.\n%s.' % (cmd,
                                                     stdout.decode('utf-8'),
                                                     stderr.decode('utf-8')))
        raise Exception('Cannot retrieve existent certificates '
                        'from namespace %s.' % namespace)


@test_k8s_health
def create_tls_secret(name, namespace, tls_crt, tls_key):
    """Create a TLS secret. TLS data needs to be provided encoded in base64.
    """
    create_cmd = (KUBE_CMD + 'create secret -n ' + namespace + ' tls ' + name +
                  ' --cert=<(echo ' + tls_crt + ' | base64 -d)' +
                  ' --key=<(echo ' + tls_key + ' | base64 -d)')

    sub = subprocess.Popen(create_cmd, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        LOG.info('TLS secret %s created in namespace %s.' % (name, namespace))
    else:
        LOG.error('Command failed:\n%s\n%s.\n%s.' % (create_cmd,
                                                     stdout.decode('utf-8'),
                                                     stderr.decode('utf-8')))
        raise Exception('Cannot create tls secret %s in namespace %s.'
                        % (name, namespace))


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
            # optional port parameter for USM upgrade
            # port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1
    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=LOG.INFO, datefmt="%FT%T")

    # Activate
    if (action == 'activate' and from_release == '22.12'):
        LOG.info("%s invoked with from_release = %s to_release = %s "
                 "action = %s"
                 % (sys.argv[0], from_release, to_release, action))
        if get_distributed_cloud_role() != 'subcloud':
            LOG.info("No action required for this system.")
            return 0

        current_net = 0
        for retry in range(0, RETRIES):
            try:
                # No Certificate object can own 'system-local-ca' secret
                certificateName = get_certificate_by_secretName(
                    'system-local-ca', 'cert-manager')
                if certificateName is not None:
                    LOG.warning("Secret system-local-ca was owned by a "
                                "Certificate object. It will be deleted.")
                    delete_certificate(certificateName, 'cert-manager')

                # We need to sync if secret isn't TLS or it was owned
                secret_type = get_secret_type('system-local-ca',
                                              'cert-manager')
                if (secret_type != 'kubernetes.io/tls' or
                        certificateName is not None):
                    LOG.info("Syncing system-local-ca w/ SystemController.")

                    # Get SSH connection parameters
                    address = get_hostname_or_ip(NETWORK_TYPES[current_net])
                    credentials = get_admin_credentials()

                    # SSH and get the data
                    LOG.info("Trying to connect to SystemController using %s"
                             " network." % NETWORK_TYPES[current_net])
                    secret_data = get_secret_data_ssh(address,
                                                      credentials,
                                                      'system-local-ca',
                                                      'cert-manager')
                    tls_crt, tls_key = parse_tls_data(secret_data)

                    # Recreate secret
                    delete_secret('system-local-ca', 'cert-manager')
                    create_tls_secret('system-local-ca', 'cert-manager',
                                      tls_crt, tls_key)
                    LOG.info("Successfully synced system-local-ca.")
                else:
                    LOG.info("No action required.")
            except Exception as e:
                if retry == RETRIES - 1:
                    LOG.error("Error syncing system-local-ca in the subcloud. "
                              "Please verify the logs.")
                    return 1
                else:
                    LOG.exception(e)
                    LOG.error("Exception ocurred during script execution, "
                              "retrying after 5 seconds.")
                    current_net = (current_net + 1) % len(NETWORK_TYPES)
                    sleep(5)
            else:
                return 0


if __name__ == "__main__":
    sys.exit(main())
