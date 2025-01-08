#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script syncs the secret system-local-ca in the subclouds
# with the one in the SystemController in DC systems, if
# required.
#
# It also includes missing ca.crt data for every system (standalone,
# DC Systemcontroller and subclouds).
#

from cryptography.hazmat.primitives import serialization
import logging as LOG
import os
import subprocess
import sys
from time import sleep
import yaml

from oslo_serialization import base64
from sysinv.common.kubernetes import test_k8s_health
from sysinv.common import utils as sysinv_utils

KUBE_CMD = 'kubectl --kubeconfig=/etc/kubernetes/admin.conf '
KUBE_IGNORE_NOT_FOUND = ' --ignore-not-found=true'
SSH_CMD = 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -q '
SSH_TIMEOUT = "30"

K8S_RESOURCES_TMP_FILENAME = '/tmp/update_cert.yml'
TRUSTED_BUNDLE_FILEPATH = '/etc/ssl/certs/ca-cert.pem'

NETWORK_TYPES = ['OAM', 'MGMT']
RETRIES = len(NETWORK_TYPES) * 3

# Wait reconfiguration after installing ssl_ca
# 60 attempts * 20 seconds ~= 20 min max
WAIT_RECONFIG_ATTEMPTS = 60
WAIT_RECONFIG_SLEEP = 20


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


def find_root_ca(certificate):
    """Search for the RCA of the certificate provided
       Returns a bool informing if the RCA is trusted and the RCA cert
    """
    with open(TRUSTED_BUNDLE_FILEPATH, 'r') as file:
        bundle = file.read().encode('utf-8')
        for rca_obj in sysinv_utils.extract_certs_from_pem(bundle):
            rca = rca_obj.public_bytes(
                serialization.Encoding.PEM).decode('utf-8')
            if sysinv_utils.verify_cert_issuer(certificate, rca):
                return True, rca

    LOG.warning("Root CA not found in the bundle for %s." % certificate)
    if sysinv_utils.verify_self_signed_ca_cert(certificate):
        return False, certificate
    else:
        LOG.error("No Root CA data is available for %s." % certificate)
        return False, ""


def create_tls_secret_body(name, namespace, tls_crt, tls_key, ca_crt=''):
    secret_body = {
        'apiVersion': 'v1',
        'kind': 'Secret',
        'metadata': {
            'name': name,
            'namespace': namespace
        },
        'type': 'kubernetes.io/tls',
        'data': {
            'ca.crt': base64.encode_as_text(ca_crt),
            'tls.crt': base64.encode_as_text(tls_crt),
            'tls.key': base64.encode_as_text(tls_key),
        }
    }

    return secret_body


@test_k8s_health
def apply_k8s_yml(resources_yml):
    with open(K8S_RESOURCES_TMP_FILENAME, 'w') as yaml_file:
        yaml.safe_dump(resources_yml, yaml_file, default_flow_style=False)

    apply_cmd = KUBE_CMD + 'apply -f ' + K8S_RESOURCES_TMP_FILENAME

    sub = subprocess.Popen(apply_cmd, shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        LOG.error('Command failed:\n%s\n%s.\n%s.' % (
            apply_cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception('Cannot apply k8s resource file.')
    else:
        os.remove(K8S_RESOURCES_TMP_FILENAME)
        LOG.info('K8s resources applied. Output: %s'
                 % stdout.decode('utf-8'))


def wait_system_reconfiguration():
    cmd = "fm alarm-list --query alarm_id=250.001"

    # Stop after two sequential attempts without 250.001 alarms. This avoids
    # missing the transition between two alarms.
    one_attempt_clear = False
    for attempt in range(WAIT_RECONFIG_ATTEMPTS):
        LOG.info("Waiting out-of-date alarms to clear. Attempt %s of %s."
                 % (attempt + 1, WAIT_RECONFIG_ATTEMPTS))
        # Sleep first as to allow cert-mon to start installing the new certs
        sleep(WAIT_RECONFIG_SLEEP)

        sub = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = sub.communicate()

        if sub.returncode == 0:
            if stdout.decode('utf-8').rstrip('\n') == "":
                if one_attempt_clear:
                    LOG.info("Out-of-date alarms cleared. Proceeding.")
                    return
                one_attempt_clear = True
            else:
                one_attempt_clear = False
        else:
            LOG.error('Command failed:\n%s\n%s.\n%s.'
                      % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
    LOG.error("NOTICE: Out-of-date alarms didn't clear out after more than %s \
              seconds. Ignoring and continuing with the upgrade activation."
              % str(WAIT_RECONFIG_ATTEMPTS * WAIT_RECONFIG_SLEEP))


@test_k8s_health
def update_system_local_ca_secret():
    """Update system-local-ca secret
    """
    tls_crt, tls_key, ca_crt = sysinv_utils.get_certificate_from_secret(
        'system-local-ca', 'cert-manager')

    if ca_crt == "" or not sysinv_utils.verify_cert_issuer(tls_crt, ca_crt):
        is_trusted, rca = find_root_ca(tls_crt)
        if rca == "":
            LOG.error("No available RCA certificate matches "
                      "system-local-ca's tls.crt data.")
            return 1
        secret_body = create_tls_secret_body('system-local-ca',
                                             'cert-manager',
                                             tls_crt,
                                             tls_key,
                                             rca)
        apply_k8s_yml(secret_body)
        LOG.info("RCA data inserted in system-local-ca secret.")
        if not is_trusted:
            wait_system_reconfiguration()


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

                # Sync subcloud data secret w/ SystemController
                if get_distributed_cloud_role() == 'subcloud':
                    # We need to sync if secret isn't TLS or it was owned
                    secret_type = get_secret_type('system-local-ca',
                                                  'cert-manager')
                    if (secret_type != 'kubernetes.io/tls' or
                            certificateName is not None):
                        LOG.info(
                            "Syncing system-local-ca w/ SystemController.")

                        # Get SSH connection parameters
                        address = \
                            get_hostname_or_ip(NETWORK_TYPES[current_net])
                        credentials = get_admin_credentials()

                        # SSH and get the data
                        LOG.info("Trying to connect to SystemController using"
                                 " %s network." % NETWORK_TYPES[current_net])
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

                # Add ca.crt data
                update_system_local_ca_secret()
            except Exception as e:
                if retry == RETRIES - 1:
                    LOG.error("Error updating system-local-ca. "
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
