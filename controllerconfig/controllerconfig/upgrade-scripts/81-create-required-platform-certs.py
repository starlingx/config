#!/usr/bin/python3
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script creates/updates required platform certificates during upgrade.
# - The secret 'system-local-ca' is updated to include the 'ca.crt' field.
#
# - Certificates are created using ansible playbooks.
#   - (Legacy) SX upgrade is already covered by upgrade playbook.
#
# - Subject is updated to match new defaults, if not otherwise customized by
#   the user:
#   - 'commonName' - default now is <cert_short_name>
#   - 'localities' - default now is <region>
#   - 'organization' - default now is 'starlingx'

import subprocess
import sys
import os
from time import sleep
import yaml

from controllerconfig.common import log
from cryptography.hazmat.primitives import serialization
from sysinv.common import utils as sysinv_utils
from oslo_serialization import base64

LOG = log.get_logger(__name__)
KUBE_CMD = 'kubectl --kubeconfig=/etc/kubernetes/admin.conf '
TMP_FILENAME = '/tmp/update_cert.yml'
RETRIES = 3
TRUSTED_BUNDLE_FILEPATH = '/etc/ssl/certs/ca-cert.pem'


def get_system_mode():
    lines = [line.rstrip('\n') for line in
             open('/etc/platform/platform.conf')]
    for line in lines:
        values = line.split('=')
        if values[0] == 'system_mode':
            return values[1]
    return None


def get_distributed_cloud_role():
    lines = [line.rstrip('\n') for line in
             open('/etc/platform/platform.conf')]
    for line in lines:
        values = line.split('=')
        if values[0] == 'distributed_cloud_role':
            return values[1]
    return None


def get_region_name():
    """Get region name
    """
    for line in open('/etc/platform/openrc'):
        if 'export ' in line:
            values = line.rstrip('\n').lstrip('export ').split('=')
            if values[0] == 'OS_REGION_NAME':
                return values[1]
    return None


def get_oam_ip():
    cmd = 'source /etc/platform/openrc && ' \
        '(system addrpool-list --nowrap | awk  \'$4 == "oam" { print $14 }\')'

    sub = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        return stdout.decode('utf-8').rstrip('\n')
    else:
        LOG.error('Command failed:\n %s\n. %s\n%s\n'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception('Cannot retrieve OAM IP.')


def create_platform_certificates(to_release):
    """Run ansible playbook to create platform certificates
    """
    playbooks_root = '/usr/share/ansible/stx-ansible/playbooks'
    upgrade_script = 'create-platform-certificates-in-upgrade.yml'
    cmd = 'ansible-playbook {}/{} -e "software_version={}"'.format(
        playbooks_root, upgrade_script, to_release)

    sub = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        LOG.error('Command failed:\n %s\n. %s\n%s\n'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception('Cannot create platform certificates.')
    LOG.info('Successfully created platform certificates. Output:\n%s\n'
             % stdout.decode('utf-8'))


def certificate_exists(certificate, namespace='deployment'):
    """Check if certificate exists
    """
    cmd = (KUBE_CMD + 'get certificates -n ' + namespace +
           ' -o custom-columns=NAME:metadata.name --no-headers')

    sub = subprocess.Popen(cmd, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        return certificate in stdout.decode('utf-8').splitlines()
    else:
        LOG.error('Command failed:\n %s\n. %s\n%s\n'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception('Cannot retrieve existent certificates '
                        'from namespace: %s.' % namespace)


def retrieve_certificate(certificate, namespace='deployment'):
    """Retrieve certificate (as YAML text)
    """
    get_cmd = (KUBE_CMD + 'get certificate ' + certificate + ' -n ' +
               namespace + ' -o yaml')

    sub = subprocess.Popen(
        get_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        return stdout.decode('utf-8')
    else:
        LOG.error('Command failed:\n %s\n. %s\n%s\n'
                  % (get_cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception('Cannot dump Certificate %s from namespace: %s.'
                        % (certificate, namespace))


def get_old_default_CN_by_cert(certificate):
    """Return the old default CN per certificate
    """
    oam_ip = get_oam_ip()
    default_CN_by_cert = {
        'system-restapi-gui-certificate': oam_ip,
        'system-registry-local-certificate': oam_ip,
        'system-openldap-local-certificate': 'system-openldap'
    }
    return default_CN_by_cert[certificate]


def find_root_ca(intermediate_ca):
    """Look in the trusted bundle for the RCA of the ICA provided
    """
    with open(TRUSTED_BUNDLE_FILEPATH, 'r') as file:
        bundle = file.read().encode('utf-8')
        for cert_obj in sysinv_utils.extract_certs_from_pem(bundle):
            cert = cert_obj.public_bytes(
                serialization.Encoding.PEM).decode('utf-8')
            if sysinv_utils.verify_cert_issuer(intermediate_ca, cert):
                return cert
    LOG.error("Root CA not found for system-local-ca. Data will be empty.")
    return ""


def update_system_local_ca_secret():
    """Update system-local-ca secret
    """
    tls_crt, tls_key, ca_crt = sysinv_utils.get_certificate_from_secret(
        'system-local-ca', 'cert-manager')

    if ca_crt == "" or not sysinv_utils.verify_cert_issuer(tls_crt, ca_crt):
        ca_crt = find_root_ca(tls_crt)
        secret_body = {
            'apiVersion': 'v1',
            'kind': 'Secret',
            'metadata': {
                'name': 'system-local-ca',
                'namespace': 'cert-manager'
            },
            'type': 'kubernetes.io/tls',
            'data': {
                'ca.crt': base64.encode_as_text(ca_crt),
                'tls.crt': base64.encode_as_text(tls_crt),
                'tls.key': base64.encode_as_text(tls_key),
            }
        }

        with open(TMP_FILENAME, 'w') as yaml_file:
            yaml.safe_dump(secret_body, yaml_file, default_flow_style=False)

        apply_cmd = KUBE_CMD + 'apply -f ' + TMP_FILENAME

        sub = subprocess.Popen(apply_cmd, shell=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        stdout, stderr = sub.communicate()
        if sub.returncode != 0:
            LOG.error('Command failed:\n %s\n. %s\n%s\n' % (
                apply_cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
            raise Exception('Cannot apply change to system-local-ca secret.')
        else:
            os.remove(TMP_FILENAME)
            LOG.info('Updated system-local-ca secret. Output:\n%s\n'
                     % stdout.decode('utf-8'))


def update_certificate(certificate, short_name):
    """Update the desired subject fields for the certificates
    """
    LOG.info("Verifying subject of certificate: %s" % certificate)
    loaded_data = yaml.safe_load(retrieve_certificate(certificate))

    if loaded_data.get('spec', None) is None:
        error = ('Certificate %s data is incorrect, missing \'spec\' field.'
                 % certificate)
        LOG.error(error)
        raise Exception(error)

    region = get_region_name()
    cert_changes = False
    same_CN = False

    common_name = loaded_data['spec'].get('commonName', None)
    if common_name == get_old_default_CN_by_cert(certificate):
        same_CN = True
        if certificate != 'system-openldap-local-certificate':
            common_name = short_name
            loaded_data['spec'].update({'commonName': common_name})
            cert_changes = True

    if same_CN and (loaded_data['spec'].get('subject', None) is None):
        loaded_data['spec'].update({
            'subject': {'localities': [region.lower()],
                        'organizations': ['starlingx']}})
        cert_changes = True
    else:
        # If localities exists, it should have two entries:
        # 1) 'subject_L' override
        # 2) <subject_prefix>:<region_name>:<cert_short_name>
        # We will remove the 2nd to match the new configuration.
        localities = \
            loaded_data['spec'].get('subject', {}).get('localities', None)
        if localities:
            if len(localities) != 2:
                LOG.warning('Unexpected number of \'L\' entries in subject '
                            'of certificate %s: %s'
                            % (certificate, len(localities)))

            unwanted_index = None
            for index, item in enumerate(localities):
                if (region.lower() + ':' + short_name) in item:
                    unwanted_index = index
                    break

            if unwanted_index is not None:
                if len(localities) == 1:
                    localities[0] = region.lower()
                else:
                    localities.pop(unwanted_index)
                loaded_data['spec']['subject'].update(
                    {'localities': localities})
                cert_changes = True
            else:
                LOG.warning('Expected subject \'L\' entry that identifies '
                            'the certificate not found for %s.' % certificate)

    if cert_changes:
        with open(TMP_FILENAME, 'w') as yaml_file:
            yaml.safe_dump(loaded_data, yaml_file, default_flow_style=False)

        apply_cmd = KUBE_CMD + 'apply -f ' + TMP_FILENAME

        sub = subprocess.Popen(apply_cmd, shell=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        stdout, stderr = sub.communicate()
        if sub.returncode != 0:
            LOG.error('Command failed:\n %s\n. %s\n%s\n' % (
                apply_cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
            raise Exception('Cannot apply change to certificate %s.'
                            % certificate)
        else:
            os.remove(TMP_FILENAME)
            LOG.info('Updated subject entries for certificate: %s. '
                     'Output:\n%s\n' % (certificate, stdout.decode('utf-8')))


def reconfigure_certificates_subject():
    """Reconfigure the subject for all desired certs
    """
    certificate_short_name = {
        'system-restapi-gui-certificate': 'system-restapi-gui',
        'system-registry-local-certificate': 'system-registry-local',
        'system-openldap-local-certificate': 'system-openldap',
    }

    cloud_role = get_distributed_cloud_role()
    for cert in certificate_short_name.keys():
        if (cert == 'system-openldap-local-certificate' and
                cloud_role == 'subcloud'):
            continue
        if certificate_exists(cert):
            update_certificate(cert, certificate_short_name[cert])


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
    log.configure()

    if (action == 'activate' and from_release == '22.12'):
        LOG.info("%s invoked with from_release = %s to_release = %s "
                 "action = %s"
                 % (sys.argv[0], from_release, to_release, action))

        for retry in range(0, RETRIES):
            try:
                update_system_local_ca_secret()
                reconfigure_certificates_subject()
                mode = get_system_mode()
                # For (legacy) SX upgrade, the role that creates the required
                # platform certificates is already executed by the upgrade
                # playbook.
                if mode != 'simplex':
                    create_platform_certificates(to_release)
                LOG.info("Successfully created/updated required platform "
                         "certificates.")
            except Exception as e:
                if retry == RETRIES - 1:
                    LOG.error("Error updating required platform certificates. "
                              "Please verify logs.")
                    return 1
                else:
                    LOG.exception(e)
                    LOG.error("Exception ocurred during script execution, "
                              "retrying after 5 seconds.")
                    sleep(5)
            else:
                return 0


if __name__ == "__main__":
    sys.exit(main())
