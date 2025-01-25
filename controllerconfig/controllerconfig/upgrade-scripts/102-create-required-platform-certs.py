#!/usr/bin/python3
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script creates/updates required platform certificates during upgrade.
# - The secret 'system-local-ca' is updated to include the 'ca.crt' field.
#
# - Subject is updated to match new defaults, if not otherwise customized by
#   the user:
#   - 'commonName' - default now is <cert_short_name>
#   - 'localities' - default now is <region>
#   - 'organization' - default now is 'starlingx'
#
# - If user upgraded with HTTPS and Docker Registry certificates not managed
#   by cert-manager (legacy configuration), the certificates are stored in
#   the expected secrets to keep the support in next version.
#
# - During rollback, HTTPS and Docker Registry certificates CRDs are deleted
#   if created by this script.

import json
import logging as LOG
import subprocess
import sys
import os
from time import sleep
import yaml

from cryptography.hazmat.primitives import serialization
from sysinv.common import utils as sysinv_utils
from sysinv.common.kubernetes import test_k8s_health
from sysinv.common.rest_api import get_token
from sysinv.common.rest_api import rest_api_request

from oslo_serialization import base64

RETRIES = 3

# At the end of activation, wait for configuration to finish
# before moving to the next scripts.
# 60 attempts * 20 seconds ~= 20 min max
WAIT_RECONFIG_ATTEMPTS = 60
WAIT_RECONFIG_SLEEP = 20

KUBE_CMD = 'kubectl --kubeconfig=/etc/kubernetes/admin.conf '
KUBE_IGNORE_NOT_FOUND = ' --ignore-not-found=true'
AUTO_CREATED_TAG = '.auto_created_cert-'

K8S_RESOURCES_TMP_FILENAME = '/tmp/update_cert.yml'
TRUSTED_BUNDLE_FILEPATH = '/etc/ssl/certs/ca-cert.pem'
CONFIG_FOLDER = '/opt/platform/config/'

OPENLDAP_CERT_NAME = 'system-openldap-local-certificate'
HTTPS_CERT_NAME = 'system-restapi-gui-certificate'
REGISTRY_CERT_NAME = 'system-registry-local-certificate'

CERT_FILES = {
    HTTPS_CERT_NAME: '/etc/ssl/private/server-cert.pem',
    REGISTRY_CERT_NAME: '/etc/ssl/private/registry-cert.crt'
}

KEY_FILES = {
    HTTPS_CERT_NAME: '/etc/ssl/private/server-cert.pem',
    REGISTRY_CERT_NAME: '/etc/ssl/private/registry-cert.key'
}

CERT_SUBJECT_INTERNAL = {
    HTTPS_CERT_NAME: 'StarlingX',
    REGISTRY_CERT_NAME: 'registry.local'
}


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
    return os.environ.get("OS_REGION_NAME")


def _get_primary_pool(network_type):
    cmd = f'(system network-list --nowrap | awk  \'$8 == "{network_type}" ' \
          f'{{ print $12 }}\')'

    sub = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        return stdout.decode('utf-8').rstrip('\n')
    else:
        LOG.error('Command failed:\n%s\n%s.\n%s.'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception(f'Cannot retrieve primary {network_type} pool.')


def get_primary_oam_ip():
    primary_oam_pool = _get_primary_pool('oam')
    cmd = f'(system addrpool-list --nowrap | awk ' \
          f'\'$2 == "{primary_oam_pool}" {{ print $14 }}\')'

    sub = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        return stdout.decode('utf-8').rstrip('\n')
    else:
        LOG.error('Command failed:\n%s\n%s.\n%s.'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception('Cannot retrieve OAM IP.')


@test_k8s_health
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
        LOG.error('Command failed:\n%s\n%s.\n%s.'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception('Cannot create platform certificates.')
    LOG.info('Successfully created platform certificates. Output: %s'
             % stdout.decode('utf-8'))


@test_k8s_health
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
        LOG.error('Command failed:\n%s\n%s.\n%s.'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception('Cannot retrieve existent certificates '
                        'from namespace: %s.' % namespace)


@test_k8s_health
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
        LOG.error('Command failed:\n%s\n%s.\n%s.'
                  % (get_cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception('Cannot dump Certificate %s from namespace: %s.'
                        % (certificate, namespace))


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
        raise Exception('Cannot delete Certificate %s from namespace: %s.'
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
        raise Exception('Cannot delete secret %s from namespace: %s.'
                        % (secret, namespace))


def get_old_default_CN_by_cert(certificate):
    """Return the old default CN per certificate
    """
    oam_ip = get_primary_oam_ip()
    default_CN_by_cert = {
        HTTPS_CERT_NAME: oam_ip,
        REGISTRY_CERT_NAME: oam_ip,
        OPENLDAP_CERT_NAME: 'system-openldap'
    }
    return default_CN_by_cert[certificate]


def find_root_ca(certificate):
    """Search for the RCA of the certificate provided
    """
    if sysinv_utils.verify_self_signed_ca_cert(certificate):
        return certificate

    with open(TRUSTED_BUNDLE_FILEPATH, 'r') as file:
        bundle = file.read().encode('utf-8')
        for rca_obj in sysinv_utils.extract_certs_from_pem(bundle):
            rca = rca_obj.public_bytes(
                serialization.Encoding.PEM).decode('utf-8')
            if sysinv_utils.verify_cert_issuer(certificate, rca):
                return rca
    LOG.error("Root CA not found for %s. Data will be empty."
              % certificate)
    return ""


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


def wait_system_reconfiguration(from_release='22.12'):
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

        if from_release == '22.12':
            # Wait HTTPS cert in case system is moving from HTTP
            if not os.path.isfile(CERT_FILES[HTTPS_CERT_NAME]):
                LOG.info("HTTPS certificate isn't ready yet.")
                continue

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
        if certificate != OPENLDAP_CERT_NAME:
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
        apply_k8s_yml(loaded_data)


def reconfigure_certificates_subject():
    """Reconfigure the subject for all desired certs
    """
    certificate_short_name = {
        HTTPS_CERT_NAME: 'system-restapi-gui',
        REGISTRY_CERT_NAME: 'system-registry-local',
        OPENLDAP_CERT_NAME: 'system-openldap',
    }

    cloud_role = get_distributed_cloud_role()
    for cert in certificate_short_name.keys():
        if (cert == OPENLDAP_CERT_NAME and cloud_role == 'subcloud'):
            continue
        if certificate_exists(cert):
            update_certificate(cert, certificate_short_name[cert])


def check_platform_certificates_updated_file_flag():
    return os.path.isfile(
        sysinv_utils.constants.PLATFORM_CERTIFICATES_UPDATED_IN_UPGRADE)


def remove_platform_certificates_updated_file_flag():
    try:
        os.remove(
            sysinv_utils.constants.PLATFORM_CERTIFICATES_UPDATED_IN_UPGRADE)
    except OSError:
        pass


def create_platform_certificates_updated_file_flag():
    remove_platform_certificates_updated_file_flag()
    sysinv_utils.touch(
        sysinv_utils.constants.PLATFORM_CERTIFICATES_UPDATED_IN_UPGRADE)


def get_cert_auto_creation_filename(cert_name, version):
    return CONFIG_FOLDER + version + '/' + AUTO_CREATED_TAG + cert_name


def check_cert_auto_creation_file_flag(cert_name, version):
    return os.path.isfile(get_cert_auto_creation_filename(cert_name, version))


def remove_cert_auto_creation_file_flag(cert_name, version):
    try:
        os.remove(get_cert_auto_creation_filename(cert_name, version))
    except OSError:
        pass


def create_cert_auto_creation_file_flag(cert_name, version):
    remove_cert_auto_creation_file_flag(cert_name, version)
    sysinv_utils.touch(get_cert_auto_creation_filename(cert_name, version))


def read_all_certs_from_file(filepath):
    """Retrieve certificate(s) from file
    """
    bundle = ''
    with open(filepath, 'r') as file:
        certs = sysinv_utils.extract_certs_from_pem(
            file.read().encode('utf-8'))
        for cert in certs:
            bundle += cert.public_bytes(
                serialization.Encoding.PEM).decode('utf-8')
    return bundle


def read_key_from_file(filepath):
    """Retrieve private key from file
    """
    cmd = 'openssl pkey -in ' + filepath

    sub = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        return stdout.decode('utf-8')
    else:
        LOG.error('Command failed:\n%s\n%s.\n%s.'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception('Cannot read private key %s from file.'
                        % (filepath))


def cert_file_exists(certificate):
    return os.path.exists(CERT_FILES[certificate])


def cert_file_internal(certificate):
    cert_subject = str(sysinv_utils.get_certificate_from_file(
        CERT_FILES[certificate]).subject)
    return cert_subject == \
        '<Name(CN=' + CERT_SUBJECT_INTERNAL[certificate] + ')>'


def save_from_file_to_secret(certificate, namespace='deployment'):
    tls_crt = read_all_certs_from_file(CERT_FILES[certificate])
    tls_key = read_key_from_file(KEY_FILES[certificate])

    secret_body = create_tls_secret_body(certificate,
                                         namespace,
                                         tls_crt,
                                         tls_key,
                                         find_root_ca(tls_crt))
    apply_k8s_yml(secret_body)


def adapt_legacy_certificate_config(to_release):
    affected_certs = [HTTPS_CERT_NAME, REGISTRY_CERT_NAME]
    legacy_cert_config = False
    for cert in affected_certs:
        if not certificate_exists(cert):
            if cert_file_exists(cert) and not cert_file_internal(cert):
                save_from_file_to_secret(cert)
                legacy_cert_config = True
            else:
                create_cert_auto_creation_file_flag(cert, to_release)
                LOG.warning("Certificate %s will be generated "
                            "with default values." % cert)
    if legacy_cert_config:
        LOG.warning("Warning: Legacy certificate configuration will "
                    "remain after upgrade.")


def patch_https_enabled(https_enabled):
    token = get_token(get_region_name())
    sysinv_url = token.get_service_internal_url(
        sysinv_utils.constants.SERVICE_TYPE_PLATFORM,
        sysinv_utils.constants.SYSINV_USERNAME)

    system_uuid = ''
    api_cmd = sysinv_url + '/isystems'
    res = rest_api_request(token, "GET", api_cmd, timeout=60)['isystems']
    if len(res) == 1:
        system = res[0]
        system_uuid = system['uuid']
    else:
        raise Exception('Failed to access system data')

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd = api_cmd + '/' + system_uuid

    https_status = str(https_enabled).lower()
    patch = []
    patch.append(
        {'op': 'replace', 'path': '/https_enabled', 'value': https_status})
    res = rest_api_request(token,
                           "PATCH",
                           api_cmd,
                           api_cmd_headers,
                           json.dumps(patch),
                           timeout=60)
    if (res is not None and
            res['capabilities']['https_enabled'] is https_enabled):
        LOG.info('https_enabled is successfully patched to %s' % https_status)
    else:
        raise Exception('https_enabled patch to %s failed! resp=%s'
                        % (https_status, res))

    if https_enabled is False:
        try:
            os.remove(CERT_FILES[HTTPS_CERT_NAME])
        except OSError:
            pass


def restore_legacy_certificate_config(from_release):
    affected_certs = [HTTPS_CERT_NAME, REGISTRY_CERT_NAME]
    for cert in affected_certs:
        if check_cert_auto_creation_file_flag(cert, from_release):
            delete_certificate(cert)
            if cert == HTTPS_CERT_NAME:
                patch_https_enabled(False)
                wait_system_reconfiguration(from_release)
            remove_cert_auto_creation_file_flag(cert, from_release)
        else:
            if not certificate_exists(cert):
                delete_secret(cert)


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
        if check_platform_certificates_updated_file_flag():
            LOG.info("Platform certificates already updated before. "
                     "Skipping.")
            return 0

        for retry in range(0, RETRIES):
            try:
                adapt_legacy_certificate_config(to_release)
                reconfigure_certificates_subject()
                create_platform_certificates(to_release)
                patch_https_enabled(True)
                create_platform_certificates_updated_file_flag()
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

    # Activate rollback
    if (action == 'activate-rollback' and from_release == '24.09'):
        LOG.info("%s invoked with from_release = %s to_release = %s "
                 "action = %s"
                 % (sys.argv[0], from_release, to_release, action))
        for retry in range(0, RETRIES):
            try:
                restore_legacy_certificate_config(from_release)
                remove_platform_certificates_updated_file_flag()
                LOG.info("Successfully restored legacy certificate "
                         "config.")
            except Exception as e:
                if retry == RETRIES - 1:
                    LOG.error("Error restoring legacy certificate config. "
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
