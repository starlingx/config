#!/usr/bin/python
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script updates the subcloud admin endpoint certificate
# to include mgmt floating IP as subjectAltName.
#
# This script can be removed in the release that follows stx.5.0
#

import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from shutil import copyfile
import socket
import subprocess
import sys
import time

from controllerconfig.common import log

LOG = log.get_logger(__name__)


sc_admin_endpoint_cert_yaml = """
---
apiVersion: cert-manager.io/v1alpha3
kind: Certificate
metadata:
  name: sc-adminep-certificate
  namespace: sc-cert
spec:
  commonName: %s
  duration: 4320h
  renewBefore: 30h
  ipAddresses:
    - "%s"
  issuerRef:
    name: sc-intermediate-ca-adminep-issuer
    kind: Issuer
  secretName: sc-adminep-certificate
"""


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
            print ("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()
    LOG.debug("%s invoked with from_release = %s to_release = %s action = %s"
              % (sys.argv[0], from_release, to_release, action))

    if from_release == '20.06' and action == 'activate':
        if is_subcloud():
            update_sc_admin_endpoint_cert(to_release)


def is_subcloud():
    with open('/etc/platform/platform.conf', 'r') as f:
        lines = f.readlines()

    for line in lines:
        if line.strip() == 'distributed_cloud_role=subcloud':
            return True

    return False


def execute_command(cmd):
    sub = subprocess.Popen(cmd, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        LOG.error('Command failed:\n %s\n. %s\n%s' % (cmd, stdout, stderr))
        raise Exception('Failed to execute command: %s' % cmd)
    return stdout


def update_sc_admin_endpoint_cert(to_release):
    mgmt_ip = socket.getaddrinfo('controller', None)[0][4][0]
    resource = sc_admin_endpoint_cert_yaml % (mgmt_ip, mgmt_ip)

    # Update certificate in cert manager and secret in k8s
    cmd = "echo '%s' | " \
          "kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f -" % \
          resource
    execute_command(cmd)

    # Wait up to 30s for admin endpoint certificate to be ready,
    # Retry if certificate is not ready yet.
    cmd = "kubectl --kubeconfig=/etc/kubernetes/admin.conf -n sc-cert \
           wait --for=condition=ready certificate sc-adminep-certificate \
           --timeout=30s"
    for attempt in range(3):
        try:
            execute_command(cmd)
        except Exception:
            LOG.info("Retry command: %s" % cmd)
            continue
        break
    else:
        raise Exception('Command failed after retries: %s' % cmd)

    # Extract subcloud admin endpoint certificate.
    # There is an issue with cert-manager where even though the certificate is
    # reported as ready from the previous command, the actual data extracted is
    # still empty. So we retry if no valid certificate data is extracted, and
    # retry for private key data for the same reason.
    cmd = "kubectl --kubeconfig=/etc/kubernetes/admin.conf get secret \
           sc-adminep-certificate -n sc-cert -o=jsonpath='{.data.tls\.crt}'"
    for attempt in range(3):
        try:
            cert = execute_command(cmd)
            if not cert:
                raise Exception('Certificate extracted is empty.')
            cert = base64.b64decode(cert)

            # Test loading the certificate to ensure it's valid
            x509.load_pem_x509_certificate(cert, default_backend())
        except Exception as e:
            LOG.info('Failed to extract certificate: %s Will retry.' % e)
            time.sleep(5)
            continue
        else:
            break
    else:
        raise Exception('Failed to extract certificate from cert-manager.')

    # Extract subcloud admin endpoint private key,
    # Retry if no valid private key data is extracted.
    cmd = "kubectl --kubeconfig=/etc/kubernetes/admin.conf get secret \
           sc-adminep-certificate -n sc-cert -o=jsonpath='{.data.tls\.key}'"
    for attempt in range(3):
        try:
            key = execute_command(cmd)
            if not key:
                raise Exception('Private key extracted is empty.')
            key = base64.b64decode(key)

            # Test loading the private key to ensure it's valid
            serialization.load_pem_private_key(key, password=None,
                                               backend=default_backend())
        except Exception as e:
            LOG.info('Failed to extract private key: %s Will retry.' % e)
            time.sleep(5)
            continue
        else:
            break
    else:
        raise Exception('Failed to extract private key from cert-manager.')

    # Create haproxy tls certificate
    cert_file = "/etc/ssl/private/admin-ep-cert.pem"
    with open(cert_file, 'w') as f:
        f.write(key + cert)

    # Copy admin endpoint certficates to the shared filesystem directory
    shared_file = "/opt/platform/config/%s/admin-ep-cert.pem" % to_release
    copyfile(cert_file, shared_file)

    # Restart haproxy to take the new cert
    cmd = "sm-restart service haproxy"
    execute_command(cmd)

    LOG.info('Subcloud admin endpoint certificate updated successfully')


if __name__ == "__main__":
    sys.exit(main())
