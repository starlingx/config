#!/usr/bin/python3
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script updates the subcloud admin endpoint certificate
# to include mgmt floating IP as subjectAltName.
#
# This script can be removed in the release that follows stx.5.0
#

from shutil import copyfile
import socket
import subprocess
import sys

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
        raise Exception('Failed to update certificate')
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

    # Extract subcloud admin endpoint certificate
    cmd = "kubectl --kubeconfig=/etc/kubernetes/admin.conf get secret \
           sc-adminep-certificate -n sc-cert -o=jsonpath='{.data.tls\.crt}' \
           | base64 --decode"
    cert = execute_command(cmd)

    # Extract subcloud admin endpoint private key
    cmd = "kubectl --kubeconfig=/etc/kubernetes/admin.conf get secret \
           sc-adminep-certificate -n sc-cert -o=jsonpath='{.data.tls\.key}' \
           | base64 --decode"
    key = execute_command(cmd)

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
