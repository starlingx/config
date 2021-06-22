#!/usr/bin/python3
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script updates the dc root ca certificate to include more
# DN information and add separated admin endpoint certificate.
# This is in preparation for the future certificate renewal.
#
# This script can be removed in the release that follows 20.06.
#

import subprocess
import socket
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
            print ("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()
    LOG.debug("%s invoked with from_release = %s to_release = %s action = %s"
              % (sys.argv[0], from_release, to_release, action))

    if to_release == '20.06' and action == 'activate':
        if is_system_controller():
            update_dc_root_ca()


def is_system_controller():
    with open('/etc/platform/platform.conf', 'r') as f:
        lines = f.readlines()

    for line in lines:
        if line.strip() == 'distributed_cloud_role=systemcontroller':
            return True

    return False


dc_root_cert_yaml = """
---
apiVersion: cert-manager.io/v1alpha3
kind: Certificate
metadata:
  name: dc-adminep-root-ca-certificate
  namespace: dc-cert
spec:
  commonName: %s
  duration: 43800h
  isCA: true
  issuerRef:
    kind: Issuer
    name: dc-selfsigning-issuer
  renewBefore: 720h
  secretName: dc-adminep-root-ca-certificate
  subject:
    organizationalUnits:
    - 'StarlingX DC Root CA'
    organizations:
    - StarlingX

---
apiVersion: cert-manager.io/v1alpha3
kind: Certificate
metadata:
  name: dc-adminep-certificate
  namespace: dc-cert
spec:
  commonName: %s
  duration: 4320h
  isCA: false
  issuerRef:
    kind: Issuer
    name: dc-adminep-root-ca-issuer
  renewBefore: 30h
  secretName: dc-adminep-certificate
"""


def update_dc_root_ca():
    mgmt_ip = socket.getaddrinfo('controller', None)[0][4][0]
    resource = dc_root_cert_yaml % (mgmt_ip, mgmt_ip)
    cmd = "echo '%s' | " \
          "kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f -" % \
          resource
    sub = subprocess.Popen(cmd, shell=True,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           universal_newlines=True)

    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        LOG.error('Command failed:\n %s\n. %s\n%s' % (cmd, stdout, stderr))
        raise Exception('Cannot update certificates')

    LOG.info('DC certificates update successfully')


if __name__ == "__main__":
    sys.exit(main())
