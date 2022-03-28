#!/usr/bin/python
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script adds pod security admission controller labels to a system
# after upgrades. These are applied by ansible and sysinv when a new
# namespace is created during application deployment. Upgrades needs
# to apply these labels to existing namespaces

import subprocess
import sys
from controllerconfig.common import log
from sysinv.helm import common
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
    if from_release == '21.12' and action == 'activate':
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (sys.argv[0], from_release, to_release, action))
        add_pod_security_admission_controller_labels()


def add_pod_security_admission_controller_labels():
    try:
        cmd = ["kubectl", "--kubeconfig=/etc/kubernetes/admin.conf",
               "get", "namespaces", "-o=name"]

        namespaces_output = subprocess.check_output(cmd)

    except Exception as exc:
        LOG.error('Command failed:\n %s' % (cmd))
        raise Exception('Cannot get namespaces for pod security labels')

    for line in namespaces_output.splitlines():
        # we add pod security admission controller labels to namespaces that
        # we create
        namespace = line.replace("namespace/", "")
        if namespace not in common.PRIVILEGED_NS \
           and namespace not in common.BASELINE_NS:
            continue

        security_version = 'v1.23'
        security_level = 'baseline'
        if namespace in common.PRIVILEGED_NS:
            security_level = 'privileged'

        try:
            cmd = ["kubectl", "--kubeconfig=/etc/kubernetes/admin.conf",
                   "label", "--overwrite", "namespaces", namespace,
                   "pod-security.kubernetes.io/enforce=%s"
                   % (security_level),
                   "pod-security.kubernetes.io/warn=%s"
                   % (security_level),
                   "pod-security.kubernetes.io/audit=%s"
                   % (security_level),
                   "pod-security.kubernetes.io/enforce-version=%s"
                   % (security_version),
                   "pod-security.kubernetes.io/warn-version=%s"
                   % (security_version),
                   "pod-security.kubernetes.io/audit-version=%s"
                   % (security_version)]
            subprocess.call(cmd)
        except Exception as exc:
            LOG.error('Command failed:\n %s\n%s' % (cmd, exc))
            raise Exception('Cannot assign pod security label')


if __name__ == "__main__":
    sys.exit(main())
