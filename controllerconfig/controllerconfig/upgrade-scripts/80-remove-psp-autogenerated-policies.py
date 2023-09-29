#!/usr/bin/python
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script removes pod security policies and all Starlingx
# previously auto-generated ClusterRoleBindings,
# RoleBindings and ClusterRoles associated with PSP policies after
# the platform upgrade to a system. The script will run only when from
# release is 22.12 and during upgrade-activate.

import subprocess
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
        elif arg == 4:
            # postgres_port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1
    log.configure()

    # only run this script if from 22.12 release and during upgrade-activate
    if from_release == '22.12' and action == 'activate':
        LOG.info("%s invoked from_release = %s invoked to_release \
                 = %s action = %s"
                 % (sys.argv[0], from_release, to_release, action))
        # Call the function to delete PSP resources
        delete_psp_resources()


def delete_resources(resources):
    for resource in resources:
        try:
            subprocess.run(resource, check=True)
            LOG.info("Successfully deleted: {resource}")
        except subprocess.CalledProcessError as e:
            LOG.error("Error occurred while deleting: {resource}")
            LOG.exception("Error: %s" % e)


def delete_psp_resources():
    # Define the resources to delete
    cluster_role_bindings = [
        ["kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", "delete",
            "clusterrolebinding", "kube-system-SAs-restricted-psp-users"],
        ["kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", "delete",
            "clusterrolebinding", "authenticated-users-restricted-psp-users"]
    ]
    role_bindings = [
        ["kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", "delete",
            "rolebinding", "kube-system-privileged-psp-users", "-n",
            "kube-system"],
        ["kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", "delete",
            "rolebinding", "kubelet-kube-system-privileged-psp-user",
            "-n", "kube-system"]
    ]
    cluster_roles = [
        ["kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", "delete",
            "clusterrole", "restricted-psp-user"],
        ["kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", "delete",
            "clusterrole", "privileged-psp-user"]
    ]
    psp_resources = [
        ["kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", "delete",
            "podsecuritypolicy", "privileged"],
        ["kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", "delete",
            "podsecuritypolicy", "restricted"]
    ]

    # Delete cluster role bindings
    delete_resources(cluster_role_bindings)
    # Delete role bindings
    delete_resources(role_bindings)
    # Delete cluster roles
    delete_resources(cluster_roles)
    # Delete PSP resources
    delete_resources(psp_resources)


if __name__ == "__main__":
    sys.exit(main())
