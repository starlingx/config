#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script deletes PodSecurityPolicy attribute
# of admission_plugins service parameter during the activate
# stage of platform upgrade if it is present.
#
# This script rely on 'security-kubeapi-service-parameters-apply.py'
# to apply the parameters to kubeapi, needing to be executed before it.
#

import subprocess
import logging as LOG
import sys


class PodSecurityPolicyRemover(object):
    """
    This class handles the deletion of the admission_plugin service parameter
    with value 'PodSecurityPolicy' and ensures Kubernetes is in a healthy state
    """
    def __init__(self) -> None:
        self.SERVICE_PARAM_DELETE_CMD = (
            "source /etc/platform/openrc && system service-parameter-list "
            "--service kubernetes --section kube_apiserver | "
            "grep 'PodSecurityPolicy' | awk -F '|' '{print $2}' | xargs"
        )

    def __system_cmd(self, command: str) -> str:
        sub = subprocess.Popen(["bash", "-c", command],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        stdout, stderr = sub.communicate()
        if sub.returncode != 0:
            return ''
        return stdout.decode('utf-8')

    def remove_pod_security_policy(self):
        LOG.info("Checking for admission_plugins service parameter with value "
                 "'PodSecurityPolicy'...")

        psp_uuid = self.__system_cmd(self.SERVICE_PARAM_DELETE_CMD).strip()

        if psp_uuid:
            LOG.info(f"Found admission_plugin service parameter with value "
                     f"'PodSecurityPolicy': {psp_uuid}")
            delete_cmd = (f"source /etc/platform/openrc && "
                          f"system service-parameter-delete {psp_uuid}")

            delete_output = self.__system_cmd(delete_cmd).strip()

            if delete_output:
                LOG.info(f"Deleted admission_plugin service parameter with "
                         f"UUID {psp_uuid}. Output: {delete_output}")
            else:
                LOG.warning(f"Failed to delete admission_plugin service "
                            f"parameter with UUID {psp_uuid}. "
                            f"Check the system command.")
        else:
            LOG.info("admission_plugin service parameter with value "
                     "'PodSecurityPolicy' not found or already removed.")


def main():
    log_format = ('%(asctime)s: [%(process)s]: %(filename)s(%(lineno)s): '
                  '%(levelname)s: %(message)s')
    LOG.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=LOG.INFO, datefmt="%FT%T")

    # Initialize variables
    action = None
    from_release = None
    to_release = None
    arg = 1

    # Process command-line arguments
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            # port = int(sys.argv[arg])
            pass
        else:
            print(f"Invalid option {sys.argv[arg]}.")
            sys.exit(1)
        arg += 1

    # Check if the necessary conditions are met
    if action != "activate" or from_release != "22.12":
        LOG.info("Skipping admission_plugin service parameter deletion.")
        sys.exit(0)
    else:
        LOG.info(
            "%s invoked from_release = %s invoked to_release = %s action = %s"
            % (sys.argv[0], from_release, to_release, action)
        )

    remover = PodSecurityPolicyRemover()
    remover.remove_pod_security_policy()


if __name__ == "__main__":
    main()
