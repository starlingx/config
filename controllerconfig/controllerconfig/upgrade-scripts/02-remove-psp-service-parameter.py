#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script deletes PodSecurityPolicy attribute
# of admission_plugins service parameter during the activate
# stage of platform upgrade if it is present.

import subprocess
import time
import datetime
import logging as LOG
import sys

from sysinv.common.kubernetes import test_k8s_health


class ServiceParametersApplier(object):
    """
    The main purpose of this class is to safely apply service parameters
    previously configured in the system.

    The command: "system service-parameters-apply kubernetes" will triggers
    many system events including the restarting of the kube-apiserver.

    Restarting the kube-apiserver is a critical process, many apps and
    services depends on it, so the script must do proper handling when applying
    service parameters to the system.
    """
    def __init__(self) -> None:
        self.KUBE_CMD = 'kubectl --kubeconfig=/etc/kubernetes/admin.conf '
        self.SP_APPLY_CMD = 'system service-parameter-apply kubernetes'
        self.sts = '{.status.conditions[?(@.type=="Ready")].status}'
        self.dt = '{.status.conditions[?(@.type=="Ready")].lastTransitionTime}'
        self.LAST_TRANSITION_TIME_CMD = "get pods -n kube-system " + \
            "kube-apiserver-{{controller}} -o jsonpath=\'" + \
            "%s %s\'" % (self.dt, self.sts)
        self.status_ctrl = dict({'controller-0': {}, 'controller-1': {}})

    def __system_cmd(self, command: str) -> str:
        sub = subprocess.Popen(["bash", "-c", command],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        stdout, stderr = sub.communicate()
        if sub.returncode != 0:
            return ''
        return stdout.decode('utf-8')

    @test_k8s_health
    def __get_available_controllers(self):
        controllers = ['controller-0', 'controller-1']
        command = self.KUBE_CMD + 'get node'
        result = self.__system_cmd(command=command)
        for controller in controllers:
            if controller not in result:
                controllers.remove(controller)
        return controllers

    def __service_parameter_apply(self) -> None:
        command = "source /etc/platform/openrc && %s" % self.SP_APPLY_CMD
        LOG.info('Applying service parameters...')
        self.__system_cmd(command)

    @test_k8s_health
    def __get_last_transition_time(self, controller):
        command = self.KUBE_CMD + self.LAST_TRANSITION_TIME_CMD.replace(
            "{{controller}}", controller)
        result = self.__system_cmd(command)
        if len(result.split(' ')) != 2 or result == ' ':
            return 0.0, False
        [timestamp, status] = result.split(' ')
        timestamp = timestamp.replace("Z", "+00:00")
        epoch_time = datetime.datetime.fromisoformat(timestamp).timestamp()
        return epoch_time, status == 'True'

    def __register_last_transition_time(self):
        for controller in self.__get_available_controllers():
            last_t_time, _ = self.__get_last_transition_time(controller)
            self.status_ctrl[controller]['last_t_time'] = last_t_time

    def __wait_kube_apiserver_ready(self):
        avail_controllers = self.__get_available_controllers()
        n_controllers = len(avail_controllers)
        n_apiserver_ready = 0
        for controller in avail_controllers:
            LOG.info("%s: Waiting kube-apiserver to restart" % controller)
            for _ in range(0, 240):
                time.sleep(1)
                t_time, status = self.__get_last_transition_time(controller)
                if self.status_ctrl[controller]['last_t_time'] != t_time \
                   and status:
                    LOG.info("%s: Kube-apiserver is ready!" % controller)
                    n_apiserver_ready += 1
                    break
        if n_controllers != n_apiserver_ready:
            LOG.error("Timeout restarting Kube-apiserver")
            return
        LOG.info("Service parameters applied")

    def apply(self):
        """
        Step-1: Register the lastTransitionTime

        Step-2: Send 'system service-parameters-apply kubernetes' command.

        Step-3: Waiting to kube-apiserver restart, check for each available
        controller if they match the expected ready condition, this will let us
        know when kube-apiserver has successfully restarted and ready to
        receive requests.
        """
        # Step-1:
        self.__register_last_transition_time()

        # Step-2:
        self.__service_parameter_apply()

        # Step-3:
        self.__wait_kube_apiserver_ready()


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
                ServiceParametersApplier().apply()
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
        LOG.info("%s invoked from_release = %s invoked to_release \
                 = %s action = %s"
                 % (sys.argv[0], from_release, to_release, action))

    remover = PodSecurityPolicyRemover()
    remover.remove_pod_security_policy()


if __name__ == "__main__":
    main()
