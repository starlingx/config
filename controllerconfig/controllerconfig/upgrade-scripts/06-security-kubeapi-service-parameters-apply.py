#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script perform the apply command for kubeapi service-parameters
# added/removed/modified in the scrips listed below (which need to be
# executed before this one), and monitors the kubeapi restart thru the
# pods.
# Scripts that should be executed before this one:
# - remove-psp-service-parameter.py
# - delete-encrypted-fs-service-parameter.sh
# - add-tls-version-cipher-parameters.sh
# - oidc-service-parameters-migration.py
#

import datetime
import logging as LOG
import subprocess
import sys
import time

from sysinv.common.kubernetes import test_k8s_health

SUCCESS = 0
ERROR = 1


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
        command = self.SP_APPLY_CMD
        LOG.info('Applying service parameters...')
        self.__system_cmd(command)

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
        ready_controllers = []
        n_controllers = len(avail_controllers)
        LOG.info("Waiting kube-apiserver to restart in the controllers")
        for _ in range(0, 300):
            time.sleep(2)
            for controller in avail_controllers:
                if controller in ready_controllers:
                    continue
                t_time, status = self.__get_last_transition_time(controller)
                if self.status_ctrl[controller]['last_t_time'] != t_time \
                   and status:
                    LOG.info("%s: Kube-apiserver is ready!" % controller)
                    ready_controllers.append(controller)
            if len(ready_controllers) == n_controllers:
                LOG.info("Service parameters applied")
                return
        # Didn't return inside the wait loop, we timed out
        raise Exception("Timeout restarting Kube-apiserver pods.")

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
            return ERROR
        arg += 1

    LOG.info(
        "%s invoked from_release = %s invoked to_release = %s action = %s"
        % (sys.argv[0], from_release, to_release, action)
    )

    # Check if the necessary conditions are met
    if action != "activate" or from_release != "22.12":
        LOG.info("Nothing to do, skipping K8s service parameter apply.")
        return SUCCESS

    try:
        ServiceParametersApplier().apply()
    except Exception as ex:
        LOG.exception(ex)
        return ERROR
    else:
        return SUCCESS


if __name__ == "__main__":
    sys.exit(main())
