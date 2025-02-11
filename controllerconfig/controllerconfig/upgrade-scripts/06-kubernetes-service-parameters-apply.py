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
# - delete-pod-eviction-timeout-service-parameter.py
# - k8s-disable-sched-controllermanager-leader-election.sh
# - remove-psp-service-parameter.py
# - delete-encrypted-fs-service-parameter.sh
# - add-tls-version-cipher-parameters.sh
# - oidc-service-parameters-migration.py
#

import datetime
import logging as LOG
import subprocess
import sys
import os
import tempfile
import time
import yaml

from sysinv.common.kubernetes import test_k8s_health

SUCCESS = 0
ERROR = 1
RETRIES = 3

CONFIG_DIR_PREFIX = '/opt/platform/config/'
PORTIERIS_BACKUP_FILENAME = 'portieris_backup.yml'
PORTIERIS_WEBHOOK_CRD = 'mutatingwebhookconfigurations image-admission-config'


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
    def __init__(self, from_side_release) -> None:
        self.KUBE_CMD = 'kubectl --kubeconfig=/etc/kubernetes/admin.conf '
        self.SP_APPLY_CMD = 'system service-parameter-apply kubernetes'
        self.sts = '{.status.conditions[?(@.type=="Ready")].status}'
        self.dt = '{.status.conditions[?(@.type=="Ready")].lastTransitionTime}'
        self.LAST_TRANSITION_TIME_CMD = "get pods -n kube-system " + \
            "kube-apiserver-{{controller}} -o jsonpath=\'" + \
            "%s %s\'" % (self.dt, self.sts)
        self.status_ctrl = dict({'controller-0': {}, 'controller-1': {}})
        # Backup in old config folder, it will be erased when upgrade ends
        self.PORTIERIS_BACKUP_FILE = CONFIG_DIR_PREFIX + from_side_release + \
            '/' + PORTIERIS_BACKUP_FILENAME

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
        if len(controllers) == 0:
            raise Exception("Couldn't retrieve nodes from kubernetes API.")
        else:
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
        if 'controller-0' in ready_controllers:
            LOG.warning("After timeout, kube-apiserver is ready in "
                        "controller-0, but not in the standby controller. "
                        "Moving forward.")
        else:
            LOG.error("Timeout restarting Kube-apiserver pods.")
            sys.exit(ERROR)

    def __get_portieris_webhook_data(self):
        get_cmd = self.KUBE_CMD + "get " + PORTIERIS_WEBHOOK_CRD + \
            " -o yaml --ignore-not-found"
        return self.__system_cmd(get_cmd)

    def __create_portieris_webhook_backup(self, yaml_data):
        if (os.path.isfile(self.PORTIERIS_BACKUP_FILE) and
                os.path.getsize(self.PORTIERIS_BACKUP_FILE) > 0):
            LOG.info("Backup for portieris webhook already present.")
            return

        with open(self.PORTIERIS_BACKUP_FILE, 'w') as backup_file:
            yaml.safe_dump(yaml_data, backup_file, default_flow_style=False)
        LOG.info("Backup created for portieris webhook.")

    def __modify_portieris_webhook(self, yaml_data):
        delete_cmd = self.KUBE_CMD + "delete " + PORTIERIS_WEBHOOK_CRD
        apply_cmd = self.KUBE_CMD + "apply -f "
        with tempfile.NamedTemporaryFile(delete=True) as tmp_file_obj:
            with open(tmp_file_obj.name, 'w') as tmp_file:
                yaml.safe_dump(yaml_data, tmp_file, default_flow_style=False)
                self.__system_cmd(delete_cmd)
                self.__system_cmd(apply_cmd + tmp_file_obj.name)

    def __disable_portieris_webhook(self):
        result = self.__get_portieris_webhook_data()
        if result != '':
            yaml_data = yaml.safe_load(result)
            self.__create_portieris_webhook_backup(yaml_data)
            yaml_data['webhooks'][0]['failurePolicy'] = 'Ignore'
            self.__modify_portieris_webhook(yaml_data)
        else:
            LOG.info("No webhook from portieris.")

    def __remove_portieris_webhook_backup(self):
        try:
            os.remove(self.PORTIERIS_BACKUP_FILE)
            LOG.info("Deleted portieris webhook backup file.")
        except OSError:
            pass

    def __restore_portieris_webhook(self):
        if (not os.path.isfile(self.PORTIERIS_BACKUP_FILE) or
                not os.path.getsize(self.PORTIERIS_BACKUP_FILE) > 0):
            LOG.info("No backup content for portieris webhook. Nothing to do.")
            self.__remove_portieris_webhook_backup()
            return

        result = self.__get_portieris_webhook_data()
        current_data = {}
        if result != '':
            current_data = yaml.safe_load(result)

        with open(self.PORTIERIS_BACKUP_FILE, 'r') as backup_file:
            backup_data = yaml.safe_load(backup_file)
            current_value = current_data.get(
                'webhooks', [{}])[0].get('failurePolicy', None)
            backup_value = backup_data['webhooks'][0]['failurePolicy']
            if current_value != backup_value:
                LOG.info("Using backup data to restore portieris webhook.")
                # Drop caBundle, cert-manager ca-injector will recreate it
                backup_data['webhooks'][0]['clientConfig'].pop('caBundle',
                                                               None)
                self.__modify_portieris_webhook(backup_data)

        self.__remove_portieris_webhook_backup()

    def apply(self):
        """
        Step-1: Register the lastTransitionTime

        Step-2: Send 'system service-parameters-apply kubernetes' command.

        Step-3: Waiting to kube-apiserver restart, check for each available
        controller if they match the expected ready condition, this will let us
        know when kube-apiserver has successfully restarted and ready to
        receive requests.
        """
        # Pre apply
        # Disable portieris webhook to avoid issues while restarting pods
        self.__disable_portieris_webhook()

        # Step-1:
        self.__register_last_transition_time()

        # Step-2:
        self.__service_parameter_apply()

        # Step-3:
        self.__wait_kube_apiserver_ready()

    def rollback(self):
        self.__restore_portieris_webhook()


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

    for retry in range(0, RETRIES):
        try:
            if action == "activate" and from_release == "22.12":
                ServiceParametersApplier(from_release).apply()
            elif action == "activate-rollback" and from_release == "24.09":
                ServiceParametersApplier(to_release).rollback()
            else:
                LOG.info("Nothing to do. "
                         "Skipping K8s service parameter apply.")
        except Exception as ex:
            if retry == RETRIES - 1:
                LOG.error("Error applying K8s service parameters. "
                          "Please verify logs.")
                return ERROR
            else:
                LOG.exception(ex)
                LOG.error("Exception ocurred during script execution, "
                          "retrying after 5 seconds.")
                time.sleep(5)
        else:
            return SUCCESS


if __name__ == "__main__":
    sys.exit(main())
