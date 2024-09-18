#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will migrate legacy oidc service parameters format
#  to the latest format.
# +---------------------+---------------------+
# |    Legacy Format    |    Latest Format    |
# +---------------------+---------------------+
# | oidc_client_id      | oidc-client-id      |
# | oidc_groups_claim   | oidc-groups-claim   |
# | oidc_issuer_url     | oidc-issuer-url     |
# | oidc_username_claim | oidc-username-claim |
# +---------------------+---------------------+
#

import argparse
import datetime
import logging as LOG
import psycopg2
import subprocess
import sys
import time

from sysinv.common.kubernetes import test_kubeapi_health

SUCCESS = 0
ERROR = 1
RELEASE_22_12 = "22.12"
RELEASE_24_09 = "24.09"
DEFAULT_POSTGRES_PORT = 5432


class PostgresAPI(object):

    def __init__(self) -> None:
        username, password = self.get_db_credentials()
        self.conn = psycopg2.connect("dbname=sysinv user=%s password=%s \
                                     host=localhost port=%s"
                                     % (username, password,
                                        DEFAULT_POSTGRES_PORT))

    def get_db_credentials(self):
        import re
        import configparser

        configparser = configparser.ConfigParser()
        configparser.read('/etc/sysinv/sysinv.conf')
        conn_string = configparser['database']['connection']
        match = re.match(r'postgresql\+psycopg2://([^:]+):([^@]+)@',
                         conn_string)
        if match:
            username = match.group(1)
            password = match.group(2)
            return username, password
        else:
            raise Exception("Failed to get database credentials, sysinv.conf")

    def db_update(self, query):
        with self.conn.cursor() as cur:
            cur.execute(query)
        self.conn.commit()
        return cur.rowcount != 0


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

    @test_kubeapi_health
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

    @test_kubeapi_health
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


class OidcServiceParametersMigrator(object):
    def __init__(self, action=None) -> None:
        self.action_handlers = {
            "activate": self.activate,
            "activate-rollback": self.activate_rollback
        }
        self.db = None
        if action in self.action_handlers:
            self.db = PostgresAPI()

    def renaming(self):
        """
        Update the OIDC service parameters names.
        """
        legacy_oidc_parameters = ['oidc_client_id',
                                  'oidc_groups_claim',
                                  'oidc_issuer_url',
                                  'oidc_username_claim']
        was_renamed = False
        for parameter in legacy_oidc_parameters:
            query = "update service_parameter set name='%s' where name='%s';"\
                % (parameter.replace('_', '-'), parameter)
            if self.db.db_update(query):
                was_renamed = True
        return was_renamed

    def execute_action(self, action: str) -> int:
        if action in self.action_handlers:
            return self.action_handlers[action]()
        # No action handler registered, nothing to do here
        return SUCCESS

    def activate(self) -> int:
        """
        Start migration process
        """
        if self.renaming():
            LOG.info("OIDC: Legacy service parameters has been renamed")
            ServiceParametersApplier().apply()
            return SUCCESS
        LOG.info("OIDC: No legacy parameters were renamed")
        return SUCCESS

    def activate_rollback(self) -> int:
        LOG.info("No Rollback needed, 22.12 also supports the latest format")
        return SUCCESS


def is_upgrading(args):
    return args.from_release == RELEASE_22_12 \
        and args.to_release == RELEASE_24_09


def is_rollingback(args):
    return args.from_release == RELEASE_24_09 \
        and args.to_release == RELEASE_22_12


def main():
    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=LOG.INFO, datefmt="%FT%T")

    parser = argparse.ArgumentParser()
    parser.add_argument("from_release", type=str)
    parser.add_argument("to_release", type=str)
    parser.add_argument("action", type=str)
    if len(sys.argv) == 5:
        parser.add_argument("postgres_port", type=int)
    args = parser.parse_args()

    oidc_sp_migrator = OidcServiceParametersMigrator(action=args.action)

    if is_upgrading(args) or is_rollingback(args):
        try:
            return oidc_sp_migrator.execute_action(action=args.action)
        except Exception as ex:
            LOG.exception(ex)
            return ERROR
    else:
        LOG.info("Nothing to do for releases from: %s and to: %s" %
                 (args.from_release, args.to_release))


if __name__ == "__main__":
    sys.exit(main())
