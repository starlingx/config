#!/usr/bin/env python
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script create the motd message in all hosts
#

import argparse
import os
import subprocess
import sys
from controllerconfig.common import log
from sysinv.conductor import rpcapiproxy as conductor_rpcapi
from cgtsclient import client as cgts_client
from oslo_config import cfg
from oslo_context import context
from sysinv.common import constants

CONF = cfg.CONF
LOG = log.get_logger(__name__)


class CgtsClient(object):
    SYSINV_API_VERSION = 1

    def __init__(self):
        self.conf = {}
        self._sysinv = None
        source_command = "source /etc/platform/openrc && env"
        with open(os.devnull, "w") as fnull:
            proc = subprocess.Popen(
                ["bash", "-c", source_command],
                stdout=subprocess.PIPE,
                stderr=fnull,
                universal_newlines=True,
            )
        for line in proc.stdout:
            key, _, value = line.partition("=")
            if key == "OS_USERNAME":
                self.conf["admin_user"] = value.strip()
            elif key == "OS_PASSWORD":
                self.conf["admin_pwd"] = value.strip()
            elif key == "OS_PROJECT_NAME":
                self.conf["admin_tenant"] = value.strip()
            elif key == "OS_AUTH_URL":
                self.conf["auth_url"] = value.strip()
            elif key == "OS_REGION_NAME":
                self.conf["region_name"] = value.strip()
            elif key == "OS_USER_DOMAIN_NAME":
                self.conf["user_domain"] = value.strip()
            elif key == "OS_PROJECT_DOMAIN_NAME":
                self.conf["project_domain"] = value.strip()
        proc.communicate()

    @property
    def sysinv(self):
        if not self._sysinv:
            self._sysinv = cgts_client.get_client(
                self.SYSINV_API_VERSION,
                os_username=self.conf["admin_user"],
                os_password=self.conf["admin_pwd"],
                os_auth_url=self.conf["auth_url"],
                os_project_name=self.conf["admin_tenant"],
                os_project_domain_name=self.conf["project_domain"],
                os_user_domain_name=self.conf["user_domain"],
                os_region_name=self.conf["region_name"],
                os_service_type="platform",
                os_endpoint_type="admin",
            )
        return self._sysinv


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("from_release", type=str)
    parser.add_argument("to_release", type=str)
    parser.add_argument("action", type=str)
    args = parser.parse_args()

    if len(sys.argv) != 4:
        print("Invalid option {}".format(sys.arg))
        return 1
    if args.action == "activate":
        log.configure()
        LOG.info(
            "{} invoked with from_release = {} "
            "to_release = {} "
            "action = {}".format(
                sys.argv[0], args.from_release, args.to_release, args.action
            )
        )
        try:
            client = CgtsClient()
            system_data = client.sysinv.isystem.list()[0]

            # Without this configuration, the system tries
            # to connect to ZeroMQ using the localhost address
            # and doesn't accept connections. By changing the bind_ip
            # to the controller hostname, the connection works.
            CONF.rpc_zeromq_conductor_bind_ip = constants.CONTROLLER_HOSTNAME

            conductor = conductor_rpcapi.ConductorAPI()
            conductor.configure_isystemname(
                context.get_admin_context(), system_data.name
            )
        except Exception as e:
            # This prevents breaking the upgrade in case of failure
            # since the update motd had no impact in system functionality
            LOG.error("Error on update sysinv motd - {}".format(e))
        return 0
    else:
        LOG.info("Nothing to do on {}".format(args.action))


if __name__ == "__main__":
    sys.exit(main())
