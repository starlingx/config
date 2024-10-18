#!/usr/bin/env python
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script create the motd message in all hosts
#

import argparse
import logging as LOG
import os
import sys
from sysinv.conductor import rpcapiproxy as conductor_rpcapi
from cgtsclient import client as cgts_client
from oslo_config import cfg
from oslo_context import context
from sysinv.common import constants

CONF = cfg.CONF


class CgtsClient(object):
    SYSINV_API_VERSION = "1"

    def __init__(self):
        self._sysinv_client = None

    @property
    def sysinv(self):
        if not self._sysinv_client:
            self._sysinv_client = cgts_client.get_client(
                self.SYSINV_API_VERSION,
                os_auth_token=os.environ.get("OS_AUTH_TOKEN"),
                system_url=os.environ.get("SYSTEM_URL"),
            )
        return self._sysinv_client


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("from_release", type=str)
    parser.add_argument("to_release", type=str)
    parser.add_argument("action", type=str)
    if len(sys.argv) == 5:
        parser.add_argument("postgres_port", type=int)
    args = parser.parse_args()

    if len(sys.argv) not in [4, 5]:
        print("Invalid option {}".format(sys.arg))
        return 1
    if args.action == "activate":
        log_format = ('%(asctime)s: ' + '[%(process)s]: '
                      '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
        LOG.basicConfig(filename="/var/log/software.log",
                        format=log_format, level=LOG.INFO, datefmt="%FT%T")
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
