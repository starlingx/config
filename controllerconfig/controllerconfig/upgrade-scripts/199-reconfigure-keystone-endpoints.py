#!/usr/bin/env python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script reconfigure the keystone endpoints using the sysinv
# version (not puppet).
# Needs to run at the end of the upgrade activation, to reduce the
# stabilization time after upgrade is concluded (less reconfigurations).

import logging as LOG
import socket
import sys
from time import sleep

from oslo_config import cfg
from oslo_context import context as mycontext
from six.moves import configparser
from sysinv.conductor import rpcapiproxy as conductor_rpcapi

CONF = cfg.CONF
SYSINV_CONFIG_FILE = '/etc/sysinv/sysinv.conf'


def get_conductor_rpc_bind_ip():
    ini_str = '[DEFAULT]\n' + open(SYSINV_CONFIG_FILE, 'r').read()
    config_applied = configparser.RawConfigParser()
    config_applied.read_string(ini_str)

    conductor_bind_ip = None
    if config_applied.has_option('DEFAULT', 'rpc_zeromq_conductor_bind_ip'):
        conductor_bind_ip = \
            config_applied.get('DEFAULT', 'rpc_zeromq_conductor_bind_ip')
    return conductor_bind_ip


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
            # optional port parameter for USM upgrade
            # port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=LOG.INFO, datefmt="%FT%T")

    # Activate
    if action == 'activate':
        LOG.info("%s invoked with from_release = %s to_release = %s "
                 "action = %s"
                 % (sys.argv[0], from_release, to_release, action))

        # Options of bind ip to the rpc call
        rpc_ip_options = [get_conductor_rpc_bind_ip(), 'controller.internal']
        while None in rpc_ip_options:
            rpc_ip_options.remove(None)

        for index, ip in enumerate(rpc_ip_options):
            try:
                CONF.rpc_zeromq_conductor_bind_ip = ip
                context = mycontext.get_admin_context()
                rpcapi = conductor_rpcapi.ConductorAPI(
                    topic=conductor_rpcapi.MANAGER_TOPIC)
                host = rpcapi.get_ihost_by_hostname(
                    context, socket.gethostname())

                LOG.info("Call Conductor to reconfigure keystone endpoints. "
                         "Bind ip: %s." % CONF.rpc_zeromq_conductor_bind_ip)
                rpcapi.reconfigure_service_endpoints(context, host)
            except Exception as e:
                if index == (len(rpc_ip_options) - 1):
                    LOG.error("Error configuring keystone endpoints. "
                              "Please verify logs.")
                    return 1
                else:
                    LOG.exception(e)
                    LOG.error("Exception ocurred during script execution, "
                              "retrying after 5 seconds.")
                    sleep(5)
            else:
                return 0


if __name__ == "__main__":
    sys.exit(main())
