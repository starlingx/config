#!/usr/bin/env python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import logging
from oslo_config import cfg
import os
from six.moves import configparser
import sys
import subprocess

from cgtsclient import client as cgts_client
from controllerconfig.common.usm_log import configure_logging

CONF = cfg.CONF

LOG = logging.getLogger('main_logger')


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

    configure_logging()
    LOG.info("%s invoked from_release = %s to_release = %s action = %s"
             % (sys.argv[0], from_release, to_release, action))
    res = 0
    if action == "activate":
        try:
            res = activate_keystone()
        except Exception:
            LOG.error("Activate keystone action failed")
            res = 1

    return res


def get_system_mode():
    ini_str = '[DEFAULT]\n' + open('/etc/platform/platform.conf', 'r').read()

    config_applied = configparser.RawConfigParser()
    config_applied.read_string(ini_str)

    if config_applied.has_option('DEFAULT', 'system_mode'):
        system_mode = config_applied.get('DEFAULT', 'system_mode')
    else:
        system_mode = None

    return system_mode


def get_shared_services():
    client = CgtsClient()
    isystem = client.sysinv.isystem.list()[0]
    shared_services = isystem.capabilities.get('shared_services', '')
    return shared_services


def activate_keystone():
    if get_system_mode() != "simplex":
        try:
            shared_services = get_shared_services()
        except Exception:
            LOG.exception("Failed to get shared services")
            return 1

        if 'identity' not in shared_services:
            keystone_cmd = ('keystone-manage db_sync --contract')
            try:
                subprocess.check_call([keystone_cmd], shell=True)
            except subprocess.CalledProcessError:
                msg = "Failed to contract Keystone databases for upgrade."
                LOG.exception(msg)
                return 1
            except Exception:
                LOG.exception("Failed to execute command %s" % keystone_cmd)
                return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
