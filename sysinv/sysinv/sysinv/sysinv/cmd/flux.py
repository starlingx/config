#!/usr/bin/env python
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
System Inventory Flux deployment tool.
"""

import sys

from oslo_config import cfg
from oslo_log import log

from sysinv.common import service
from sysinv.db import api
from sysinv.helm import flux

CONF = cfg.CONF
LOG = log.getLogger(__name__)


def upgrade_controllers():
    """ Upgrade Flux controllers

    Returns:
        bool: True if upgrade is sucessful. False otherwise.
    """

    dbapi = api.get_instance()
    flux_deployment = flux.FluxDeploymentManager(dbapi)
    return flux_deployment.upgrade_controllers()


def add_action_parsers(subparsers):
    """ Parse command-line actions """

    parser = subparsers.add_parser('upgrade-controllers')
    parser.set_defaults(func=upgrade_controllers)


CONF.register_cli_opt(
    cfg.SubCommandOpt('action',
                      title='actions',
                      help='Perform the application check operation',
                      handler=add_action_parsers))


def main():
    service.prepare_service(sys.argv)
    success = False
    if CONF.action.name == "upgrade-controllers":
        success = CONF.action.func()
    else:
        print(f"Unsupported action verb: {CONF.action.name}", file=sys.stderr)

    if success:
        exit(0)
    else:
        exit(1)
