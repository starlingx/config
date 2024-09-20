#!/usr/bin/env python
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
System Inventory Kubernetes Health Utility
"""

import sys

from oslo_config import cfg
from oslo_log import log

from sysinv.common import service
from sysinv.common.kubernetes import k8s_wait_for_endpoints_health

CONF = cfg.CONF
LOG = log.getLogger(__name__)
SUPPORTED_ACTIONS = ['check']


def add_action_parsers(subparsers):
    parser = subparsers.add_parser('check')
    parser.set_defaults(func=k8s_wait_for_endpoints_health)
    parser.add_argument('tries', type=int, nargs='?', default=20)
    parser.add_argument('try_sleep', type=int, nargs='?', default=5)
    parser.add_argument('timeout', type=int, nargs='?', default=5)


CONF.register_cli_opt(
    cfg.SubCommandOpt('action',
                      title='actions',
                      help='Check Kubernetes health',
                      handler=add_action_parsers))


def main():
    service.prepare_service(sys.argv)
    if CONF.action.name in SUPPORTED_ACTIONS:
        if CONF.action.func(CONF.action.tries, CONF.action.try_sleep, CONF.action.timeout):
            exit(0)
    else:
        print(f"Unsupported action: {CONF.action.name}. Supported actions: {SUPPORTED_ACTIONS}",
              file=sys.stderr)

    exit(1)
