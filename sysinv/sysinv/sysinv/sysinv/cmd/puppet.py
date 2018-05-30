#!/usr/bin/env python
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


"""
System Inventory Puppet Utility.
"""

import sys

from oslo_config import cfg

from sysinv.common import service
from sysinv.db import api
from sysinv.puppet import puppet

CONF = cfg.CONF


def create_static_config_action(path):
    operator = puppet.PuppetOperator(path=path)
    operator.create_static_config()
    operator.create_secure_config()


def create_system_config_action(path):
    dbapi = api.get_instance()
    operator = puppet.PuppetOperator(dbapi=dbapi, path=path)
    operator.update_system_config()
    operator.update_secure_system_config()


def create_host_config_action(path, hostname=None):
    dbapi = api.get_instance()
    operator = puppet.PuppetOperator(dbapi=dbapi, path=path)

    if hostname:
        host = dbapi.ihost_get_by_hostname(hostname)
        operator.update_host_config(host)
    else:
        hosts = dbapi.ihost_get_list()
        for host in hosts:
            operator.update_host_config(host)


def add_action_parsers(subparsers):
    parser = subparsers.add_parser('create-static-config')
    parser.set_defaults(func=create_static_config_action)
    parser.add_argument('path', nargs='?')

    parser = subparsers.add_parser('create-system-config')
    parser.set_defaults(func=create_system_config_action)
    parser.add_argument('path', nargs='?')

    parser = subparsers.add_parser('create-host-config')
    parser.set_defaults(func=create_host_config_action)
    parser.add_argument('path', nargs='?')
    parser.add_argument('hostname', nargs='?')


CONF.register_cli_opt(
    cfg.SubCommandOpt('action',
                      title='actions',
                      help='Perform the puppet operation',
                      handler=add_action_parsers))


def main():
    service.prepare_service(sys.argv)
    if CONF.action.name == 'create-host-config':
        CONF.action.func(CONF.action.path, CONF.action.hostname)
    else:
        CONF.action.func(CONF.action.path)
