#!/usr/bin/env python
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
System Inventory Helm Utility.
"""

import sys

from oslo_config import cfg

from sysinv.common import service
from sysinv.db import api
from sysinv.helm import helm

CONF = cfg.CONF


def create_app_overrides_action(path, app_name=None, repository=None, namespace=None):
    dbapi = api.get_instance()
    operator = helm.HelmOperator(dbapi=dbapi, path=path, docker_repository=repository)
    operator.generate_helm_application_overrides(app_name, namespace)


def create_armada_app_overrides_action(path, app_name=None, repository=None, namespace=None):
    dbapi = api.get_instance()
    operator = helm.HelmOperator(dbapi=dbapi, path=path, docker_repository=repository)
    operator.generate_helm_application_overrides(app_name, namespace,
                                                 armada_format=True)


def create_chart_override_action(path, chart_name=None, repository=None, namespace=None):
    dbapi = api.get_instance()
    operator = helm.HelmOperator(dbapi=dbapi, path=path, docker_repository=repository)
    operator.generate_helm_chart_overrides(chart_name, namespace)


def add_action_parsers(subparsers):
    parser = subparsers.add_parser('create-app-overrides')
    parser.set_defaults(func=create_app_overrides_action)
    parser.add_argument('path', nargs='?')
    parser.add_argument('app_name', nargs='?')
    parser.add_argument('repository', nargs='?')
    parser.add_argument('namespace', nargs='?')

    parser = subparsers.add_parser('create-armada-app-overrides')
    parser.set_defaults(func=create_armada_app_overrides_action)
    parser.add_argument('path', nargs='?')
    parser.add_argument('app_name', nargs='?')
    parser.add_argument('repository', nargs='?')
    parser.add_argument('namespace', nargs='?')

    parser = subparsers.add_parser('create-chart-overrides')
    parser.set_defaults(func=create_chart_override_action)
    parser.add_argument('path', nargs='?')
    parser.add_argument('chart_name', nargs='?')
    parser.add_argument('repository', nargs='?')
    parser.add_argument('namespace', nargs='?')


CONF.register_cli_opt(
    cfg.SubCommandOpt('action',
                      title='actions',
                      help='Perform helm override operation',
                      handler=add_action_parsers))


def main():
    service.prepare_service(sys.argv)
    if CONF.action.name == 'create-app-overrides':

        CONF.action.func(CONF.action.path,
                         CONF.action.app_name,
                         CONF.action.repository,
                         CONF.action.namespace)
    elif CONF.action.name == 'create-armada-app-overrides':
        CONF.action.func(CONF.action.path,
                         CONF.action.app_name,
                         CONF.action.repository,
                         CONF.action.namespace)
    elif CONF.action.name == 'create-chart-overrides':
        try:
            CONF.action.func(CONF.action.path,
                             CONF.action.chart_name,
                             CONF.action.repository,
                             CONF.action.namespace)
        except Exception as e:
            print(e)
