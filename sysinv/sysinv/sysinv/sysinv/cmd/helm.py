#!/usr/bin/env python
#
# Copyright (c) 2021-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
System Inventory Helm Utility.
"""

import sys
import urllib3

from oslo_config import cfg
from oslo_log import log

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import service
from sysinv.conductor import kube_app
from sysinv.db import api
from sysinv.helm import helm

CONF = cfg.CONF

LOG = log.getLogger(__name__)


def create_fluxcd_app_overrides_action(path, app_name=None, namespace=None):
    dbapi = api.get_instance()

    try:
        db_app = dbapi.kube_app_get(app_name)
    except exception.KubeAppNotFound:
        LOG.info("FluxCD Application %s not found" % app_name)
        return

    helm_operator = helm.HelmOperator(dbapi=dbapi)
    app_operator = kube_app.AppOperator(dbapi, helm_operator, {})

    if not app_operator.app_has_system_plugins(db_app):
        LOG.info("Overrides generation for application %s is "
                 "not supported via this command." % app_name)
    else:
        if db_app.status == constants.APP_UPLOAD_SUCCESS:
            app_operator.activate_app_plugins(db_app)
            helm_operator.generate_helm_application_overrides(
                path, app_name, mode=None, cnamespace=namespace,
                armada_format=False, chart_info=None, combined=False,
                is_fluxcd_app=True)
            app_operator.deactivate_app_plugins(db_app)
        else:
            helm_operator.generate_helm_application_overrides(
                path, app_name, mode=None, cnamespace=namespace,
                is_fluxcd_app=True)


def create_armada_app_overrides_action(path, app_name=None, namespace=None):
    dbapi = api.get_instance()

    try:
        db_app = dbapi.kube_app_get(app_name)
    except exception.KubeAppNotFound:
        LOG.info("Application %s not found" % app_name)
        return

    helm_operator = helm.HelmOperator(dbapi=dbapi)
    app_operator = kube_app.AppOperator(dbapi, helm_operator, {})

    if not app_operator.app_has_system_plugins(db_app):
        LOG.info("Overrides generation for application %s is "
                 "not supported via this command." % app_name)
    else:
        if db_app.status == constants.APP_UPLOAD_SUCCESS:
            app_operator.activate_app_plugins(db_app)
            helm_operator.generate_helm_application_overrides(
                path, app_name, mode=None, cnamespace=namespace,
                armada_format=False, chart_info=None, combined=False,
                is_fluxcd_app=False)
            app_operator.deactivate_app_plugins(db_app)
        else:
            helm_operator.generate_helm_application_overrides(
                path, app_name, mode=None, cnamespace=namespace,
                is_fluxcd_app=False)


def add_action_parsers(subparsers):
    parser = subparsers.add_parser('create-fluxcd-app-overrides')
    parser.set_defaults(func=create_fluxcd_app_overrides_action)
    parser.add_argument('path', nargs='?')
    parser.add_argument('app_name', nargs='?')
    parser.add_argument('namespace', nargs='?')

    parser = subparsers.add_parser('create-armada-app-overrides')
    parser.set_defaults(func=create_armada_app_overrides_action)
    parser.add_argument('path', nargs='?')
    parser.add_argument('app_name', nargs='?')
    parser.add_argument('namespace', nargs='?')


CONF.register_cli_opt(
    cfg.SubCommandOpt('action',
                      title='actions',
                      help='Perform helm override operation',
                      handler=add_action_parsers))


def main():
    urllib3.disable_warnings()

    service.prepare_service(sys.argv)
    if CONF.action.name == 'create-fluxcd-app-overrides':
        if not CONF.action.path:
            LOG.error("A path is required to save overrides")
        elif not CONF.action.app_name:
            LOG.error("FluxCD application name is required")
        else:
            CONF.action.func(CONF.action.path,
                             CONF.action.app_name,
                             CONF.action.namespace)
    elif CONF.action.name == 'create-armada-app-overrides':
        if not CONF.action.path:
            LOG.error("A path is required to save overrides")
        elif not CONF.action.app_name:
            LOG.error("Armada application name is required")
        else:
            CONF.action.func(CONF.action.path,
                             CONF.action.app_name,
                             CONF.action.namespace)
