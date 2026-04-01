#!/usr/bin/env python
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
System Inventory Plugin list tool.
"""

import sys

from oslo_config import cfg
from oslo_context import context
from oslo_log import log

from cgtsclient.common.utils import print_list
from sysinv.common import service
from sysinv.conductor import rpcapiproxy


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class ObjWrapper:  # noqa: H238
    def __init__(self, d):
        for k, v in d.items():
            setattr(self, k, v)


def list_plugins(plugin_name=None, project=None, namespace=None):
    conductor_api = rpcapiproxy.ConductorAPI()
    admin_context = context.get_admin_context()
    plugins = conductor_api.get_active_plugins(admin_context)
    fields = ["name", "project_name", "namespace", "project_path"]
    field_labels = ["Name", "Project", "Namespace", "Path"]
    plugins_objs = [
        ObjWrapper(plugin) for plugin in plugins
        if (plugin_name is None or plugin['name'] == plugin_name)
        and (project is None or plugin['project_name'] == project)
        and (namespace is None or plugin['namespace'] == namespace)
    ]
    print_list(plugins_objs, fields, field_labels)


def add_action_parsers(subparsers):
    """ Parse command-line actions """

    parser = subparsers.add_parser('list')
    parser.set_defaults(func=list_plugins)
    parser.add_argument('--name', dest='plugin_name', required=False)
    parser.add_argument('--project', dest='project', required=False)
    parser.add_argument('--namespace', dest='namespace', required=False)


CONF.register_cli_opt(
    cfg.SubCommandOpt('action',
                      title='actions',
                      help='Perform the application check operation',
                      handler=add_action_parsers))


def main():
    service.prepare_service(sys.argv)
    success = False
    if CONF.action.name == "list":
        success = CONF.action.func(
            plugin_name=CONF.action.plugin_name,
            project=CONF.action.project,
            namespace=CONF.action.namespace
        )
    else:
        print(f"Unsupported action verb: {CONF.action.name}", file=sys.stderr)

    if success:
        exit(0)
    else:
        exit(1)
