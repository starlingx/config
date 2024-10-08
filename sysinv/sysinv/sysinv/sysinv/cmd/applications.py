#!/usr/bin/env python
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
System Inventory Application Verification & Validation Utility.
"""

import sys

from oslo_config import cfg
from oslo_log import log

from sysinv.common import app_metadata
from sysinv.common import service
from sysinv.common.app_metadata import verify_application
from sysinv.common.app_metadata import verify_application_tarball

CONF = cfg.CONF

LOG = log.getLogger(__name__)


def verify_application_tox(path):
    """Verify an application using tox.

    Args:
        path: This is the direct path to the metadata.yaml file
    """
    verify_application(path)


def verify_application_metadata(path):
    """Verify an application from tarball format.

    Args:
        path: This is a path to the app tarball.
    """
    verify_application_tarball(path)


def make_application_query(k8s_ver, include_path=False):
    """Query which applications are compatible.

    From the current K8S to the target K8S version
    specified, print out a list of compatible apps
    to terminal.

    Args:
        k8s_ver: String kubernetes version.
        include_path: (Optional) if True, then the output
        will use the full tgz path to specify compatible
        app instead of just the name.
    """

    try:
        compatible_apps = app_metadata.make_application_query(k8s_ver[0], include_path)
        for app in compatible_apps:
            print(app)
    except Exception as e:
        msg_error = f"Unable to obtain compatible app list. Reason: {e}"
        print(msg_error)
        LOG.error(msg_error)
        sys.exit(1)


def get_reorder_apps():
    """Reorders apps based on the metadata.yaml presenting the application tarball

    The purpose of this function is to print the updated apps
    order based on the metadata.yaml of the tarballs.
    """
    try:
        order_apps = app_metadata.get_reorder_apps()
        for app in order_apps:
            print(app)
    except Exception as e:
        msg_error = f"Unable to get order of apps. Reason: {e}"
        print(msg_error)
        LOG.error(msg_error)
        sys.exit(1)


def add_action_parsers(subparsers):
    parser = subparsers.add_parser('verify-metadata')
    parser.set_defaults(func=verify_application_metadata)
    parser.add_argument('path', nargs='?')

    parser = subparsers.add_parser('tox')
    parser.set_defaults(func=verify_application_tox)
    parser.add_argument('path', nargs='?')

    parser = subparsers.add_parser('query')
    parser.set_defaults(func=make_application_query)
    parser.add_argument('k8s_ver', nargs=1)
    parser.add_argument('--include-path', action='store_true', default=False)

    parser = subparsers.add_parser('get_reorder_apps')
    parser.set_defaults(func=get_reorder_apps)


CONF.register_cli_opt(
    cfg.SubCommandOpt('action',
                      title='actions',
                      help='Perform the application check operation',
                      handler=add_action_parsers))


def main():
    service.prepare_service(sys.argv)
    if CONF.action.name == "tox" or CONF.action.name == "verify-metadata":
        CONF.action.func(CONF.action.path)
    elif CONF.action.name == "query":
        include_path = True if '--include-path' in sys.argv else False
        CONF.action.func(CONF.action.k8s_ver, include_path=include_path)
    elif CONF.action.name == "get_reorder_apps":
        CONF.action.func()
    else:
        print(f"Unsupported action verb: {CONF.action.name}", file=sys.stderr)
