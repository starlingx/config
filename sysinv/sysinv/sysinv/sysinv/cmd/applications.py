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

from sysinv.common import service
from sysinv.common.app_metadata import verify_application
from sysinv.common.app_metadata import verify_application_tarball

CONF = cfg.CONF


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


def add_action_parsers(subparsers):
    parser = subparsers.add_parser('verify-metadata')
    parser.set_defaults(func=verify_application_metadata)
    parser.add_argument('path', nargs='?')

    parser = subparsers.add_parser('tox')
    parser.set_defaults(func=verify_application_tox)
    parser.add_argument('path', nargs='?')


CONF.register_cli_opt(
    cfg.SubCommandOpt('action',
                      title='actions',
                      help='Perform the application check operation',
                      handler=add_action_parsers))


def main():
    service.prepare_service(sys.argv)
    CONF.action.func(CONF.action.path)
