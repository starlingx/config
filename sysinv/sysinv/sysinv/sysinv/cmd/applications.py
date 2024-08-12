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

from distutils.version import LooseVersion
from oslo_config import cfg
from oslo_log import log

from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import service
from sysinv.common.app_metadata import verify_application
from sysinv.common.app_metadata import verify_application_tarball
from sysinv.db import api

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
    # K8S Version
    target_version = k8s_ver[0]

    # Cleanup input:
    if 'v' in target_version:
        target_version = target_version.lstrip('v').strip()

    dbapi = api.get_instance()
    k8s_operator = kubernetes.KubeOperator()

    # Get current kubernetes version of the platform
    try:
        version = k8s_operator.kube_get_kubernetes_version()
        version = version.lstrip('v')  # Remove leading 'v'
    except Exception:
        # During initial installation of the first controller,
        # kubernetes may not be running yet. In that case, none of the
        # puppet manifests being applied will need the kubernetes
        # version.
        LOG.warning("Unable to retrieve kubernetes version")

    # All installed K8S Apps.
    try:
        db_apps = dbapi.kube_app_get_all()
    except exception.KubeAppNotFound:
        LOG.info("Unable to obtain K8s app list.")
        return

    # Check to see if the target version is valid first.
    supported_versions = \
        [x['version'].lstrip('v') for x in kubernetes.get_kube_versions()]

    if target_version not in supported_versions:
        print("Error: The supplied version is not supported. Exiting...", file=sys.stderr)
        sys.exit(1)

    # If target_version is less than current version, throw an error and exit.
    if LooseVersion(target_version) < LooseVersion(version):
        print(
            "Error: Target version cannot be lower than the current version."
            " Exiting...", file=sys.stderr
        )
        sys.exit(1)

    # Now check all apps to see which are compatible.
    compatible_apps = []
    for app in db_apps:
        app_name = app.name
        bundle = dbapi.kube_app_bundle_get_all(name=app_name)

        # The kube_app_bundle table maps the contents of the application folder. If no instances of
        # that application are returned, it will be ignored from the update. This usually happens
        # for third-party applications.
        if not bundle:
            LOG.warning("Skipping update for {} because it is not listed on database table "
                        "that maps the content of the applications folder.".format(app_name))
            continue

        if len(bundle) > 1:
            print(
                f"Error: App: {app_name} Should only have 1 bundle object! "
                "Exiting...", file=sys.stderr
            )
            sys.exit(1)

        bundle = bundle[0]
        update_compatible = dbapi.kube_app_bundle_is_k8s_compatible(
            app_name,
            bundle.k8s_timing,
            target_version,
            current_k8s_version=version
        )

        if update_compatible:
            if include_path:
                compatible_apps.append(bundle.file_path)
            else:
                compatible_apps.append(app_name)

    for app in compatible_apps:
        print(app)


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
    else:
        print(f"Unsupported action verb: {CONF.action.name}", file=sys.stderr)
