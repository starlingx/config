#!/usr/bin/env python
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
System Inventory Application Verification & Validation Utility.
"""

import io
import os
import re
import ruamel.yaml as yaml
import sys

from distutils.version import LooseVersion
from oslo_config import cfg
from oslo_log import log

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import service
from sysinv.common.app_metadata import verify_application
from sysinv.common.app_metadata import verify_application_tarball
from sysinv.common import utils as cutils
from sysinv.db import api

CONF = cfg.CONF

LOG = log.getLogger(__name__)


# TODO(dbarbosa): Remove the get_kube_api function and return imports to the top of the file
# after the issue with fm_core import was resolved in the Fault repository
def get_kube_api():
    """Import kube_app from sysinv.api.controllers.v1 only when needed

    It is necessary to import kube_app separately only when needed due to the fm_core package
    (which is imported inside kube_app by fault repository) failing if imported when the
    "sysinv tox" or "sysinv verify-metadata" command is run.
    """
    from sysinv.api.controllers.v1 import kube_app
    return kube_app


# TODO(dbarbosa): Remove the get_kube_app function and return imports to the top of the file
# after the issue with fm_core import was resolved in the Fault repository
def get_kube_app():
    """Import kube_app from sysinv.conductor only when needed

    It is necessary to import kube_app separately only when needed due to the fm_core package
    (which is imported inside kube_app by fault repository) failing if imported when the
    "sysinv tox" or "sysinv verify-metadata" command is run.
    """
    from sysinv.conductor import kube_app
    return kube_app


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


def load_metadata_of_apps(apps_metadata):
    """ Extracts the tarball and loads the metadata of the
    loaded/applied applications.

    :param apps_metadata: metadata dictionary of the applications
    """

    dbapi = api.get_instance()
    kube_api = get_kube_api()
    kube_app = get_kube_app()
    kube_app_helper = kube_api.KubeAppHelper(dbapi)

    # All installed K8S Apps.
    try:
        db_apps = dbapi.kube_app_get_all()
    except exception.KubeAppNotFound:
        LOG.error("Unable to obtain K8s app list.")
        return

    loaded_apps = []
    for app in db_apps:
        loaded_apps.append(app.name)

    for app_bundle in os.listdir(constants.HELM_APP_ISO_INSTALL_PATH):
        # Get the app name from the tarball name
        app_name = None
        pattern = re.compile("^(.*)-([0-9]+\.[0-9]+-[0-9]+)")

        match = pattern.search(app_bundle)
        if match:
            app_name = match.group(1)

        # Extract the tarball for only the loaded applications
        if app_name in loaded_apps:
            # Proceed with extracting the tarball
            tarball_name = '{}/{}'.format(
                constants.HELM_APP_ISO_INSTALL_PATH, app_bundle)

            with cutils.TempDirectory() as app_path:
                if not cutils.extract_tarfile(app_path, tarball_name):
                    LOG.error("Failed to extract tar file {}.".format(
                        os.path.basename(tarball_name)))
                    continue

                # If checksum file is included in the tarball, verify its contents.
                if not cutils.verify_checksum(app_path):
                    LOG.error("Checksum validation failed for %s." % tarball_name)
                    continue

                try:
                    name, version, patches = \
                        kube_app_helper._verify_metadata_file(
                            app_path, None, None)
                except exception.SysinvException as e:
                    LOG.error("Extracting tarfile for %s failed: %s." % (
                        tarball_name, str(e)))
                    continue

                metadata_file = os.path.join(app_path, constants.APP_METADATA_FILE)

                if os.path.exists(metadata_file):
                    with io.open(metadata_file, 'r', encoding='utf-8') as f:
                        # The RoundTripLoader removes the superfluous quotes by default.
                        # Set preserve_quotes=True to preserve all the quotes.
                        # The assumption here: there is just one yaml section
                        metadata = yaml.load(
                            f, Loader=yaml.RoundTripLoader, preserve_quotes=True)

                if name and metadata:
                    # Update metadata only if it was not loaded during conductor init
                    # The reason is that we don't want to lose the modified version
                    # by loading the default metadata from the bundled app.
                    kube_app.AppOperator.update_and_process_app_metadata(
                        apps_metadata, name, metadata)


def get_reorder_apps():
    """Reorders apps based on the metada.yaml presenting the application tarball

    The purpose of this function is to print the updated apps
    order based on the metadata.yaml of the tarballs.
    """

    apps_metadata = {constants.APP_METADATA_APPS: {},
                     constants.APP_METADATA_PLATFORM_MANAGED_APPS: {},
                     constants.APP_METADATA_DESIRED_STATES: {},
                     constants.APP_METADATA_ORDERED_APPS: []}

    load_metadata_of_apps(apps_metadata)

    for app in apps_metadata[constants.APP_METADATA_ORDERED_APPS]:
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
