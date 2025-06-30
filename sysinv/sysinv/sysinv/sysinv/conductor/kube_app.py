# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System Inventory Kubernetes Application Operator."""

import copy

import docker
from eventlet.green import subprocess
import glob
import grp
import functools
import json
import io
import os
import pkg_resources
import pwd
import random
import re
import ruamel.yaml as yaml
import shutil
import site
import six
from six.moves.urllib.parse import urlparse
import sys
import tempfile
import threading
import time
import zipfile

from collections import namedtuple
from distutils.util import strtobool
from distutils.version import LooseVersion
from eventlet import greenpool
from eventlet import queue
from eventlet import Timeout
from fm_api import constants as fm_constants
from fm_api import fm_api
from oslo_log import log as logging
from oslo_config import cfg
from oslo_serialization import base64
from sysinv._i18n import _
from sysinv.api.controllers.v1 import kube_app
from sysinv.common import app_metadata
from sysinv.common import constants
from sysinv.common import app_dependents
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common.retrying import retry
from sysinv.common import utils as cutils
from sysinv.conductor import openstack
from sysinv.helm import base as helm_base
from sysinv.helm import common
from sysinv.helm import utils as helm_utils
from sysinv.helm.lifecycle_constants import LifecycleConstants
from sysinv.helm.lifecycle_hook import LifecycleHookInfo

CONF = cfg.CONF


# Log and config
LOG = logging.getLogger(__name__)

# Constants
APPLY_SEARCH_PATTERN = 'Processing Chart,'
CONTAINER_ABNORMAL_EXIT_CODE = 137
DELETE_SEARCH_PATTERN = 'Deleting release|no release to delete'
ROLLBACK_SEARCH_PATTERN = 'Helm rollback of release'
MAX_DOWNLOAD_THREAD = 5
MAX_DOWNLOAD_ATTEMPTS = 3
DOWNLOAD_WAIT_BEFORE_RETRY = 15
TARFILE_DOWNLOAD_CONNECTION_TIMEOUT = 60
TARFILE_TRANSFER_CHUNK_SIZE = 1024 * 512

LOCK_NAME_APP_REAPPLY = 'app_reapply'
LOCK_NAME_PROCESS_APP_METADATA = 'process_app_metadata'

CHART_UPLOAD_COPY_ERROR_CODE = 1
CHART_UPLOAD_FILE_EXISTS_ERROR_CODE = 2
CHART_UPLOAD_VERSION_EXISTS_ERROR_CODE = 3


# Helper functions
def generate_install_manifest_fqpn(app_name, app_version, manifest_filename):
    return os.path.join(constants.APP_INSTALL_PATH,
                        app_name, app_version, manifest_filename)


def generate_synced_helm_overrides_dir(app_name, app_version):
    return os.path.join(common.HELM_OVERRIDES_PATH, app_name, app_version)


def generate_synced_app_plugins_dir(app_name, app_version):
    return os.path.join(
        generate_synced_helm_overrides_dir(app_name, app_version),
        'plugins')


def generate_synced_fluxcd_images_fqpn(app_name, app_version):
    return os.path.join(
        constants.APP_FLUXCD_DATA_PATH, app_name, app_version,
        app_name + '-images.yaml')


def create_app_path(path):
    uid = pwd.getpwnam(constants.SYSINV_USERNAME).pw_uid
    gid = os.getgid()

    if not os.path.exists(constants.APP_INSTALL_PATH):
        os.makedirs(constants.APP_INSTALL_PATH)
        os.chown(constants.APP_INSTALL_PATH, uid, gid)

    os.makedirs(path)
    os.chown(path, uid, gid)


def get_app_install_root_path_ownership():
    uid = os.stat(constants.APP_INSTALL_ROOT_PATH).st_uid
    gid = os.stat(constants.APP_INSTALL_ROOT_PATH).st_gid
    return (uid, gid)


FluxCDChart = namedtuple('FluxCDChart', 'metadata_name name namespace location '
                                        'release chart_os_path chart_label '
                                        'helm_repo_name filesystem_location '
                                        'chart_version')


class AppOperator(object):
    """Class to encapsulate Kubernetes App operations for System Inventory"""
    DOCKER_REGISTRY_SECRET = 'default-registry-key'

    # List of in progress apps and their abort status
    abort_requested = {}

    def __init__(self, dbapi, helm_op, apps_metadata):
        self._dbapi = dbapi
        self._helm = helm_op
        self._apps_metadata = apps_metadata
        self._plugins = PluginHelper(self._dbapi, self._helm)
        self._fm_api = fm_api.FaultAPIs()
        self._docker = DockerHelper(self._dbapi)
        self._kube = kubernetes.KubeOperator()
        self._utils = kube_app.KubeAppHelper(self._dbapi)
        self._image = AppImageParser()
        self._lock = threading.Lock()
        self._fluxcd = FluxCDHelper(self._dbapi, self._kube)

        # Load apps metadata
        # Clearing stuck application behavior depends on the metadata
        for app in self._dbapi.kube_app_get_all():
            self.load_application_metadata_from_database(app)

        if not os.path.isfile(constants.ANSIBLE_BOOTSTRAP_FLAG):
            self._clear_stuck_applications()

        self._plugins.activate_apps_plugins()

    def activate_app_plugins(self, rpc_app):
        app = AppOperator.Application(rpc_app)
        self._plugins.activate_plugins(app)

    def deactivate_app_plugins(self, rpc_app):
        app = AppOperator.Application(rpc_app)
        self._plugins.deactivate_plugins(app)

    def app_has_system_plugins(self, rpc_app):
        app = AppOperator.Application(rpc_app)
        return app.system_app

    def _clear_stuck_applications(self):
        db_apps = self._dbapi.kube_app_get_all()
        for db_app in db_apps:
            if db_app.status in [constants.APP_UPLOAD_IN_PROGRESS,
                              constants.APP_APPLY_IN_PROGRESS,
                              constants.APP_UPDATE_IN_PROGRESS,
                              constants.APP_RECOVER_IN_PROGRESS,
                              constants.APP_REMOVE_IN_PROGRESS]:
                app = AppOperator.Application(db_app)
                self._abort_operation(app, app.status, reset_status=True)
            else:
                continue

    def _raise_app_alarm(self, app_name, app_action, alarm_id, severity,
                         reason_text, alarm_type, repair_action,
                         service_affecting):

        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_APPLICATION,
                                        app_name)
        app_alarms = self._fm_api.get_faults(entity_instance_id)
        if app_alarms:
            if ((app_action == constants.APP_APPLY_FAILURE and
                 app_alarms[0].alarm_id ==
                     fm_constants.FM_ALARM_ID_APPLICATION_APPLY_FAILED) or
                (app_action == constants.APP_UPLOAD_FAILURE and
                 app_alarms[0].alarm_id ==
                     fm_constants.FM_ALARM_ID_APPLICATION_UPLOAD_FAILED) or
                (app_action == constants.APP_REMOVE_FAILURE and
                 app_alarms[0].alarm_id ==
                     fm_constants.FM_ALARM_ID_APPLICATION_REMOVE_FAILED) or
                (app_action == constants.APP_APPLY_IN_PROGRESS and
                 app_alarms[0].alarm_id ==
                     fm_constants.FM_ALARM_ID_APPLICATION_APPLYING) or
                (app_action == constants.APP_UPDATE_IN_PROGRESS and
                 app_alarms[0].alarm_id ==
                     fm_constants.FM_ALARM_ID_APPLICATION_UPDATING)):
                # The same alarm was raised before, will re-raise to set the
                # latest timestamp.
                pass
            else:
                # Clear existing alarm for this app if it differs than the one to
                # be raised.
                self._fm_api.clear_fault(app_alarms[0].alarm_id,
                                         app_alarms[0].entity_instance_id)
        fault = fm_api.Fault(
                alarm_id=alarm_id,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_APPLICATION,
                entity_instance_id=entity_instance_id,
                severity=severity,
                reason_text=reason_text,
                alarm_type=alarm_type,
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_UNKNOWN,
                proposed_repair_action=repair_action,
                service_affecting=service_affecting)

        self._fm_api.set_fault(fault)

    def _clear_app_alarm(self, app_name):
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_APPLICATION,
                                        app_name)
        app_alarms = self._fm_api.get_faults(entity_instance_id)
        if app_alarms:
            # There can only exist one alarm per app
            self._fm_api.clear_fault(app_alarms[0].alarm_id,
                                     app_alarms[0].entity_instance_id)

    def _register_app_abort(self, app_name):
        with self._lock:
            AppOperator.abort_requested[app_name] = False
        LOG.info("Register the initial abort status of app %s" % app_name)

    def _deregister_app_abort(self, app_name):
        with self._lock:
            try:
                del AppOperator.abort_requested[app_name]
            except KeyError:
                pass
        LOG.info("Deregister the abort status of app %s" % app_name)

    @staticmethod
    def is_app_aborted(app_name):
        try:
            return AppOperator.abort_requested[app_name]
        except KeyError:
            return False

    def _set_abort_flag(self, app_name):
        with self._lock:
            AppOperator.abort_requested[app_name] = True
        LOG.info("Abort set for app %s" % app_name)

    def _cleanup(self, app, app_dir=True):
        """" Remove application directories and override files """
        self._plugins.uninstall_plugins(app)
        try:
            if os.path.exists(app.sync_overrides_dir):
                shutil.rmtree(app.sync_overrides_dir)
                if app_dir:
                    shutil.rmtree(os.path.dirname(
                        app.sync_overrides_dir))

            if os.path.exists(app.inst_path):
                shutil.rmtree(app.inst_path)
                if app_dir:
                    shutil.rmtree(os.path.dirname(
                        app.inst_path))

            if os.path.exists(app.sync_fluxcd_manifest_dir):
                shutil.rmtree(app.sync_fluxcd_manifest_dir)
                if app_dir:
                    shutil.rmtree(os.path.dirname(
                        app.sync_fluxcd_manifest_dir))

        except OSError as e:
            LOG.error(e)
            raise

    def _update_app_status(self, app, new_status=None, new_progress=None):
        """ Persist new app status """

        if new_status is None:
            new_status = app.status

        # New progress info can contain large messages from exceptions raised.
        # It may need to be truncated to fit the corresponding database field.
        if new_progress is not None:
            new_progress = cutils.truncate_message(new_progress)

        with self._lock:
            app.update_status(new_status, new_progress)

    def _abort_operation(self, app, operation,
                         progress=constants.APP_PROGRESS_ABORTED,
                         user_initiated=False, reset_status=False,
                         forced_operation=False):
        """Abort application operations

        This function is responsible for canceling operations
        like upload, apply, remove

        :param app: Instance of the AppOperation.Application
        :operation: String with application status
        """

        # Adds the app object error message if it exists
        if (app.error_message):
            progress = "{}: {}".format(app.error_message, progress)
            app.clear_error_message()

        if user_initiated:
            progress = constants.APP_PROGRESS_ABORTED_BY_USER

        if app.status == constants.APP_UPLOAD_IN_PROGRESS:
            new_status = constants.APP_UPLOAD_FAILURE
            op = 'application-upload'
            self._raise_app_alarm(
                app.name, constants.APP_UPLOAD_FAILURE,
                fm_constants.FM_ALARM_ID_APPLICATION_UPLOAD_FAILED,
                fm_constants.FM_ALARM_SEVERITY_WARNING,
                _("Application Upload Failure"),
                fm_constants.FM_ALARM_TYPE_3,
                _("Check system inventory log for cause."),
                False)
        elif (app.status == constants.APP_APPLY_IN_PROGRESS or
              app.status == constants.APP_UPDATE_IN_PROGRESS or
              app.status == constants.APP_RECOVER_IN_PROGRESS):
            new_status = constants.APP_APPLY_FAILURE
            if reset_status:
                if app.status == constants.APP_APPLY_IN_PROGRESS:
                    op = 'application-apply'
                else:
                    op = 'application-update'

                if app.name in self._apps_metadata[
                        constants.APP_METADATA_PLATFORM_MANAGED_APPS].keys():
                    # For platform core apps, set the new status
                    # to 'uploaded'. The audit task will kick in with
                    # all its pre-requisite checks before reapplying.
                    new_status = constants.APP_UPLOAD_SUCCESS
                    self._clear_app_alarm(app.name)

            if (not reset_status or
                    app.name not in self._apps_metadata[
                        constants.APP_METADATA_PLATFORM_MANAGED_APPS].keys()):
                self._raise_app_alarm(
                    app.name, constants.APP_APPLY_FAILURE,
                    fm_constants.FM_ALARM_ID_APPLICATION_APPLY_FAILED,
                    fm_constants.FM_ALARM_SEVERITY_MAJOR,
                    _("Application Apply Failure"),
                    fm_constants.FM_ALARM_TYPE_3,
                    _("Retry applying the application. If the issue persists, "
                      "please check system inventory log for cause."),
                    True)
        elif app.status == constants.APP_REMOVE_IN_PROGRESS:
            op = 'application-remove'
            if not forced_operation:
                new_status = constants.APP_REMOVE_FAILURE
                self._raise_app_alarm(
                    app.name, constants.APP_REMOVE_FAILURE,
                    fm_constants.FM_ALARM_ID_APPLICATION_REMOVE_FAILED,
                    fm_constants.FM_ALARM_SEVERITY_MAJOR,
                    _("Application Remove Failure"),
                    fm_constants.FM_ALARM_TYPE_3,
                    _("Retry removing the application. If the issue persists, "
                        "please check system inventory log for cause. "
                        "Using --force will set the app status to 'uploaded' "
                        "in case the error persists."),
                    True)
            else:
                # In case there is an existing alarm for previous remove failure
                self._clear_app_alarm(app.name)

                new_status = constants.APP_UPLOAD_SUCCESS
                progress = constants.APP_PROGRESS_REMOVE_FAILED_WARNING.format(new_status)
                LOG.warning(progress)

        else:
            # Should not get here, perhaps a new status was introduced?
            LOG.error("No abort handling code for app status = '%s'!" % app.status)
            return

        # Run post lifecycle hook for the abort operation
        lifecycle_hook_info = LifecycleHookInfo()
        lifecycle_hook_info.operation = constants.APP_ABORT_OP
        lifecycle_hook_info.relative_timing = LifecycleConstants.APP_LIFECYCLE_TIMING_POST
        lifecycle_hook_info.lifecycle_type = LifecycleConstants.APP_LIFECYCLE_TYPE_OPERATION
        lifecycle_hook_info.extra[LifecycleConstants.ABORTED_OP] = operation
        try:
            self.app_lifecycle_actions(None, None, app._kube_app, lifecycle_hook_info)
        except Exception as e:
            LOG.error(f"Error while performing post abort lifecycle actions: {e}")

        if not reset_status:
            self._update_app_status(app, new_status, progress)
            if not user_initiated:
                LOG.error("Application %s aborted!." % operation)
            else:
                LOG.info("Application %s aborted by user!." % operation)
        else:
            LOG.info("Resetting status of app %s from '%s' to '%s' " %
                     (app.name, app.status, new_status))
            error_msg = "Unexpected process termination while " + op +\
                        " was in progress. The application status " +\
                        "has changed from \'" + app.status +\
                        "\' to \'" + new_status + "\'."
            values = {'progress': error_msg, 'status': new_status}
            self._dbapi.kube_app_update(app.id, values)

    def _download_tarfile(self, app):
        from six.moves.urllib.request import urlopen
        from six.moves.urllib.error import HTTPError
        from six.moves.urllib.error import URLError
        from socket import timeout as socket_timeout
        from six.moves.urllib.parse import urlsplit

        def _handle_download_failure(reason):
            raise exception.KubeAppUploadFailure(
                name=app.name,
                version=app.version,
                reason=reason)

        try:
            remote_file = urlopen(
                app.tarfile, timeout=TARFILE_DOWNLOAD_CONNECTION_TIMEOUT)
            try:
                remote_filename = remote_file.info()['Content-Disposition']
            except KeyError:
                remote_filename = os.path.basename(
                    urlsplit(remote_file.url).path)

            filename_avail = True if (remote_filename is None or
                                      remote_filename == '') else False

            if filename_avail:
                if (not remote_filename.endswith('.tgz') and
                        not remote_filename.endswith('.tar.gz')):
                    reason = app.tarfile + ' has unrecognizable tar file ' + \
                        'extension. Supported extensions are: .tgz and .tar.gz.'
                    _handle_download_failure(reason)
                    return None

                filename = '/tmp/' + remote_filename
            else:
                filename = '/tmp/' + app.name + '.tgz'

            with open(filename, 'w') as dest:
                shutil.copyfileobj(remote_file, dest, TARFILE_TRANSFER_CHUNK_SIZE)
            return filename

        except HTTPError as err:
            LOG.error(err)
            reason = 'failed to download tarfile ' + app.tarfile + \
                     ', error code = ' + str(err.code)
            _handle_download_failure(reason)
        except URLError as err:
            LOG.error(err)
            reason = app.tarfile + ' is unreachable.'
            _handle_download_failure(reason)
        except shutil.Error as err:
            LOG.error(err)
            err_file = os.path.basename(filename) if filename_avail else app.tarfile
            reason = 'failed to process tarfile ' + err_file
            _handle_download_failure(reason)
        except socket_timeout as e:
            LOG.error(e)
            reason = 'failed to download tarfile ' + app.tarfile + \
                     ', connection timed out.'
            _handle_download_failure(reason)

    def _extract_tarfile(self, app):
        def _handle_extract_failure(
                reason='failed to extract tarfile content.'):
            raise exception.KubeAppUploadFailure(
                name=app.name,
                version=app.version,
                reason=reason)

        orig_uid, orig_gid = get_app_install_root_path_ownership()

        try:
            # One time set up of fluxcd manifest path for the system
            if not os.path.isdir(constants.APP_FLUXCD_DATA_PATH):
                os.makedirs(constants.APP_FLUXCD_DATA_PATH)

            if not os.path.isdir(app.sync_fluxcd_manifest_dir):
                os.makedirs(app.sync_fluxcd_manifest_dir)

            if not os.path.isdir(app.inst_path):
                create_app_path(app.inst_path)

            # Temporarily change /scratch group ownership to sys_protected
            os.chown(constants.APP_INSTALL_ROOT_PATH, orig_uid,
                     grp.getgrnam(constants.SYSINV_SYSADMIN_GRPNAME).gr_gid)

            # Extract the tarfile as sysinv user
            if not cutils.extract_tarfile(app.inst_path, app.tarfile, demote_user=True):
                _handle_extract_failure()

            if app.downloaded_tarfile:
                name, version, patches = self._utils._verify_metadata_file(
                    app.inst_path, app.name, app.version)
                if (name != app.name or version != app.version):
                    # Save the official application info. They will be
                    # persisted in the next status update
                    app.regenerate_application_info(name, version, patches)

                if not cutils.verify_checksum(app.inst_path):
                    _handle_extract_failure('checksum validation failed.')

                mname, manifest = self._utils._find_manifest(app.inst_path, app.name)
                # Save the official manifest file info. They will be persisted
                # in the next status update
                app.regenerate_manifest_filename(mname, os.path.basename(manifest))
            else:
                name, version, patches = app_metadata.validate_metadata_file(
                    app.inst_path, constants.APP_METADATA_FILE)
                app.patch_dependencies = patches

            self._utils._extract_helm_charts(app.inst_path)

        except exception.SysinvException as e:
            _handle_extract_failure(str(e))
        except OSError as e:
            LOG.error(e)
            _handle_extract_failure()
        finally:
            os.chown(constants.APP_INSTALL_ROOT_PATH, orig_uid, orig_gid)

    def get_image_tags_by_charts(self, app):
        """ Mine the image tags for charts from the images file. Add the
            image tags to the manifest file if the image tags from the
            charts do not exist in the manifest file. Convert the image
            tags in in both override files and manifest file. Intended
            for both system and custom apps.

            The image tagging conversion(local docker registry address prepended):
            ${LOCAL_REGISTRY_SERVER}:${REGISTRY_PORT}/<image-name>
            (ie..registry.local:9001/docker.io/mariadb:10.2.13)

        """
        return self._get_image_tags_by_charts_fluxcd(app.sync_imgfile,
                                                         app.sync_fluxcd_manifest,
                                                         app.sync_overrides_dir)

    @staticmethod
    def get_global_namespace(root_kustomization_yaml):
        """ Retrieve the namespace of a top level kustomization """
        return root_kustomization_yaml.get("namespace", constants.FLUXCD_K8S_FALLBACK_NAMESPACE)

    def _get_charts_in_use_except(self, excluded_apps_id_list=None):
        """ Get all charts currently in use by applications

        :param excluded_apps_id_list: list of application ids that should not
                                      have their charts included
        """

        charts_in_use = []
        for db_app in self._dbapi.kube_app_get_all():
            app = AppOperator.Application(db_app)
            if excluded_apps_id_list is None or \
                    (excluded_apps_id_list is not None and db_app.id
                     not in excluded_apps_id_list):
                charts_in_use = charts_in_use + self._get_list_of_charts(app)

        return charts_in_use

    def _remove_app_charts_from_repo(self, app_id, app_charts):
        """ Remove application charts from Helm repository

        :param app_id: identifier of the application that is having
                       its charts removed.
        :param app_charts: charts to be removed
        """

        chart_files_in_use = [c.filesystem_location for c in
                              self._get_charts_in_use_except([app_id])]
        repo_set = set()
        for chart in app_charts:
            try:
                if not chart.filesystem_location:
                    LOG.error("Filesystem location not available for "
                              "chart {}. Unable to delete from repository."
                              .format(chart.name))
                elif chart.filesystem_location not in chart_files_in_use:
                    os.remove(chart.filesystem_location)
                    repo_set.add(os.path.dirname(chart.filesystem_location))
            except OSError:
                LOG.error("Error while removing chart {} from repository".
                          format(chart.filesystem_location))

        # Re-index repositories
        for repo_path in repo_set:
            helm_utils.index_repo(repo_path)

    def _get_image_tags_by_charts_fluxcd(self, app_images_file, manifest, overrides_dir):
        app_imgs = []
        images_file = None

        if os.path.exists(app_images_file):
            with io.open(app_images_file, 'r', encoding='utf-8') as f:
                images_file = yaml.safe_load(f)

        helmrepo_path = os.path.join(manifest, "base", "helmrepository.yaml")
        root_kustomization_path = os.path.join(
            manifest, constants.APP_ROOT_KUSTOMIZE_FILE)
        for f in (helmrepo_path, root_kustomization_path):
            if not os.path.isfile(f):
                raise exception.SysinvException(_(
                    "Mandatory FluxCD yaml file doesn't exist "
                    "%s" % helmrepo_path))

        # get namespace
        with io.open(root_kustomization_path, 'r', encoding='utf-8') as f:
            root_kustomization_yaml = next(yaml.safe_load_all(f))
            charts_groups = root_kustomization_yaml["resources"]

        for chart_group in charts_groups:
            if chart_group != "base":
                chart_path = os.path.join(manifest, chart_group)
                helmrelease_path = os.path.join(chart_path, "helmrelease.yaml")
                chart_kustomization_path = os.path.join(chart_path, "kustomization.yaml")
                if not os.path.isfile(chart_kustomization_path) or \
                        not os.path.isfile(helmrelease_path):
                    continue
                with io.open(helmrelease_path, 'r', encoding='utf-8') as f:
                    helmrelease_yaml = next(yaml.safe_load_all(f))
                    chart_name = helmrelease_yaml["metadata"]["name"]

                # Get the image tags by chart from the images file
                helm_chart_imgs = {}
                if images_file and chart_name in images_file:
                    helm_chart_imgs = images_file[chart_name]

                # Get the image tags from the chart overrides file
                overrides = helm_utils.build_overrides_filename(chart_name)
                app_overrides_file = os.path.join(overrides_dir, overrides)
                overrides_file = {}
                if os.path.exists(app_overrides_file):
                    with io.open(app_overrides_file, 'r', encoding='utf-8') as f:
                        overrides_file = yaml.safe_load(f)
                else:
                    LOG.warn("Cannot find overrides file {}".format(app_overrides_file))

                override_imgs = self._image.find_images_in_dict(overrides_file)
                override_imgs_copy = copy.deepcopy(override_imgs)

                # Get the image tags from the fluxcd static overrides file
                static_overrides_path = None
                if "valuesFrom" not in helmrelease_yaml["spec"]:
                    raise exception.SysinvException(_(
                        "FluxCD app chart doesn't have overrides files "
                        "defined in helmrelease.yaml"
                        "%s" % chart_name))

                for override_file in helmrelease_yaml["spec"]["valuesFrom"]:
                    if override_file["valuesKey"].endswith("static-overrides.yaml"):
                        static_overrides_path = os.path.join(chart_path,
                                                             override_file["valuesKey"])

                if not static_overrides_path or \
                        not os.path.isfile(static_overrides_path):
                    raise exception.SysinvException(_(
                        "FluxCD app chart static overrides file doesn't exist "
                        "%s" % chart_name))

                with io.open(static_overrides_path, 'r', encoding='utf-8') as f:
                    static_overrides_file = yaml.safe_load(f) or {}

                # get the image tags from the static overrides file
                static_overrides_imgs = self._image.find_images_in_dict(static_overrides_file)
                static_overrides_imgs_copy = copy.deepcopy(static_overrides_imgs)
                static_overrides_imgs = self._image.merge_dict(helm_chart_imgs, static_overrides_imgs)

                self._add_local_registry_to_repository(static_overrides_imgs, override_imgs)

                # Update image tags with local registry prefix
                override_imgs = self._image.update_images_with_local_registry(override_imgs)
                static_overrides_imgs = self._image.update_images_with_local_registry(static_overrides_imgs)

                # Generate a list of required images by chart
                download_imgs = copy.deepcopy(static_overrides_imgs)
                download_imgs = self._image.merge_dict(download_imgs, override_imgs)
                download_imgs = self._image.update_images_with_local_registry(download_imgs)
                download_imgs_list = self._image.generate_download_images_list(download_imgs, [])
                app_imgs.extend(download_imgs_list)

                # Update chart override file if needed
                if override_imgs != override_imgs_copy:
                    with open(app_overrides_file, 'w') as f:
                        try:
                            overrides_file = self._image.merge_dict(
                                overrides_file, override_imgs)
                            yaml.safe_dump(overrides_file, f, default_flow_style=False)
                            LOG.info("Overrides file %s updated with new image tags" %
                                     app_overrides_file)
                        except (TypeError, KeyError):
                            LOG.error("Overrides file %s fails to update" %
                                      app_overrides_file)

                # Update static overrides if needed
                if static_overrides_imgs != static_overrides_imgs_copy:
                    static_overrides_to_dump = self._image.merge_dict(static_overrides_file,
                                                                      static_overrides_imgs)
                    with io.open(static_overrides_path, 'w', encoding='utf-8') as f:
                        yaml.safe_dump(static_overrides_to_dump, f, default_flow_style=False)

        return list(set(app_imgs))

    def _add_local_registry_to_repository(self, static_override, override_imgs):
        """adds local registry to static overrides, mutating the static_override dict

        :param static_override: dict with static override
        :param overrides_imgs: dict with user overrides
        """
        for k, v in override_imgs.items():
            if isinstance(v, dict):
                self._add_local_registry_to_repository(static_override.get(k, {}), v)
            else:
                if k == 'registry' and cutils.is_empty_value(v):
                    if constants.DOCKER_REGISTRY_SERVER not in static_override['repository']:
                        static_override['repository'] = \
                            f"{constants.DOCKER_REGISTRY_SERVER}/{static_override['repository']}"

    def _register_embedded_images(self, app):
        """
        TODO(tngo): When we're ready to support air-gap scenario and private
        images, the following need to be done:
            a. load the embedded images
            b. tag and push them to the docker registery on the controller
            c. find image tag IDs in each chart and replace their values with
               new tags. Alternatively, document the image tagging convention
               ${LOCAL_REGISTRY_SERVER}:${REGISTRY_PORT}/<image-name>
               (e.g. registry.local:9001/prom/mysqld-exporter)
               to be referenced in the application Helm charts.
        """
        raise exception.KubeAppApplyFailure(
            name=app.name,
            version=app.version,
            reason="embedded images are not yet supported.")

    def _save_images_list(self, app):
        # Extract the list of images from the charts and overrides where
        # applicable. Save the list to the same location as the fluxcd manifest
        # so it can be sync'ed.
        app.charts = self._get_list_of_charts(app, include_disabled=True)

        self._plugins.activate_plugins(app)
        LOG.info("Generating application overrides to discover required images.")
        self._helm.generate_helm_application_overrides(
            app.sync_overrides_dir, app.name, mode=None, cnamespace=None,
            chart_info=app.charts, combined=True)
        self._plugins.deactivate_plugins(app)

        self._save_images_list_by_charts(app)
        # Get the list of images from the updated images overrides
        images_to_download = self.get_image_tags_by_charts(app)

        if not images_to_download:
            # TODO(tngo): We may want to support the deployment of apps that
            # set up resources only in the future. In which case, generate
            # an info log and let it advance to the next step.
            raise exception.KubeAppUploadFailure(
                name=app.name,
                version=app.version,
                reason="charts specify no docker images.")

        with open(app.sync_imgfile, 'a') as f:
            yaml.safe_dump({"download_images": images_to_download}, f,
                           default_flow_style=False)

    def _save_images_list_by_charts(self, app):
        # Mine the images from values.yaml files in the charts directory.
        # The list of images for each chart are saved to the images file.
        images_by_charts = {}
        for chart in app.charts:
            chart_name = os.path.join(app.inst_charts_dir, chart.name)

            if not os.path.exists(chart_name):
                # If the helm chart name is not the same as the fluxcd
                # chart name in the manifest, try using the source
                # to find the chart directory.
                try:
                    # helm charts should be of the standard format:
                    # <chartname>-X.X.X.tgz
                    url_path = os.path.basename(urlparse(chart.location).path)
                    # strip the .tgz
                    chart_and_version = re.sub('\.tgz$', '', url_path)
                    # strip the version
                    chart_name_no_version = re.sub('-(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)',
                        '', chart_and_version)
                    chart_name = os.path.join(app.inst_charts_dir, chart_name_no_version)
                except Exception as e:
                    LOG.info("Cannot parse chart path: %s" % e)
                    pass

            chart_path = os.path.join(chart_name, 'values.yaml')
            if os.path.exists(chart_path):
                with io.open(chart_path, 'r', encoding='utf-8') as f:
                    y = yaml.safe_load(f)

                chart_images = self._image.find_images_in_dict(y)
                if chart_images:
                    images_by_charts.update({chart.name: chart_images})

        if images_by_charts:
            with open(app.sync_imgfile, 'w') as f:
                yaml.safe_dump(images_by_charts, f, explicit_start=True,
                               default_flow_style=False)

    def _retrieve_images_list(self, app_images_file):
        with io.open(app_images_file, 'r', encoding='utf-8') as f:
            images_list = yaml.safe_load(f)
        return images_list

    def download_images(self, app):
        if os.path.isdir(app.inst_images_dir):
            return self._register_embedded_images(app)

        if app.system_app:
            # Some images could have been overwritten via user overrides
            # between upload and apply, or between applies. Refresh the
            # saved images list.
            saved_images_list = self._retrieve_images_list(app.sync_imgfile)
            saved_download_images_list = list(saved_images_list.get("download_images"))
            images_to_download = self.get_image_tags_by_charts(app)
            if set(saved_download_images_list) != set(images_to_download):
                saved_images_list.update({"download_images": images_to_download})
                with open(app.sync_imgfile, 'w') as f:
                    yaml.safe_dump(saved_images_list, f, explicit_start=True,
                                   default_flow_style=False)
        else:
            images_to_download = self._retrieve_images_list(
                app.sync_imgfile).get("download_images")

        total_count = len(images_to_download)
        threads = min(MAX_DOWNLOAD_THREAD, total_count)

        self._docker.set_crictl_image_list([])

        start = time.time()
        try:
            registries_info = self._docker.retrieve_specified_registries()
        except Exception as e:
            raise exception.KubeAppApplyFailure(
                name=app.name,
                version=app.version,
                reason=str(e))
        for idx in reversed(range(MAX_DOWNLOAD_ATTEMPTS)):
            pool = greenpool.GreenPool(size=threads)
            for tag, success in pool.imap(
                    functools.partial(self._docker.download_an_image,
                                      app,
                                      registries_info),
                    images_to_download):
                if success:
                    continue
                if AppOperator.is_app_aborted(app.name):
                    raise exception.KubeAppApplyFailure(
                        name=app.name,
                        version=app.version,
                        reason="operation aborted by user.")
                else:
                    LOG.info("Failed to download image: %s", tag)
                    break
            else:
                elapsed = time.time() - start
                LOG.info("All docker images for application %s were successfully "
                         "downloaded in %d seconds", app.name, elapsed)
                break
            # don't sleep after last download attempt
            if idx:
                # Exponential backoff, the wait time = 15s *2**retry_times + random
                # between 0-15s, e.g.:
                #    1st retry: 15*2**1 + random, max wait time 45s,
                #    2nd retry: 15*2**2 + random, max wait time 75s,
                # The current max_wait_time: 15*2**3+15=135s
                # NOTE(yuxing): the wait time will increase if we add more retries
                wait_before_retry = \
                    DOWNLOAD_WAIT_BEFORE_RETRY * 2 ** (MAX_DOWNLOAD_ATTEMPTS - idx + 1) \
                    + random.uniform(0, DOWNLOAD_WAIT_BEFORE_RETRY)
                LOG.info("Retry docker images download for application %s "
                         "after %d seconds", app.name, wait_before_retry)
                time.sleep(wait_before_retry)
        else:
            # Clears the error cache caused by failure to download one or more images
            # in 'def download_an_image'. At this point it wasn't just one image that
            # failed, but all of them. The 'raise' below already reports the error
            # correctly.
            app.clear_error_message()

            raise exception.KubeAppApplyFailure(
                name=app.name,
                version=app.version,
                reason=constants.APP_PROGRESS_IMAGES_DOWNLOAD_FAILED)

    def _validate_helm_charts(self, app):
        failed_charts = []
        for r, f in cutils.get_files_matching(app.inst_charts_dir, 'Chart.yaml'):
            # Eliminate redundant validation for system app
            if app.system_app and '/charts/helm-toolkit' in r:
                continue
            try:
                output = subprocess.check_output(  # pylint: disable=not-callable
                    ['helm', 'lint', r], universal_newlines=True)
                if "linted, 0 chart(s) failed" in output:
                    LOG.info("Helm chart %s validated" % os.path.basename(r))
                else:
                    LOG.error("Validation failed for helm chart %s" %
                              os.path.basename(r))
                    failed_charts.append(r)
            except Exception as e:
                raise exception.KubeAppUploadFailure(
                    name=app.name, version=app.version, reason=str(e))

        if len(failed_charts) > 0:
            raise exception.KubeAppUploadFailure(
                name=app.name, version=app.version, reason="one or more charts failed validation.")

    def _get_chart_data_from_metadata(self, app):
        """Get chart related data from application metadata

        This extracts the helm repo from the application metadata where the
        chart should be loaded.

        This also returns the list of charts that are disabled by default.

        :param app: application
        """
        repo = common.HELM_REPO_FOR_APPS
        disabled_charts = []
        lfile = os.path.join(app.inst_path, constants.APP_METADATA_FILE)

        if os.path.exists(lfile) and os.path.getsize(lfile) > 0:
            with io.open(lfile, 'r', encoding='utf-8') as f:
                try:
                    y = yaml.safe_load(f)
                    repo = y.get('helm_repo', common.HELM_REPO_FOR_APPS)
                    disabled_charts = y.get('disabled_charts', [])
                except KeyError:
                    pass

        LOG.info("Application %s (%s) will load charts to chart repo %s" % (
            app.name, app.version, repo))
        LOG.info("Application %s (%s) will disable charts %s by default" % (
            app.name, app.version, disabled_charts))
        return (repo, disabled_charts)

    def _upload_helm_charts(self, app):
        # Set env path for helm-upload execution
        env = os.environ.copy()
        env['PATH'] = '/usr/local/sbin:' + env['PATH']
        charts = [os.path.join(r, f)
                  for r, f in cutils.get_files_matching(app.inst_charts_dir, '.tgz')]

        orig_uid, orig_gid = get_app_install_root_path_ownership()
        (helm_repo, disabled_charts) = self._get_chart_data_from_metadata(app)
        try:
            # Temporarily change /scratch group ownership to sys_protected
            os.chown(constants.APP_INSTALL_ROOT_PATH, orig_uid,
                     grp.getgrnam(constants.SYSINV_SYSADMIN_GRPNAME).gr_gid)
            with open(os.devnull, "w") as fnull:

                # Check if all charts are good to be uploaded
                charts_to_upload = set()
                for chart in charts:
                    try:
                        subprocess.check_call(['helm-upload',  # pylint: disable=not-callable
                                               'check-only',
                                               helm_repo, chart],
                                              env=env, stdout=fnull, stderr=fnull)
                        charts_to_upload.add(chart)
                        LOG.debug("Helm chart %s ready to be uploaded" % os.path.basename(chart))
                    except subprocess.CalledProcessError as e:
                        if e.returncode == CHART_UPLOAD_FILE_EXISTS_ERROR_CODE:
                            # If the exact same chart already exists then just log a
                            # warning and proceed with the upload process.
                            LOG.warning("Chart %s already exists in the %s repository. "
                                        "Skipping upload." % (os.path.basename(chart), helm_repo))
                            continue
                        else:
                            raise

                # All charts checked. They can be uploaded now.
                for chart in charts_to_upload:
                    subprocess.check_call(['helm-upload',  # pylint: disable=not-callable
                                           'upload-only',
                                           helm_repo, chart],
                                          env=env, stdout=fnull, stderr=fnull)
                    LOG.info("Helm chart %s uploaded" % os.path.basename(chart))

            # Make sure any helm repo changes are reflected for the users
            helm_utils.refresh_helm_repo_information()

        except subprocess.CalledProcessError as e:
            if e.returncode == CHART_UPLOAD_COPY_ERROR_CODE:
                reason = "Error while copying chart file %s to %s repository" \
                          % (chart, helm_repo)
            elif e.returncode == CHART_UPLOAD_VERSION_EXISTS_ERROR_CODE:
                reason = "The incoming chart %s matches the same version of " \
                         "an existing chart in the %s repository that " \
                         "has a different implementation." \
                            % (os.path.basename(chart), helm_repo)
            else:
                reason = str(e)

            raise exception.KubeAppUploadFailure(
                name=app.name, version=app.version, reason=reason)
        except Exception as e:
            raise exception.KubeAppUploadFailure(
                name=app.name, version=app.version, reason=str(e))
        finally:
            os.chown(constants.APP_INSTALL_ROOT_PATH, orig_uid, orig_gid)

        # For system applications with plugin support, establish user override
        # entries and disable charts based on application metadata.
        self._plugins.activate_plugins(app)
        db_app = self._dbapi.kube_app_get(app.name)
        app_ns = self._helm.get_helm_application_namespaces(db_app.name)
        for chart, namespaces in six.iteritems(app_ns):
            for namespace in namespaces:
                try:
                    db_chart = self._dbapi.helm_override_get(
                        db_app.id, chart, namespace)
                except exception.HelmOverrideNotFound:
                    # Create it
                    try:
                        db_chart = self._dbapi.helm_override_create(
                            {'app_id': db_app.id, 'name': chart,
                             'namespace': namespace})
                    except Exception as e:
                        LOG.exception(e)

                # Since we are uploading a fresh application. Ensure that
                # charts are disabled based on metadata
                system_overrides = db_chart.system_overrides
                system_overrides.update({common.HELM_CHART_ATTR_ENABLED:
                                         chart not in disabled_charts})

                try:
                    self._dbapi.helm_override_update(
                        db_app.id, chart, namespace, {'system_overrides':
                                                      system_overrides})
                except exception.HelmOverrideNotFound:
                    LOG.exception("Helm Override Not Found")
        self._plugins.deactivate_plugins(app)

    def _validate_labels(self, labels):
        expr = re.compile(r'[a-z0-9]([-a-z0-9]*[a-z0-9])')
        for label in labels:
            if not expr.match(label):
                return False
        return True

    def _update_kubernetes_labels(self, hostname, label_dict):
        body = {
            'metadata': {
                'labels': {}
            }
        }
        body['metadata']['labels'].update(label_dict)
        if (common.LABEL_COMPUTE_LABEL in label_dict and
           label_dict[common.LABEL_COMPUTE_LABEL] is None):
            host = self.dbapi.ihost_get_by_hostname(hostname)
            app_isolated_cpus = helm_base._get_host_cpu_list(host,
                                                             function=constants.ISOLATED_FUNCTION,
                                                             threads=True)
            vswitch_cpus = helm_base._get_host_cpu_list(host,
                                                        function=constants.VSWITCH_FUNCTION,
                                                        threads=True)
            if len(app_isolated_cpus) > 0 and len(vswitch_cpus) > 0:
                raise exception.SysinvException(_(
                    "Failed to update kubernetes labels:"
                    " Only compute nodes may have application-isolated cores"
                    " and vswitch cores at the same time."))
        try:
            self._kube.kube_patch_node(hostname, body)
        except exception.KubeNodeNotFound:
            pass

    def _assign_host_labels(self, hosts, labels):
        for host in hosts:
            if host.administrative != constants.ADMIN_LOCKED:
                continue
            for label_str in labels:
                k, v = label_str.split('=')
                try:
                    self._dbapi.label_create(
                        host.id, {'host_id': host.id,
                                  'label_key': k,
                                  'label_value': v})
                except exception.HostLabelAlreadyExists:
                    pass
            label_dict = {k: v for k, v in (i.split('=') for i in labels)}
            try:
                self._update_kubernetes_labels(host.hostname, label_dict)
            except Exception as e:
                LOG.exception(e)

    def _find_label(self, host_uuid, label_str):
        host_labels = self._dbapi.label_get_by_host(host_uuid)
        for label_obj in host_labels:
            if label_str == label_obj.label_key + '=' + label_obj.label_value:
                return label_obj
        return None

    def _remove_host_labels(self, hosts, labels):
        for host in hosts:
            if host.administrative != constants.ADMIN_LOCKED:
                continue
            null_labels = {}
            for label_str in labels:
                lbl_obj = self._find_label(host.uuid, label_str)
                if lbl_obj:
                    self._dbapi.label_destroy(lbl_obj.uuid)
                    key = lbl_obj.label_key
                    null_labels[key] = None
            if null_labels:
                try:
                    self._update_kubernetes_labels(host.hostname, null_labels)
                except Exception as e:
                    LOG.exception(e)

    def audit_local_registry_secrets(self, context, username=None):
        """
        local registry uses admin's username&password for authentication.
        K8s stores the authentication info in secrets in order to access
        local registry, while admin's password is saved in keyring.
        Admin's password could be changed by openstack client cmd outside of
        sysinv and K8s. It will cause info mismatch between keyring and
        k8s's secrets, and leads to authentication failure.
        There are two ways to keep k8s's secrets updated with data in keyring:
        1. Polling. Use a periodic task to sync info from keyring to secrets.
        2. Notification. Keystone send out notification when there is password
           update, and notification receiver to do the data sync.
        To ensure k8s's secrets are timely and always synced with keyring, both
        methods are used here. And this function will be called in both cases
        to audit password info between keyring and registry-local-secret, and
        update keyring's password to all local registry secrets if need.
        """

        # Use lock to synchronize call from timer and notification
        lock_name = "AUDIT_LOCAL_REGISTRY_SECRETS"

        @cutils.synchronized(lock_name, external=False)
        def _sync_audit_local_registry_secrets(self):
            try:
                secret = self._kube.kube_get_secret("registry-local-secret", kubernetes.NAMESPACE_KUBE_SYSTEM)
                if secret is None:
                    return
                secret_auth_body = base64.decode_as_text(secret.data['.dockerconfigjson'])
                secret_auth_info = (secret_auth_body.split('auth":')[1]).split('"')[1]
                registry_auth = cutils.get_local_docker_registry_auth()
                registry_auth_info = '{0}:{1}'.format(registry_auth['username'],
                                                      registry_auth['password'])
                if secret_auth_info == base64.encode_as_text(registry_auth_info):
                    LOG.debug("Auth info is the same, no update is needed for k8s secret.")
                    return
            except Exception as e:
                LOG.error(e)
                return
            try:
                # update secret with new auth info
                token = '{{\"auths\": {{\"{0}\": {{\"auth\": \"{1}\"}}}}}}'.format(
                        constants.DOCKER_REGISTRY_SERVER, base64.encode_as_text(registry_auth_info))
                secret.data['.dockerconfigjson'] = base64.encode_as_text(token)
                self._kube.kube_patch_secret("registry-local-secret", kubernetes.NAMESPACE_KUBE_SYSTEM, secret)
                LOG.info("Secret registry-local-secret under Namespace kube-system is updated")
            except Exception as e:
                LOG.error("Failed to update Secret %s under Namespace kube-system: %s"
                      % ("registry-local-secret", e))
                return

            # update "default-registry-key" secret info under all namespaces
            try:
                ns_list = self._kube.kube_get_namespace_name_list()
                for ns in ns_list:
                    secret = self._kube.kube_get_secret(AppOperator.DOCKER_REGISTRY_SECRET, ns)
                    if secret is None:
                        continue

                    try:
                        secret_auth_body = base64.decode_as_text(secret.data['.dockerconfigjson'])
                        if constants.DOCKER_REGISTRY_SERVER in secret_auth_body:
                            secret.data['.dockerconfigjson'] = base64.encode_as_text(token)
                            self._kube.kube_patch_secret(AppOperator.DOCKER_REGISTRY_SECRET, ns, secret)
                            LOG.info("Secret %s under Namespace %s is updated"
                                     % (AppOperator.DOCKER_REGISTRY_SECRET, ns))
                    except Exception as e:
                        LOG.error("Failed to update Secret %s under Namespace %s: %s"
                                  % (AppOperator.DOCKER_REGISTRY_SECRET, ns, e))
                        continue
            except Exception as e:
                LOG.error(e)
                return

        _sync_audit_local_registry_secrets(self)

    def _wait_for_pod_termination(self, namespace):
        loop_timeout = 0
        loop_check_interval = 10
        timeout = 300
        try:
            LOG.info("Waiting for pod termination in namespace %s ..." % namespace)

            # Pod termination timeout 5mins
            while(loop_timeout <= timeout):
                if not self._kube.kube_namespaced_pods_exist(namespace):
                    # Pods have terminated
                    break
                loop_timeout += loop_check_interval
                time.sleep(loop_check_interval)

            if loop_timeout > timeout:
                raise exception.KubePodTerminateTimeout(name=namespace)
            LOG.info("Pod termination in Namespace %s completed." % namespace)
        except Exception as e:
            LOG.error(e)
            raise

    def _get_list_of_charts(self, app, include_disabled=False):
        """Get the charts information from the manifest directory

        The following chart data for each chart in the manifest file
        are extracted and stored into a namedtuple Chart object:
         - metadata_name
         - chart_name
         - namespace
         - location
         - release

         :param app: application
         :param include_disabled: boolean value to add disabled charts on function return

         :return: Array with chart object for each chart present in the application
         """

        manifest = app.sync_fluxcd_manifest
        helmrepo_path = os.path.join(manifest, "base", "helmrepository.yaml")

        if include_disabled:
            app_root_kustomize_file = constants.APP_ROOT_KUSTOMIZE_ORIG_FILE
        else:
            app_root_kustomize_file = constants.APP_ROOT_KUSTOMIZE_FILE

        root_kustomization_path = \
            os.path.join(manifest, app_root_kustomize_file)

        # In the event include_disabed is set to True, make sure the file exists.
        # Possible that the file has not yet been created yet.
        if not os.path.exists(root_kustomization_path) and include_disabled:
            LOG.info(
                "_get_list_of_charts: Function called with include_disabled=True, "
                "but the kustomize-orig.yaml file does not exist yet. Creating it "
                "now."
            )
            original_root_kustomization_path = os.path.join(
                manifest, constants.APP_ROOT_KUSTOMIZE_FILE
            )
            shutil.copy(original_root_kustomization_path, root_kustomization_path)

        for f in (helmrepo_path, root_kustomization_path):
            if not os.path.isfile(f):
                raise exception.SysinvException(_(
                    "Mandatory FluxCD yaml file doesn't exist "
                    "%s" % f))

        # get charts groups
        with io.open(root_kustomization_path, 'r', encoding='utf-8') as f:
            root_kustomization_yaml = next(yaml.safe_load_all(f))
            charts_groups = root_kustomization_yaml["resources"]

        helm_repo_dict = helm_utils.extract_repository_info(helmrepo_path)
        helm_repo_url = helm_repo_dict["url"]
        helm_repo_name = helm_repo_dict["name"]
        helm_repo_local_path = helm_repo_dict["path"]

        charts = []

        # Getting helmrelease result of "kubectl kustomize <fluxcd_directory>"
        if include_disabled:
            with tempfile.TemporaryDirectory() as temp_dirname:
                # By default, the "kubectl kustomize <dir>" command always uses the
                # kustomization.yaml file to build the set of KRM. To use the
                # kustomization-orig.yaml file as a data source for command, a temporary folder is
                # created and the files are copied there. Immediately after this operation,
                # kustomization.yaml is deleted and kustomization-orig.yaml is renamed to
                # kustomization.yaml.

                # Copy fluxcd files to temp dir
                temp_manifest_dir = os.path.join(temp_dirname, os.path.basename(manifest))
                shutil.copytree(manifest, temp_manifest_dir)

                # Rename kustomization-orig.yaml to kustomization.yaml
                temp_kustomization_path = \
                    os.path.join(temp_manifest_dir, constants.APP_ROOT_KUSTOMIZE_FILE)
                kustomization_orig_path = \
                    os.path.join(temp_manifest_dir, constants.APP_ROOT_KUSTOMIZE_ORIG_FILE)
                os.rename(kustomization_orig_path, temp_kustomization_path)

                resources_list = cutils.get_resources_list_via_kubectl_kustomize(temp_manifest_dir)
        else:
            resources_list = cutils.get_resources_list_via_kubectl_kustomize(manifest)

        if not resources_list:
            return charts
        helmreleases_from_kustomize_command = cutils.filter_helm_releases(resources_list)

        for chart_group in charts_groups:
            if chart_group != "base":
                chart_path = os.path.join(manifest, chart_group)
                helmrelease_path = os.path.join(chart_path, "helmrelease.yaml")
                chart_kustomization_path = os.path.join(chart_path, "kustomization.yaml")
                if not os.path.isfile(chart_kustomization_path) or \
                        not os.path.isfile(helmrelease_path):
                    continue
                with io.open(helmrelease_path, 'r', encoding='utf-8') as f:
                    helmrelease_yaml = next(yaml.safe_load_all(f))
                    metadata_name = helmrelease_yaml["metadata"]["name"]
                    chart_spec = helmrelease_yaml["spec"]["chart"]
                    chart_name = chart_spec["spec"]["chart"]
                    chart_version = chart_spec["spec"]["version"]
                    location = "%s/%s-%s%s" % (helm_repo_url.rstrip("/"),
                                               chart_name,
                                               chart_spec["spec"]["version"],
                                               ".tgz")
                    filesystem_location = helm_utils.get_chart_tarball_path(
                        helm_repo_local_path,
                        chart_name,
                        chart_version)
                    release = helmrelease_yaml["spec"]["releaseName"]

                    # Get the helmrelease namespace resulting from the "kubectl kustomize" command
                    for helmrelease in helmreleases_from_kustomize_command:
                        if helmrelease["spec"]["chart"]["spec"]["chart"] == chart_name:
                            namespace = helmrelease['metadata']['namespace']
                            break

                    # Dunno if we need to return these in order respecting dependsOn?
                    # dependencies = [dep["name"] for dep in helmrelease_yaml["spec"].
                    # get(["dependsOn"], [])]
                    if (not app.system_app or
                        include_disabled or
                        cutils.is_chart_enabled(self._dbapi,
                                                app.name,
                                                metadata_name,
                                                namespace)):
                        chart_obj = FluxCDChart(
                            metadata_name=metadata_name,
                            name=metadata_name,
                            namespace=namespace,
                            location=location,
                            filesystem_location=filesystem_location,
                            release=release,
                            chart_os_path=chart_path,
                            chart_label=chart_name,
                            chart_version=chart_version,
                            helm_repo_name=helm_repo_name
                        )
                        LOG.info(f"_get_list_of_charts: Adding Chart: {chart_name}")
                        charts.append(chart_obj)
        return charts

    def _get_overrides_files(self, app):
        return self._get_overrides_from_charts(app.sync_overrides_dir, app.charts)

    def _get_overrides_from_charts(self, overrides_dir, charts):
        missing_helm_overrides = []
        available_helm_overrides = []

        for chart in charts:
            overrides = helm_utils.build_overrides_filename(chart.name)
            overrides_file = os.path.join(overrides_dir, overrides)
            if os.path.exists(overrides_file):
                available_helm_overrides.append(overrides_file)
            else:
                # Also check for the naming format used on previous releases.
                # TODO(ipiresso): This can be removed when the master branch
                # version moves on from stx 10.
                # Story: https://storyboard.openstack.org/#!/story/2011171
                overrides = helm_utils.build_overrides_filename(chart.name, chart.namespace)
                overrides_file = os.path.join(overrides_dir, overrides)

                if os.path.exists(overrides_file):
                    available_helm_overrides.append(overrides_file)
                else:
                    missing_helm_overrides.append(overrides_file)

        if missing_helm_overrides:
            LOG.error("Missing the following overrides: %s" % missing_helm_overrides)
            return None

        return available_helm_overrides

    def _write_fluxcd_overrides(self, charts, helm_files):

        for chart in charts:
            override_file = helm_utils.build_overrides_filename(chart.name)

            for f in os.listdir(chart.chart_os_path):
                if f.endswith("-system-overrides.yaml"):
                    chart_system_overrides_path = os.path.join(chart.chart_os_path, f)
                    break
            else:
                LOG.error("Missing system-overrides.yaml file for chart %s" % chart.name)
                continue

            # copy helm chart overrides file to chart's system-overrides.yaml file
            for helm_file in helm_files:
                if os.path.basename(helm_file) == override_file:
                    shutil.copy(helm_file, chart_system_overrides_path)

    def _remove_chart_overrides(self, overrides_dir, app):
        charts = self._get_list_of_charts(app)
        for chart in charts:
            if chart.name in self._helm.chart_operators:
                self._helm.remove_helm_chart_overrides(overrides_dir,
                                                       chart.name,
                                                       chart.namespace)

    def _update_app_releases_version(self, app_name):
        """Update application helm releases records

        This method retrieves the deployed helm releases and updates the
        releases records in sysinv db if needed
        :param app_name: the name of the application
        """
        try:
            deployed_releases = helm_utils.retrieve_helm_releases()
            LOG.debug('deployed_releases = %s', deployed_releases)
            app = self._dbapi.kube_app_get(app_name)
            app_releases = self._dbapi.kube_app_chart_release_get_all(app.id)

            for r in app_releases:
                LOG.debug('app.id=%r, release=%r, version=%r, namespace=%r',
                          app.id, r.release, r.version, r.namespace)
                if (r.release in deployed_releases and
                        r.namespace in deployed_releases[r.release] and
                        r.version != deployed_releases[r.release][r.namespace]):

                    self._dbapi.kube_app_chart_release_update(
                        app.id, r.release, r.namespace,
                        {'version': deployed_releases[r.release][r.namespace]})
        except Exception as e:
            LOG.exception(e)
            raise exception.SysinvException(_(
                "Failed to update/record application %s releases' versions." % str(e)))

    def _create_app_releases_version(self, app_name, app_charts):
        """Create application helm releases records

        This method creates/initializes the helm releases objects for the application.
        :param app_name: the name of the application
        :param app_charts: the charts of the application
        """
        kube_app = self._dbapi.kube_app_get(app_name)
        app_releases = self._dbapi.kube_app_chart_release_get_all(kube_app.id)
        if app_releases:
            return

        for chart in app_charts:
            values = {
                'release': chart.release,
                'version': 0,
                'namespace': chart.namespace,
                'app_id': kube_app.id
            }

            try:
                self._dbapi.kube_app_chart_release_create(values)
            except Exception as e:
                LOG.exception(e)

    def _get_metadata_value(self, app, key_or_keys, default=None,
                           enforce_type=False):
        """
        Get application metadata value from nested dictionary.

        If a default value is specified, this will enforce that
        the value returned is of the same type.

        :param app: application object
        :param key_or_keys: single key string, or list of keys
        :param default: default value (and type)
        :param enforce_type: enforce type check between return value and default

        :return: The value from nested dictionary D[key1][key2][...] = value
                 assuming all keys are present, otherwise default.
        """
        value = default

        if isinstance(key_or_keys, list):
            keys = key_or_keys
        else:
            keys = [key_or_keys]

        metadata_file = os.path.join(app.inst_path,
                                     constants.APP_METADATA_FILE)
        if os.path.exists(metadata_file) and os.path.getsize(metadata_file) > 0:
            with io.open(metadata_file, 'r', encoding='utf-8') as f:
                try:
                    metadata = yaml.safe_load(f) or {}
                    value = cutils.deep_get(metadata, keys, default=default)
                    # TODO(jgauld): There is inconsistent treatment of YAML
                    # boolean between the module ruamel.yaml and module yaml
                    # in utils.py, health.py, and kube_app.py. Until these
                    # usage variants are unified, leave the following check
                    # as optional.
                    if enforce_type and default is not None and value is not None:
                        default_type = type(default)
                        if type(value) != default_type:
                            raise exception.SysinvException(_(
                                "Invalid {}: {} {!r} expected value is {}."
                                "".format(metadata_file, '.'.join(keys),
                                          value, default_type)))
                except KeyError:
                    # metadata file does not have the key
                    pass
        LOG.debug('_get_metadata_value: metadata_file=%s, keys=%s, default=%r, value=%r',
                  metadata_file, keys, default, value)
        return value

    def _preserve_user_overrides(self, from_app, to_app):
        """Dump user overrides

        In the scenario of updating application to a new version, this
        method is used to copy the user overrides from the old version
        to the new version.

        :param from_app: application object that application updating from
        :param to_app: application object that application updating to
        """
        to_db_app = self._dbapi.kube_app_get(to_app.name)
        from_db_app = self._dbapi.kube_app_get_inactive_by_name_version(
            from_app.name, version=from_app.version)

        from_app_db_charts = self._dbapi.helm_override_get_all(from_db_app.id)
        from_app_charts = {}
        for chart in from_app_db_charts:
            from_app_charts.setdefault(chart.name, {}).update(
                {chart.namespace: chart.user_overrides})

        for chart in to_app.charts:
            if (chart.name in from_app_charts and
                    chart.namespace in from_app_charts[chart.name] and
                    from_app_charts[chart.name][chart.namespace]):
                user_overrides = {'user_overrides': from_app_charts[chart.name][chart.namespace]}
                try:
                    self._dbapi.helm_override_update(
                        app_id=to_db_app.id, name=chart.name,
                        namespace=chart.namespace, values=user_overrides)
                except exception.HelmOverrideNotFound:
                    # Unexpected
                    values = {
                        'name': chart.name,
                        'namespace': chart.namespace,
                        'app_id': to_db_app.id
                    }
                    values.update(user_overrides)
                    self._dbapi.helm_override_create(values=values)
                LOG.info("Application %s (%s) will apply the user overrides for"
                         "Chart %s from version %s" % (to_app.name, to_app.version,
                                                       chart.name, from_app.version))

    def _preserve_attributes(self, from_app, to_app):
        """
        In the scenario of updating application to a new version, this
        method is used to copy the attributes from the old version
        to the new version.

        :param from_app: application object that application updating from
        :param to_app: application object that application updating to
        """
        to_db_app = self._dbapi.kube_app_get(to_app.name)
        from_db_app = self._dbapi.kube_app_get_inactive_by_name_version(
            from_app.name, version=from_app.version)

        from_app_db_charts = self._dbapi.helm_override_get_all(from_db_app.id)
        from_app_charts = {}
        for chart in from_app_db_charts:
            from_app_charts.setdefault(chart.name, {}).update(
                {chart.namespace: chart.system_overrides})

        for chart in to_app.charts:
            if (chart.name in from_app_charts and
                    chart.namespace in from_app_charts[chart.name] and
                    from_app_charts[chart.name][chart.namespace]):
                system_overrides = {'system_overrides': from_app_charts[chart.name][chart.namespace]}
                try:
                    self._dbapi.helm_override_update(
                        app_id=to_db_app.id, name=chart.name,
                        namespace=chart.namespace, values=system_overrides)
                except exception.HelmOverrideNotFound:
                    # Unexpected
                    values = {
                        'name': chart.name,
                        'namespace': chart.namespace,
                        'app_id': to_db_app.id
                    }
                    values.update(system_overrides)
                    self._dbapi.helm_override_create(values=values)
                LOG.info("Application %s (%s) will apply the attributes for"
                         "Chart %s from version %s" % (to_app.name, to_app.version,
                                                       chart.name, from_app.version))

    def _make_app_request(self, app, request, is_reapply_process=False, caller=None):
        return self._make_fluxcd_operation_with_monitor(app, request, is_reapply_process, caller)

    @retry(retry_on_exception=lambda x: isinstance(x, exception.ApplicationApplyFailure),
           stop_max_attempt_number=5, wait_fixed=30 * 1000)
    @kubernetes.test_k8s_health
    def _make_fluxcd_operation_with_monitor(self, app, request, is_reapply_process=False,
                                            caller=None):
        def _recover_from_helm_operation_in_progress_on_app_apply(metadata_name, namespace,
                                                                  flux_error_message):
            """ Recovery logic for FluxCD on apply

            In case a helm operation is already in progress, FluxCD will raise
            an error. Recover by patching the helm release secret, forcing
            the status to be 'failed'.

            :param metadata_name: metadata name from helmrelease.yaml
            :param namespace: namespace from kustomization.yaml
            :param flux_error_message: Error message FluxCD encountered

            :return: tuple(attempt, error).
                     attempt is True if recovery is triggered
                     error is True if an error was encountered
            """
            helm_release_name = metadata_name
            attempt = False

            for error_string in constants.FLUXCD_RECOVERY_HELM_RELEASE_STATUS_ERRORS:
                if flux_error_message.startswith(error_string):
                    LOG.info("For helm release {} found a matching error string "
                             "we can attempt to recover from: {}"
                             "".format(helm_release_name, error_string))
                    attempt = True
                    break

            if not attempt:
                return attempt, False

            try:
                secret_list = self._kube.kube_list_secret(namespace)
            except Exception as err:
                LOG.warning("Failed to get secrets in namespace {}: {}"
                            "".format(namespace, err))
                return attempt, True

            recover_list = []
            for secret in secret_list:
                label = secret.metadata.labels
                if not label:
                    continue
                if 'owner' not in label:
                    continue
                if 'status' not in label:
                    continue
                if label['owner'] == 'helm' and \
                        label['status'] in constants.FLUXCD_RECOVERABLE_HELM_RELEASE_STATUS:
                    LOG.info("Found helm release {} in state {}"
                             "".format(secret.metadata.name, label['status']))
                    recover_list.append(secret)

            # Force 'failed' status for helm releases
            for secret in recover_list:
                release_data = helm_utils.decompress_helm_release_data(secret.data['release'])

                for status in constants.FLUXCD_RECOVERABLE_HELM_RELEASE_STATUS:
                    release_data = release_data.replace('"status":"{}"'.format(status), '"status":"failed"')

                release_data = helm_utils.compress_helm_release_data(release_data)

                secret.data['release'] = release_data
                try:
                    self._kube.kube_patch_secret(secret.metadata.name,
                                                 secret.metadata.namespace, secret)
                except Exception as err:
                    LOG.warning("Failed to patch secret {} in namespace {}: {}"
                                "".format(secret.metadata.name,
                                          secret.metadata.namespace, err))
                    return attempt, True

            return attempt, False

        def _check_upgrade_retries_exhausted(helm_rel, released_err_msg):
            """ Check if the number of upgrade retries were exhausted
                due to another operation in progress

            :param helm_rel: helm release object containing the conditions
            :param released_err_msg: error message from released condition type

            :return: True if retries are exhausted. False otherwise.
            """

            if "another operation (install/upgrade/rollback) is in progress" in released_err_msg:
                latest_status, latest_msg = self._fluxcd.get_helm_release_status(helm_rel)
                if latest_status == "False" and latest_msg == "upgrade retries exhausted":
                    return True

            return False

        def _recover_via_removal(release_name, release_err_msg):
            """ Verify if a given helm release error can be recovered
                by removing the app and applying it again.

            This leverages the retry mechanism triggered when an
            ApplicationApplyFailure exception is raised.

            :param release_name: helm release name
            :param released_err_msg: helm error message
            """

            for error_string in \
                    constants.FLUXCD_RECOVERY_HELM_RELEASE_STATUS_ERRORS_REMOVAL_REQUIRED:
                if release_err_msg.startswith(error_string):
                    LOG.info("For helm release {} found a matching error string. "
                                "Application removal is required to recover from: {}"
                                "".format(release_name, release_err_msg))

                    lifecycle_hook_info_app_remove = LifecycleHookInfo()
                    lifecycle_hook_info_app_remove.operation = constants.APP_REMOVE_OP
                    self.perform_app_remove(app._kube_app, lifecycle_hook_info_app_remove)

                    progress_str = "Recovering from: {}.".format(error_string)
                    self._update_app_status(app,
                                            constants.APP_RECOVER_IN_PROGRESS,
                                            progress_str
                                            )

                    lifecycle_hook_info_app_apply = LifecycleHookInfo()
                    lifecycle_hook_info_app_apply.operation = constants.APP_APPLY_OP
                    self.perform_app_apply(app._kube_app, mode=None,
                                lifecycle_hook_info_app_apply=lifecycle_hook_info_app_apply,
                                caller=constants.RECOVER_VIA_REMOVAL)

                    raise exception.ApplicationApplyFailure(name=app.name)

        @kubernetes.test_k8s_health(quiet=True)
        def _get_helmrelease_info(release_name, namespace):
            """ get helmrelease data from a given chart

            The _kube.get_custom_resource function gets the helmrelease data from a given chart
            via the k8s API. For this reason, it was encapsulated in a specific function to be
            able to use the test_k8s_health decorator and ensure that k8s is healthy.

            Param: release_name (string): helmrelease name
            param: namespace (string): namespace where the target helmrelease is installed

            return: dictionary with helmrelease data
            """

            helm_rel = self._kube.get_custom_resource(
                constants.FLUXCD_CRD_HELM_REL_GROUP,
                constants.FLUXCD_CRD_HELM_REL_VERSION,
                namespace,
                constants.FLUXCD_CRD_HELM_REL_PLURAL,
                release_name)

            return helm_rel

        def _check_progress():
            tadjust = 0
            last_successful_chart = None
            adjust = self._get_metadata_value(app,
                                              constants.APP_METADATA_APPLY_PROGRESS_ADJUST,
                                              constants.APP_METADATA_APPLY_PROGRESS_ADJUST_DEFAULT_VALUE)

            # Build the list of expected chart releases. Re-read the
            # kustomization.yaml file as charts may have been enabled/disabled
            # via the plugins (helm or kustomize operator).
            charts = {
                c.metadata_name: {
                    "namespace": c.namespace,
                    "chart_label": c.chart_label,
                    "helm_repo_name": c.helm_repo_name
                }
                for c in self._get_list_of_charts(app)
            }
            charts_count = len(charts)

            if app.system_app:
                tadjust = adjust
                if tadjust >= charts_count:
                    LOG.error("Application metadata key '{}'"
                              "has an invalid value {} (too few charts)".
                              format(constants.APP_METADATA_APPLY_PROGRESS_ADJUST,
                                     adjust))
                    tadjust = 0

            # fluxcd is forced to reconcile within the reapply/update process. This happens to
            # prevent the previous status of the helmrelease from being used.
            if is_reapply_process or caller == constants.APP_UPDATE_OP:
                for release_name, chart_obj in list(charts.items()):
                    LOG.info(f"Forcing reconciliation for release: {release_name}")
                    try:
                        helm_utils.call_fluxcd_reconciliation(release_name,
                                                              chart_obj["namespace"])
                    except Exception as e:
                        LOG.error(f"Error while forcing FluxCD reconciliation for release \
                                  {release_name}: {e}")

            while charts:
                if AppOperator.is_app_aborted(app.name):
                    return False
                num = charts_count - len(charts)

                percent = round((float(num) /  # pylint: disable=W1619, W1633
                                 (charts_count - tadjust)) * 100)

                # Check if we had a successful chart applied previously
                if last_successful_chart:
                    progress_str = "Applying app {}. Chart {} applied. Overall completion: {}%". \
                        format(app.name, last_successful_chart, percent)
                else:
                    progress_str = "Applying app {}. Overall completion: {}%". \
                        format(app.name, percent)

                if app.progress != progress_str:
                    LOG.info("%s" % progress_str)
                    self._update_app_status(app, new_progress=progress_str)

                for release_name, chart_obj in list(charts.items()):
                    # Request the helm release info
                    helm_rel = _get_helmrelease_info(release_name, chart_obj["namespace"])

                    if not helm_rel:
                        LOG.info("FluxCD Helm release info for {} is not "
                                 "available".format(release_name))
                        continue

                    release_status, msg = self._fluxcd.get_helm_release_status(helm_rel)
                    if release_status == "False":
                        # If the helm release failed the app must also be in a
                        # failed state
                        helm_err_msg = "{}".format(msg) if msg else ""
                        # Handle corner cases in which retries are exhausted due to another operation in progress.
                        # If retries are exhausted we fail.
                        if _check_upgrade_retries_exhausted(helm_rel, helm_err_msg):
                            return False

                        attempt, _ = _recover_from_helm_operation_in_progress_on_app_apply(
                            metadata_name=release_name,
                            namespace=chart_obj['namespace'],
                            flux_error_message=helm_err_msg)

                        if not attempt:
                            # Handle corner cases in which application removal
                            # and apply are required to recover from failure
                            _recover_via_removal(release_name, helm_err_msg)

                            LOG.exception("Application {}: release {}: Failed during {} :{}"
                                          "".format(app.name, release_name, request, helm_err_msg))

                            # Store the error in the app object for use in def _abort_operation
                            app.update_error_message("Failed to apply helm "
                                                     "release \"{}\".".format(release_name))

                            return False
                    elif release_status == "True":
                        # Special validation check needed for AIO-SX only, can
                        # go away once upstream issues are addressed. See method
                        # for details.
                        if self._fluxcd.verify_pods_status_for_release(chart_obj):
                            charts.pop(release_name)
                            last_successful_chart = chart_obj["chart_label"]
                    else:
                        # Noisy log, so make it debug only, but good for debugging apps dev.
                        LOG.debug("Application {}: release {}: Helm release "
                                  "status is unknown. Checking again.".format(
                                      app.name, release_name))

                # wait a bit to check again if the charts are ready
                time.sleep(5)

                # lifecycle to handle custom k8s services from apps
                # that need to be checked after helmrelease is installed
                try:
                    lifecycle_hook_info.relative_timing = \
                        LifecycleConstants.APP_LIFECYCLE_TIMING_STATUS
                    lifecycle_hook_info.lifecycle_type = \
                        LifecycleConstants.APP_LIFECYCLE_TYPE_FLUXCD_REQUEST
                    self.app_lifecycle_actions(None, None, app._kube_app, lifecycle_hook_info)
                except exception.LifecycleStatusCheckNotReady:
                    return False

            return True

        # This check is for cases where an abort is issued while
        # this function waits between retries. In such cases, it
        # should just return False
        if AppOperator.is_app_aborted(app.name):
            return False

        lifecycle_hook_info = LifecycleHookInfo()
        lifecycle_hook_info.operation = request
        lifecycle_hook_info.relative_timing = LifecycleConstants.APP_LIFECYCLE_TIMING_PRE
        lifecycle_hook_info.lifecycle_type = LifecycleConstants.APP_LIFECYCLE_TYPE_FLUXCD_REQUEST
        self.app_lifecycle_actions(None, None, app._kube_app, lifecycle_hook_info)
        try:
            with Timeout(constants.APP_INSTALLATION_TIMEOUT,
                         exception.KubeAppProgressMonitorTimeout()):

                rc = self._fluxcd.make_fluxcd_operation(
                    request,
                    app.sync_fluxcd_manifest)

                # check progress only for apply for now
                if rc and request == constants.APP_APPLY_OP:
                    rc = _check_progress()
        except (exception.ApplicationApplyFailure):
            raise
        except Exception as e:
            # timeout or subprocess error
            LOG.exception(e)
            rc = False

        # Here a manifest retry can be performed by throwing ApplicationApplyFailure
        lifecycle_hook_info.relative_timing = LifecycleConstants.APP_LIFECYCLE_TIMING_POST
        lifecycle_hook_info.lifecycle_type = LifecycleConstants.APP_LIFECYCLE_TYPE_FLUXCD_REQUEST
        lifecycle_hook_info[LifecycleConstants.EXTRA][LifecycleConstants.RETURN_CODE] = rc
        self.app_lifecycle_actions(None, None, app._kube_app, lifecycle_hook_info)
        return rc

    def _record_auto_update_failed_versions(self, from_app, to_app):
        """Record the new application version in the old application
           metadata when the new application fails to be updated"""

        new_metadata = copy.deepcopy(from_app.app_metadata)
        try:
            failed_versions = new_metadata[constants.APP_METADATA_UPGRADES][
                constants.APP_METADATA_FAILED_VERSIONS]
            if to_app.version not in failed_versions:
                failed_versions.append(to_app.version)
        except KeyError:
            new_metadata.setdefault(constants.APP_METADATA_UPGRADES, {}).update(
                {constants.APP_METADATA_FAILED_VERSIONS: [to_app.version]})

        with self._lock:
            from_app.update_app_metadata(new_metadata)

    def _perform_app_recover(self, rpc_app, old_app, new_app,
                             lifecycle_hook_info_app,
                             fluxcd_process_required=True):
        """Perform application recover

        This recover method is triggered when application update failed, it cleans
        up the files/data for the new application and recover helm charts for the
        old application. If the fluxcd process is required, fluxcd apply is invoked
        to recover the application releases for the old version.

        The app status will be populated to "apply-failed" if recover fails so that
        the user can re-apply app.

        :param rpc_app: application object in the RPC request
        :param old_app: the application object that application recovering to
        :param new_app: the application object that application recovering from
        :param lifecycle_hook_info_app: LifecycleHookInfo object
        :param fluxcd_process_required: boolean, whether fluxcd operation is needed
        """

        def _activate_old_app_plugins(old_app):
            # Enable the old app plugins.
            self._plugins.activate_plugins(old_app)

        LOG.info("Starting recover Application %s from version: %s to version: %s" %
                 (old_app.name, new_app.version, old_app.version))

        self._deregister_app_abort(old_app.name)

        lifecycle_hook_info_app_recover = copy.deepcopy(lifecycle_hook_info_app)
        lifecycle_hook_info_app_recover.operation = constants.APP_RECOVER_OP

        for lifecycle_type in (
            LifecycleConstants.APP_LIFECYCLE_TYPE_RBD,
            LifecycleConstants.APP_LIFECYCLE_TYPE_RESOURCE
        ):
            try:
                lifecycle_hook_info_app_recover.lifecycle_type = lifecycle_type
                self.app_lifecycle_actions(None, None, rpc_app, lifecycle_hook_info_app_recover)
            except Exception as e:
                LOG.error(
                    f"The lifecycle recover {lifecycle_type} failed with error: {e}"
                    "The system will still attempt to run the recovery process"
                )

        # Ensure that the the failed app plugins are disabled prior to cleanup
        self._plugins.deactivate_plugins(new_app)

        self._update_app_status(
            old_app, constants.APP_RECOVER_IN_PROGRESS,
            constants.APP_PROGRESS_UPDATE_ABORTED.format(old_app.version, new_app.version) +
            constants.APP_PROGRESS_RECOVER_IN_PROGRESS.format(old_app.version))
        # Set the status for the new app to inactive
        self._update_app_status(new_app, constants.APP_INACTIVE_STATE)

        try:
            self._utils._patch_report_app_dependencies(
                new_app.name + '-' + new_app.version)
            self._dbapi.kube_app_destroy(new_app.name,
                                         version=new_app.version,
                                         inactive=True)

            LOG.info("Recovering helm charts for Application %s (%s)..."
                     % (old_app.name, old_app.version))
            self._update_app_status(old_app,
                                    new_progress=constants.APP_PROGRESS_RECOVER_CHARTS)
            with self._lock:
                self._upload_helm_charts(old_app)

            rc = True
            if fluxcd_process_required:
                old_app.charts = self._get_list_of_charts(old_app)

                # Ensure that the old app plugins are enabled prior to fluxcd process.
                _activate_old_app_plugins(old_app)

                helm_files = self._helm.generate_helm_application_overrides(
                    old_app.sync_overrides_dir, old_app.name, old_app.mode, cnamespace=None,
                    chart_info=old_app.charts, combined=True)

                if helm_files:
                    LOG.info("Application overrides generated.")
                    LOG.info("Writing fluxcd overrides...")
                    # Put the helm_overrides in the chart's system-overrides.yaml
                    self._write_fluxcd_overrides(old_app.charts, helm_files)
                    LOG.info("Fluxcd overrides generated.")

                    if self._make_app_request(old_app, constants.APP_APPLY_OP):
                        old_app_charts = [c.release for c in old_app.charts]
                        deployed_releases = helm_utils.retrieve_helm_releases()
                        for new_chart in new_app.charts:
                            # Cleanup the releases in the new application version
                            # but are not in the old application version
                            if (new_chart.release not in old_app_charts and
                                    new_chart.release in deployed_releases):

                                # Deletes secrets that are not in the version N of the app
                                self._fluxcd.run_kubectl_kustomize(
                                    constants.KUBECTL_KUSTOMIZE_DELETE,
                                    new_chart.chart_os_path)

                                # Send delete request in FluxCD so it doesn't
                                # recreate the helm release
                                self._kube.delete_custom_resource(
                                    constants.FLUXCD_CRD_HELM_REL_GROUP,
                                    constants.FLUXCD_CRD_HELM_REL_VERSION,
                                    new_chart.namespace,
                                    constants.FLUXCD_CRD_HELM_REL_PLURAL,
                                    new_chart.metadata_name)
                                # Use helm to immediately remove the release
                                helm_utils.delete_helm_release(new_chart.release,
                                                               new_chart.namespace)
                    else:
                        rc = False
                else:
                    LOG.error(f"No Helm charts found for application {old_app.name}.")
                    rc = False

            self._cleanup(new_app, app_dir=False)

        except exception.ApplicationApplyFailure:
            rc = False
        except Exception as e:
            # ie. patch report error, cleanup application files error
            #     helm release delete failure
            self._update_app_status(
                old_app, constants.APP_APPLY_SUCCESS,
                constants.APP_PROGRESS_UPDATE_ABORTED.format(old_app.version, new_app.version) +
                constants.APP_PROGRESS_RECOVER_COMPLETED.format(old_app.version) +
                constants.APP_PROGRESS_CLEANUP_FAILED.format(new_app.version) +
                'Please check logs for details.')
            LOG.error(e)
            return
        finally:
            self._record_auto_update_failed_versions(old_app, new_app)

        if rc:
            # Ensure that the old app plugins are enabled after recovery
            _activate_old_app_plugins(old_app)

            self._update_app_status(
                old_app, constants.APP_APPLY_SUCCESS,
                constants.APP_PROGRESS_UPDATE_ABORTED.format(old_app.version, new_app.version) +
                constants.APP_PROGRESS_RECOVER_COMPLETED.format(old_app.version) +
                'Please check logs for details.')
            # Recovery from an app update failure succeeded, clear app alarm
            self._clear_app_alarm(old_app.name)
            LOG.info("Application %s recover to version %s completed."
                     % (old_app.name, old_app.version))
        else:
            self._plugins.deactivate_plugins(old_app)
            self._update_app_status(
                old_app, constants.APP_APPLY_FAILURE,
                constants.APP_PROGRESS_UPDATE_ABORTED.format(old_app.version, new_app.version) +
                constants.APP_PROGRESS_RECOVER_ABORTED.format(old_app.version) +
                old_app.error_message +
                'Please check logs for details.')
            LOG.error("Application %s recover to version %s aborted!"
                    % (old_app.name, old_app.version))

    def perform_app_upload(self, rpc_app, tarfile, images=False, transitory_state=None):
        """Process application upload request

        This method validates the application manifest. If Helm charts are
        included, they are validated and uploaded to local Helm repo. It also
        downloads the required docker images for custom apps during upload
        stage.

        :param rpc_app: application object in the RPC request
        :param tarfile: location of application tarfile
        :param images: save application images in the registry as part of app upload

        """

        app = AppOperator.Application(rpc_app)
        LOG.info("Application %s (%s) upload started." % (app.name, app.version))

        try:
            app.tarfile = tarfile

            if cutils.is_url(app.tarfile):
                self._update_app_status(
                    app, new_progress=constants.APP_PROGRESS_TARFILE_DOWNLOAD)

                downloaded_tarfile = self._download_tarfile(app)

                if downloaded_tarfile is None:
                    raise exception.KubeAppUploadFailure(
                        name=app.name,
                        version=app.version,
                        reason="Failed to find the downloaded tarball.")
                else:
                    app.tarfile = downloaded_tarfile

                app.downloaded_tarfile = True

            # Full extraction of application tarball at /scratch/apps.
            # Manifest file is placed under /opt/platform/fluxcd
            # which is managed by drbd-sync and visible to fluxcd.
            self._update_app_status(
                app, new_progress=constants.APP_PROGRESS_EXTRACT_TARFILE)

            with self._lock:
                self._extract_tarfile(app)
                self._plugins.install_plugins(app)

            manifest_sync_path = app.sync_fluxcd_manifest
            manifest_sync_dir_path = app.sync_fluxcd_manifest_dir
            validate_manifest = manifest_sync_path
            validate_function = self._fluxcd.make_fluxcd_operation

            # Copy the manifest and metadata file to the drbd
            if os.path.isdir(app.inst_mfile):
                shutil.copytree(app.inst_mfile, manifest_sync_path)
            else:
                shutil.copy(app.inst_mfile, manifest_sync_path)
            inst_metadata_file = os.path.join(
                app.inst_path, constants.APP_METADATA_FILE)
            if os.path.exists(inst_metadata_file):
                sync_metadata_file = os.path.join(
                    manifest_sync_dir_path, constants.APP_METADATA_FILE)
                shutil.copy(inst_metadata_file, sync_metadata_file)

            validation_result = validate_function(constants.APP_VALIDATE_OP,
                                                     validate_manifest)
            if not validation_result:
                raise exception.KubeAppUploadFailure(
                    name=app.name,
                    version=app.version,
                    reason="Failed to validate application manifest.")

            self._update_app_status(
                app, new_progress=constants.APP_PROGRESS_VALIDATE_UPLOAD_CHARTS)

            if os.path.isdir(app.inst_charts_dir):
                self._validate_helm_charts(app)
                with self._lock:
                    self._upload_helm_charts(app)

            # System overrides will be generated here.
            self._save_images_list(app)

            if images:
                # We need to download the images at upload_app so that subclouds
                # may use the distributed cloud registry
                self._update_app_status(
                    app, new_progress=constants.APP_PROGRESS_DOWNLOAD_IMAGES)

                if AppOperator.is_app_aborted(app.name):
                    raise exception.KubeAppAbort()

                self.download_images(app)

            if app.patch_dependencies:
                self._utils._patch_report_app_dependencies(
                    app.name + '-' + app.version, app.patch_dependencies)
            self._create_app_releases_version(app.name, app.charts)

            # Retrieve the application metadata from the metadata file
            metadata_file = self.retrieve_application_metadata_from_file(app.sync_metadata_file)

            # Check if the application has dependent apps missing
            dependent_apps_missing_list = app_dependents.get_dependent_apps_missing(
                metadata_file, self._dbapi)

            operation_status = transitory_state if transitory_state \
                else constants.APP_UPLOAD_SUCCESS

            if dependent_apps_missing_list:
                # Update the application status to APP_UPLOAD_SUCCESS with a message
                # indicating that the application has dependent apps missing.
                missing_apps = ', '.join(
                    [f"{app['name']} (version: {app['version']})"
                     for app in dependent_apps_missing_list]
                )

                LOG.warning(
                    f"Application {app.name} ({app.version}) upload completed. "
                    f"This app has dependent apps missing: {missing_apps}. "
                    "Please install the missing apps first before starting the apply process."
                )

                # Merge the progress message with the dependent apps missing message
                progress_msg = (
                    f"{constants.APP_PROGRESS_COMPLETED} - "
                    f"this app depends on the following missing apps: {missing_apps}"
                )
                self._update_app_status(app, operation_status, progress_msg)
            else:
                self._update_app_status(app, operation_status, constants.APP_PROGRESS_COMPLETED)
                LOG.info("Application %s (%s) upload completed." % (app.name, app.version))

            return app
        except exception.KubeAppUploadFailure as e:
            LOG.exception(e)
            self._abort_operation(app, constants.APP_UPLOAD_OP, str(e))
            raise
        except Exception as e:
            LOG.exception(e)
            self._abort_operation(app, constants.APP_UPLOAD_OP)
            raise exception.KubeAppUploadFailure(
                name=app.name, version=app.version, reason=e)

    def set_reapply(self, app_name):
        lock_name = "%s_%s" % (LOCK_NAME_APP_REAPPLY, app_name)

        @cutils.synchronized(lock_name, external=False)
        def _sync_set_reapply(app_name):
            return self._unsafe_set_reapply(app_name)
        return _sync_set_reapply(app_name)

    def _unsafe_set_reapply(self, app_name):
        # Create app reapply flag
        reapply_flag = cutils.app_reapply_flag_file(app_name)
        open(reapply_flag, "w").close()

        # Raise the pending automatic reapply alarm
        entity = cutils.app_reapply_pending_fault_entity(app_name)
        fault = fm_api.Fault(
                alarm_id=fm_constants.FM_ALARM_ID_APPLICATION_REAPPLY_PENDING,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_APPLICATION,
                entity_instance_id=entity,
                severity=fm_constants.FM_ALARM_SEVERITY_WARNING,
                reason_text=_(
                    "A configuration change requires a reapply of "
                    "the %s application.") % app_name,
                alarm_type=fm_constants.FM_ALARM_TYPE_0,
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_UNKNOWN,
                proposed_repair_action=_(
                    "The application will be automatically reapplied."),
                service_affecting=False)
        self._fm_api.set_fault(fault)

    def clear_reapply(self, app_name):
        lock_name = "%s_%s" % (LOCK_NAME_APP_REAPPLY, app_name)

        @cutils.synchronized(lock_name, external=False)
        def _sync_clear_reapply(app_name):
            return self._unsafe_clear_reapply(app_name)
        return _sync_clear_reapply(app_name)

    def _unsafe_clear_reapply(self, app_name):
        # Remove app reapply flag
        try:
            reapply_flag = cutils.app_reapply_flag_file(app_name)
            os.remove(reapply_flag)
        except OSError:
            pass

        # Clear the pending automatic reapply alarm
        target_entity = cutils.app_reapply_pending_fault_entity(app_name)
        for alarm in self._fm_api.get_faults_by_id(
                fm_constants.FM_ALARM_ID_APPLICATION_REAPPLY_PENDING) or []:
            if alarm.entity_instance_id == target_entity:
                self._fm_api.clear_fault(alarm.alarm_id,
                                         alarm.entity_instance_id)

    def needs_reapply(self, app_name):
        lock_name = "%s_%s" % (LOCK_NAME_APP_REAPPLY, app_name)

        @cutils.synchronized(lock_name, external=False)
        def _sync_needs_reapply(app_name):
            return self._unsafe_needs_reapply(app_name)
        return _sync_needs_reapply(app_name)

    def _unsafe_needs_reapply(self, app_name):
        reapply_flag = cutils.app_reapply_flag_file(app_name)
        flag_exists = os.path.isfile(reapply_flag)
        if not flag_exists:
            # Clear any stuck reapply alarm
            target_entity = cutils.app_reapply_pending_fault_entity(app_name)
            for alarm in self._fm_api.get_faults_by_id(
                    fm_constants.FM_ALARM_ID_APPLICATION_REAPPLY_PENDING) or []:
                if alarm.entity_instance_id == target_entity:
                    self._fm_api.clear_fault(alarm.alarm_id,
                                             alarm.entity_instance_id)
        return flag_exists

    def app_lifecycle_actions(self, context, conductor_obj, rpc_app, hook_info):
        """Perform application specific lifecycle actions

        This method will perform any lifecycle actions necessary for the
        application based on the operation and relative_timing of the operation.

        :param context: request context
        :param conductor_obj: conductor object
        :param rpc_app: application object in the RPC request
        :param hook_info: LifecycleHookInfo object

        """

        app = AppOperator.Application(rpc_app)

        # TODO(dvoicule): activate plugins once on upload, deactivate once during delete
        # create another commit for this
        self.activate_app_plugins(rpc_app)

        LOG.info("lifecycle hook for application {} ({}) started {}."
                 .format(app.name, app.version, hook_info))

        lifecycle_op = self._helm.get_app_lifecycle_operator(app.name)
        lifecycle_op.app_lifecycle_actions(context, conductor_obj, self, app, hook_info)

    @staticmethod
    def recompute_app_evaluation_order(apps_metadata_dict):
        """
        Recomputes the evaluation order of applications based on their metadata
        and categorizes them into dependent apps, class-based apps, and independent apps.
        Args:
            apps_metadata_dict (dict): A dictionary containing metadata about applications.
                It must include the following keys:
                - constants.APP_METADATA_PLATFORM_MANAGED_APPS: A list of platform-managed app names.
                - constants.APP_METADATA_APPS: A dictionary where keys are app names and values
                  are metadata dictionaries for each app.
        Modifies:
            apps_metadata_dict (dict): Adds a new key, constants.APP_METADATA_ORDERED_APPS,
            which contains an ordered dictionary.
        """

        # Initialize the ordered_apps dictionary
        ordered_apps = {
            constants.APP_METADATA_DEPENDENT_APPS: [],
            constants.APP_METADATA_CLASS: {
                constants.APP_METADATA_CLASS_CRITICAL: [],
                constants.APP_METADATA_CLASS_STORAGE: [],
                constants.APP_METADATA_CLASS_DISCOVERY: [],
                constants.APP_METADATA_CLASS_OPTIONAL: [],
                constants.APP_METADATA_CLASS_REPORTING: []
            },
            constants.APP_METADATA_INDEPENDENT_APPS: []
        }

        # Iterate through the platform-managed apps
        # and categorize them based on their metadata
        for app_name in apps_metadata_dict[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:

            app_metadata = apps_metadata_dict[constants.APP_METADATA_APPS][app_name]
            app_class = app_metadata.get(constants.APP_METADATA_CLASS, None)

            if app_metadata.get(constants.APP_METADATA_DEPENDENT_APPS, None):
                # This app has dependent apps
                ordered_apps[constants.APP_METADATA_DEPENDENT_APPS].append(app_name)

                # If the app has dependent apps, it should not be in the class-based apps
                continue
            elif app_class:
                # This app has class
                ordered_apps[constants.APP_METADATA_CLASS][app_class].append(app_name)
            else:
                # This app is independent
                ordered_apps[constants.APP_METADATA_INDEPENDENT_APPS].append(app_name)

        # Sort the dependent apps
        ordered_apps[constants.APP_METADATA_DEPENDENT_APPS].sort()
        # Sort the independent apps
        ordered_apps[constants.APP_METADATA_INDEPENDENT_APPS].sort()

        LOG.info("Applications reapply order dict: {}".format(ordered_apps))
        apps_metadata_dict[constants.APP_METADATA_ORDERED_APPS] = ordered_apps

    @staticmethod
    def recompute_app_evaluation_order_by_after_key(apps_metadata_dict):
        """ Get the order of app reapplies based on dependencies

        The following algorithm uses these concepts:
        Root apps are apps that have no dependency.
        Chain depth for an app is the number of apps that form the longest
        chain ending in the current app.

        Main logic:
        Compute reverse graph (after_apps).
        Determine root apps.
        Detect cycles and abort.
        Compute the longest dependency chain.
        Traverse again to populate ordered list.

        Assumptions:
        In theory there is one or few root apps that are dominant vertices.
        Other than the dominant vertices, there are very sparse vertices with
        a degree more than one, most of the vertices are either leaves or
        isolated.
        Chain depth is usually 0 or 1, few apps have a chain depth of 2, 3, 4
        The structure is a sparse digraph, or multiple separate sparse digraphs
        with a total number of vertices equal to the number of apps.

        Complexity analysis:
        Spatial complexity O(V+E)
        Cycle detection: O(V+E)

        After cycle detection the graph is a DAG.
        For computing the chain depth and final traversal a subgraph may be
        revisited. Complexity would be O(V*E).

        Let k = number of apps with a vertex that have the in degree > 1 and
        that are not leaf apps. We can bind k to be 0<=k<=10000, shall we reach
        that app number.

        Each node and each vertex will be visited once O(V+E) (root apps
        + vertex to leaf).
        Only k nodes will trigger a revisit of a subset of vertices (k * O(E)).

        Complexity now becomes O(V+(k+1)*E) = O(V+E)

        Limitations:
        If an app(current) depends only on non-existing apps, then
        current app will not be properly ordered. It will not be present in
        the ordered list before other apps based on it.
        If an app(current) depends only on non platform managed apps, then
        current app will not be properly ordered. It will not be present in
        the ordered list before other apps based on it.

        :param: apps_metadata_dict dictionary containing parsed and processed
                metadata collection

        :return: Sorted list containing the app reapply order.
        """
        # Apps directly after current
        after_apps = {}

        # Remember the maximum depth
        chain_depth = {}

        # Used to detect cycles
        cycle_depth = {}

        # Used for second traversal when populating ordered list
        traverse_depth = {}

        # Final result
        ordered_apps = []
        apps_metadata_dict[constants.APP_METADATA_ORDERED_APPS_BY_AFTER_KEY] = ordered_apps

        # Initialize structures
        for app_name in apps_metadata_dict[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
            after_apps[app_name] = []
            chain_depth[app_name] = 0
            cycle_depth[app_name] = 0
            traverse_depth[app_name] = 0

        # For each app remember which apps are directly after
        for app_name in apps_metadata_dict[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
            app_metadata = apps_metadata_dict[constants.APP_METADATA_APPS][app_name]
            metadata_after = app_metadata.get(constants.APP_METADATA_BEHAVIOR, None)

            if metadata_after is not None:
                metadata_after = metadata_after.get(constants.APP_METADATA_EVALUATE_REAPPLY, None)
            if metadata_after is not None:
                metadata_after = metadata_after.get(constants.APP_METADATA_AFTER, None)
            if metadata_after is not None:
                for before_app in metadata_after:
                    # This one may be a non-existing app, need to initialize
                    if after_apps.get(before_app, None) is None:
                        after_apps[before_app] = []

                    # Store information
                    after_apps[before_app].append(app_name)

                    # Remember that current app is before at least one
                    chain_depth[app_name] = 1
                    traverse_depth[app_name] = 1

        # Identify root apps
        root_apps = []
        for app_name in apps_metadata_dict[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
            if chain_depth.get(app_name, None) == 0:
                root_apps.append(app_name)

        # Used for cycle detection
        stack_ = queue.LifoQueue()
        cycle_checked = {}
        max_depth = len(apps_metadata_dict[constants.APP_METADATA_PLATFORM_MANAGED_APPS])

        # Detect cycles and abort
        for app_name in apps_metadata_dict[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
            # Skip already checked app
            if cycle_checked.get(app_name, False) is True:
                continue

            # Start from this
            stack_.put(app_name)

            # Reinitialize temporary visited
            visited = {}

            # Traverse DFS to detect cycles
            while not stack_.empty():
                app_name = stack_.get_nowait()
                visited[app_name] = True

                # Skip already checked app
                if cycle_checked.get(app_name, False) is True:
                    continue

                for after in after_apps[app_name]:
                    cycle_depth[after] = max(cycle_depth[app_name] + 1, cycle_depth[after])
                    # Detected cycle
                    if cycle_depth[after] > max_depth:
                        return ordered_apps

                    stack_.put(after)

            # Remember the temporary visited apps to skip them in the future
            for r in visited.keys():
                cycle_checked[r] = True

        # Used for traversal
        queue_ = queue.Queue()

        # Compute the longest dependency chain starting from root apps
        for app_name in root_apps:
            queue_.put(app_name)

        # Traverse similar to BFS to compute the longest dependency chain
        while not queue_.empty():
            app_name = queue_.get_nowait()
            for after in after_apps[app_name]:
                chain_depth[after] = max(chain_depth[app_name] + 1, chain_depth[after])
                queue_.put(after)

        # Traverse graph again similar to BFS
        # Add to ordered list when the correct chain depth is reached
        found = {}
        for app_name in root_apps:
            queue_.put(app_name)
            found[app_name] = True
            ordered_apps.append(app_name)

        while not queue_.empty():
            app_name = queue_.get_nowait()

            for after in after_apps[app_name]:
                traverse_depth[after] = max(traverse_depth[app_name] + 1, traverse_depth[after])

                # This is the correct depth, add to ordered list
                if traverse_depth[after] == chain_depth[after]:
                    # Skip if already added
                    if found.get(after, False) is True:
                        continue

                    found[after] = True
                    ordered_apps.append(after)

                queue_.put(after)

        # Add apps that have dependencies on non-existing apps
        for app_name in apps_metadata_dict[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
            if found.get(app_name, False) is True:
                continue
            ordered_apps.append(app_name)

        LOG.info("Applications reapply order: {}".format(ordered_apps))
        apps_metadata_dict[constants.APP_METADATA_ORDERED_APPS_BY_AFTER_KEY] = ordered_apps

    @staticmethod
    @cutils.synchronized(LOCK_NAME_PROCESS_APP_METADATA, external=False)
    def update_and_process_app_metadata(apps_metadata_dict, app_name, metadata, overwrite=True):
        """ Update the cached metadata for an app

        :param apps_metadata_dict: The dictionary being the cache
        :param app_name: Name of the app
        :param metadata: Metadata that will replace the old one
        :param overwrite: If metadata is already present in the cache for this app,
                          then overwrite needs to be enabled to do the replacement

        """

        # sysinv-helm command execution produces an empty cache. If empty, prime the
        # cache with expected keys.
        if not bool(apps_metadata_dict):
            for k in [constants.APP_METADATA_APPS,
                      constants.APP_METADATA_PLATFORM_MANAGED_APPS,
                      constants.APP_METADATA_DESIRED_STATES]:
                apps_metadata_dict[k] = {}

        if not overwrite and \
                app_name in apps_metadata_dict[constants.APP_METADATA_APPS]:
            LOG.info("Updating metadata for app {} skipped because metadata "
                     "is present and overwrite is not enabled"
                     "".format(app_name))
            return

        apps_metadata_dict[constants.APP_METADATA_APPS][app_name] = metadata
        LOG.info("Loaded metadata for app {}: {}".format(app_name, metadata))

        behavior = metadata.get(constants.APP_METADATA_BEHAVIOR, None)
        if behavior is not None:
            is_managed = behavior.get(constants.APP_METADATA_PLATFORM_MANAGED_APP, None)
            desired_state = behavior.get(constants.APP_METADATA_DESIRED_STATE, None)

            # Remember if the app wants to be managed by the platform
            if cutils.is_valid_boolstr(is_managed):
                apps_metadata_dict[
                    constants.APP_METADATA_PLATFORM_MANAGED_APPS][app_name] = None
                LOG.info("App {} requested to be platform managed"
                         "".format(app_name))

                # Recompute app reapply order
                # TODO(dbarbosa): remove this after the previous release no longer use
                # the after key in the metadata of the platform apps
                if app_metadata.has_after_key_in_apps_metadata(
                        apps_metadata_dict[constants.APP_METADATA_APPS]):
                    AppOperator.recompute_app_evaluation_order_by_after_key(apps_metadata_dict)
                else:
                    AppOperator.recompute_app_evaluation_order(apps_metadata_dict)

            # Remember the desired state the app should achieve
            if desired_state is not None:
                apps_metadata_dict[
                    constants.APP_METADATA_DESIRED_STATES][app_name] = desired_state
                LOG.info("App {} requested to achieve {} state"
                         "".format(app_name, desired_state))

        dependent_apps = metadata.get(constants.APP_METADATA_DEPENDENT_APPS, None)
        if dependent_apps is not None:
            apps_metadata_dict[constants.APP_METADATA_APPS][app_name][
                constants.APP_METADATA_DEPENDENT_APPS] = dependent_apps
            LOG.info("App {} has dependent apps: {}"
                     "".format(app_name, dependent_apps))

    def load_application_metadata_from_database(self, rpc_app):
        """ Load the application metadata from the database

        :param rpc_app: KubeApp model object

        """
        LOG.info("Loading application metadata for {} from database"
                 "".format(rpc_app.name))

        app = AppOperator.Application(rpc_app)
        metadata = {}

        # Load metadata as a dictionary from a column in the database
        db_app = self._dbapi.kube_app_get(app.name)
        if db_app.app_metadata:
            metadata = db_app.app_metadata or {}

        AppOperator.update_and_process_app_metadata(self._apps_metadata,
                                                    app.name,
                                                    metadata)

    @staticmethod
    def retrieve_application_metadata_from_file(sync_metadata_file):
        """ Retrieve application metadata from the metadata file of the app

        :param sync_metadata_file: metadata file path

        :return dictionary: metadata fields and respective values
        """

        metadata = {}
        if os.path.exists(sync_metadata_file):
            with io.open(sync_metadata_file, 'r', encoding='utf-8') as f:
                # The RoundTripLoader removes the superfluous quotes by default.
                # Set preserve_quotes=True to preserve all the quotes.
                # The assumption here: there is just one yaml section
                metadata = yaml.load(
                    f, Loader=yaml.RoundTripLoader, preserve_quotes=True) or {}

        return metadata

    def load_application_metadata_from_file(self, rpc_app):
        """ Load the application metadata from the metadata file of the app

        :param rpc_app: data object provided in the rpc request

        """
        LOG.info("Loading application metadata for {} from file"
                 "".format(rpc_app.name))

        app = AppOperator.Application(rpc_app)
        metadata = self.retrieve_application_metadata_from_file(app.sync_metadata_file)

        AppOperator.update_and_process_app_metadata(self._apps_metadata,
                                                    app.name,
                                                    metadata)

        # Save metadata as a dictionary in a column in the database
        rpc_app.app_metadata = metadata
        rpc_app.save()

    @staticmethod
    def get_desired_state_from_metadata(app_metadata):
        """ Retrieve desired state from application metadata

        :param app_metadata: full application metadata

        :return string: desired application state
        """

        desired_state = None
        behavior = app_metadata.get(constants.APP_METADATA_BEHAVIOR, None)
        if behavior is not None:
            desired_state = behavior.get(constants.APP_METADATA_DESIRED_STATE, None)

        return desired_state

    def update_desired_state(self, app, required_desired_state, new_desired_state):
        """ Update application desired state

        This method updates the application 'desired_state'
        metadata field on the database.

        :param app: AppOperator application object
        :param required_desired_state: desired state the app is required
                                       to have in the database
        :param new_desired_state: new desired state that will be saved
                                  to the database
        """

        current_desired_state = self.get_desired_state_from_metadata(app.app_metadata)

        if current_desired_state == required_desired_state:
            metadata = copy.deepcopy(app.app_metadata)

            if new_desired_state is None and \
                    constants.APP_METADATA_BEHAVIOR in metadata and \
                    constants.APP_METADATA_DESIRED_STATE in metadata[constants.APP_METADATA_BEHAVIOR]:
                del metadata[
                    constants.APP_METADATA_BEHAVIOR][
                    constants.APP_METADATA_DESIRED_STATE]
            else:
                metadata[
                    constants.APP_METADATA_BEHAVIOR][
                    constants.APP_METADATA_DESIRED_STATE] = new_desired_state

            app.update_app_metadata(metadata)
            AppOperator.update_and_process_app_metadata(self._apps_metadata,
                                                        app.name,
                                                        metadata)

    def _remove_from_metadata_dict(self, app_name):
        """Remove all the information about an app in apps_metadada dict

        This method will perform the removal of an app in all collections from
        self._apps_metadata. It is called after an application delete.

        :param app_name: Name of the app
        """

        if app_name in self._apps_metadata[constants.APP_METADATA_APPS]:
            del self._apps_metadata[constants.APP_METADATA_APPS][app_name]
        if app_name in self._apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
            del self._apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS][app_name]
        if app_name in self._apps_metadata[constants.APP_METADATA_DESIRED_STATES]:
            del self._apps_metadata[constants.APP_METADATA_DESIRED_STATES][app_name]
        if app_metadata.has_after_key_in_apps_metadata(self._apps_metadata[
                constants.APP_METADATA_APPS]):
            if app_name in self._apps_metadata[constants.APP_METADATA_ORDERED_APPS]:
                self._apps_metadata[
                    constants.APP_METADATA_ORDERED_APPS_BY_AFTER_KEY].remove(app_name)
        else:
            # Remove from dependent_apps
            if app_name in self._apps_metadata[constants.APP_METADATA_ORDERED_APPS][
                    constants.APP_METADATA_DEPENDENT_APPS]:
                self._apps_metadata[constants.APP_METADATA_ORDERED_APPS][
                    constants.APP_METADATA_DEPENDENT_APPS].remove(app_name)

            # Remove from class categories
            for category in self._apps_metadata[constants.APP_METADATA_ORDERED_APPS][
                    constants.APP_METADATA_CLASS]:
                if app_name in self._apps_metadata[constants.APP_METADATA_ORDERED_APPS][
                        constants.APP_METADATA_CLASS][category]:
                    self._apps_metadata[constants.APP_METADATA_ORDERED_APPS][
                        constants.APP_METADATA_CLASS][category].remove(app_name)

            # Remove from independent_apps
            if app_name in self._apps_metadata[constants.APP_METADATA_ORDERED_APPS][
                    constants.APP_METADATA_INDEPENDENT_APPS]:
                self._apps_metadata[constants.APP_METADATA_ORDERED_APPS][
                    constants.APP_METADATA_INDEPENDENT_APPS].remove(app_name)

        LOG.info(f"Removed app {app_name} from ordered_apps")

    def perform_app_apply(self, rpc_app, mode, lifecycle_hook_info_app_apply, caller=None,
                          is_reapply_process=False):
        """Process application install request

        This method processes node labels per configuration and invokes
        fluxcd to apply the application manifest.

        For OpenStack app (system app), the method generates combined
        overrides (a merge between system and user overrides if available)
        for the charts that comprise the app before downloading docker images
        and applying the manifest.

        Usage: the method can be invoked at initial install or after the
               user has either made some manual configuration changes or
               or applied (new) user overrides to some Helm chart(s) to
               correct/update a previous manifest apply.

        :param rpc_app: application object in the RPC request
        :param mode: mode to control how to apply application manifest
        :param lifecycle_hook_info_app_apply: LifecycleHookInfo object
        :param caller: internal caller, None if it is an RPC call,
                       otherwise apply is invoked from update method

        :return boolean: whether application apply was successful
        """

        def promote_desired_state(app):
            """ Promote application desired state from uploaded to applied

            This method makes sure that applied apps will keep the 'applied'
            state when reapplying them across sysinv-conductor restarts.

            :param app: AppOperator application object
            """

            self.update_desired_state(app, constants.APP_UPLOAD_SUCCESS, constants.APP_APPLY_SUCCESS)

        app = AppOperator.Application(rpc_app)

        # If apply is called from update method, the app's abort status has
        # already been registered.
        if not caller:
            self._register_app_abort(app.name)
            self._raise_app_alarm(app.name, constants.APP_APPLY_IN_PROGRESS,
                                  fm_constants.FM_ALARM_ID_APPLICATION_APPLYING,
                                  fm_constants.FM_ALARM_SEVERITY_WARNING,
                                  _("Application Apply In Progress"),
                                  fm_constants.FM_ALARM_TYPE_0,
                                  _("No action required."),
                                  True)

        self.clear_reapply(app.name)

        LOG.info("Application %s (%s) apply started." % (app.name, app.version))

        ready = True

        # Retrieve the application metadata from the metadata file
        app_metadata = self.retrieve_application_metadata_from_file(app.sync_metadata_file)
        # Check if the application has dependent apps missing
        dependent_apps_missing_list = app_dependents.get_dependent_apps_missing(
            app_metadata, self._dbapi)

        try:
            # Check if the application has dependent apps missing of action type 'APPLY'
            dependent_apps_error_type = app_dependents.get_dependent_apps_by_action(
                dependent_apps_missing_list, constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR)

            if dependent_apps_error_type:
                # Update the application status to APP_APPLY_FAILURE with a message
                # indicating that the application has dependent apps missing of
                # action type 'error'.
                progress_msg = (
                    "This app depends on the following missing apps: "
                    f"{dependent_apps_error_type}. Please install them and try to apply again."
                )
                self._update_app_status(
                    app, constants.APP_APPLY_FAILURE, progress_msg
                )
                LOG.error(
                    f"Application {app.name} ({app.version}) apply failed "
                    f"with dependent apps missing: {dependent_apps_error_type}."
                )
                return False

            # Helm Application overrides must be generated first so that any
            # helm overrides, such as enabling a chart will be added to the app
            # object.
            LOG.info("Generating application overrides...")

            self._update_app_status(
                app, new_progress=constants.APP_PROGRESS_GENERATE_OVERRIDES)

            app.charts = self._get_list_of_charts(app, include_disabled=True)

            helm_files = self._helm.generate_helm_application_overrides(
                    app.sync_overrides_dir, app.name, mode, cnamespace=None,
                    chart_info=app.charts, combined=True)

            if AppOperator.is_app_aborted(app.name):
                raise exception.KubeAppAbort()

            # Promote desired state if needed
            promote_desired_state(app)

            # Perform app resources actions
            lifecycle_hook_info_app_apply.relative_timing = \
                LifecycleConstants.APP_LIFECYCLE_TIMING_PRE
            lifecycle_hook_info_app_apply.lifecycle_type = \
                LifecycleConstants.APP_LIFECYCLE_TYPE_RESOURCE
            self.app_lifecycle_actions(None, None, rpc_app, lifecycle_hook_info_app_apply)

            # Perform rbd actions
            lifecycle_hook_info_app_apply.relative_timing = \
                LifecycleConstants.APP_LIFECYCLE_TIMING_PRE
            lifecycle_hook_info_app_apply.lifecycle_type = \
                LifecycleConstants.APP_LIFECYCLE_TYPE_RBD
            self.app_lifecycle_actions(None, None, rpc_app, lifecycle_hook_info_app_apply)

            if AppOperator.is_app_aborted(app.name):
                raise exception.KubeAppAbort()

            if helm_files:
                LOG.info("Application overrides generated.")
                LOG.info("Writing fluxcd overrides...")
                # put the helm_overrides in the chart's system-overrides.yaml
                self._write_fluxcd_overrides(app.charts, helm_files)
                LOG.info("Fluxcd overrides generated.")

                self._update_app_status(
                    app, new_progress=constants.APP_PROGRESS_DOWNLOAD_IMAGES)

                if AppOperator.is_app_aborted(app.name):
                    raise exception.KubeAppAbort()

                self.download_images(app)
            else:
                ready = False
                LOG.error(f"No Helm charts found for application {app.name}.")
        except Exception as e:
            LOG.exception(e)
            if AppOperator.is_app_aborted(app.name):
                self._abort_operation(app, constants.APP_APPLY_OP,
                                      user_initiated=True)
            else:
                self._abort_operation(app, constants.APP_APPLY_OP, str(e))

            if not caller:
                # If apply is not called from update method, deregister the app's
                # abort status. Otherwise, it will be done in the update method.
                self._deregister_app_abort(app.name)

            if isinstance(e, exception.KubeAppApplyFailure):
                # ex:Image download failure
                raise
            else:
                # ex:K8s resource creation failure, user abort
                raise exception.KubeAppApplyFailure(
                    name=app.name, version=app.version, reason=e)

        try:
            if ready:
                # Perform pre apply manifest actions
                lifecycle_hook_info_app_apply.relative_timing = \
                    LifecycleConstants.APP_LIFECYCLE_TIMING_PRE
                lifecycle_hook_info_app_apply.lifecycle_type = \
                    LifecycleConstants.APP_LIFECYCLE_TYPE_MANIFEST
                self.app_lifecycle_actions(None, None, rpc_app, lifecycle_hook_info_app_apply)

                self._update_app_status(
                    app, new_progress=constants.APP_PROGRESS_APPLY_MANIFEST)

                if AppOperator.is_app_aborted(app.name):
                    raise exception.KubeAppAbort()

                if caller == constants.RECOVER_VIA_REMOVAL:
                    return True

                if self._make_app_request(app, constants.APP_APPLY_OP, is_reapply_process, caller):
                    # Check if the application has dependent apps missing of action type 'warn'
                    dependent_apps_warn_type = app_dependents.get_dependent_apps_by_action(
                        dependent_apps_missing_list,
                        constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN
                    )

                    progress_msg = constants.APP_PROGRESS_COMPLETED
                    if dependent_apps_warn_type:
                        # Update the application status to APP_APPLY_SUCCESS with a message
                        # indicating that the application has dependent apps missing of
                        # action type 'warn'.
                        progress_msg = (
                            f"{constants.APP_PROGRESS_COMPLETED} - check /var/log/sysinv.log to "
                            "verify missing dependencies."
                        )

                    self._update_app_releases_version(app.name)
                    self._update_app_status(app,
                                            constants.APP_APPLY_SUCCESS,
                                            progress_msg)
                    app.update_active(True)
                    if not caller:
                        self._clear_app_alarm(app.name)

                    if dependent_apps_missing_list and dependent_apps_warn_type:
                        LOG.warning(
                            f"Application {app.name} ({app.version}) apply completed "
                            f"with dependent apps missing: {dependent_apps_warn_type}."
                        )
                    else:
                        LOG.info(f"Application {app.name} ({app.version}) apply completed.")

                    # Perform post apply manifest actions
                    lifecycle_hook_info_app_apply.relative_timing = \
                        LifecycleConstants.APP_LIFECYCLE_TIMING_POST
                    lifecycle_hook_info_app_apply.lifecycle_type = \
                        LifecycleConstants.APP_LIFECYCLE_TYPE_MANIFEST
                    (
                        lifecycle_hook_info_app_apply[LifecycleConstants.EXTRA]
                        [LifecycleConstants.MANIFEST_APPLIED]
                    ) = True
                    self.app_lifecycle_actions(None, None, rpc_app, lifecycle_hook_info_app_apply)

                    return True
        except Exception as e:
            # ex: update release version failure, user abort
            LOG.exception(e)

            # Perform post apply manifest actions
            lifecycle_hook_info_app_apply.relative_timing = \
                LifecycleConstants.APP_LIFECYCLE_TIMING_POST
            lifecycle_hook_info_app_apply.lifecycle_type = \
                LifecycleConstants.APP_LIFECYCLE_TYPE_MANIFEST
            (
                lifecycle_hook_info_app_apply[LifecycleConstants.EXTRA]
                [LifecycleConstants.MANIFEST_APPLIED]
            ) = False
            self.app_lifecycle_actions(None, None, rpc_app, lifecycle_hook_info_app_apply)

        # Perform rbd actions
        lifecycle_hook_info_app_apply.relative_timing = \
            LifecycleConstants.APP_LIFECYCLE_TIMING_POST
        lifecycle_hook_info_app_apply.lifecycle_type = LifecycleConstants.APP_LIFECYCLE_TYPE_RBD
        self.app_lifecycle_actions(None, None, rpc_app, lifecycle_hook_info_app_apply)

        # Perform app resources actions
        lifecycle_hook_info_app_apply.relative_timing = \
            LifecycleConstants.APP_LIFECYCLE_TIMING_POST
        lifecycle_hook_info_app_apply.lifecycle_type = \
            LifecycleConstants.APP_LIFECYCLE_TYPE_RESOURCE
        self.app_lifecycle_actions(None, None, rpc_app, lifecycle_hook_info_app_apply)

        # If it gets here, something went wrong
        if AppOperator.is_app_aborted(app.name):
            self._abort_operation(app, constants.APP_APPLY_OP, user_initiated=True)
        else:
            self._abort_operation(app, constants.APP_APPLY_OP)

        if not caller:
            # If apply is not called from update method, deregister the app's abort status.
            # Otherwise, it will be done in the update method.
            self._deregister_app_abort(app.name)

        return False

    def perform_app_update(self, from_rpc_app, to_rpc_app, tarfile,
                           lifecycle_hook_info_app_update, reuse_user_overrides=None,
                           reuse_attributes=None, k8s_version=None):
        """Process application update request

        This method leverages the existing application upload workflow to
        validate/upload the new application tarfile, then invokes fluxcd
        apply or rollback to update application from an applied version
        to the new version. If any failure happens during updating, the
        recover action will be triggered to recover the application to
        the old version.

        After apply/rollback to the new version is done, the files for the
        old application version will be cleaned up as well as the releases
        which are not in the new application version.

        The app status will be populated to "applied" once update is completed
        so that user can continue applying app with user overrides.

        Usage ex: the method can be used to update from v1 to v2 and also
                  update back from v2 to v1

        :param from_rpc_app: application object in the RPC request that
                             application updating from
        :param to_rpc_app: application object in the RPC request that
                           application updating to
        :param tarfile: location of application tarfile
        :param lifecycle_hook_info_app_update: LifecycleHookInfo object
        :param reuse_user_overrides: (optional) True or False
        :param reuse_attributes: (optional) True or False
        :param k8s_version: (optional) Target Kubernetes version
        :return: True if the update to the new version was successful. False otherwise.
        """

        from_app = AppOperator.Application(from_rpc_app)
        to_app = AppOperator.Application(to_rpc_app)

        self._register_app_abort(to_app.name)
        self._raise_app_alarm(to_app.name, constants.APP_UPDATE_IN_PROGRESS,
                              fm_constants.FM_ALARM_ID_APPLICATION_UPDATING,
                              fm_constants.FM_ALARM_SEVERITY_WARNING,
                              _("Application Update In Progress"),
                              fm_constants.FM_ALARM_TYPE_0,
                              _("No action required."),
                              True)
        LOG.info("Start updating Application %s from version %s to version %s ..."
                 % (to_app.name, from_app.version, to_app.version))

        try:
            self._update_app_status(
                to_app, new_progress=constants.APP_PROGRESS_UPDATE_STARTING)

            # Check if it's a downgrade operation. If true, create a lifecycle action.
            if LooseVersion(from_app.version) > LooseVersion(to_app.version):
                lifecycle_downgrade = copy.deepcopy(lifecycle_hook_info_app_update)
                lifecycle_downgrade.operation = constants.APP_DOWNGRADE_OP
                lifecycle_downgrade.relative_timing = LifecycleConstants.APP_LIFECYCLE_TIMING_PRE
                lifecycle_downgrade.lifecycle_type = LifecycleConstants.APP_LIFECYCLE_TYPE_RESOURCE
                lifecycle_downgrade[LifecycleConstants.EXTRA][
                    LifecycleConstants.FROM_APP_VERSION] = from_app.version
                lifecycle_downgrade[LifecycleConstants.EXTRA][
                    LifecycleConstants.TO_APP_VERSION] = to_app.version
                self.app_lifecycle_actions(None, None, from_rpc_app, lifecycle_downgrade)

            # Upload new app tarball. The upload will enable the new plugins to
            # generate overrides for images. Disable the plugins for the current
            # application as the new plugin module will have the same name. Only
            # one version of the module can be enabled at any given moment
            self._plugins.deactivate_plugins(from_app)

            to_app = self.perform_app_upload(
                to_rpc_app,
                tarfile,
                transitory_state=constants.APP_UPDATE_STARTING
            )

            # Reconcile existing FluxCD's Helm repositories
            resources_list = \
                cutils.get_resources_list_via_kubectl_kustomize(from_app.sync_fluxcd_manifest)
            helm_repos = cutils.filter_helm_repositories(resources_list)
            helm_utils.call_fluxcd_repository_reconciliation(helm_repos)

            lifecycle_hook_info_app_update.operation = constants.APP_UPDATE_OP

            # Get the skip_recovery flag from app metadata
            keys = [constants.APP_METADATA_UPGRADES,
                    constants.APP_METADATA_UPDATE_FAILURE_SKIP_RECOVERY]
            skip_recovery = bool(strtobool(str(self._get_metadata_value(to_app, keys, False))))

            # Semantic checking for N+1 app
            semantic_check_result = False
            try:
                lifecycle_hook_info = copy.deepcopy(lifecycle_hook_info_app_update)
                lifecycle_hook_info.relative_timing = LifecycleConstants.APP_LIFECYCLE_TIMING_PRE
                lifecycle_hook_info.lifecycle_type = \
                    LifecycleConstants.APP_LIFECYCLE_TYPE_SEMANTIC_CHECK
                lifecycle_hook_info[LifecycleConstants.EXTRA][LifecycleConstants.TO_APP] = True

                self.app_lifecycle_actions(None, None, to_rpc_app, lifecycle_hook_info)
                semantic_check_result = True
            except exception.LifecycleSemanticCheckException as e:
                LOG.info("App {} rejected operation {} for reason: {}"
                         "".format(to_app.name, constants.APP_UPDATE_OP, str(e)))
                if not skip_recovery:
                    self._perform_app_recover(to_rpc_app, from_app, to_app,
                                              lifecycle_hook_info_app_update,
                                              fluxcd_process_required=False)
                    return False
            except Exception as e:
                LOG.error("App {} operation {} semantic check error: {}"
                          "".format(to_app.name, constants.APP_UPDATE_OP, str(e)))
                if not skip_recovery:
                    self._perform_app_recover(to_rpc_app, from_app, to_app,
                                              lifecycle_hook_info_app_update,
                                              fluxcd_process_required=False)
                    return False

            if semantic_check_result:
                self.load_application_metadata_from_file(to_rpc_app)

                # Check whether the new application is compatible with the given k8s version.
                # If k8s_version is none the check is performed against the active version.
                self._utils._check_app_compatibility(to_app.name,
                                                     to_app.version,
                                                     k8s_version)

                self._update_app_status(to_app, constants.APP_UPDATE_IN_PROGRESS)

                lifecycle_hook_info.relative_timing = \
                   LifecycleConstants.APP_LIFECYCLE_TIMING_PRE
                lifecycle_hook_info.lifecycle_type = \
                    LifecycleConstants.APP_LIFECYCLE_TYPE_RESOURCE
                self.app_lifecycle_actions(None, None, to_rpc_app, lifecycle_hook_info)

                reuse_overrides = \
                    self._get_metadata_value(to_app,
                                                constants.APP_METADATA_MAINTAIN_USER_OVERRIDES,
                                                False)
                if reuse_user_overrides is not None:
                    reuse_overrides = reuse_user_overrides

                # Preserve user overrides for the new app
                if reuse_overrides:
                    self._preserve_user_overrides(from_app, to_app)

                reuse_app_attributes = \
                    self._get_metadata_value(to_app,
                                                constants.APP_METADATA_MAINTAIN_ATTRIBUTES,
                                                False)
                if reuse_attributes is not None:
                    reuse_app_attributes = reuse_attributes

                # Preserve attributes for the new app
                if reuse_app_attributes:
                    self._preserve_attributes(from_app, to_app)

                # The app_apply will generate new versioned overrides for the
                # app upgrade and will enable the new plugins for that version.
                lifecycle_hook_info_app_update.operation = constants.APP_APPLY_OP
                result = self.perform_app_apply(
                    to_rpc_app, mode=None,
                    lifecycle_hook_info_app_apply=lifecycle_hook_info_app_update,
                    caller=constants.APP_UPDATE_OP)
                lifecycle_hook_info_app_update.operation = constants.APP_UPDATE_OP

                operation_successful = result
            else:
                operation_successful = semantic_check_result

            # If operation failed consider doing the app recovery
            do_recovery = not operation_successful

            # Here the app operation failed (do_recovery is True)
            # but skip_recovery requested.
            if skip_recovery and do_recovery:
                LOG.info("Application %s (%s) has configured skip_recovery %s"
                         ", recovery skipped.",
                         to_app.name, to_app.version, skip_recovery)
                do_recovery = False

            # If recovery is requested stop the flow of execution here
            if do_recovery:
                LOG.error("Application %s update from version %s to version "
                          "%s aborted." % (to_app.name, from_app.version, to_app.version))
                self._perform_app_recover(to_rpc_app, from_app, to_app,
                                          lifecycle_hook_info_app_update)
                return False

            self._update_app_status(to_app, constants.APP_UPDATE_IN_PROGRESS,
                                    "cleanup application version {}".format(from_app.version))

            # App apply/rollback succeeded or it failed but skip_recovery was set
            # Starting cleanup old application
            from_app.charts = self._get_list_of_charts(from_app)
            to_app_charts = [c.release for c in to_app.charts]
            deployed_releases = helm_utils.retrieve_helm_releases()
            charts_to_delete = []
            for from_chart in from_app.charts:
                # Cleanup the releases in the old application version
                # but are not in the new application version
                if (from_chart.release not in to_app_charts and
                        from_chart.release in deployed_releases):

                    # Deletes secrets that are not in the n+1 app
                    self._fluxcd.run_kubectl_kustomize(constants.KUBECTL_KUSTOMIZE_DELETE,
                                                       from_chart.chart_os_path)

                    # Send delete request in FluxCD so it doesn't
                    # recreate the helm release
                    self._kube.delete_custom_resource(
                        constants.FLUXCD_CRD_HELM_REL_GROUP,
                        constants.FLUXCD_CRD_HELM_REL_VERSION,
                        from_chart.namespace,
                        constants.FLUXCD_CRD_HELM_REL_PLURAL,
                        from_chart.metadata_name)
                    # Use helm to immediately remove the release
                    helm_utils.delete_helm_release(from_chart.release,
                                                   from_chart.namespace)
                    LOG.info("Helm release %s for Application %s (%s) deleted"
                             % (from_chart.release, from_app.name,
                                from_app.version))
                for to_app_chart in to_app.charts:
                    if from_chart.chart_label == to_app_chart.chart_label \
                            and from_chart.chart_version \
                            != to_app_chart.chart_version:
                        charts_to_delete.append(from_chart)

            self._remove_app_charts_from_repo(from_app._kube_app.id,
                                              charts_to_delete)
            self._cleanup(from_app, app_dir=False)
            self._utils._patch_report_app_dependencies(
                from_app.name + '-' + from_app.version)

            # The initial operation for to_app is successful
            if operation_successful:
                self._update_app_status(
                    to_app, constants.APP_APPLY_SUCCESS,
                    constants.APP_PROGRESS_UPDATE_COMPLETED.format(
                        from_app.version, to_app.version))
                LOG.info("Application %s update from version %s to version "
                         "%s completed." % (to_app.name, from_app.version, to_app.version))

            # The initial operation for to_app failed
            # This is reached here only when skip_recovery is requested
            # Need to inform the user
            else:
                message = constants.APP_PROGRESS_UPDATE_FAILED_SKIP_RECOVERY.format(
                    to_app.name, from_app.version, to_app.version)
                self._update_app_status(to_app, constants.APP_APPLY_FAILURE, message)
                LOG.info(message)

        except (exception.IncompatibleKubeVersion,
                exception.KubeAppUploadFailure,
                exception.KubeAppApplyFailure,
                exception.KubeAppAbort) as e:
            # Error occurs during app uploading or applying but before
            # apply process...
            # ie.images download/k8s resource creation failure
            # Start recovering without trigger fluxcd process
            LOG.exception(e)
            self._perform_app_recover(to_rpc_app, from_app, to_app,
                                      lifecycle_hook_info_app_update,
                                      fluxcd_process_required=False)
            return False
        except Exception as e:
            # Application update successfully(fluxcd apply/rollback)
            # Error occurs during cleanup old app
            # ie. delete app files failure, patch controller failure,
            #     helm release delete failure
            self._update_app_status(
                to_app, constants.APP_APPLY_SUCCESS,
                constants.APP_PROGRESS_UPDATE_COMPLETED.format(from_app.version, to_app.version) +
                constants.APP_PROGRESS_CLEANUP_FAILED.format(from_app.version) +
                'please check logs for detail.')
            LOG.exception(e)
        finally:
            self._deregister_app_abort(to_app.name)

        self._clear_app_alarm(to_app.name)
        return operation_successful

    def perform_app_remove(self, rpc_app, lifecycle_hook_info_app_remove, force=False):
        """Process application remove request

        This method invokes fluxcd to delete the application manifest.
        For system app, it also cleans up old test pods.

        :param rpc_app: application object in the RPC request
        :param lifecycle_hook_info_app_remove: LifecycleHookInfo object
        :param force: If set to True, will set the app state to 'uploaded'
            instead of 'remove-failed' in case of an error

        :return boolean: whether application remove was successful
        """

        def demote_desired_state(app):
            """ Demote application desired state

            This method demotes applications that were promoted to the 'applied'
            desired state back to their original desired state.

            :param app: AppOperator application object
            """

            metadata = self.retrieve_application_metadata_from_file(app.sync_metadata_file)
            original_desired_state = self.get_desired_state_from_metadata(metadata)

            self.update_desired_state(app, constants.APP_APPLY_SUCCESS, original_desired_state)

        app = AppOperator.Application(rpc_app)
        self._register_app_abort(app.name)

        self.clear_reapply(app.name)
        LOG.info("Application (%s) remove started." % app.name)
        rc = True

        app.charts = self._get_list_of_charts(app)
        app.update_active(False)
        self._update_app_status(
            app, new_progress=constants.APP_PROGRESS_DELETE_MANIFEST)

        # Delete helm releases which have a helm operation running.
        # eg.: pending-install, pending-upgrade, etc.
        for chart in app.charts:
            release = chart.metadata_name
            namespace = chart.namespace

            helm_release_dict = self._kube.get_custom_resource(
                    constants.FLUXCD_CRD_HELM_REL_GROUP,
                    constants.FLUXCD_CRD_HELM_REL_VERSION,
                    namespace,
                    constants.FLUXCD_CRD_HELM_REL_PLURAL,
                    release)
            if not helm_release_dict:
                LOG.warning("FluxCD Helm release info for {} is not available".format(release))
                continue

            helm_release_status, _ = self._fluxcd.get_helm_release_status(helm_release_dict)
            if helm_release_status == self._fluxcd.HELM_RELEASE_STATUS_UNKNOWN:
                LOG.info("Removing helm release which has an operation in "
                         "progress: {} - {}".format(namespace, release))
                # Send delete request in FluxCD so it doesn't recreate the helm
                # release
                self._kube.delete_custom_resource(
                    constants.FLUXCD_CRD_HELM_REL_GROUP,
                    constants.FLUXCD_CRD_HELM_REL_VERSION,
                    namespace,
                    constants.FLUXCD_CRD_HELM_REL_PLURAL,
                    release)
                # Remove resource in Helm
                helm_utils.delete_helm_release(
                    helm_release_dict['spec']['releaseName'],
                    namespace=namespace)

        if self._make_app_request(app, constants.APP_REMOVE_OP):
            # After fluxcd delete, the data for the releases are purged from
            # tiller/etcd, the releases info for the active app stored in sysinv
            # db should be set back to 0 and the inactive apps require to be
            # destroyed too.
            db_app = self._dbapi.kube_app_get(app.name)
            app_releases = self._dbapi.kube_app_chart_release_get_all(db_app.id)
            for r in app_releases:
                if r.version != 0:
                    self._dbapi.kube_app_chart_release_update(
                        db_app.id, r.release, r.namespace, {'version': 0})
            if self._dbapi.kube_app_get_inactive(app.name):
                self._dbapi.kube_app_destroy(app.name, inactive=True)

            try:
                # Restore original desired state if needed
                demote_desired_state(app)

                # Perform rbd actions
                lifecycle_hook_info_app_remove.relative_timing = \
                    LifecycleConstants.APP_LIFECYCLE_TIMING_POST
                lifecycle_hook_info_app_remove.lifecycle_type = \
                    LifecycleConstants.APP_LIFECYCLE_TYPE_RBD
                self.app_lifecycle_actions(None, None, rpc_app, lifecycle_hook_info_app_remove)

                # Perform app resources actions
                lifecycle_hook_info_app_remove.relative_timing = \
                    LifecycleConstants.APP_LIFECYCLE_TIMING_POST
                lifecycle_hook_info_app_remove.lifecycle_type = \
                    LifecycleConstants.APP_LIFECYCLE_TYPE_RESOURCE
                self.app_lifecycle_actions(None, None, rpc_app, lifecycle_hook_info_app_remove)

            except Exception as e:
                self._abort_operation(app, constants.APP_REMOVE_OP, forced_operation=force)
                LOG.exception(e)
                self._deregister_app_abort(app.name)
                return False

            self._update_app_status(app, constants.APP_UPLOAD_SUCCESS,
                                    constants.APP_PROGRESS_COMPLETED)
            # In case there is an existing alarm for previous remove failure
            self._clear_app_alarm(app.name)
            LOG.info("Application (%s) remove completed." % app.name)
        else:
            if AppOperator.is_app_aborted(app.name):
                # App is always set to APP_REMOVE_FAILURE if abort is initiated by user.
                self._abort_operation(app, constants.APP_REMOVE_OP,
                                      user_initiated=True, forced_operation=False)
            else:
                self._abort_operation(app, constants.APP_REMOVE_OP, forced_operation=force)
            rc = False

        self._deregister_app_abort(app.name)
        return rc

    def activate(self, rpc_app):
        app = AppOperator.Application(rpc_app)
        with self._lock:
            return app.update_active(True)

    def deactivate(self, rpc_app):
        app = AppOperator.Application(rpc_app)
        with self._lock:
            return app.update_active(False)

    def get_appname(self, rpc_app):
        app = AppOperator.Application(rpc_app)
        return app.name

    def is_app_active(self, rpc_app):
        app = AppOperator.Application(rpc_app)
        return app.active

    def perform_app_abort(self, rpc_app, lifecycle_hook_info):
        """Process application abort request

        This method retrieves the latest application status from the
        database and sets the abort flag if the apply/update/remove
        operation is still in progress. The corresponding app processing
        thread will check the flag and abort the operation in the very
        next opportunity.

        :param rpc_app: application object in the RPC request
        :param lifecycle_hook_info_app_abort: LifecycleHookInfo object

        """

        app = AppOperator.Application(rpc_app)

        # Retrieve the latest app status from the database
        db_app = self._dbapi.kube_app_get(app.name)

        aborted_operation = None
        if db_app.status == constants.APP_APPLY_IN_PROGRESS:
            aborted_operation = constants.APP_APPLY_OP
        elif db_app.status == constants.APP_UPDATE_IN_PROGRESS:
            aborted_operation = constants.APP_UPDATE_OP
        elif db_app.status == constants.APP_REMOVE_IN_PROGRESS:
            aborted_operation = constants.APP_REMOVE_OP

        if aborted_operation:
            # Run pre lifecycle hook for the abort operation
            lifecycle_hook_info.relative_timing = LifecycleConstants.APP_LIFECYCLE_TIMING_PRE
            lifecycle_hook_info.lifecycle_type = LifecycleConstants.APP_LIFECYCLE_TYPE_OPERATION
            lifecycle_hook_info.extra[LifecycleConstants.ABORTED_OP] = aborted_operation
            try:
                self.app_lifecycle_actions(None, None, rpc_app, lifecycle_hook_info)
            except Exception as e:
                LOG.error(f"Error while performing pre abort lifecycle actions: {e}")

            # Turn on the abort flag so the processing thread that is
            # in progress can bail out in the next opportunity.
            self._set_abort_flag(app.name)
        else:
            # Either the previous operation has completed or already failed
            LOG.info("Abort request ignored. The previous operation for app %s "
                     "has either completed or failed." % app.name)

    def perform_app_delete(self, rpc_app, lifecycle_hook_info_app_delete):
        """Process application remove request

        This method removes the application entry from the database and
        performs cleanup which entails removing node labels where applicable
        and purge all application files from the system.

        :param rpc_app: application object in the RPC request
        :param lifecycle_hook_info_app_delete: LifecycleHookInfo object

        """

        app = AppOperator.Application(rpc_app)
        try:
            # Perform rbd actions
            lifecycle_hook_info_app_delete.relative_timing = \
                LifecycleConstants.APP_LIFECYCLE_TIMING_PRE
            lifecycle_hook_info_app_delete.lifecycle_type = \
                LifecycleConstants.APP_LIFECYCLE_TYPE_RBD
            self.app_lifecycle_actions(None, None, rpc_app, lifecycle_hook_info_app_delete)

            # Perform app resources actions
            lifecycle_hook_info_app_delete.relative_timing = \
                LifecycleConstants.APP_LIFECYCLE_TIMING_PRE
            lifecycle_hook_info_app_delete.lifecycle_type = \
                LifecycleConstants.APP_LIFECYCLE_TYPE_RESOURCE
            self.app_lifecycle_actions(None, None, rpc_app, lifecycle_hook_info_app_delete)

            self._plugins.deactivate_plugins(app)

            self._dbapi.kube_app_destroy(app.name)
            app.charts = self._get_list_of_charts(app, include_disabled=True)
            self._cleanup(app)
            self._utils._patch_report_app_dependencies(app.name + '-' + app.version)
            # One last check of app alarm, should be no-op unless the
            # user deletes the application following an upload failure.
            self._clear_app_alarm(app.name)

            # Remove the deleted app from _apps_metadata, since it's
            # not in the system anymore.
            self._remove_from_metadata_dict(app.name)

            # Remove charts from Helm repository
            self._remove_app_charts_from_repo(app._kube_app.id, app.charts)

            LOG.info("Application (%s) has been purged from the system." %
                     app.name)
            msg = None
        except Exception as e:
            # Possible exceptions are KubeAppDeleteFailure,
            # OSError and unexpectedly KubeAppNotFound
            LOG.exception(e)
            msg = str(e)
        return msg

    class Application(object):
        """ Data object to encapsulate all data required to
            support application related operations.
        """

        def __init__(self, rpc_app):
            self._kube_app = rpc_app

            self.id = self._kube_app.get('id')
            self.tarfile = None
            self.downloaded_tarfile = False

            # Directories: Installation specific, local to a controller. Not
            # synced
            self.inst_path = os.path.join(constants.APP_INSTALL_PATH,
                                     self._kube_app.get('name'),
                                     self._kube_app.get('app_version'))
            self.inst_charts_dir = os.path.join(self.inst_path, 'charts')
            self.inst_images_dir = os.path.join(self.inst_path, 'images')
            self.inst_plugins_dir = os.path.join(self.inst_path, 'plugins')

            # Files: Installation specific, local to a controller. Not synced
            self.inst_mfile = generate_install_manifest_fqpn(
                self._kube_app.get('name'),
                self._kube_app.get('app_version'),
                self._kube_app.get('manifest_file'))

            # Directories: DRBD Synced between controllers
            self.sync_overrides_dir = generate_synced_helm_overrides_dir(
                self._kube_app.get('name'),
                self._kube_app.get('app_version'))
            self.sync_plugins_dir = generate_synced_app_plugins_dir(
                self._kube_app.get('name'),
                self._kube_app.get('app_version'))
            self.sync_fluxcd_manifest_dir = cutils.generate_synced_fluxcd_dir(
                self._kube_app.get('name'),
                self._kube_app.get('app_version'))

            # Files: DRBD synced between controllers
            self.sync_fluxcd_manifest = cutils.generate_synced_fluxcd_manifests_fqpn(
                self._kube_app.get('name'),
                self._kube_app.get('app_version'))

            self.sync_imgfile = generate_synced_fluxcd_images_fqpn(
                self._kube_app.get('name'),
                self._kube_app.get('app_version'))

            self.sync_metadata_file = cutils.generate_synced_fluxcd_metadata_fqpn(
                self._kube_app.get('name'),
                self._kube_app.get('app_version'))

            self.patch_dependencies = []
            self.charts = []
            self.releases = []
            self.error_message = ""

        @property
        def system_app(self):
            if (os.path.exists(self.sync_plugins_dir) and
                    os.listdir(self.sync_plugins_dir)):
                return True
            return False

        @property
        def name(self):
            return self._kube_app.get('name')

        @property
        def version(self):
            return self._kube_app.get('app_version')

        @property
        def status(self):
            return self._kube_app.get('status')

        @property
        def progress(self):
            return self._kube_app.get('progress')

        @property
        def active(self):
            return self._kube_app.get('active')

        @property
        def recovery_attempts(self):
            return self._kube_app.get('recovery_attempts')

        @property
        def mode(self):
            return self._kube_app.get('mode')

        @property
        def app_metadata(self):
            return self._kube_app.get('app_metadata')

        def update_app_metadata(self, new_metadata):
            if self.app_metadata != new_metadata:
                self._kube_app.app_metadata = new_metadata
                self._kube_app.save()

        def update_status(self, new_status, new_progress):
            self._kube_app.status = new_status
            if new_progress:
                self._kube_app.progress = new_progress
            self._kube_app.save()

        def update_active(self, active):
            was_active = self.active
            if active != self.active:
                self._kube_app.active = active
                self._kube_app.save()
            return was_active

        def update_error_message(self, new_error_message):
            self.error_message = new_error_message

        def clear_error_message(self):
            self.error_message = ""

        def regenerate_manifest_filename(self, new_mname, new_mfile):
            self._kube_app.manifest_name = new_mname
            self._kube_app.manifest_file = new_mfile
            self.inst_mfile = generate_install_manifest_fqpn(
                self.name, self.version, new_mfile)
            self.sync_fluxcd_manifest = cutils.generate_synced_fluxcd_manifests_fqpn(
                self.name, self.version)

        def regenerate_application_info(self, new_name, new_version, new_patch_dependencies):
            self._kube_app.name = new_name
            self._kube_app.app_version = new_version

            new_fluxcd_dir = cutils.generate_synced_fluxcd_dir(self.name, self.version)
            shutil.move(self.sync_fluxcd_manifest_dir, new_fluxcd_dir)
            shutil.rmtree(os.path.dirname(self.sync_fluxcd_manifest_dir))
            self.sync_fluxcd_manifest_dir = new_fluxcd_dir
            new_sync_imgfile = generate_synced_fluxcd_images_fqpn(self.name, self.version)

            new_path = os.path.join(
                constants.APP_INSTALL_PATH, self.name, self.version)
            shutil.move(self.inst_path, new_path)
            shutil.rmtree(os.path.dirname(self.inst_path))
            self.inst_path = new_path

            self.inst_charts_dir = os.path.join(self.inst_path, 'charts')
            self.inst_images_dir = os.path.join(self.inst_path, 'images')
            self.sync_imgfile = new_sync_imgfile
            self.sync_overrides_dir = generate_synced_helm_overrides_dir(self.name, self.version)
            self.patch_dependencies = new_patch_dependencies
            self.inst_plugins_dir = os.path.join(self.inst_path, 'plugins')
            self.sync_plugins_dir = generate_synced_app_plugins_dir(new_name, new_version)

    def check_fluxcd_pod_status(self):
        return self._fluxcd.check_fluxcd_pods_status()


class DockerHelper(object):
    """ Utility class to encapsulate Docker related operations """

    def __init__(self, dbapi):
        self._dbapi = dbapi
        self._crictl_image_list = []

    def _get_crictl_image_list(self):
        cmd = ['crictl', 'images', '--output=json']
        try:
            output = subprocess.check_output(  # pylint: disable=not-callable
                cmd, stderr=subprocess.STDOUT)
            crictl_output = json.loads(output)
        except json.JSONDecodeError as e:
            LOG.error('Could not parse json output, error=%s', e)
        except subprocess.CalledProcessError as e:
            LOG.error('Could not list images, error=%s', e)
        else:
            self._crictl_image_list = []
            for img in crictl_output['images']:
                self._crictl_image_list.extend(img['repoTags'])

        return self._crictl_image_list

    def set_crictl_image_list(self, image_list):
        self._crictl_image_list = image_list

    def _parse_barbican_secret(self, secret_ref):
        """Get the registry credentials from the
           barbican secret payload

           The format of the credentials stored in
           barbican secret:
           username:xxx password:xxx

        :param secret_ref: barbican secret ref/uuid
        :return: dict of registry credentials
        """
        operator = openstack.OpenStackOperator(self._dbapi)
        payload = operator.get_barbican_secret_payload(secret_ref)
        if not payload:
            raise exception.SysinvException(_(
                "Unable to get the payload of Barbican secret "
                "%s" % secret_ref))

        try:
            if not isinstance(payload, str):
                payload = payload.decode('utf-8')
            username, password = payload.split()
            username = username.split('username:')[1]
            password = password.split('password:')[1]
            return dict(username=username, password=password)
        except Exception as e:
            LOG.error("Unable to parse the secret payload, "
                      "unknown format of the registry secret: %s" % e)
            raise exception.SysinvException(_(
                "Unable to parse the secret payload"))

    def retrieve_specified_registries(self):
        registries_info = \
            copy.deepcopy(constants.DEFAULT_REGISTRIES_INFO)

        registries_url = {}
        registries_type = {}
        registries_auth = {}
        registries_overrides = {}

        registries = self._dbapi.service_parameter_get_all(
            service=constants.SERVICE_TYPE_DOCKER)
        for r in registries:
            if r.name == constants.SERVICE_PARAM_NAME_DOCKER_URL:
                registries_url.update({r.section: str(r.value)})
            elif r.name == constants.SERVICE_PARAM_NAME_DOCKER_TYPE:
                registries_type.update({r.section: str(r.value)})
            elif r.name == constants.SERVICE_PARAM_NAME_DOCKER_AUTH_SECRET:
                registries_auth.update({r.section: str(r.value)})
            elif r.name == constants.SERVICE_PARAM_NAME_DOCKER_ADDITIONAL_OVERRIDES:
                registries_overrides.update({r.section: str(r.value)})

        if not registries_url:
            # return directly if no user specified registries
            return registries_info

        for section, url in registries_url.items():
            try:
                registries_info[section]['registry_replaced'] = str(url)

                if section in registries_overrides:
                    registries_info[section]['registry_default'] = \
                        registries_overrides[section]

                if section in registries_auth:
                    secret_ref = registries_auth[section]
                    if secret_ref != 'None':
                        # If user specified registry requires the
                        # authentication, get the registry auth
                        # from barbican secret
                        auth = self._parse_barbican_secret(secret_ref)
                        if (section in registries_type and
                                registries_type[section] == constants.DOCKER_REGISTRY_TYPE_AWS_ECR):
                            auth = cutils.get_aws_ecr_registry_credentials(
                                self._dbapi, url, auth['username'], auth['password'])
                        registries_info[section]['registry_auth'] = auth
            except exception.SysinvException:
                raise exception.SysinvException(_(
                    "Unable to get the credentials to access "
                    "registry %s" % url))
            except KeyError:
                # Unexpected
                pass

        return registries_info

    def _get_img_tag_with_registry(self, pub_img_tag, registries_info):
        """Regenerate public image tag with user specified registries

           An example of passed public image reference:
           docker.io/starlingx/stx-keystone:latest
        """

        if registries_info == constants.DEFAULT_REGISTRIES_INFO:
            # return if no user specified registries
            return pub_img_tag, None

        for registry_info in registries_info.values():
            registry_auth = registry_info['registry_auth']

            if pub_img_tag.startswith(registry_info['registry_default']):
                registry = registry_info['registry_replaced']

                if registry:
                    img_name = pub_img_tag.split(
                        registry_info['registry_default'])[1]
                    return registry + img_name, registry_auth
                return pub_img_tag, registry_auth

            elif pub_img_tag.startswith(registry_info['registry_replaced']):
                return pub_img_tag, registry_auth

        # In case the image is overridden via "system helm-override-update"
        # with a custom registry that is not from any of the known registries
        # (ie..k8s.gcr.io, gcr.io, quay.io, docker.io. docker.elastic.co)
        # , pull directly from the custom registry (Note: The custom registry
        # must be unauthenticated in this case.)
        return pub_img_tag, None

    def download_an_image(self, app, registries_info, img_tag):

        rc = True

        if not self._crictl_image_list:
            self._get_crictl_image_list()

        start = time.time()
        if img_tag.startswith(constants.DOCKER_REGISTRY_HOST):
            try:
                if AppOperator.is_app_aborted(app.name):
                    LOG.info("User aborted. Skipping download of image %s " % img_tag)
                    return img_tag, False

                if img_tag not in self._crictl_image_list:
                    LOG.info("Image %s download started from local registry" % img_tag)
                    local_registry_auth = cutils.get_local_docker_registry_auth()
                    auth = '{0}:{1}'.format(local_registry_auth['username'],
                                            local_registry_auth['password'])
                    subprocess.check_call(  # pylint: disable=not-callable
                        ["crictl", "pull", "--creds", auth, img_tag])
                else:
                    LOG.info("Image %s exists in the local registry" % img_tag)
            except subprocess.CalledProcessError:
                try:
                    # Pull the image from the public/private registry
                    LOG.info("Image %s is not available in local registry, "
                             "download started from public/private registry"
                             % img_tag)

                    pub_img_tag = img_tag.replace(
                        constants.DOCKER_REGISTRY_SERVER + "/", "")

                    target_img_tag, registry_auth = \
                        self._get_img_tag_with_registry(pub_img_tag, registries_info)

                    client = docker.APIClient(
                        timeout=constants.APP_INSTALLATION_TIMEOUT)
                    client.pull(target_img_tag, auth_config=registry_auth)

                except Exception as e:
                    # Store the error in the app object for use in def _abort_operation
                    app.update_error_message("Failed to download image: " + target_img_tag)

                    rc = False
                    LOG.error("Image %s download failed from public/private"
                              "registry: %s" % (img_tag, e))
                    return img_tag, rc

                try:
                    # Tag and push the image to the local registry
                    client.tag(target_img_tag, img_tag)
                    # admin password may be changed by openstack client cmd in parallel.
                    # So we cannot cache auth info, need refresh it each time.
                    local_registry_auth = cutils.get_local_docker_registry_auth()
                    client.push(img_tag, auth_config=local_registry_auth)

                    # Test inspecting the image. This avoids a scenario where the push command
                    # returns a false positive result during docker service restarts.
                    client.inspect_distribution(img_tag, auth_config=local_registry_auth)
                    LOG.info("Image %s successfully pushed to local registry." % (img_tag))
                except Exception as e:
                    rc = False
                    LOG.error("Image %s push failed to local registry: %s" % (img_tag, e))
                    return img_tag, rc

                try:
                    # remove docker container image after it is pushed to local registry.
                    LOG.info("Remove image %s after push to local registry." % (target_img_tag))
                    client.remove_image(target_img_tag)
                    client.remove_image(img_tag)
                except Exception as e:
                    LOG.warning("Image %s remove failed: %s" % (target_img_tag, e))

            except Exception as e:
                rc = False
                LOG.error("Image %s download failed from local registry: %s" % (img_tag, e))

        else:
            try:
                LOG.info("Image %s download started from public/private registry" % img_tag)
                client = docker.APIClient(timeout=constants.APP_INSTALLATION_TIMEOUT)
                target_img_tag, registry_auth = \
                    self._get_img_tag_with_registry(img_tag, registries_info)
                client.pull(target_img_tag, auth_config=registry_auth)
                client.tag(target_img_tag, img_tag)
            except Exception as e:
                rc = False
                LOG.error("Image %s download failed from public/private registry: %s" % (img_tag, e))

        elapsed_time = time.time() - start
        if rc:
            LOG.info("Image %s download succeeded in %d seconds" %
                     (img_tag, elapsed_time))
        return img_tag, rc


class AppImageParser(object):
    """Utility class to help find images for an application"""

    TAG_LIST = ['tag', 'imageTag', 'imagetag']

    def _find_images_in_dict(self, var_dict):
        """A generator to find image references in a nested dictionary.

            Supported image formats in app:
              1. images:
                   tags: <dict>

              2. images: <dict>

              3. image: <str>

              4. image:
                   repository: <str>
                   tag: <str>

              5. image: <str>
                 imageTag(tag/imagetag): <str>

              6. image:
                    registry: <str>
                    repository: <str>

        :param var_dict: dict
        :return: a list of image references
        """
        if isinstance(var_dict, dict):
            for k, v in six.iteritems(var_dict):
                dict_key = k
                if isinstance(dict_key, str):
                    dict_key = dict_key.lower()

                if dict_key == 'images':
                    try:
                        yield {k: {'tags': v['tags']}}
                    except (KeyError, TypeError):
                        if v and isinstance(v, dict):
                            yield {k: v}
                        pass

                elif dict_key == 'image':
                    try:
                        image = {}
                        keys = v.keys()
                        if 'registry' in keys and 'repository' in keys:
                            image.update({'registry': v['registry']})
                            image.update({'repository': v['repository']})
                        if 'registry' not in keys and 'repository' in keys:
                            image.update({'repository': v['repository']})
                        if 'registry' in keys and cutils.is_empty_value(v['registry']):
                            image.update({'registry': v['registry']})
                        if 'tag' in keys:
                            image.update({'tag': v['tag']})
                        if image:
                            yield {k: image}
                    except (KeyError, TypeError, AttributeError):
                        if isinstance(v, str) or v is None:
                            yield {k: v}

                elif dict_key in self.TAG_LIST:
                    if isinstance(v, str) or v is None:
                        yield {k: v}

                elif isinstance(v, dict):
                    for result in self._find_images_in_dict(v):
                        yield {k: result}

    def find_images_in_dict(self, var_dict):
        """Find image references in a nested dictionary.

        This function is used to find images from helm chart,
        chart overrides file and manifest file.

        :param var_dict: dict
        :return: a dict of image references
        """
        images_dict = {}
        images = list(self._find_images_in_dict(var_dict))
        for img in images:
            images_dict = self.merge_dict(images_dict, img)

        return images_dict

    def merge_dict(self, source_dict, overrides_dict):
        """Recursively merge two nested dictionaries. The
        'overrides_dict' is merged into 'source_dict'.
        """
        for k, v in six.iteritems(overrides_dict):
            if isinstance(v, dict):
                source_dict[k] = self.merge_dict(
                    source_dict.get(k, {}), v)
            else:
                source_dict[k] = v
        return source_dict

    def update_images_with_local_registry(self, imgs_dict):
        """Update image references with local registry prefix.

        :param imgs_dict: a dict of images
        :return: a dict of images with local registry prefix
        """
        if not isinstance(imgs_dict, dict):
            raise exception.SysinvException(_(
                "Unable to update images with local registry "
                "prefix: %s is not a dict." % imgs_dict))

        for k, v in six.iteritems(imgs_dict):
            if v and isinstance(v, str):
                if (not re.search(r'^.+:.+/', v) and
                        k not in self.TAG_LIST):
                    if not cutils.is_valid_domain_name(v[:v.find('/')]):
                        # Explicitly specify 'docker.io' in the image
                        v = '{}/{}'.format(
                            constants.DEFAULT_DOCKER_DOCKER_REGISTRY, v)
                    v = '{}/{}'.format(constants.DOCKER_REGISTRY_SERVER, v)
                    imgs_dict[k] = v

            elif isinstance(v, dict):
                if ("registry" in v and "repository" in v and
                        cutils.is_empty_value(v["registry"]) and
                        constants.DOCKER_REGISTRY_SERVER not in v["repository"]):
                    v["repository"] = '{}/{}'.format(
                        constants.DOCKER_REGISTRY_SERVER, v["repository"])
                elif ("registry" in v and "repository" in v and
                        constants.DOCKER_REGISTRY_SERVER not in v["repository"]):
                    if (not re.search(r'^.+:.+/', v["registry"]) and ":" not in v["registry"]):
                        v["registry"] = '{}/{}'.format(
                            constants.DOCKER_REGISTRY_SERVER, v["registry"])
                else:
                    self.update_images_with_local_registry(v)
        return imgs_dict

    def generate_download_images_list(self, download_imgs_dict, download_imgs_list):
        """Generate a list of images that is required to be downloaded.
        """
        if not isinstance(download_imgs_dict, dict):
            raise exception.SysinvException(_(
                "Unable to generate download images list: %s "
                "is not a dict." % download_imgs_dict))

        for k, v in six.iteritems(download_imgs_dict):
            dict_key = k
            if isinstance(dict_key, str):
                dict_key = dict_key.lower()

            if dict_key == 'images':
                try:
                    imgs = [_f for _f in v['tags'].values() if _f]
                    download_imgs_list.extend(imgs)
                except (KeyError, TypeError):
                    if v and isinstance(v, dict):
                        imgs = [_f for _f in v.values()
                                if _f and not isinstance(_f, dict)]
                        download_imgs_list.extend(imgs)
                    pass

            elif dict_key == 'image':
                try:
                    if "registry" in v and not cutils.is_empty_value(v['registry']):
                        img = v['registry'] + '/' + v['repository'] + ':' + v['tag']
                    else:
                        img = v['repository'] + ':' + v['tag']
                except (KeyError, TypeError):
                    img = ''
                    if v and isinstance(v, str):
                        img = v
                        for t in self.TAG_LIST:
                            if t in download_imgs_dict and download_imgs_dict[t]:
                                img = img + ':' + download_imgs_dict[t]
                                break
                if re.search(r'/.+:.+$', img):
                    download_imgs_list.append(img)

            elif isinstance(v, dict):
                self.generate_download_images_list(v, download_imgs_list)

        return list(set(download_imgs_list))


class PluginHelper(object):
    """ Utility class to help manage application plugin lifecycle """

    def __init__(self, dbapi, helm_op):
        self._dbapi = dbapi
        self._helm_op = helm_op

    def _get_pth_fqpn(self, app):
        return "{}/{}{}-{}.pth".format(
            common.APP_PLUGIN_PATH, common.APP_PTH_PREFIX, app.name, app.version)

    def activate_apps_plugins(self):
        # Examine existing applications in an applying/restoring state and make
        # sure they are activated
        apps = self._dbapi.kube_app_get_all()
        for app in apps:
            # If the app is in some form of apply/restore the the plugins
            # should be enabled
            if app.status in [constants.APP_APPLY_IN_PROGRESS,
                              constants.APP_APPLY_SUCCESS,
                              constants.APP_APPLY_FAILURE,
                              constants.APP_RESTORE_REQUESTED]:
                try:
                    self.activate_plugins(AppOperator.Application(app))
                except exception.SysinvException:
                    LOG.exception("Error while loading plugins for {}".format(app.name))

    def install_plugins(self, app):
        """ Install application plugins. """

        # An app may be packaged with multiple wheels, discover and install them
        # in the synced app plugin directory

        pattern = '{}/*.whl'.format(app.inst_plugins_dir)
        discovered_whls = glob.glob(pattern)

        if not discovered_whls:
            LOG.info("PluginHelper: %s does not contains any platform plugins." %
                     app.name)
            return

        if not os.path.isdir(app.sync_plugins_dir):
            LOG.info("PluginHelper: Creating %s plugin directory %s." % (
                app.name, app.sync_plugins_dir))
            os.makedirs(app.sync_plugins_dir)

        for whl in discovered_whls:
            LOG.info("PluginHelper: Installing %s plugin %s to %s." % (
                app.name, whl, app.sync_plugins_dir))
            with zipfile.ZipFile(whl) as zf:
                zf.extractall(app.sync_plugins_dir)

    def uninstall_plugins(self, app):
        """ Uninstall application plugins."""
        if os.path.isdir(app.sync_plugins_dir):
            try:
                LOG.info("PluginHelper: Removing plugin directory %s" %
                         app.sync_plugins_dir)
                shutil.rmtree(app.sync_plugins_dir)
            except OSError:
                LOG.exception("PluginHelper: Failed to remove plugin directory:"
                              " %s" % app.sync_plugins_dir)
        else:
            LOG.info("PluginHelper: Plugin directory %s does not exist. No "
                     "need to remove." % app.sync_plugins_dir)

    def activate_plugins(self, app):
        pth_fqpn = self._get_pth_fqpn(app)

        # Check if plugins are available for the given app and already loaded
        if app.system_app and app.sync_plugins_dir in site.removeduppaths():
            return

        # If a plugin path does not exist but a .pth files does then raise an
        # exception because the path was supposed to be available at this point.
        # If a plugin path does exist then activate the plugins.
        # Otherwise, the app does not have any plugins and activation should
        # be skipped.
        # Note: If app.system_app equals true that implies that app.sync_plugins_dir
        # exists and is readable.
        if not app.system_app and os.path.isfile(pth_fqpn):
            raise exception.SysinvException(_(
                    "Error while activating plugins for {}. "
                    "File {} was found but the required plugin "
                    "directory {} does not exist."
                    .format(app.name, pth_fqpn, app.sync_plugins_dir)))
        elif app.system_app:
            # Add a .pth file to a site-packages directory so the plugin is picked
            # automatically on a conductor restart
            if not os.path.isfile(pth_fqpn):
                with open(pth_fqpn, 'w') as f:
                    f.write(app.sync_plugins_dir + '\n')
                    LOG.info("PluginHelper: Enabled plugin directory %s: created %s" % (
                        app.sync_plugins_dir, pth_fqpn))

            # Make sure the sys.path reflects enabled plugins Add the plugin to
            # sys.path
            site.addsitedir(app.sync_plugins_dir)

            # Find the distribution and add it to the resources working set
            for d in pkg_resources.find_distributions(app.sync_plugins_dir,
                                                      only=True):
                pkg_resources.working_set.add(d, entry=None, insert=True,
                                              replace=True)

            if self._helm_op:
                self._helm_op.discover_plugins()

    def deactivate_plugins(self, app):
        # If the application doesn't have any plugins, skip deactivation
        if not app.system_app:
            return

        if self._helm_op:
            LOG.info("PluginHelper: Purge cache for plugins located"
                     " in directory %s " % app.sync_plugins_dir)
            # purge this plugin from the stevedore plugin cache so this version
            # of the plugin endpoints are not discoverable
            self._helm_op.purge_cache_by_location(app.sync_plugins_dir)

        pth_fqpn = self._get_pth_fqpn(app)
        if os.path.exists(pth_fqpn):
            # Remove the pth file, so on a conductor restart this installed
            # plugin is not discoverable
            try:
                os.remove(pth_fqpn)
                LOG.info("PluginHelper: Disabled plugin directory %s: removed "
                         "%s" % (app.sync_plugins_dir, pth_fqpn))
            except OSError as e:
                # Not present, should be, but continue on...
                LOG.warning("PluginHelper: Failed to remove plugin directory:"
                            " %s. Error: %s" % (pth_fqpn, e))
                pass

        # Make sure the sys.path reflects only enabled plugins
        try:
            sys.path.remove(app.sync_plugins_dir)
        except ValueError:
            # Not present, should be, but continue on...
            LOG.warning("sys.path (%s) is missing plugin (%s)" % (
                sys.path, app.sync_plugins_dir))

        # Determine distributions installed by this plugin
        plugins_realpath = os.path.realpath(app.sync_plugins_dir)
        if plugins_realpath in pkg_resources.working_set.entry_keys:
            plugin_distributions = pkg_resources.working_set.entry_keys[plugins_realpath]
            LOG.info("PluginHelper: Disabling distributions: %s" % plugin_distributions)

            # Clean up the distribution(s) module names
            module_name_cleanup = []
            for module_name, value in six.iteritems(sys.modules):
                for distribution in plugin_distributions:
                    distribution_module_name = distribution.replace('-', '_')
                    if ((module_name == distribution_module_name) or
                            (module_name.startswith(distribution_module_name + '.'))):
                        LOG.debug("PluginHelper: Removing module name: %s: %s" % (module_name, value))
                        module_name_cleanup.append(module_name)

            for module_name in module_name_cleanup:
                del sys.modules[module_name]

            # Clean up the working set
            for distribution in plugin_distributions:
                try:
                    del pkg_resources.working_set.by_key[distribution]
                except KeyError:
                    LOG.warn("Plugin distribution %s not enabled for version %s"
                             ", but expected to be. Continuing with plugin "
                             "deactivation." % (distribution, app.version))

            try:
                del pkg_resources.working_set.entry_keys[plugins_realpath]
            except Exception:
                pass
            try:
                pkg_resources.working_set.entries.remove(plugins_realpath)
            except Exception:
                pass

            if plugins_realpath != app.sync_plugins_dir:
                try:
                    del pkg_resources.working_set.entry_keys[app.sync_plugins_dir]
                except Exception:
                    pass
                try:
                    pkg_resources.working_set.entries.remove(app.sync_plugins_dir)
                except Exception:
                    pass


class FluxCDHelper(object):
    """ FluxCD class to encapsulate FluxCD related operations """

    HELM_RELEASE_STATUS_UNKNOWN = 'Unknown'

    def __init__(self, dbapi, kube):
        self._dbapi = dbapi
        self._kube = kube

    def make_fluxcd_operation(self, operation, manifest_dir=""):

        self.check_fluxcd_pods_status()

        LOG.info("Doing FluxCD operation %s with the following manifest: %s"
                 % (operation, manifest_dir))
        rc = True
        try:
            if operation == constants.APP_APPLY_OP:
                rc = self._apply(manifest_dir)
                if rc:
                    rc = self._cleanup_disabled_helm_releases(manifest_dir)
                else:
                    LOG.error("Applying %s failed. Skipping helm release "
                              "cleanup..." % manifest_dir)
            elif operation in [constants.APP_DELETE_OP, constants.APP_REMOVE_OP]:
                rc = self._delete(manifest_dir)
            elif operation == constants.APP_VALIDATE_OP:
                self._validate(manifest_dir)
            else:
                LOG.error("Unsupported FluxCD app operation %s" % operation)
                rc = False
        except Exception as e:
            LOG.error("FluxCD operation %s failed for manifest %s : %s" %
                      (operation, manifest_dir, e))
            rc = False

        return rc

    def run_kubectl_kustomize(self, operation_type, manifest_dir):
        if operation_type == constants.KUBECTL_KUSTOMIZE_VALIDATE:
            cmd = ['kubectl', '--kubeconfig', kubernetes.KUBERNETES_ADMIN_CONF,
               constants.KUBECTL_KUSTOMIZE_APPLY, '-k', manifest_dir, '--dry-run=server']
        elif operation_type == constants.KUBECTL_KUSTOMIZE_DELETE:
            cmd = ['kubectl', '--kubeconfig', kubernetes.KUBERNETES_ADMIN_CONF,
                   operation_type, '-k', manifest_dir, '--ignore-not-found=true']
        else:
            cmd = ['kubectl', '--kubeconfig', kubernetes.KUBERNETES_ADMIN_CONF,
                   operation_type, '-k', manifest_dir]

        process = subprocess.Popen(cmd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True)

        _, stderr = process.communicate()

        if process.returncode == 0 and stderr:
            LOG.warning("Command: %s; %s" % (' '.join(cmd), stderr))

        if process.returncode != 0:
            namespace_error_keys = ["namespaces", "not found"]
            has_namespace_error = all(substring in stderr for substring in namespace_error_keys)

            # This log is being suppressed only if the error is related to the namespace not being
            # found during the app upload process. This is expected because in this process the
            # namespace for the application has not yet been created.
            if (not has_namespace_error and operation_type != constants.KUBECTL_KUSTOMIZE_VALIDATE):
                LOG.error("Command: %s; Error: %s" % (' '.join(cmd), stderr))

            return False

        return True

    def _apply(self, manifest_dir):
        return self.run_kubectl_kustomize(constants.KUBECTL_KUSTOMIZE_APPLY, manifest_dir)

    def _delete(self, manifest_dir):
        return self.run_kubectl_kustomize(constants.KUBECTL_KUSTOMIZE_DELETE, manifest_dir)

    def _validate(self, manifest_dir):
        return self.run_kubectl_kustomize(constants.KUBECTL_KUSTOMIZE_VALIDATE, manifest_dir)

    def _rollback(self, manifest_dir):
        pass

    def get_pod_ready_conditions(self, pod):
        """ Get conditions of a given ready pod

        :param pod: Pod object as returned by self._kube.kube_get_pods_by_selector
        :return: A list containing the pod ready conditions.
                 If conditions are not available or the pod is not ready then returns
                 an empty list.
         """
        conditions = pod.status.conditions if pod.status.conditions is not None else []

        if conditions:
            ready_conditions = [x for x in conditions if x.type == 'Ready']
            if not ready_conditions:
                LOG.debug(f"Pod {pod.metadata.name} is not ready")
            return ready_conditions
        else:
            LOG.warning(f"No conditions are available for pod {pod.metadata.name} at the moment")

        return conditions

    def check_pod_running_and_ready_probe(self, pod):
        """Pod is of the form returned by self._kube.kube_get_pods_by_selector.
        Returns: true if last probe shows the container is in 'Ready' state.
        """

        ready_conditions = self.get_pod_ready_conditions(pod)

        if ready_conditions:
            return ready_conditions[0].status == 'True'
        else:
            return False

    def check_pod_completed(self, pod):
        """Pod is of the form returned by self._kube.kube_get_pods_by_selector.

        Returns: true if last probe shows the container 'Ready' status is False
                 and the reason is PodCompleted
        """
        ready_conditions = self.get_pod_ready_conditions(pod)

        if ready_conditions:
            return (ready_conditions[0].status == 'False' and ready_conditions[0].reason == 'PodCompleted')
        else:
            return False

    def verify_pods_status_for_release(self, chart_obj):
        """ chart_obj has the information required to query for pods associated
                      with the chart release
            Returns: if the release is ready (True/False)
        """
        # On AIO-SX an issue may be seen
        # (https://github.com/fluxcd/helm-controller/issues/81) during chart
        # install. Basically, the status of helmrelease ends up with ready but
        # the pods are not actually ready/running.
        #
        # This is due to helm upstream issues:
        #  - https://github.com/helm/helm/issues/3173,
        #  - https://github.com/helm/helm/issues/5814,
        # -  https://github.com/helm/helm/issues/8660.
        #
        # To solve this we need to check if the pods of the helm chart are
        # ready/running using the kubernetes python client

        # Nothing to worry about in a non AIO-SX install
        if not cutils.is_aio_simplex_system(self._dbapi):
            return True

        # Get all pods with the appropriate label
        label_selector = "app.kubernetes.io/name={}".format(chart_obj["chart_label"])
        pods = self._kube.kube_get_pods_by_selector(chart_obj["namespace"], label_selector, "")

        if not pods:
            return True

        for pod in pods:
            completed = self.check_pod_completed(pod)
            running_and_ready = self.check_pod_running_and_ready_probe(pod)

            LOG.info("Pod {} has been found with label {}: Completed?: {}, "
                     "Running/Ready?: {}".format(pod.metadata.name,
                        label_selector, completed, running_and_ready))

            if not completed and not running_and_ready:
                return False

        return True

    # TODO (lfagunde):
    # Some methods in this class receive helm_chart_dict as a parameter.
    # Can move the call to _kube.get_custom_resource() into these functions
    # or create a helper function inside the class for it.
    def get_helm_release_status(self, helm_release_dict):
        """helm_release_dict is of the form returned by _kube.get_custom_resource().

        The helm_release_dict is a list of dictionaries where position 0 reflects
        the most current release status and it should be the source of truth whether
        the release was successfully installed or not.

        To determine that helmrelease was successfully installed, the key "status" must
        be "True" and the type must be "Ready".

        Below is an example of a successful installation of the
        ic-nginx-ingress release:

        Intermediate state:
        [{
            "lastTransitionTime": "2024-11-04T20:34:12Z",
            "message": "Running 'install' action with timeout of 30m0s",
            "observedGeneration": 1,
            "reason": "Progressing",
            "status": "True",
            "type": "Reconciling",
        },
        {
            "lastTransitionTime": "2024-11-04T20:34:12Z",
            "message": "Running 'install' action with timeout of 30m0s",
            "observedGeneration": 1,
            "reason": "Progressing",
            "status": "Unknown",
            "type": "Ready",
        }]

        Installed successfully:
        [{
            "lastTransitionTime": "2024-11-04T20:34:26Z",
            "message": "Helm install succeeded for release kube-system/ic-nginx-ingress.v1
                        with chart ingress-nginx@4.11.1+STX.3",
            "observedGeneration": 1,
            "reason": "InstallSucceeded",
            "status": "True",
            "type": "Ready",
        },
        {
            "lastTransitionTime": "2024-11-04T20:34:26Z",
            "message": "Helm install succeeded for release kube-system/ic-nginx-ingress.v1
                        with chart ingress-nginx@4.11.1+STX.3",
            "observedGeneration": 1,
            "reason": "InstallSucceeded",
            "status": "True",
            "type": "Released",
        }]


        Below is an example of a failed ic-nginx-ingress version upgrade due to bad
        user-overrides values:

        Intermediate state:
        [{
            "lastTransitionTime": "2024-11-04T20:38:02Z",
            "message": "Fulfilling prerequisites",
            "observedGeneration": 2,
            "reason": "Progressing",
            "status": "True",
            "type": "Reconciling",
        },
        {
            "lastTransitionTime": "2024-11-04T20:34:26Z",
            "message": "Helm install succeeded for release kube-system/ic-nginx-ingress.v1
                        with chart ingress-nginx@4.11.1+STX.3",
            "observedGeneration": 1,
            "reason": "InstallSucceeded",
            "status": "True",
            "type": "Ready",
        },
        {
            "lastTransitionTime": "2024-11-04T20:34:26Z",
            "message": "Helm install succeeded for release kube-system/ic-nginx-ingress.v1
                        with chart ingress-nginx@4.11.1+STX.3",
            "observedGeneration": 1,
            "reason": "InstallSucceeded",
            "status": "True",
            "type": "Released",
        }]

        Upgrade failed:
        [{
            "lastTransitionTime": "2024-11-04T20:38:11Z",
            "message": "Failed to upgrade after 1 attempt(s)",
            "observedGeneration": 2,
            "reason": "RetriesExceeded",
            "status": "True",
            "type": "Stalled",
        },
        {
            "lastTransitionTime": "2024-11-04T20:38:10Z",
            "message": 'Helm upgrade failed for release kube-system/ic-nginx-ingress with
                        chart ingress-nginx@4.11.1+STX.3: cannot patch
                        "ic-nginx-ingress-ingress-nginx-controller" with kind DaemonSet:
                        DaemonSet.apps "ic-nginx-ingress-ingress-nginx-controller" is
                        invalid: spec.template.spec.containers[0].resources.requests:
                        Invalid value: "255": must be less than or equal to cpu limit of 10',
            "observedGeneration": 2,
            "reason": "UpgradeFailed",
            "status": "False",
            "type": "Ready",
        },
        {
            "lastTransitionTime": "2024-11-04T20:38:10Z",
            "message": 'Helm upgrade failed for release kube-system/ic-nginx-ingress with
                        chart ingress-nginx@4.11.1+STX.3: cannot patch
                        "ic-nginx-ingress-ingress-nginx-controller" with kind DaemonSet:
                        DaemonSet.apps "ic-nginx-ingress-ingress-nginx-controller" is invalid:
                        spec.template.spec.containers[0].resources.requests: Invalid value:
                        "255": must be less than or equal to cpu limit of 10',
            "observedGeneration": 2,
            "reason": "UpgradeFailed",
            "status": "False",
            "type": "Released",
        }]

        Below is an example of a successful upgrade after fixing the user-overrides:

        Intermediate state:
        [{
            "lastTransitionTime": "2024-11-04T20:52:16Z",
            "message": "Fulfilling prerequisites",
            "observedGeneration": 3,
            "reason": "Progressing",
            "status": "True",
            "type": "Reconciling",
        },
        {
            "lastTransitionTime": "2024-11-04T20:38:10Z",
            "message": 'Helm upgrade failed for release kube-system/ic-nginx-ingress
                        with chart ingress-nginx@4.11.1+STX.3: cannot patch
                        "ic-nginx-ingress-ingress-nginx-controller" with kind DaemonSet:
                        DaemonSet.apps "ic-nginx-ingress-ingress-nginx-controller" is
                        invalid: spec.template.spec.containers[0].resources.requests:
                        Invalid value: "255": must be less than or equal to cpu limit
                        of 10',
            "observedGeneration": 2,
            "reason": "UpgradeFailed",
            "status": "False",
            "type": "Ready",
        },
        {
            "lastTransitionTime": "2024-11-04T20:38:10Z",
            "message": 'Helm upgrade failed for release kube-system/ic-nginx-ingress with
                        chart ingress-nginx@4.11.1+STX.3: cannot patch
                        "ic-nginx-ingress-ingress-nginx-controller" with kind DaemonSet:
                        DaemonSet.apps "ic-nginx-ingress-ingress-nginx-controller" is
                        invalid: spec.template.spec.containers[0].resources.requests:
                        Invalid value: "255": must be less than or equal to cpu limit
                        of 10',
            "observedGeneration": 2,
            "reason": "UpgradeFailed",
            "status": "False",
            "type": "Released",
        }]

        Upgrade success:
        [{
            "lastTransitionTime": "2024-11-04T20:52:30Z",
            "message": "Helm upgrade succeeded for release kube-system/ic-nginx-ingress.v3
                        with chart ingress-nginx@4.11.1+STX.3",
            "observedGeneration": 3,
            "reason": "UpgradeSucceeded",
            "status": "True",
            "type": "Ready",
        },
        {
            "lastTransitionTime": "2024-11-04T20:52:30Z",
            "message": "Helm upgrade succeeded for release kube-system/ic-nginx-ingress.v3
                        with chart ingress-nginx@4.11.1+STX.3",
            "observedGeneration": 3,
            "reason": "UpgradeSucceeded",
            "status": "True",
            "type": "Released",
        }]

        Returns: 'status' of the release (Unlnown,True,False) and 'message'
                  associated with the status
        """
        if "status" in helm_release_dict and "conditions" in helm_release_dict["status"]:
            conditions_list = helm_release_dict['status']['conditions']

            status = strtobool(conditions_list[0]['status'])
            type = conditions_list[0]['type']

            if status and type == common.HELM_RELEASE_TYPE_READY:
                return conditions_list[0]['status'], conditions_list[0]['message']
            elif type == common.HELM_RELEASE_TYPE_RECONCILING:
                return self.HELM_RELEASE_STATUS_UNKNOWN, None
            else:
                return "False", conditions_list[0]['message']
        else:
            return self.HELM_RELEASE_STATUS_UNKNOWN, None

    def _cleanup_disabled_helm_releases(self, manifest_dir):
        helmrelease_cleanup_fqpn = os.path.join(
            manifest_dir, constants.APP_RELEASE_CLEANUP_FILE)

        # See if we have any helm releases that we must make sure are cleaned up
        if not os.path.exists(helmrelease_cleanup_fqpn):
            return True

        with io.open(helmrelease_cleanup_fqpn, 'r', encoding='utf-8') as f:
            helmrelease_doc = list(yaml.load_all(f,
                Loader=yaml.RoundTripLoader, preserve_quotes=True))

        for release in helmrelease_doc[0]['releases']:
            try:
                if self._kube.get_custom_resource(
                        constants.FLUXCD_CRD_HELM_REL_GROUP,
                        constants.FLUXCD_CRD_HELM_REL_VERSION,
                        release["namespace"],
                        constants.FLUXCD_CRD_HELM_REL_PLURAL,
                        release['name']):

                    self._kube.delete_custom_resource(
                        constants.FLUXCD_CRD_HELM_REL_GROUP,
                        constants.FLUXCD_CRD_HELM_REL_VERSION,
                        release["namespace"],
                        constants.FLUXCD_CRD_HELM_REL_PLURAL,
                        release['name'])
            except Exception as e:
                LOG.error("Attemting to cleanup HelmRelease {}/{} "
                          "failed".format(release["namespace"],
                                          release['name']))
                LOG.exception(e)
                return False
        return True

    def _check_fluxcd_pod_status(self, pod_label):
        """ Check if a FluxCD pod is ready given its app label.
            Log an error if it is not ready.
        """

        try:
            pods = self._kube.kube_get_pods_by_selector(constants.FLUXCD_NAMESPACE, "app={}".format(pod_label), "")
        except Exception:
            LOG.error("Could not check if FluxCD pod with with label {} is running on {} namespace"
                        .format(pod_label, constants.FLUXCD_NAMESPACE))
            return False

        if not pods:
            LOG.warning("No FluxCD pods found on {} namespace with label {}"
                        .format(constants.FLUXCD_NAMESPACE, pod_label))
            return False

        for pod in pods:
            if pod.status is None:
                LOG.warning("Error while retrieving status for FluxCD pod {}"
                            .format(pod.metadata.name))
                return False
            if not self.check_pod_running_and_ready_probe(pod):
                LOG.warning("FluxCD pod {} is not ready. Phase: {}. Message: {}"
                            .format(pod.metadata.name,
                                    pod.status.phase,
                                    pod.status.message))
                return False

        return True

    def check_fluxcd_pods_status(self):
        """ Check if helm-controller and source-controller pods are ready.
            Return False if they are not.
        """

        if self._check_fluxcd_pod_status(constants.FLUXCD_HELM_CONTROLLER_LABEL) and \
                self._check_fluxcd_pod_status(constants.FLUXCD_SOURCE_CONTROLLER_LABEL):
            return True
        else:
            return False
