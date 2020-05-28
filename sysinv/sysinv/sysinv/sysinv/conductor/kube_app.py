# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018-2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System Inventory Kubernetes Application Operator."""

import base64
import copy
import docker
from eventlet.green import subprocess
import glob
import grp
import functools
import os
import pkg_resources
import pwd
import re
import ruamel.yaml as yaml
import shutil
import site
import six
import sys
import threading
import time
import zipfile

from collections import namedtuple
from eventlet import greenpool
from eventlet import greenthread
from eventlet import queue
from eventlet import Timeout
from fm_api import constants as fm_constants
from fm_api import fm_api
from oslo_log import log as logging
from sysinv._i18n import _
from sysinv.api.controllers.v1 import kube_app
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import image_versions
from sysinv.common.retrying import retry
from sysinv.common import utils as cutils
from sysinv.common.storage_backend_conf import K8RbdProvisioner
from sysinv.common.storage_backend_conf import StorageBackendConfig
from sysinv.conductor import kube_pod_helper as kube_pod
from sysinv.conductor import openstack
from sysinv.helm import common
from sysinv.helm import utils as helm_utils


# Log and config
LOG = logging.getLogger(__name__)

# Constants
APPLY_SEARCH_PATTERN = 'Processing Chart,'
ARMADA_CONTAINER_NAME = 'armada_service'
ARMADA_MANIFEST_APPLY_SUCCESS_MSG = 'Done applying manifest'
ARMADA_RELEASE_ROLLBACK_FAILURE_MSG = 'Error while rolling back tiller release'
CONTAINER_ABNORMAL_EXIT_CODE = 137
DELETE_SEARCH_PATTERN = 'Deleting release'
ROLLBACK_SEARCH_PATTERN = 'Helm rollback of release'
INSTALLATION_TIMEOUT = 3600
MAX_DOWNLOAD_THREAD = 5
MAX_DOWNLOAD_ATTEMPTS = 3
DOWNLOAD_WAIT_BEFORE_RETRY = 30
TARFILE_DOWNLOAD_CONNECTION_TIMEOUT = 60
TARFILE_TRANSFER_CHUNK_SIZE = 1024 * 512
DOCKER_REGISTRY_SECRET = 'default-registry-key'
CHARTS_PENDING_INSTALL_ITERATIONS = 60

ARMADA_LOG_MAX = 10
ARMADA_HOST_LOG_LOCATION = '/var/log/armada'
ARMADA_CONTAINER_LOG_LOCATION = '/logs'
ARMADA_LOCK_GROUP = 'armada.process'
ARMADA_LOCK_VERSION = 'v1'
ARMADA_LOCK_NAMESPACE = 'kube-system'
ARMADA_LOCK_PLURAL = 'locks'
ARMADA_LOCK_NAME = 'lock'

LOCK_NAME_APP_REAPPLY = 'app_reapply'


# Helper functions
def generate_armada_service_manifest_fqpn(app_name, app_version, manifest_filename):
    return os.path.join('/manifests', app_name, app_version,
                        app_name + '-' + manifest_filename)


def generate_install_manifest_fqpn(app_name, app_version, manifest_filename):
    return os.path.join(constants.APP_INSTALL_PATH,
                        app_name, app_version, manifest_filename)


def generate_synced_images_fqpn(app_name, app_version):
    return os.path.join(
        constants.APP_SYNCED_ARMADA_DATA_PATH, app_name, app_version,
        app_name + '-images.yaml')


def generate_synced_helm_overrides_dir(app_name, app_version):
    return os.path.join(common.HELM_OVERRIDES_PATH, app_name, app_version)


def generate_synced_app_plugins_dir(app_name, app_version):
    return os.path.join(
        generate_synced_helm_overrides_dir(app_name, app_version),
        'plugins')


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


Chart = namedtuple('Chart', 'metadata_name name namespace location release labels sequenced')


class AppOperator(object):
    """Class to encapsulate Kubernetes App operations for System Inventory"""

    APP_OPENSTACK_RESOURCE_CONFIG_MAP = 'ceph-etc'
    # List of in progress apps and their abort status
    abort_requested = {}

    def __init__(self, dbapi, helm_op):
        self._dbapi = dbapi
        self._helm = helm_op
        self._plugins = PluginHelper(self._dbapi, self._helm)
        self._fm_api = fm_api.FaultAPIs()
        self._docker = DockerHelper(self._dbapi)
        self._kube = kubernetes.KubeOperator()
        self._utils = kube_app.KubeAppHelper(self._dbapi)
        self._image = AppImageParser()
        self._kube_pod = kube_pod.K8sPodOperator(self._kube)
        self._lock = threading.Lock()

        if not os.path.isfile(constants.ANSIBLE_BOOTSTRAP_FLAG):
            self._clear_stuck_applications()

        # Audit discoverable app plugins to remove any stale plugins that may
        # have been removed since this host was last tasked to manage
        # applications
        self._plugins.audit_plugins()

    def _clear_armada_locks(self):
        lock_name = "{}.{}.{}".format(ARMADA_LOCK_PLURAL,
                                      ARMADA_LOCK_GROUP,
                                      ARMADA_LOCK_NAME)
        try:
            self._kube.delete_custom_resource(ARMADA_LOCK_GROUP,
                                              ARMADA_LOCK_VERSION,
                                              ARMADA_LOCK_NAMESPACE,
                                              ARMADA_LOCK_PLURAL,
                                              lock_name)
        except Exception:
            # Best effort delete
            LOG.warning("Failed to clear Armada locks.")
            pass

    def _clear_stuck_applications(self):
        apps = self._dbapi.kube_app_get_all()
        for app in apps:
            if app.status in [constants.APP_UPLOAD_IN_PROGRESS,
                              constants.APP_APPLY_IN_PROGRESS,
                              constants.APP_UPDATE_IN_PROGRESS,
                              constants.APP_RECOVER_IN_PROGRESS,
                              constants.APP_REMOVE_IN_PROGRESS]:
                self._abort_operation(app, app.status, reset_status=True)
            else:
                continue

        # Delete the Armada locks that might have been acquired previously
        # for a fresh start. This guarantees that a re-apply, re-update or
        # a re-remove attempt following a status reset will not fail due
        # to a lock related issue.
        self._clear_armada_locks()

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

            if os.path.exists(app.sync_armada_mfile_dir):
                shutil.rmtree(app.sync_armada_mfile_dir)
                if app_dir:
                    shutil.rmtree(os.path.dirname(
                        app.sync_armada_mfile_dir))

            if os.path.exists(app.inst_path):
                shutil.rmtree(app.inst_path)
                if app_dir:
                    shutil.rmtree(os.path.dirname(
                        app.inst_path))
        except OSError as e:
            LOG.error(e)
            raise

    def _update_app_status(self, app, new_status=None, new_progress=None):
        """ Persist new app status """

        if new_status is None:
            new_status = app.status

        with self._lock:
            app.update_status(new_status, new_progress)

    def _abort_operation(self, app, operation,
                         progress=constants.APP_PROGRESS_ABORTED,
                         user_initiated=False, reset_status=False):
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

                if app.name in constants.HELM_APPS_PLATFORM_MANAGED:
                    # For platform core apps, set the new status
                    # to 'uploaded'. The audit task will kick in with
                    # all its pre-requisite checks before reapplying.
                    new_status = constants.APP_UPLOAD_SUCCESS
                    self._clear_app_alarm(app.name)

            if (not reset_status or
                    app.name not in constants.HELM_APPS_PLATFORM_MANAGED):
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
            new_status = constants.APP_REMOVE_FAILURE
            op = 'application-remove'
            self._raise_app_alarm(
                app.name, constants.APP_REMOVE_FAILURE,
                fm_constants.FM_ALARM_ID_APPLICATION_REMOVE_FAILED,
                fm_constants.FM_ALARM_SEVERITY_MAJOR,
                _("Application Remove Failure"),
                fm_constants.FM_ALARM_TYPE_3,
                _("Retry removing the application. If the issue persists, "
                  "please check system inventory log for cause."),
                True)
        else:
            # Should not get here, perhaps a new status was introduced?
            LOG.error("No abort handling code for app status = '%s'!" % app.status)
            return

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

            with open(filename, 'wb') as dest:
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
            # One time set up of base armada manifest path for the system
            if not os.path.isdir(constants.APP_SYNCED_ARMADA_DATA_PATH):
                os.makedirs(constants.APP_SYNCED_ARMADA_DATA_PATH)

            if not os.path.isdir(app.sync_armada_mfile_dir):
                os.makedirs(app.sync_armada_mfile_dir)

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
                mname, mfile = self._utils._find_manifest_file(app.inst_path)
                # Save the official manifest file info. They will be persisted
                # in the next status update
                app.regenerate_manifest_filename(mname, os.path.basename(mfile))
            else:
                name, version, patches = cutils.find_metadata_file(
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

    def _get_image_tags_by_charts(self, app_images_file, app_manifest_file, overrides_dir):
        """ Mine the image tags for charts from the images file. Add the
            image tags to the manifest file if the image tags from the
            charts do not exist in the manifest file. Convert the image
            tags in in both override files and manifest file. Intended
            for both system and custom apps.

            The image tagging conversion(local docker registry address prepended):
            ${LOCAL_REGISTRY_SERVER}:${REGISTRY_PORT}/<image-name>
            (ie..registry.local:9001/docker.io/mariadb:10.2.13)

        """
        app_imgs = []
        manifest_update_required = False

        if os.path.exists(app_images_file):
            with open(app_images_file, 'r') as f:
                images_file = yaml.safe_load(f)

        if os.path.exists(app_manifest_file):
            with open(app_manifest_file, 'r') as f:
                charts = list(yaml.load_all(f, Loader=yaml.RoundTripLoader))

        for chart in charts:
            if "armada/Chart/" in chart['schema']:
                chart_data = chart['data']
                chart_name = chart_data['chart_name']
                chart_namespace = chart_data['namespace']

                # Get the image tags by chart from the images file
                helm_chart_imgs = {}
                if chart_name in images_file:
                    helm_chart_imgs = images_file[chart_name]

                # Get the image tags from the chart overrides file
                overrides = chart_namespace + '-' + chart_name + '.yaml'
                app_overrides_file = os.path.join(overrides_dir, overrides)
                overrides_file = {}
                if os.path.exists(app_overrides_file):
                    with open(app_overrides_file, 'r') as f:
                        overrides_file = yaml.safe_load(f)

                override_imgs = self._image.find_images_in_dict(
                    overrides_file.get('data', {}).get('values', {}))
                override_imgs_copy = copy.deepcopy(override_imgs)

                # Get the image tags from the armada manifest file
                armada_chart_imgs = self._image.find_images_in_dict(
                    chart_data.get('values', {}))
                armada_chart_imgs_copy = copy.deepcopy(armada_chart_imgs)
                armada_chart_imgs = self._image.merge_dict(helm_chart_imgs, armada_chart_imgs)

                # Update image tags with local registry prefix
                override_imgs = self._image.update_images_with_local_registry(override_imgs)
                armada_chart_imgs = self._image.update_images_with_local_registry(armada_chart_imgs)

                # Generate a list of required images by chart
                download_imgs = copy.deepcopy(armada_chart_imgs)
                download_imgs = self._image.merge_dict(download_imgs, override_imgs)
                download_imgs_list = self._image.generate_download_images_list(download_imgs, [])
                app_imgs.extend(download_imgs_list)

                # Update chart override file if needed
                if override_imgs != override_imgs_copy:
                    with open(app_overrides_file, 'w') as f:
                        try:
                            overrides_file['data']['values'] = self._image.merge_dict(
                                overrides_file['data']['values'], override_imgs)
                            yaml.safe_dump(overrides_file, f, default_flow_style=False)
                            LOG.info("Overrides file %s updated with new image tags" %
                                     app_overrides_file)
                        except (TypeError, KeyError):
                            LOG.error("Overrides file %s fails to update" %
                                      app_overrides_file)

                # Update armada chart if needed
                if armada_chart_imgs != armada_chart_imgs_copy:
                    # This is to convert a empty orderedDict to dict
                    if 'values' in chart_data:
                        if not chart_data['values']:
                            chart_data['values'] = {}

                    chart_data['values'] = self._image.merge_dict(
                        chart_data.get('values', {}), armada_chart_imgs)
                    manifest_update_required = True

        # Update manifest file if needed
        if manifest_update_required:
            with open(app_manifest_file, 'w') as f:
                try:
                    yaml.dump_all(charts, f, Dumper=yaml.RoundTripDumper,
                                  explicit_start=True, default_flow_style=False)
                    LOG.info("Manifest file %s updated with new image tags" %
                             app_manifest_file)
                except Exception as e:
                    LOG.error("Manifest file %s fails to update with "
                              "new image tags: %s" % (app_manifest_file, e))

        return list(set(app_imgs))

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
        # applicable. Save the list to the same location as the armada manifest
        # so it can be sync'ed.
        app.charts = self._get_list_of_charts(app.sync_armada_mfile)

        self._plugins.activate_plugins(app)
        LOG.info("Generating application overrides to discover required images.")
        self._helm.generate_helm_application_overrides(
            app.sync_overrides_dir, app.name, mode=None, cnamespace=None,
            armada_format=True, armada_chart_info=app.charts, combined=True)
        self._plugins.deactivate_plugins(app)

        self._save_images_list_by_charts(app)
        # Get the list of images from the updated images overrides
        images_to_download = self._get_image_tags_by_charts(
            app.sync_imgfile, app.sync_armada_mfile, app.sync_overrides_dir)

        if not images_to_download:
            # TODO(tngo): We may want to support the deployment of apps that
            # set up resources only in the future. In which case, generate
            # an info log and let it advance to the next step.
            raise exception.KubeAppUploadFailure(
                name=app.name,
                version=app.version,
                reason="charts specify no docker images.")

        with open(app.sync_imgfile, 'ab') as f:
            yaml.safe_dump({"download_images": images_to_download}, f,
                           default_flow_style=False)

    def _save_images_list_by_charts(self, app):
        from six.moves.urllib.parse import urlparse

        # Mine the images from values.yaml files in the charts directory.
        # The list of images for each chart are saved to the images file.
        images_by_charts = {}
        for chart in app.charts:
            chart_name = os.path.join(app.inst_charts_dir, chart.name)

            if not os.path.exists(chart_name):
                # If the helm chart name is not the same as the armada
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
                with open(chart_path, 'r') as f:
                    y = yaml.safe_load(f)

                chart_images = self._image.find_images_in_dict(y)
                if chart_images:
                    images_by_charts.update({chart.name: chart_images})

        with open(app.sync_imgfile, 'wb') as f:
            yaml.safe_dump(images_by_charts, f, explicit_start=True,
                           default_flow_style=False)

    def _retrieve_images_list(self, app_images_file):
        with open(app_images_file, 'rb') as f:
            images_list = yaml.safe_load(f)
        return images_list

    def _download_images(self, app):
        if os.path.isdir(app.inst_images_dir):
            return self._register_embedded_images(app)

        if app.system_app:
            # Some images could have been overwritten via user overrides
            # between upload and apply, or between applies. Refresh the
            # saved images list.
            saved_images_list = self._retrieve_images_list(app.sync_imgfile)
            saved_download_images_list = list(saved_images_list.get("download_images"))
            images_to_download = self._get_image_tags_by_charts(
                app.sync_imgfile, app.sync_armada_mfile, app.sync_overrides_dir)
            if set(saved_download_images_list) != set(images_to_download):
                saved_images_list.update({"download_images": images_to_download})
                with open(app.sync_imgfile, 'wb') as f:
                    yaml.safe_dump(saved_images_list, f, explicit_start=True,
                                   default_flow_style=False)
        else:
            images_to_download = self._retrieve_images_list(
                app.sync_imgfile).get("download_images")

        total_count = len(images_to_download)
        threads = min(MAX_DOWNLOAD_THREAD, total_count)

        start = time.time()
        try:
            with self._lock:
                self._docker._retrieve_specified_registries()
        except Exception as e:
            raise exception.KubeAppApplyFailure(
                name=app.name,
                version=app.version,
                reason=str(e))
        for idx in reversed(range(MAX_DOWNLOAD_ATTEMPTS)):
            pool = greenpool.GreenPool(size=threads)
            for tag, success in pool.imap(
                    functools.partial(self._docker.download_an_image,
                                      app.name),
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
                with self._lock:
                    self._docker._reset_registries_info()
                elapsed = time.time() - start
                LOG.info("All docker images for application %s were successfully "
                         "downloaded in %d seconds", app.name, elapsed)
                break
            # don't sleep after last download attempt
            if idx:
                LOG.info("Retry docker images download for application %s "
                         "after %d seconds", app.name, DOWNLOAD_WAIT_BEFORE_RETRY)
                time.sleep(DOWNLOAD_WAIT_BEFORE_RETRY)
        else:
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
                output = subprocess.check_output(['helm', 'lint', r])
                if "no failures" in output:
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
            with open(lfile, 'r') as f:
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
                for chart in charts:
                    subprocess.check_call(['helm-upload', helm_repo, chart],
                                          env=env, stdout=fnull, stderr=fnull)
                    LOG.info("Helm chart %s uploaded" % os.path.basename(chart))

            # Make sure any helm repo changes are reflected for the users
            helm_utils.refresh_helm_repo_information()

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
            self._update_kubernetes_labels(host.hostname, label_dict)

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
                self._update_kubernetes_labels(host.hostname, null_labels)

    def _rbd_provisioner_required(self, app_name):
        """ Check if Ceph's RBD provisioner is required """
        # Since RBD provisioner requires Ceph, return false when not enabled
        if not StorageBackendConfig.has_backend(
            self._dbapi,
            constants.SB_TYPE_CEPH
        ):
            return False

        check_rbd_provisioner_apps = [constants.HELM_APP_MONITOR]
        if app_name not in check_rbd_provisioner_apps:
            return True

        system = self._dbapi.isystem_get_one()
        if system.distributed_cloud_role == \
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            return False
        else:
            return True

    def _create_rbd_provisioner_secrets(self, app_name):
        """ Provide access to the system persistent RBD provisioner.

        The rbd-provsioner is installed as part of system provisioning and has
        created secrets for all common default namespaces. Copy the secret to
        this application's namespace(s) to provide resolution for PVCs

        :param app_name: Name of the application
        """

        # Only set up a secret for the default storage pool (i.e. ignore
        # additional storage tiers)
        pool_secret = K8RbdProvisioner.get_user_secret_name({
            'name': constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH]})
        app_ns = self._helm.get_helm_application_namespaces(app_name)
        namespaces = \
            list(set([ns for ns_list in app_ns.values() for ns in ns_list]))
        for ns in namespaces:
            if (ns in [common.HELM_NS_HELM_TOOLKIT,
                       common.HELM_NS_RBD_PROVISIONER] or
                    self._kube.kube_get_secret(pool_secret, ns) is not None):
                # Secret already exist
                continue

            try:
                if not self._kube.kube_get_namespace(ns):
                    self._kube.kube_create_namespace(ns)
                self._kube.kube_copy_secret(
                    pool_secret, common.HELM_NS_RBD_PROVISIONER, ns)
            except Exception as e:
                LOG.error(e)
                raise

    def _delete_rbd_provisioner_secrets(self, app_name):
        """ Remove access to the system persistent RBD provisioner.

        As part of launching a supported application, secrets were created to
        allow access to the provisioner from the application namespaces. This
        will remove those created secrets.

        :param app_name: Name of the application
        """

        # Only set up a secret for the default storage pool (i.e. ignore
        # additional storage tiers)
        pool_secret = K8RbdProvisioner.get_user_secret_name({
            'name': constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH]})
        app_ns = self._helm.get_helm_application_namespaces(app_name)
        namespaces = \
            list(set([ns for ns_list in app_ns.values() for ns in ns_list]))

        for ns in namespaces:
            if (ns == common.HELM_NS_HELM_TOOLKIT or
                    ns == common.HELM_NS_RBD_PROVISIONER):
                continue

            try:
                LOG.info("Deleting Secret %s under Namespace "
                         "%s ..." % (pool_secret, ns))
                self._kube.kube_delete_secret(
                    pool_secret, ns, grace_period_seconds=0)
                LOG.info("Secret %s under Namespace %s delete "
                         "completed." % (pool_secret, ns))
            except Exception as e:
                LOG.error(e)
                raise

    def _create_local_registry_secrets(self, app_name):
        # Temporary function to create default registry secret
        # which would be used by kubernetes to pull images from
        # local registry.
        # This should be removed after OSH supports the deployment
        # with registry has authentication turned on.
        # https://blueprints.launchpad.net/openstack-helm/+spec/
        # support-docker-registry-with-authentication-turned-on
        body = {
            'type': 'kubernetes.io/dockerconfigjson',
            'metadata': {},
            'data': {}
        }

        app_ns = self._helm.get_helm_application_namespaces(app_name)
        namespaces = \
            list(set([ns for ns_list in app_ns.values() for ns in ns_list]))
        for ns in namespaces:
            if (ns == common.HELM_NS_HELM_TOOLKIT or
                 self._kube.kube_get_secret(DOCKER_REGISTRY_SECRET, ns) is not None):
                # Secret already exist
                continue

            try:
                local_registry_auth = cutils.get_local_docker_registry_auth()

                auth = '{0}:{1}'.format(local_registry_auth['username'],
                                        local_registry_auth['password'])
                token = '{{\"auths\": {{\"{0}\": {{\"auth\": \"{1}\"}}}}}}'.format(
                    constants.DOCKER_REGISTRY_SERVER, base64.b64encode(auth))

                body['data'].update({'.dockerconfigjson': base64.b64encode(token)})
                body['metadata'].update({'name': DOCKER_REGISTRY_SECRET,
                                         'namespace': ns})

                if not self._kube.kube_get_namespace(ns):
                    self._kube.kube_create_namespace(ns)
                self._kube.kube_create_secret(ns, body)
                LOG.info("Secret %s created under Namespace %s." % (DOCKER_REGISTRY_SECRET, ns))
            except Exception as e:
                LOG.error(e)
                raise

    def _delete_local_registry_secrets(self, app_name):
        # Temporary function to delete default registry secrets
        # which created during stx-opesntack app apply.
        # This should be removed after OSH supports the deployment
        # with registry has authentication turned on.
        # https://blueprints.launchpad.net/openstack-helm/+spec/
        # support-docker-registry-with-authentication-turned-on

        app_ns = self._helm.get_helm_application_namespaces(app_name)
        namespaces = \
            list(set([ns for ns_list in app_ns.values() for ns in ns_list]))

        for ns in namespaces:
            if ns == common.HELM_NS_HELM_TOOLKIT:
                continue

            try:
                LOG.info("Deleting Secret %s under Namespace "
                         "%s ..." % (DOCKER_REGISTRY_SECRET, ns))
                self._kube.kube_delete_secret(
                    DOCKER_REGISTRY_SECRET, ns, grace_period_seconds=0)
                LOG.info("Secret %s under Namespace %s delete "
                         "completed." % (DOCKER_REGISTRY_SECRET, ns))
            except Exception as e:
                LOG.error(e)
                raise

    def audit_local_registry_secrets(self):
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
                secret_auth_body = base64.b64decode(secret.data['.dockerconfigjson'])
                secret_auth_info = (secret_auth_body.split('auth":')[1]).split('"')[1]
                registry_auth = cutils.get_local_docker_registry_auth()
                registry_auth_info = '{0}:{1}'.format(registry_auth['username'],
                                                      registry_auth['password'])
                if secret_auth_info == base64.b64encode(registry_auth_info):
                    LOG.debug("Auth info is the same, no update is needed for k8s secret.")
                    return
            except Exception as e:
                LOG.error(e)
                return
            try:
                # update secret with new auth info
                token = '{{\"auths\": {{\"{0}\": {{\"auth\": \"{1}\"}}}}}}'.format(
                        constants.DOCKER_REGISTRY_SERVER, base64.b64encode(registry_auth_info))
                secret.data['.dockerconfigjson'] = base64.b64encode(token)
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
                    secret = self._kube.kube_get_secret(DOCKER_REGISTRY_SECRET, ns)
                    if secret is None:
                        continue

                    try:
                        secret_auth_body = base64.b64decode(secret.data['.dockerconfigjson'])
                        if constants.DOCKER_REGISTRY_SERVER in secret_auth_body:
                            secret.data['.dockerconfigjson'] = base64.b64encode(token)
                            self._kube.kube_patch_secret(DOCKER_REGISTRY_SECRET, ns, secret)
                            LOG.info("Secret %s under Namespace %s is updated"
                                     % (DOCKER_REGISTRY_SECRET, ns))
                    except Exception as e:
                        LOG.error("Failed to update Secret %s under Namespace %s: %s"
                                  % (DOCKER_REGISTRY_SECRET, ns, e))
                        continue
            except Exception as e:
                LOG.error(e)
                return

        _sync_audit_local_registry_secrets(self)

    def _delete_namespace(self, namespace):
        loop_timeout = 1
        timeout = 300
        try:
            LOG.info("Deleting Namespace %s ..." % namespace)
            self._kube.kube_delete_namespace(namespace,
                                             grace_periods_seconds=0)

            # Namespace termination timeout 5mins
            while(loop_timeout <= timeout):
                if not self._kube.kube_get_namespace(namespace):
                    # Namepace has been terminated
                    break
                loop_timeout += 1
                time.sleep(1)

            if loop_timeout > timeout:
                raise exception.KubeNamespaceDeleteTimeout(name=namespace)
            LOG.info("Namespace %s delete completed." % namespace)
        except Exception as e:
            LOG.error(e)
            raise

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

    def _delete_persistent_volume_claim(self, namespace):
        try:
            LOG.info("Deleting Persistent Volume Claim "
                     "under Namespace %s ..." % namespace)
            self._kube.kube_delete_persistent_volume_claim(namespace,
                                                           timeout_seconds=10)
            LOG.info("Persistent Volume Claim delete completed.")
        except Exception as e:
            LOG.error(e)
            raise

    def _get_list_of_charts(self, manifest_file):
        """Get the charts information from the manifest file

        The following chart data for each chart in the manifest file
        are extracted and stored into a namedtuple Chart object:
         - metadata_name
         - chart_name
         - namespace
         - location
         - release
         - pre-delete job labels

        The method returns a list of namedtuple charts which following
        the install order in the manifest chart_groups.

        :param manifest_file: the manifest file of the application
        :return: a list of namedtuple charts
        """
        charts = []
        release_prefix = ""
        chart_group = {}
        chart_groups = []
        armada_charts = {}

        with open(manifest_file, 'r') as f:
            docs = yaml.safe_load_all(f)
            for doc in docs:
                # iterative docs in the manifest file to get required
                # chart information
                try:
                    if "armada/Manifest/" in doc['schema']:
                        release_prefix = doc['data']['release_prefix']
                        chart_groups = doc['data']['chart_groups']

                    elif "armada/ChartGroup/" in doc['schema']:
                        chart_group.update(
                            {doc['metadata']['name']: {
                                'chart_group': doc['data']['chart_group'],
                                'sequenced': doc.get('data').get('sequenced', False)}})

                    elif "armada/Chart/" in doc['schema']:
                        labels = []
                        delete_resource = \
                            doc['data'].get('upgrade', {}).get('pre', {}).get('delete', [])
                        for resource in delete_resource:
                            if resource.get('type') == 'job':
                                label = ''
                                for k, v in resource['labels'].items():
                                    label = k + '=' + v + ',' + label
                                labels.append(label[:-1])

                        armada_charts.update(
                            {doc['metadata']['name']: {
                                'chart_name': doc['data']['chart_name'],
                                'namespace': doc['data']['namespace'],
                                'location': doc['data']['source']['location'],
                                'release': doc['data']['release'],
                                'labels': labels}})
                        LOG.debug("Manifest: Chart: {} Namespace: {} "
                                  "Location: {} Release: {}".format(
                                      doc['data']['chart_name'],
                                      doc['data']['namespace'],
                                      doc['data']['source']['location'],
                                      doc['data']['release']))
                except KeyError:
                    pass

            # Push Chart to the list that following the order
            # in the chart_groups(install list)
            for c_group in chart_groups:
                for chart in chart_group[c_group]['chart_group']:
                    charts.append(Chart(
                        metadata_name=chart,
                        name=armada_charts[chart]['chart_name'],
                        namespace=armada_charts[chart]['namespace'],
                        location=armada_charts[chart]['location'],
                        release=armada_charts[chart]['release'],
                        labels=armada_charts[chart]['labels'],
                        sequenced=chart_group[c_group]['sequenced']))
                    del armada_charts[chart]
                del chart_group[c_group]

            # Push Chart to the list that are not referenced
            # in the chart_groups (install list)
            if chart_group:
                for c_group in chart_group:
                    for chart in chart_group[c_group]['chart_group']:
                        charts.append(Chart(
                            metadata_name=chart,
                            name=armada_charts[chart]['chart_name'],
                            namespace=armada_charts[chart]['namespace'],
                            location=armada_charts[chart]['location'],
                            release=armada_charts[chart]['release'],
                            labels=armada_charts[chart]['labels'],
                            sequenced=chart_group[c_group]['sequenced']))
                        del armada_charts[chart]

            if armada_charts:
                for chart in armada_charts:
                    charts.append(Chart(
                        metadata_name=chart,
                        name=armada_charts[chart]['chart_name'],
                        namespace=armada_charts[chart]['namespace'],
                        location=armada_charts[chart]['location'],
                        release=armada_charts[chart]['release'],
                        labels=armada_charts[chart]['labels'],
                        sequenced=False))

        # Update each Chart in the list if there has release prefix
        # for each release
        if release_prefix:
            for i, chart in enumerate(charts):
                charts[i] = chart._replace(
                    release=release_prefix + "-" + chart.release)

        return charts

    def _get_overrides_files(self, overrides_dir, charts, app_name, mode):
        """Returns list of override files or None, used in
           application-install and application-delete."""

        missing_helm_overrides = []
        available_helm_overrides = []

        for chart in charts:
            overrides = chart.namespace + '-' + chart.name + '.yaml'
            overrides_file = os.path.join(overrides_dir, overrides)
            if not os.path.exists(overrides_file):
                missing_helm_overrides.append(overrides_file)
            else:
                available_helm_overrides.append(overrides_file)

        if missing_helm_overrides:
            LOG.error("Missing the following overrides: %s" % missing_helm_overrides)
            return None

        # Get the armada manifest overrides files
        manifest_op = self._helm.get_armada_manifest_operator(app_name)
        armada_overrides = manifest_op.load_summary(overrides_dir)

        return (available_helm_overrides, armada_overrides)

    def _generate_armada_overrides_str(self, app_name, app_version,
                                       helm_files, armada_files):
        overrides_str = ""
        if helm_files:
            overrides_str += " ".join([
                ' --values /overrides/{0}/{1}/{2}'.format(
                    app_name, app_version, os.path.basename(i))
                for i in helm_files
            ])
        if armada_files:
            overrides_str += " ".join([
                ' --values /manifests/{0}/{1}/{2}'.format(
                    app_name, app_version, os.path.basename(i))
                for i in armada_files
            ])
        return overrides_str

    def _remove_chart_overrides(self, overrides_dir, manifest_file):
        charts = self._get_list_of_charts(manifest_file)
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

            app = self._dbapi.kube_app_get(app_name)
            app_releases = self._dbapi.kube_app_chart_release_get_all(app.id)

            for r in app_releases:
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

    def _get_user_overrides_flag_from_metadata(self, app):
        # This function gets the "maintain_user_overrides"
        # parameter from application metadata
        reuse_overrides = False
        metadata_file = os.path.join(app.inst_path,
                                     constants.APP_METADATA_FILE)
        if os.path.exists(metadata_file) and os.path.getsize(metadata_file) > 0:
            with open(metadata_file, 'r') as f:
                try:
                    y = yaml.safe_load(f)
                    reuse_overrides = y.get('maintain_user_overrides', False)
                except KeyError:
                    # metadata file does not have the key
                    pass
        return reuse_overrides

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

    @retry(retry_on_exception=lambda x: isinstance(x, exception.PlatformApplicationApplyFailure),
           stop_max_attempt_number=5, wait_fixed=30 * 1000)
    def _make_armada_request_with_monitor(self, app, request, overrides_str=None):
        """Initiate armada request with monitoring

        This method delegates the armada request to docker helper and starts
        a monitoring thread to persist status and progress along the way.

        :param app: application data object
        :param request: type of request (apply or delete)
        :param overrides_str: list of overrides in string format to be applied
        """

        def _get_armada_log_stats(pattern, logfile):
            """
            TODO(tngo): In the absence of an Armada API that provides the current
            status of an apply/delete manifest operation, the progress is derived
            from specific log entries extracted from the execution logs. This
            inner method is to be replaced with an official API call when
            it becomes available.
            """
            if pattern == ROLLBACK_SEARCH_PATTERN:
                print_chart = '{print $10}'
            else:
                print_chart = '{print $NF}'
            p1 = subprocess.Popen(['docker', 'exec', ARMADA_CONTAINER_NAME,
                                   'grep', pattern, logfile],
                                   stdout=subprocess.PIPE)
            p2 = subprocess.Popen(['awk', print_chart], stdin=p1.stdout,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p1.stdout.close()
            result, err = p2.communicate()
            if result:
                # Strip out ANSI color code that might be in the text stream
                r = re.compile("\x1b\[[0-9;]*m")
                result = r.sub('', result).replace(',', '')
                matches = result.split()
                num_chart_processed = len(matches)
                last_chart_processed = matches[num_chart_processed - 1]
                if '=' in last_chart_processed:
                    last_chart_processed = last_chart_processed.split('=')[1]
                return last_chart_processed, num_chart_processed

            return None, None

        def _check_progress(monitor_flag, app, pattern, logfile):
            """ Progress monitoring task, to be run in a separate thread """
            LOG.info("Starting progress monitoring thread for app %s" % app.name)

            def _progress_adjust(app):
                # helm-toolkit doesn't count; it is not in stx-monitor
                non_helm_toolkit_apps = [constants.HELM_APP_MONITOR]
                if app.name in non_helm_toolkit_apps:
                    adjust = 0
                else:
                    adjust = 1
                return adjust

            try:
                with Timeout(INSTALLATION_TIMEOUT,
                             exception.KubeAppProgressMonitorTimeout()):
                    while True:
                        try:
                            monitor_flag.get_nowait()
                            LOG.debug("Received monitor stop signal for %s" % app.name)
                            monitor_flag.task_done()
                            break
                        except queue.Empty:
                            last, num = _get_armada_log_stats(pattern, logfile)
                            if last:
                                if app.system_app:
                                    adjust = _progress_adjust(app)
                                    percent = \
                                        round(float(num) /
                                              (len(app.charts) - adjust) * 100)
                                else:
                                    percent = round(float(num) / len(app.charts) * 100)
                                progress_str = 'processing chart: ' + last +\
                                    ', overall completion: ' + str(percent) + '%'
                                if app.progress != progress_str:
                                    LOG.info("%s" % progress_str)
                                    self._update_app_status(
                                        app, new_progress=progress_str)
                            greenthread.sleep(1)
            except Exception as e:
                # timeout or subprocess error
                LOG.exception(e)
            finally:
                LOG.info("Exiting progress monitoring thread for app %s" % app.name)

        def _cleanup_armada_log(location, app_name, request):
            """Cleanup the oldest armada log if reach the maximum"""
            list_of_logs = [os.path.join(location, f) for f in os.listdir(location)
                            if re.match(r'{}-{}.*.log'.format(app_name, request), f)]

            try:
                if len(list_of_logs) > ARMADA_LOG_MAX:
                    oldest_logfile = min(list_of_logs, key=os.path.getctime)
                    os.remove(oldest_logfile)
            except OSError:
                pass

        # Body of the outer method

        # This check is for cases where an abort is issued while
        # this function waits between retries. In such cases, it
        # should just return False
        if AppOperator.is_app_aborted(app.name):
            return False

        mqueue = queue.Queue()
        rc = True
        logname = time.strftime(app.name + '-' + request + '_%Y-%m-%d-%H-%M-%S.log')
        logfile = ARMADA_CONTAINER_LOG_LOCATION + '/' + logname

        if request == constants.APP_APPLY_OP:
            pattern = APPLY_SEARCH_PATTERN
        elif request == constants.APP_DELETE_OP:
            pattern = DELETE_SEARCH_PATTERN
        else:
            pattern = ROLLBACK_SEARCH_PATTERN

        monitor = greenthread.spawn_after(1, _check_progress, mqueue, app,
                                          pattern, logfile)
        rc = self._docker.make_armada_request(request, app.armada_service_mfile,
                                              overrides_str, app.releases, logfile)

        _cleanup_armada_log(ARMADA_HOST_LOG_LOCATION, app.name, request)
        mqueue.put('done')
        monitor.kill()

        # In case platform-integ-apps apply fails, we raise a specific exception
        # to be caught by the retry decorator and attempt a re-apply
        if (not rc and request == constants.APP_APPLY_OP and
                app.name == constants.HELM_APP_PLATFORM and
                not AppOperator.is_app_aborted(app.name)):
            LOG.info("%s app failed applying. Retrying." % str(app.name))
            raise exception.PlatformApplicationApplyFailure(name=app.name)

        return rc

    def _create_app_specific_resources(self, app_name):
        """Add application specific k8s resources.

        Some applications may need resources created outside of the existing
        charts to properly integrate with the current capabilities of the
        system. Create these resources here.

        :param app_name: Name of the application.
        """

        if app_name == constants.HELM_APP_OPENSTACK:
            try:
                # Copy the latest configmap with the ceph monitor information
                # required by the application into the application namespace
                if self._kube.kube_get_config_map(
                        self.APP_OPENSTACK_RESOURCE_CONFIG_MAP,
                        common.HELM_NS_OPENSTACK):

                    # Already have one. Delete it, in case it changed
                    self._kube.kube_delete_config_map(
                        self.APP_OPENSTACK_RESOURCE_CONFIG_MAP,
                        common.HELM_NS_OPENSTACK)

                # Copy the latest config map
                self._kube.kube_copy_config_map(
                    self.APP_OPENSTACK_RESOURCE_CONFIG_MAP,
                    common.HELM_NS_RBD_PROVISIONER,
                    common.HELM_NS_OPENSTACK)
            except Exception as e:
                LOG.error(e)
                raise

    def _delete_app_specific_resources(self, app_name, operation_type):
        """Remove application specific k8s resources.

        Some applications may need resources created outside of the existing
        charts to properly integrate with the current capabilities of the
        system. Remove these resources here.

        :param app_name: Name of the application.
        """

        def _delete_ceph_persistent_volume_claim(namespace):
            self._delete_persistent_volume_claim(namespace)

            try:
                # Remove the configmap with the ceph monitor information
                # required by the application into the application namespace
                self._kube.kube_delete_config_map(
                    self.APP_OPENSTACK_RESOURCE_CONFIG_MAP,
                    namespace)
            except Exception as e:
                LOG.error(e)
                raise
            self._delete_namespace(namespace)

        if (app_name == constants.HELM_APP_OPENSTACK and
                operation_type == constants.APP_REMOVE_OP):
            _delete_ceph_persistent_volume_claim(common.HELM_NS_OPENSTACK)
        elif app_name == constants.HELM_APP_MONITOR:
            if operation_type == constants.APP_DELETE_OP:
                _delete_ceph_persistent_volume_claim(common.HELM_NS_MONITOR)
            elif (operation_type == constants.APP_REMOVE_OP):
                self._wait_for_pod_termination(common.HELM_NS_MONITOR)

    def _perform_app_recover(self, old_app, new_app, armada_process_required=True):
        """Perform application recover

        This recover method is triggered when application update failed, it cleans
        up the files/data for the new application and recover helm charts for the
        old application. If the armada process is required, armada apply is invoked
        to recover the application releases for the old version.

        The app status will be populated to "apply-failed" if recover fails so that
        the user can re-apply app.

        :param old_app: the application object that application recovering to
        :param new_app: the application object that application recovering from
        :param armada_process_required: boolean, whether armada operation is needed
        """
        LOG.info("Starting recover Application %s from version: %s to version: %s" %
                 (old_app.name, new_app.version, old_app.version))

        self._update_app_status(
            old_app, constants.APP_RECOVER_IN_PROGRESS,
            constants.APP_PROGRESS_UPDATE_ABORTED.format(old_app.version, new_app.version) +
            constants.APP_PROGRESS_RECOVER_IN_PROGRESS.format(old_app.version))
        # Set the status for the new app to inactive
        self._update_app_status(new_app, constants.APP_INACTIVE_STATE)

        try:
            self._cleanup(new_app, app_dir=False)
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
            if armada_process_required:
                overrides_str = ''
                old_app.charts = self._get_list_of_charts(old_app.sync_armada_mfile)
                if old_app.system_app:
                    (helm_files, armada_files) = self._get_overrides_files(
                        old_app.sync_overrides_dir, old_app.charts, old_app.name, mode=None)

                    overrides_str = self._generate_armada_overrides_str(
                        old_app.name, old_app.version, helm_files, armada_files)

                if self._make_armada_request_with_monitor(old_app,
                                                          constants.APP_APPLY_OP,
                                                          overrides_str):
                    old_app_charts = [c.release for c in old_app.charts]
                    deployed_releases = helm_utils.retrieve_helm_releases()
                    for new_chart in new_app.charts:
                        if (new_chart.release not in old_app_charts and
                                new_chart.release in deployed_releases):
                            # Cleanup the releases in the new application version
                            # but are not in the old application version
                            helm_utils.delete_helm_release(new_chart.release)
                else:
                    rc = False

        except exception.PlatformApplicationApplyFailure:
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

        if rc:
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
            self._update_app_status(
                old_app, constants.APP_APPLY_FAILURE,
                constants.APP_PROGRESS_UPDATE_ABORTED.format(old_app.version, new_app.version) +
                constants.APP_PROGRESS_RECOVER_ABORTED.format(old_app.version) +
                'Please check logs for details.')
            LOG.error("Application %s recover to version %s aborted!"
                      % (old_app.name, old_app.version))

    def _perform_app_rollback(self, from_app, to_app):
        """Perform application rollback request

        This method invokes Armada to rollback the application releases to
        previous installed versions. The jobs for the current installed
        releases require to be cleaned up before starting armada rollback.

        :param from_app: application object that application updating from
        :param to_app: application object that application updating to
        :return boolean: whether application rollback was successful
        """

        LOG.info("Application %s (%s) rollback started." % (to_app.name, to_app.version))

        try:
            if AppOperator.is_app_aborted(to_app.name):
                raise exception.KubeAppAbort()

            to_db_app = self._dbapi.kube_app_get(to_app.name)
            to_app_releases = \
                self._dbapi.kube_app_chart_release_get_all(to_db_app.id)

            from_db_app = self._dbapi.kube_app_get_inactive_by_name_version(
                from_app.name, version=from_app.version)
            from_app_releases = \
                self._dbapi.kube_app_chart_release_get_all(from_db_app.id)
            from_app_r_dict = {r.release: r.version for r in from_app_releases}

            self._update_app_status(
                to_app, new_progress=constants.APP_PROGRESS_ROLLBACK_RELEASES)

            if AppOperator.is_app_aborted(to_app.name):
                raise exception.KubeAppAbort()

            charts_sequence = {c.release: c.sequenced for c in to_app.charts}
            charts_labels = {c.release: c.labels for c in to_app.charts}
            for to_app_r in to_app_releases:
                if to_app_r.version != 0:
                    if (to_app_r.release not in from_app_r_dict or
                            (to_app_r.release in from_app_r_dict and
                             to_app_r.version != from_app_r_dict[to_app_r.release])):
                        # Append the release which needs to be rolled back
                        to_app.releases.append(
                            {'release': to_app_r.release,
                             'version': to_app_r.version,
                             'sequenced': charts_sequence[to_app_r.release]})

                        # Cleanup the jobs for the current installed release
                        if to_app_r.release in charts_labels:
                            for label in charts_labels[to_app_r.release]:
                                self._kube.kube_delete_collection_namespaced_job(
                                    to_app_r.namespace, label)
                        LOG.info("Jobs deleted for release %s" % to_app_r.release)

            if AppOperator.is_app_aborted(to_app.name):
                raise exception.KubeAppAbort()

            if self._make_armada_request_with_monitor(to_app,
                                                      constants.APP_ROLLBACK_OP):
                self._update_app_status(to_app, constants.APP_APPLY_SUCCESS,
                                        constants.APP_PROGRESS_COMPLETED)
                LOG.info("Application %s (%s) rollback completed."
                         % (to_app.name, to_app.version))
                return True
        except exception.KubeAppAbort:
            # If the update operation is aborted before Armada request is made,
            # we don't want to return False which would trigger the recovery
            # routine with an Armada request.
            raise
        except Exception as e:
            # unexpected KubeAppNotFound, KubeAppInactiveNotFound, KeyError
            # k8s exception:fail to cleanup release jobs
            LOG.exception(e)

        LOG.error("Application rollback aborted!")
        return False

    def perform_app_upload(self, rpc_app, tarfile):
        """Process application upload request

        This method validates the application manifest. If Helm charts are
        included, they are validated and uploaded to local Helm repo. It also
        downloads the required docker images for custom apps during upload
        stage.

        :param rpc_app: application object in the RPC request
        :param tarfile: location of application tarfile
        """

        app = AppOperator.Application(rpc_app)
        LOG.info("Application %s (%s) upload started." % (app.name, app.version))

        try:
            # TODO (rchurch): Remove this version check once all applications
            # have been decoupled. Since compatible plugins will be delivered
            # with the versioned application tarball, no version check will be
            # required. For decoupled apps, plugins are loaded later in this
            # method and this base class version check is called.
            if not self._helm.version_check(app.name, app.version):
                LOG.info("Application %s (%s) upload rejected. Unsupported version."
                         % (app.name, app.version))
                raise exception.KubeAppUploadFailure(
                    name=app.name,
                    version=app.version,
                    reason="Unsupported application version.")

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
            # Manifest file is placed under /opt/platform/armada
            # which is managed by drbd-sync and visible to Armada.
            self._update_app_status(
                app, new_progress=constants.APP_PROGRESS_EXTRACT_TARFILE)

            with self._lock:
                self._extract_tarfile(app)
                self._plugins.install_plugins(app)

            # Copy the armada manfest and metadata file to the drbd
            shutil.copy(app.inst_armada_mfile, app.sync_armada_mfile)
            inst_metadata_file = os.path.join(
                app.inst_path, constants.APP_METADATA_FILE)
            if os.path.exists(inst_metadata_file):
                sync_metadata_file = os.path.join(
                    app.sync_armada_mfile_dir, constants.APP_METADATA_FILE)
                shutil.copy(inst_metadata_file, sync_metadata_file)

            if not self._docker.make_armada_request(
                    'validate', manifest_file=app.armada_service_mfile):
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

            # System overrides will be generated here. Plugins must be activated
            # prior to scraping chart/system/armada overrides for images
            self._save_images_list(app)

            if app.patch_dependencies:
                self._utils._patch_report_app_dependencies(
                    app.name + '-' + app.version, app.patch_dependencies)
            self._create_app_releases_version(app.name, app.charts)
            self._update_app_status(app, constants.APP_UPLOAD_SUCCESS,
                                    constants.APP_PROGRESS_COMPLETED)
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
                self._fm_api.clear_fault(alarm.id,
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
                    self._fm_api.clear_fault(alarm.id,
                                             alarm.entity_instance_id)
        return flag_exists

    def perform_app_apply(self, rpc_app, mode, caller=None):
        """Process application install request

        This method processes node labels per configuration and invokes
        Armada to apply the application manifest.

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
        :param caller: internal caller, None if it is an RPC call,
                       otherwise apply is invoked from update method
        :return boolean: whether application apply was successful
        """

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
        # WORKAROUND: For k8s NodeAffinity issue. Look for and clean up any
        #             pods that could block manifest apply
        #
        #             Upstream reports of this:
        #             - https://github.com/kubernetes/kubernetes/issues/80745
        #             - https://github.com/kubernetes/kubernetes/issues/85334
        #
        #             Outstanding PR that was tested and fixed this issue:
        #             - https://github.com/kubernetes/kubernetes/pull/80976
        self._kube_pod.delete_failed_pods_by_reason(reason='NodeAffinity')

        LOG.info("Application %s (%s) apply started." % (app.name, app.version))

        overrides_str = ''
        ready = True
        try:
            app.charts = self._get_list_of_charts(app.sync_armada_mfile)
            self._create_local_registry_secrets(app.name)
            if app.system_app:
                if AppOperator.is_app_aborted(app.name):
                    raise exception.KubeAppAbort()

                if self._rbd_provisioner_required(app.name):
                    self._create_rbd_provisioner_secrets(app.name)
                self._create_app_specific_resources(app.name)
                self._plugins.activate_plugins(app)

            self._update_app_status(
                app, new_progress=constants.APP_PROGRESS_GENERATE_OVERRIDES)

            if AppOperator.is_app_aborted(app.name):
                raise exception.KubeAppAbort()

            LOG.info("Generating application overrides...")
            self._helm.generate_helm_application_overrides(
                app.sync_overrides_dir, app.name, mode, cnamespace=None,
                armada_format=True, armada_chart_info=app.charts, combined=True)
            (helm_files, armada_files) = self._get_overrides_files(
                app.sync_overrides_dir, app.charts, app.name, mode)

            if helm_files or armada_files:
                LOG.info("Application overrides generated.")
                overrides_str = self._generate_armada_overrides_str(
                    app.name, app.version, helm_files, armada_files)

                self._update_app_status(
                    app, new_progress=constants.APP_PROGRESS_DOWNLOAD_IMAGES)

                if AppOperator.is_app_aborted(app.name):
                    raise exception.KubeAppAbort()

                self._download_images(app)
            else:
                ready = False
        except Exception as e:
            LOG.exception(e)
            if AppOperator.is_app_aborted(app.name):
                self._abort_operation(app, constants.APP_APPLY_OP,
                                      user_initiated=True)
            else:
                self._abort_operation(app, constants.APP_APPLY_OP,
                                      constants.APP_PROGRESS_ABORTED)

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
                if app.name == constants.HELM_APP_OPENSTACK:
                    # For stx-openstack app, if the apply operation was terminated
                    # (e.g. user aborted, controller swacted, sysinv conductor
                    # restarted) while compute-kit charts group was being deployed,
                    # Tiller may still be processing these charts. Issuing another
                    # manifest apply request while there are pending install of libvirt,
                    # neutron and/or nova charts will result in reapply failure.
                    #
                    # Wait up to 10 minutes for Tiller to finish its transaction
                    # from previous apply before making a new manifest apply request.
                    LOG.info("Wait if there are openstack charts in pending install...")
                    for i in range(CHARTS_PENDING_INSTALL_ITERATIONS):
                        result = helm_utils.get_openstack_pending_install_charts()
                        if not result:
                            break

                        if AppOperator.is_app_aborted(app.name):
                            raise exception.KubeAppAbort()
                        greenthread.sleep(10)
                    if result:
                        self._abort_operation(app, constants.APP_APPLY_OP)
                        raise exception.KubeAppApplyFailure(
                            name=app.name, version=app.version,
                            reason="Timed out while waiting for some charts that "
                                   "are still in pending install in previous application "
                                   "apply to clear. Please try again later.")

                self._update_app_status(
                    app, new_progress=constants.APP_PROGRESS_APPLY_MANIFEST)

                if AppOperator.is_app_aborted(app.name):
                    raise exception.KubeAppAbort()
                if self._make_armada_request_with_monitor(app,
                                                          constants.APP_APPLY_OP,
                                                          overrides_str):
                    self._update_app_releases_version(app.name)
                    self._update_app_status(app,
                                            constants.APP_APPLY_SUCCESS,
                                            constants.APP_PROGRESS_COMPLETED)
                    app.update_active(True)
                    if not caller:
                        self._clear_app_alarm(app.name)
                    LOG.info("Application %s (%s) apply completed." % (app.name, app.version))
                    return True
        except Exception as e:
            # ex: update release version failure, user abort
            LOG.exception(e)

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
                           operation, reuse_user_overrides=None):
        """Process application update request

        This method leverages the existing application upload workflow to
        validate/upload the new application tarfile, then invokes Armada
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
        :param operation: apply or rollback
        :param reuse_user_overrides: (optional) True or False
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
            # Upload new app tarball. The upload will enable the new plugins to
            # generate overrides for images. Disable the plugins for the current
            # application as the new plugin module will have the same name. Only
            # one version of the module can be enabled at any given moment
            self._plugins.deactivate_plugins(from_app)
            to_app = self.perform_app_upload(to_rpc_app, tarfile)
            # Check whether the new application is compatible with the current k8s version
            self._utils._check_app_compatibility(to_app.name, to_app.version)

            self._update_app_status(to_app, constants.APP_UPDATE_IN_PROGRESS)

            result = False
            if operation == constants.APP_APPLY_OP:
                reuse_overrides = \
                    self._get_user_overrides_flag_from_metadata(to_app)
                if reuse_user_overrides is not None:
                    reuse_overrides = reuse_user_overrides

                # Preserve user overrides for the new app
                if reuse_overrides:
                    self._preserve_user_overrides(from_app, to_app)

                # The app_apply will generate new versioned overrides for the
                # app upgrade and will enable the new plugins for that version.
                result = self.perform_app_apply(to_rpc_app, mode=None, caller='update')
            elif operation == constants.APP_ROLLBACK_OP:
                # The app_rollback will use the previous helm releases known to
                # the k8s cluster. Overrides are not generated from any plugins
                # in the case. Make sure that the enabled plugins correspond to
                # the version expected to be activated
                self._plugins.activate_plugins(to_app)
                result = self._perform_app_rollback(from_app, to_app)

            if not result:
                LOG.error("Application %s update from version %s to version "
                          "%s aborted." % (to_app.name, from_app.version, to_app.version))
                return self._perform_app_recover(from_app, to_app)

            self._update_app_status(to_app, constants.APP_UPDATE_IN_PROGRESS,
                                    "cleanup application version {}".format(from_app.version))

            # App apply/rollback succeeded
            # Starting cleanup old application
            from_app.charts = self._get_list_of_charts(from_app.sync_armada_mfile)
            to_app_charts = [c.release for c in to_app.charts]
            deployed_releases = helm_utils.retrieve_helm_releases()
            for from_chart in from_app.charts:
                if (from_chart.release not in to_app_charts and
                        from_chart.release in deployed_releases):
                    # Cleanup the releases in the old application version
                    # but are not in the new application version
                    helm_utils.delete_helm_release(from_chart.release)
                    LOG.info("Helm release %s for Application %s (%s) deleted"
                             % (from_chart.release, from_app.name, from_app.version))

            self._cleanup(from_app, app_dir=False)
            self._utils._patch_report_app_dependencies(
                from_app.name + '-' + from_app.version)

            self._update_app_status(
                to_app, constants.APP_APPLY_SUCCESS,
                constants.APP_PROGRESS_UPDATE_COMPLETED.format(from_app.version,
                                                               to_app.version))
            LOG.info("Application %s update from version %s to version "
                     "%s completed." % (to_app.name, from_app.version, to_app.version))
        except (exception.IncompatibleKubeVersion,
                exception.KubeAppUploadFailure,
                exception.KubeAppApplyFailure,
                exception.KubeAppAbort) as e:
            # Error occurs during app uploading or applying but before
            # armada apply process...
            # ie.images download/k8s resource creation failure
            # Start recovering without trigger armada process
            LOG.exception(e)
            return self._perform_app_recover(from_app, to_app,
                                             armada_process_required=False)
        except Exception as e:
            # Application update successfully(armada apply/rollback)
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
        return True

    def perform_app_remove(self, rpc_app):
        """Process application remove request

        This method invokes Armada to delete the application manifest.
        For system app, it also cleans up old test pods.

        :param rpc_app: application object in the RPC request
        :return boolean: whether application remove was successful
        """

        app = AppOperator.Application(rpc_app)
        self._register_app_abort(app.name)

        self.clear_reapply(app.name)
        LOG.info("Application (%s) remove started." % app.name)
        rc = True

        app.charts = self._get_list_of_charts(app.sync_armada_mfile)
        app.update_active(False)
        self._update_app_status(
            app, new_progress=constants.APP_PROGRESS_DELETE_MANIFEST)

        if self._make_armada_request_with_monitor(app, constants.APP_DELETE_OP):
            # After armada delete, the data for the releases are purged from
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
                self._delete_local_registry_secrets(app.name)
                if app.system_app:
                    if self._rbd_provisioner_required(app.name):
                        self._delete_rbd_provisioner_secrets(app.name)
                    self._delete_app_specific_resources(app.name, constants.APP_REMOVE_OP)
                    self._plugins.deactivate_plugins(app)
            except Exception as e:
                self._abort_operation(app, constants.APP_REMOVE_OP)
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
                self._abort_operation(app, constants.APP_REMOVE_OP,
                                      user_initiated=True)
            else:
                self._abort_operation(app, constants.APP_REMOVE_OP)
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

    def perform_app_abort(self, rpc_app):
        """Process application abort request

        This method retrieves the latest application status from the
        database and sets the abort flag if the apply/update/remove
        operation is still in progress. The corresponding app processing
        thread will check the flag and abort the operation in the very
        next opportunity. The method also stops the Armada service and
        clears locks in case the app processing thread has made a
        request to Armada.

        :param rpc_app: application object in the RPC request
        """

        app = AppOperator.Application(rpc_app)

        # Retrieve the latest app status from the database
        db_app = self._dbapi.kube_app_get(app.name)
        if db_app.status in [constants.APP_APPLY_IN_PROGRESS,
                             constants.APP_UPDATE_IN_PROGRESS,
                             constants.APP_REMOVE_IN_PROGRESS]:
            # Turn on the abort flag so the processing thread that is
            # in progress can bail out in the next opportunity.
            self._set_abort_flag(app.name)

            # Stop the Armada request in case it has reached this far and
            # remove locks.
            with self._lock:
                self._docker.stop_armada_request()
                self._clear_armada_locks()
        else:
            # Either the previous operation has completed or already failed
            LOG.info("Abort request ignored. The previous operation for app %s "
                     "has either completed or failed." % app.name)

    def perform_app_delete(self, rpc_app):
        """Process application remove request

        This method removes the application entry from the database and
        performs cleanup which entails removing node labels where applicable
        and purge all application files from the system.

        :param rpc_app: application object in the RPC request
        """

        app = AppOperator.Application(rpc_app)
        try:
            if app.system_app:
                self._delete_app_specific_resources(app.name, constants.APP_DELETE_OP)
            self._dbapi.kube_app_destroy(app.name)
            self._cleanup(app)
            self._utils._patch_report_app_dependencies(app.name + '-' + app.version)
            # One last check of app alarm, should be no-op unless the
            # user deletes the application following an upload failure.
            self._clear_app_alarm(app.name)
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
            self.inst_armada_mfile = generate_install_manifest_fqpn(
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
            self.sync_armada_mfile_dir = cutils.generate_synced_armada_dir(
                self._kube_app.get('name'),
                self._kube_app.get('app_version'))

            # Files: DRBD synced between controllers
            self.sync_armada_mfile = cutils.generate_synced_armada_manifest_fqpn(
                self._kube_app.get('name'),
                self._kube_app.get('app_version'),
                self._kube_app.get('manifest_file'))
            self.sync_imgfile = generate_synced_images_fqpn(
                self._kube_app.get('name'),
                self._kube_app.get('app_version'))

            # Files: FQPN formatted for the docker armada_service
            self.armada_service_mfile = generate_armada_service_manifest_fqpn(
                self._kube_app.get('name'),
                self._kube_app.get('app_version'),
                self._kube_app.get('manifest_file'))

            self.patch_dependencies = []
            self.charts = []
            self.releases = []

        @property
        def system_app(self):

            # TODO(rchurch): This will be refactored as plugins become bundled
            # with applications. A system app can be determined if it has any
            # installed plugins after being uploaded.
            return ((self.name == constants.HELM_APP_MONITOR) or
                    (True if (os.path.exists(self.sync_plugins_dir) and
                              os.listdir(self.sync_plugins_dir)) else False))

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

        def regenerate_manifest_filename(self, new_mname, new_mfile):
            self._kube_app.manifest_name = new_mname
            self._kube_app.manifest_file = new_mfile
            self.armada_service_mfile = generate_armada_service_manifest_fqpn(
                self.name, self.version, new_mfile)
            self.sync_armada_mfile = cutils.generate_synced_armada_manifest_fqpn(
                self.name, self.version, new_mfile)
            self.inst_armada_mfile = generate_install_manifest_fqpn(
                self.name, self.version, new_mfile)

        def regenerate_application_info(self, new_name, new_version, new_patch_dependencies):
            self._kube_app.name = new_name
            self._kube_app.app_version = new_version

            new_armada_dir = cutils.generate_synced_armada_dir(
                self.name, self.version)
            shutil.move(self.sync_armada_mfile_dir, new_armada_dir)
            shutil.rmtree(os.path.dirname(self.sync_armada_mfile_dir))
            self.sync_armada_mfile_dir = new_armada_dir

            new_path = os.path.join(
                constants.APP_INSTALL_PATH, self.name, self.version)
            shutil.move(self.inst_path, new_path)
            shutil.rmtree(os.path.dirname(self.inst_path))
            self.inst_path = new_path

            self.inst_charts_dir = os.path.join(self.inst_path, 'charts')
            self.inst_images_dir = os.path.join(self.inst_path, 'images')
            self.sync_imgfile = generate_synced_images_fqpn(self.name, self.version)
            self.sync_overrides_dir = generate_synced_helm_overrides_dir(self.name, self.version)
            self.patch_dependencies = new_patch_dependencies


class DockerHelper(object):
    """ Utility class to encapsulate Docker related operations """

    def __init__(self, dbapi):
        self._dbapi = dbapi
        self._lock = threading.Lock()
        self.registries_info = \
            copy.deepcopy(constants.DEFAULT_REGISTRIES_INFO)

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
            username, password = payload.split()
            username = username.split('username:')[1]
            password = password.split('password:')[1]
            return dict(username=username, password=password)
        except Exception as e:
            LOG.error("Unable to parse the secret payload, "
                      "unknown format of the registry secret: %s" % e)
            raise exception.SysinvException(_(
                "Unable to parse the secret payload"))

    def _retrieve_specified_registries(self):
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
            return

        for section, url in registries_url.items():
            try:
                self.registries_info[section]['registry_replaced'] = str(url)

                if section in registries_overrides:
                    self.registries_info[section]['registry_default'] = \
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
                        self.registries_info[section]['registry_auth'] = auth
            except exception.SysinvException:
                raise exception.SysinvException(_(
                    "Unable to get the credentials to access "
                    "registry %s" % url))
            except KeyError:
                # Unexpected
                pass

    def _reset_registries_info(self):
        # Set cached registries information
        # back to default
        if self.registries_info != \
                constants.DEFAULT_REGISTRIES_INFO:
            self.registries_info = copy.deepcopy(
                constants.DEFAULT_REGISTRIES_INFO)

    def _get_img_tag_with_registry(self, pub_img_tag):
        """Regenerate public image tag with user specified registries

           An example of passed public image reference:
           docker.io/starlingx/stx-keystone:latest
        """

        if self.registries_info == constants.DEFAULT_REGISTRIES_INFO:
            # return if no user specified registries
            return pub_img_tag, None

        for registry_info in self.registries_info.values():
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

    def _start_armada_service(self, client):
        try:
            container = client.containers.get(ARMADA_CONTAINER_NAME)
            if container.status != 'running':
                LOG.info("Restarting Armada service...")
                container.restart()
            return container
        except Exception:
            LOG.info("Starting Armada service...")
            try:
                # Create the armada log folder if it does not exists
                if not os.path.exists(ARMADA_HOST_LOG_LOCATION):
                    os.mkdir(ARMADA_HOST_LOG_LOCATION)
                    os.chmod(ARMADA_HOST_LOG_LOCATION, 0o755)
                    os.chown(ARMADA_HOST_LOG_LOCATION, 1000, grp.getgrnam("sys_protected").gr_gid)

                # First make kubernetes config accessible to Armada. This
                # is a work around the permission issue in Armada container.
                kube_config = os.path.join(constants.APP_SYNCED_ARMADA_DATA_PATH,
                                           'admin.conf')
                shutil.copy(kubernetes.KUBERNETES_ADMIN_CONF, kube_config)
                os.chown(kube_config, 1000, grp.getgrnam("sys_protected").gr_gid)

                overrides_dir = common.HELM_OVERRIDES_PATH
                manifests_dir = constants.APP_SYNCED_ARMADA_DATA_PATH
                logs_dir = ARMADA_HOST_LOG_LOCATION
                LOG.info("kube_config=%s, manifests_dir=%s, "
                         "overrides_dir=%s, logs_dir=%s." %
                         (kube_config, manifests_dir, overrides_dir, logs_dir))

                binds = {
                    kube_config: {'bind': '/armada/.kube/config', 'mode': 'ro'},
                    manifests_dir: {'bind': '/manifests', 'mode': 'ro'},
                    overrides_dir: {'bind': '/overrides', 'mode': 'ro'},
                    logs_dir: {'bind': ARMADA_CONTAINER_LOG_LOCATION, 'mode': 'rw'}}

                # Armada img was pushed to local registry (registry.local:9001/quay.io/)
                # at bootstrap time
                armada_image_tag = constants.DOCKER_REGISTRY_SERVER + '/' + \
                                   constants.DEFAULT_DOCKER_QUAY_REGISTRY + \
                                   image_versions.ARMADA_IMAGE_NAME + ":" + \
                                   image_versions.ARMADA_IMAGE_VERSION

                armada_image = client.images.list(armada_image_tag)
                # Pull Armada image if it's not available
                if not armada_image:
                    LOG.info("Downloading Armada image %s ..." % armada_image_tag)
                    local_registry_auth = cutils.get_local_docker_registry_auth()
                    client.images.pull(armada_image_tag,
                                       auth_config=local_registry_auth)
                    LOG.info("Armada image %s downloaded!" % armada_image_tag)

                container = client.containers.run(
                    armada_image_tag,
                    name=ARMADA_CONTAINER_NAME,
                    detach=True,
                    volumes=binds,
                    restart_policy={'Name': 'always'},
                    network_mode='host',
                    command=None)
                LOG.info("Armada service started!")
                return container
            except IOError as ie:
                if not kubernetes.is_k8s_configured():
                    LOG.error("Unable to start Armada service: %s" % ie)
            except OSError as oe:
                LOG.error("Unable to make kubernetes config accessible to "
                          "armada: %s" % oe)
            except Exception as e:
                # Possible docker exceptions are: RuntimeError, ContainerError,
                # ImageNotFound and APIError
                LOG.error("Docker error while launching Armada container: %s", e)
                os.unlink(kube_config)
            return None

    def make_armada_request(self, request, manifest_file='', overrides_str='',
                            app_releases=None, logfile=None):

        if logfile is None:
            logfile = time.strftime(request + '_%Y-%m-%d-%H-%M-%S.log')

        if app_releases is None:
            app_releases = []

        rc = True

        # Instruct Armada to use the tiller service since it does not properly
        # process IPv6 endpoints, therefore use a resolvable hostname
        tiller_host = " --tiller-host tiller-deploy.kube-system.svc.cluster.local"

        try:
            client = docker.from_env(timeout=INSTALLATION_TIMEOUT)

            # It causes problem if multiple threads attempt to start the
            # same container, so add lock to ensure only one thread can
            # start the Armada container at a time
            with self._lock:
                armada_svc = self._start_armada_service(client)

            if armada_svc:
                if request == 'validate':
                    cmd = 'armada validate ' + manifest_file
                    (exit_code, exec_logs) = armada_svc.exec_run(cmd)
                    if exit_code == 0:
                        LOG.info("Manifest file %s was successfully validated." %
                                 manifest_file)
                    else:
                        rc = False
                        if exit_code == CONTAINER_ABNORMAL_EXIT_CODE:
                            LOG.error("Failed to validate application manifest %s. "
                                      "Armada service has exited abnormally." %
                                      manifest_file)
                        else:
                            LOG.error("Failed to validate application manifest "
                                      "%s: %s." % (manifest_file, exec_logs))
                elif request == constants.APP_APPLY_OP:
                    cmd = ("/bin/bash -c 'set -o pipefail; armada apply "
                           "--enable-chart-cleanup --debug {m} {o} {t} | "
                           "tee {lf}'".format(m=manifest_file, o=overrides_str,
                                             t=tiller_host, lf=logfile))
                    LOG.info("Armada apply command = %s" % cmd)
                    (exit_code, exec_logs) = armada_svc.exec_run(cmd)
                    if exit_code == 0:
                        LOG.info("Application manifest %s was successfully "
                                 "applied/re-applied." % manifest_file)
                    else:
                        rc = False
                        if exit_code == CONTAINER_ABNORMAL_EXIT_CODE:
                            LOG.error("Failed to apply application manifest %s. "
                                      "Armada service has exited abnormally." %
                                      manifest_file)
                        else:
                            LOG.error("Failed to apply application manifest %s. See "
                                      "/var/log/armada/%s for details." %
                                      (manifest_file, os.path.basename(logfile)))
                elif request == constants.APP_ROLLBACK_OP:
                    cmd_rm = "rm " + logfile
                    armada_svc.exec_run(cmd_rm)

                    for app_release in app_releases:
                        release = app_release.get('release')
                        version = app_release.get('version')
                        sequenced = app_release.get('sequenced')

                        if sequenced:
                            cmd = "/bin/bash -c 'set -o pipefail; armada rollback " +\
                                  "--debug --wait --timeout 1800 --release " +\
                                  release + " --version " + str(version) + tiller_host +\
                                  " | tee -a " + logfile + "'"
                        else:
                            cmd = "/bin/bash -c 'set -o pipefail; armada rollback " +\
                                  "--debug --release " + release + " --version " +\
                                  str(version) + tiller_host + " | tee -a " + logfile + "'"
                        (exit_code, exec_logs) = armada_svc.exec_run(cmd)
                        if exit_code != 0:
                            rc = False
                            if exit_code == CONTAINER_ABNORMAL_EXIT_CODE:
                                LOG.error("Failed to rollback release (%s). "
                                          "Armada service has exited abnormally."
                                          % release)
                            else:
                                LOG.error("Failed to rollback release %s. See  "
                                          "/var/log/armada/%s for details." %
                                          (release, os.path.basename(logfile)))
                            break
                    if rc:
                        LOG.info("Application releases %s were successfully "
                                 "rolled back." % app_releases)
                elif request == constants.APP_DELETE_OP:
                    # Since armada delete doesn't support --values overrides
                    # files, use the delete manifest generated from the
                    # ArmadaManifestOperator during overrides generation. It
                    # will contain an accurate view of what was applied
                    manifest_delete_file = "%s-del%s" % os.path.splitext(manifest_file)
                    cmd = "/bin/bash -c 'set -o pipefail; armada delete --debug " +\
                          "--manifest " + manifest_delete_file + tiller_host + " | tee " +\
                          logfile + "'"
                    LOG.info("Armada delete command = %s" % cmd)
                    (exit_code, exec_logs) = armada_svc.exec_run(cmd)
                    if exit_code == 0:
                        LOG.info("Application charts were successfully "
                                 "deleted with manifest %s." % manifest_delete_file)
                    else:
                        rc = False
                        if exit_code == CONTAINER_ABNORMAL_EXIT_CODE:
                            LOG.error("Failed to delete application manifest %s. "
                                      "Armada service has exited abnormally." %
                                      manifest_file)
                        else:
                            LOG.error("Failed to delete application manifest %s. See "
                                      "/var/log/armada/%s for details." %
                                      (manifest_file, os.path.basename(logfile)))
                else:
                    rc = False
                    LOG.error("Unsupported armada request: %s." % request)
            else:
                # Armada sevice failed to start/restart
                rc = False
        except Exception as e:
            # Failed to get a docker client
            rc = False
            LOG.error("Armada request %s for manifest %s failed: %s " %
                      (request, manifest_file, e))
        return rc

    def stop_armada_request(self):
        """A simple way to cancel an on-going manifest apply/rollback/delete
           request. This logic will be revisited in the future.
        """

        try:
            client = docker.from_env(timeout=INSTALLATION_TIMEOUT)
            container = client.containers.get(ARMADA_CONTAINER_NAME)
            if container.status == 'running':
                LOG.info("Stopping Armada service...")
                container.stop()
        except Exception as e:
            # Failed to get a docker client
            LOG.error("Failed to stop Armada service : %s " % e)

    def download_an_image(self, app_name, img_tag):

        rc = True

        start = time.time()
        if img_tag.startswith(constants.DOCKER_REGISTRY_HOST):
            try:
                if AppOperator.is_app_aborted(app_name):
                    LOG.info("User aborted. Skipping download of image %s " % img_tag)
                    return img_tag, False

                LOG.info("Image %s download started from local registry" % img_tag)
                client = docker.APIClient(timeout=INSTALLATION_TIMEOUT)
                local_registry_auth = cutils.get_local_docker_registry_auth()
                auth = '{0}:{1}'.format(local_registry_auth['username'],
                                        local_registry_auth['password'])
                subprocess.check_call(["crictl", "pull", "--creds", auth, img_tag])
            except subprocess.CalledProcessError:
                try:
                    # Pull the image from the public/private registry
                    LOG.info("Image %s is not available in local registry, "
                             "download started from public/private registry"
                             % img_tag)
                    pub_img_tag = img_tag.replace(
                        constants.DOCKER_REGISTRY_SERVER + "/", "")
                    target_img_tag, registry_auth = self._get_img_tag_with_registry(pub_img_tag)
                    client.pull(target_img_tag, auth_config=registry_auth)
                except Exception as e:
                    rc = False
                    LOG.error("Image %s download failed from public/private"
                              "registry: %s" % (target_img_tag, e))
                    return img_tag, rc

                try:
                    # Tag and push the image to the local registry
                    client.tag(target_img_tag, img_tag)
                    # admin password may be changed by openstack client cmd in parallel.
                    # So we cannot cache auth info, need refresh it each time.
                    local_registry_auth = cutils.get_local_docker_registry_auth()
                    client.push(img_tag, auth_config=local_registry_auth)
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
                client = docker.APIClient(timeout=INSTALLATION_TIMEOUT)
                target_img_tag, registry_auth = self._get_img_tag_with_registry(img_tag)
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

              2. image: <str>

              3. image:
                   repository: <str>
                   tag: <str>

              4. image: <str>
                 imageTag(tag/imagetag): <str>

        :param var_dict: dict
        :return: a list of image references
        """
        if isinstance(var_dict, dict):
            for k, v in six.iteritems(var_dict):
                if k == 'images':
                    try:
                        yield {k: {'tags': v['tags']}}
                    except (KeyError, TypeError):
                        pass

                elif k == 'image':
                    try:
                        image = {}
                        keys = v.keys()
                        if 'repository' in keys:
                            image.update({'repository': v['repository']})
                        if 'tag' in keys:
                            image.update({'tag': v['tag']})
                        if image:
                            yield {k: image}
                    except (KeyError, TypeError, AttributeError):
                        if isinstance(v, str) or v is None:
                            yield {k: v}

                elif k in self.TAG_LIST:
                    if isinstance(v, str) or v is None:
                        yield {k: v}

                elif isinstance(v, dict):
                    for result in self._find_images_in_dict(v):
                        yield {k: result}

    def find_images_in_dict(self, var_dict):
        """Find image references in a nested dictionary.

        This function is used to find images from helm chart,
        chart overrides file and armada manifest file.

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
            if k == 'images':
                try:
                    imgs = filter(None, v['tags'].values())
                    download_imgs_list.extend(imgs)
                except (KeyError, TypeError):
                    pass

            elif k == 'image':
                try:
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

    # An enabled plugin will have a python path configuration file name with the
    # following format: stx_app-platform-integ-apps-1.0-8.pth
    PTH_PREFIX = 'stx_app-'
    PTH_PATTERN = re.compile("{}/([\w-]+)/(\d+\.\d+-\d+)".format(common.HELM_OVERRIDES_PATH))

    def __init__(self, dbapi, helm_op):
        self._dbapi = dbapi
        self._helm_op = helm_op
        self._system_path = self._get_python_system_path()

    def _get_python_system_path(self):
        path = None
        try:
            path = site.getsitepackages()[0]
        except AttributeError:
            # Based on https://github.com/pypa/virtualenv/issues/737.
            # site.getsitepackages() function is not available in a virtualenv.
            # So use a tox friendly method when in a virtualenv
            try:
                from distutils.sysconfig import get_python_lib
                path = get_python_lib()
            except Exception as e:
                raise exception.SysinvException(_(
                    "Failed to determine the python site packages path" % str(e)))

        if not path:
            raise exception.SysinvException(_(
                "Failed to determine the python site packages path."))

        return path

    def _get_pth_fqpn(self, app):
        return "{}/{}{}-{}.pth".format(
            self._system_path, self.PTH_PREFIX, app.name, app.version)

    def audit_plugins(self):
        """ Verify that only enabled application plugins are discoverable """

        pattern = '{}/{}*.pth'.format(self._system_path, self.PTH_PREFIX)
        discoverable_pths = glob.glob(pattern)
        LOG.debug("PluginHelper: Discoverable app plugins: %s" % discoverable_pths)

        for pth in discoverable_pths:
            with open(pth, 'r') as f:
                contents = f.readlines()

            if len(contents) == 1:
                LOG.debug("PluginHelper: Plugin Path: %s" % contents[0])
                match = self.PTH_PATTERN.match(contents[0])
                if match:
                    app = match.group(1)
                    ver = match.group(2)
                    try:
                        app_obj = self._dbapi.kube_app_get(app)
                        if app_obj.app_version == ver:
                            LOG.info("PluginHelper: App %s, version %s: Found "
                                     "valid plugin" % (app, ver))
                            continue
                        else:
                            LOG.warning("PluginHelper: Stale plugin pth file "
                                        "found %s: Wrong plugin version "
                                        "enabled %s." % (pth, ver))
                    except exception.KubeAppNotFound:
                        LOG.warning("PluginHelper: Stale plugin pth file found"
                                    " %s: App is not active." % pth)
                else:
                    LOG.warning("PluginHelper: Invalid pth file %s: Invalid "
                                "name or version." % pth)
            else:
                LOG.warning("PluginHelper: Invalid pth file %s: Only one path"
                            " is expected." % pth)

            LOG.info("PluginHelper: Removing invalid plugin pth: %s" % pth)
            os.remove(pth)

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
        # Add a .pth file to a site-packages directory so the plugin is picked
        # automatically on a conductor restart
        pth_fqpn = self._get_pth_fqpn(app)
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
        pth_fqpn = self._get_pth_fqpn(app)
        if os.path.exists(pth_fqpn):
            # Remove the pth file, so on a conductor restart this installed
            # plugin is not discoverable
            try:
                os.remove(pth_fqpn)
                LOG.info("PluginHelper: Disabled plugin directory %s: removed "
                         "%s" % (app.sync_plugins_dir, pth_fqpn))
            except OSError:
                # Not present, should be, but continue on...
                pass

        # Make sure the sys.path reflects only enabled plugins
        try:
            sys.path.remove(app.sync_plugins_dir)
        except ValueError:
            # Not present, should be, but continue on...
            LOG.warning("sys.path (%s) is missing plugin (%s)" % (
                sys.path, app.sync_plugins_dir))

        # Determine distributions installed by this plugin
        if app.sync_plugins_dir in pkg_resources.working_set.entry_keys:
            plugin_distributions = pkg_resources.working_set.entry_keys[app.sync_plugins_dir]
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
                del pkg_resources.working_set.by_key[distribution]
            del pkg_resources.working_set.entry_keys[app.sync_plugins_dir]
            pkg_resources.working_set.entries.remove(app.sync_plugins_dir)

        if self._helm_op:
            # purge this plugin from the stevedore plugin cache so this version
            # of the plugin endoints are not discoverable
            self._helm_op.purge_cache_by_location(app.sync_plugins_dir)
