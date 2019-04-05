# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System Inventory Kubernetes Application Operator."""

import base64
import docker
import grp
import keyring
import os
import pwd
import re
import ruamel.yaml as yaml
import shutil
import subprocess
import threading
import time

from collections import namedtuple
from eventlet import greenpool
from eventlet import greenthread
from eventlet import queue
from eventlet import Timeout
from oslo_config import cfg
from oslo_log import log as logging
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import utils as cutils
from sysinv.helm import common
from sysinv.helm import helm


# Log and config
LOG = logging.getLogger(__name__)
kube_app_opts = [
    cfg.StrOpt('armada_image_tag',
               default=('quay.io/airshipit/armada:'
                        'f807c3a1ec727c883c772ffc618f084d960ed5c9'),
               help='Docker image tag of Armada.'),
                ]
CONF = cfg.CONF
CONF.register_opts(kube_app_opts)


# Constants
APPLY_SEARCH_PATTERN = 'Processing Chart,'
ARMADA_CONTAINER_NAME = 'armada_service'
ARMADA_MANIFEST_APPLY_SUCCESS_MSG = 'Done applying manifest'
CONTAINER_ABNORMAL_EXIT_CODE = 137
DELETE_SEARCH_PATTERN = 'Deleting release'
INSTALLATION_TIMEOUT = 3600
MAX_DOWNLOAD_THREAD = 20
TARFILE_DOWNLOAD_CONNECTION_TIMEOUT = 60
TARFILE_TRANSFER_CHUNK_SIZE = 1024 * 512
DOCKER_REGISTRY_USER = 'admin'
DOCKER_REGISTRY_SERVICE = 'CGCS'
DOCKER_REGISTRY_SECRET = 'default-registry-key'
DOCKER_REGISTRY_PORT = '9001'


# Helper functions
def generate_armada_manifest_filename(app_name, manifest_filename):
    return os.path.join('/manifests', app_name + '-' + manifest_filename)


def generate_armada_manifest_filename_abs(app_name, manifest_filename):
    return os.path.join(constants.APP_SYNCED_DATA_PATH,
                        app_name + '-' + manifest_filename)


def generate_manifest_filename_abs(app_name, manifest_filename):
    return os.path.join(constants.APP_INSTALL_PATH,
                        app_name, manifest_filename)


def generate_images_filename_abs(app_name):
    return os.path.join(constants.APP_SYNCED_DATA_PATH,
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


def get_local_docker_registry_auth():
    registry_password = keyring.get_password(
        DOCKER_REGISTRY_SERVICE, DOCKER_REGISTRY_USER)
    if not registry_password:
        raise exception.DockerRegistryCredentialNotFound(
            name=DOCKER_REGISTRY_USER)

    return dict(username=DOCKER_REGISTRY_USER,
                password=registry_password)


Chart = namedtuple('Chart', 'name namespace')


class AppOperator(object):
    """Class to encapsulate Kubernetes App operations for System Inventory"""

    def __init__(self, dbapi):
        self._dbapi = dbapi
        self._docker = DockerHelper(self._dbapi)
        self._helm = helm.HelmOperator(self._dbapi)
        self._kube = kubernetes.KubeOperator(self._dbapi)
        self._lock = threading.Lock()

    def _cleanup(self, app):
        """" Remove application directories and override files """
        try:
            if (app.status != constants.APP_UPLOAD_FAILURE and
                    os.path.exists(os.path.join(app.path, 'metadata.yaml'))):
                self._process_node_labels(app, op=constants.LABEL_REMOVE_OP)
            if app.system_app and app.status != constants.APP_UPLOAD_FAILURE:
                self._remove_chart_overrides(app.armada_mfile_abs)

            if os.path.exists(app.armada_mfile_abs):
                os.unlink(app.armada_mfile_abs)
            if os.path.exists(app.imgfile_abs):
                os.unlink(app.imgfile_abs)

            if os.path.exists(app.path):
                shutil.rmtree(app.path)
        except OSError as e:
            LOG.error(e)

    def _update_app_status(self, app, new_status=None, new_progress=None):
        """ Persist new app status """

        if new_status is None:
            new_status = app.status
        elif (new_status in [constants.APP_UPLOAD_SUCCESS,
                             constants.APP_APPLY_SUCCESS]):
            new_progress = constants.APP_PROGRESS_COMPLETED

        with self._lock:
            app.update_status(new_status, new_progress)

    def _abort_operation(self, app, operation,
                         progress=constants.APP_PROGRESS_ABORTED):
        if (app.status == constants.APP_UPLOAD_IN_PROGRESS):
            self._update_app_status(app, constants.APP_UPLOAD_FAILURE,
                                    progress)
        elif (app.status == constants.APP_APPLY_IN_PROGRESS):
            self._update_app_status(app, constants.APP_APPLY_FAILURE,
                                    progress)
        elif (app.status == constants.APP_REMOVE_IN_PROGRESS):
            self._update_app_status(app, constants.APP_REMOVE_FAILURE,
                                    progress)
        LOG.error("Application %s aborted!." % operation)

    def _download_tarfile(self, app):
        from six.moves.urllib.request import urlopen
        from six.moves.urllib.error import HTTPError
        from six.moves.urllib.error import URLError
        from socket import timeout as socket_timeout
        from six.moves.urllib.parse import urlparse

        def _handle_download_failure(reason):
            raise exception.KubeAppUploadFailure(
                name=app.name,
                reason=reason)

        try:
            remote_file = urlopen(
                app.tarfile, timeout=TARFILE_DOWNLOAD_CONNECTION_TIMEOUT)
            try:
                remote_filename = remote_file.info()['Content-Disposition']
            except KeyError:
                remote_filename = os.path.basename(
                    urlparse.urlsplit(remote_file.url).path)

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
                reason=reason)

        def _find_manifest_file(app_path):
            mfiles = cutils.find_manifest_file(app_path)

            if mfiles is None:
                _handle_extract_failure('manifest file is corrupted.')

            if mfiles:
                if len(mfiles) == 1:
                    return mfiles[0]
                else:
                    _handle_extract_failure(
                        'tarfile contains more than one manifest file.')
            else:
                _handle_extract_failure('manifest file is missing.')

        orig_uid, orig_gid = get_app_install_root_path_ownership()

        try:
            # One time set up of Armada manifest path for the system
            if not os.path.isdir(constants.APP_SYNCED_DATA_PATH):
                os.makedirs(constants.APP_SYNCED_DATA_PATH)

            if not os.path.isdir(app.path):
                create_app_path(app.path)

            # Temporarily change /scratch group ownership to wrs_protected
            os.chown(constants.APP_INSTALL_ROOT_PATH, orig_uid,
                     grp.getgrnam(constants.SYSINV_WRS_GRPNAME).gr_gid)

            # Extract the tarfile as sysinv user
            if not cutils.extract_tarfile(app.path, app.tarfile, demote_user=True):
                _handle_extract_failure()

            if app.downloaded_tarfile:
                if not cutils.verify_checksum(app.path):
                    _handle_extract_failure('checksum validation failed.')
                mname, mfile = _find_manifest_file(app.path)
                # Save the official manifest file info. They will be persisted
                # in the next status update
                app.regenerate_manifest_filename(mname, os.path.basename(mfile))

            if os.path.isdir(app.charts_dir):
                if len(os.listdir(app.charts_dir)) == 0:
                    _handle_extract_failure('tarfile contains no Helm charts.')

                tar_filelist = cutils.get_files_matching(app.charts_dir,
                                                         '.tgz')
                if not tar_filelist:
                    reason = 'tarfile contains no Helm charts of expected ' + \
                             'file extension (.tgz).'
                    _handle_extract_failure(reason)

                for p, f in tar_filelist:
                    if not cutils.extract_tarfile(
                            p, os.path.join(p, f), demote_user=True):
                        _handle_extract_failure()
        except OSError as e:
            LOG.error(e)
            _handle_extract_failure()
        finally:
            os.chown(constants.APP_INSTALL_ROOT_PATH, orig_uid, orig_gid)

    def _get_image_tags_by_path(self, path):
        """ Mine the image tags from values.yaml files in the chart directory,
            intended for custom apps.

            TODO(awang): Support custom apps to pull images from local registry
        """

        image_tags = []
        ids = []
        for r, f in cutils.get_files_matching(path, 'values.yaml'):
            with open(os.path.join(r, f), 'r') as value_f:
                try:
                    y = yaml.safe_load(value_f)
                    ids = y["images"]["tags"].values()
                except (TypeError, KeyError):
                    pass
            image_tags.extend(ids)
        return list(set(image_tags))

    def _get_image_tags_by_charts(self, app_images_file, app_manifest_file):
        """ Mine the image tags for charts from the images file. Add the
            image tags to the manifest file if the image tags from the charts
            do not exist in both overrides file and manifest file. Convert
            the image tags in the manifest file. Intended for system app.

            The image tagging conversion(local docker registry address prepended):
            ${LOCAL_DOCKER_REGISTRY_IP}:${REGISTRY_PORT}/<image-name>
            (ie..192.168.204.2:9001/docker.io/mariadb:10.2.13)
        """

        local_registry_server = self._docker.get_local_docker_registry_server()
        manifest_image_tags_updated = False
        image_tags = []

        if os.path.exists(app_images_file):
            with open(app_images_file, 'r') as f:
                images_file = yaml.safe_load(f)

        if os.path.exists(app_manifest_file):
            with open(app_manifest_file, 'r') as f:
                charts = list(yaml.load_all(f, Loader=yaml.RoundTripLoader))

        for chart in charts:
            images_charts = {}
            images_overrides = {}
            images_manifest = {}

            overrides_image_tags_updated = False
            chart_image_tags_updated = False

            if "armada/Chart/" in chart['schema']:
                chart_data = chart['data']
                chart_name = chart_data['chart_name']
                chart_namespace = chart_data['namespace']

                # Get the image tags by chart from the images file
                if chart_name in images_file:
                    images_charts = images_file[chart_name]

                # Get the image tags from the overrides file
                overrides = chart_namespace + '-' + chart_name + '.yaml'
                app_overrides_file = os.path.join(common.HELM_OVERRIDES_PATH, overrides)
                if os.path.exists(app_overrides_file):
                    try:
                        with open(app_overrides_file, 'r') as f:
                            overrides_file = yaml.safe_load(f)
                            images_overrides = overrides_file['data']['values']['images']['tags']
                    except (TypeError, KeyError):
                        pass

                # Get the image tags from the armada manifest file
                try:
                    images_manifest = chart_data['values']['images']['tags']
                except (TypeError, KeyError):
                    LOG.info("Armada manifest file has no img tags for "
                             "chart %s" % chart_name)
                    pass

                # For the image tags from the chart path which do not exist
                # in the overrides and manifest file, add to manifest file.
                # Convert the image tags in the overrides and manifest file
                # with local docker registry address.
                # Append the required images to the image_tags list.
                for key in images_charts:
                    if key not in images_overrides:
                        if key not in images_manifest:
                            images_manifest.update({key: images_charts[key]})
                        if not re.match(r'^.+:.+/', images_manifest[key]):
                            images_manifest.update(
                                {key: '{}/{}'.format(local_registry_server, images_manifest[key])})
                            chart_image_tags_updated = True
                        image_tags.append(images_manifest[key])
                    else:
                        if not re.match(r'^.+:.+/', images_overrides[key]):
                            images_overrides.update(
                                {key: '{}/{}'.format(local_registry_server, images_overrides[key])})
                            overrides_image_tags_updated = True
                        image_tags.append(images_overrides[key])

                if overrides_image_tags_updated:
                    with open(app_overrides_file, 'w') as f:
                        try:
                            overrides_file["data"]["values"]["images"] = {"tags": images_overrides}
                            yaml.safe_dump(overrides_file, f, default_flow_style=False)
                            LOG.info("Overrides file %s updated with new image tags" %
                                     app_overrides_file)
                        except (TypeError, KeyError):
                            LOG.error("Overrides file %s fails to update" %
                                      app_overrides_file)

                if chart_image_tags_updated:
                    if 'values' in chart_data:
                        chart_data['values']['images'] = {'tags': images_manifest}
                    else:
                        chart_data["values"] = {"images": {"tags": images_manifest}}
                    manifest_image_tags_updated = True

        if manifest_image_tags_updated:
            with open(app_manifest_file, 'w') as f:
                try:
                    yaml.dump_all(charts, f, Dumper=yaml.RoundTripDumper,
                                  explicit_start=True, default_flow_style=False)
                    LOG.info("Manifest file %s updated with new image tags" %
                             app_manifest_file)
                except Exception as e:
                    LOG.error("Manifest file %s fails to update with "
                              "new image tags: %s" % (app_manifest_file, e))

        return list(set(image_tags))

    def _register_embedded_images(self, app):
        """
        TODO(tngo): When we're ready to support air-gap scenario and private
        images, the following need to be done:
            a. load the embedded images
            b. tag and push them to the docker registery on the controller
            c. find image tag IDs in each chart and replace their values with
               new tags. Alternatively, document the image tagging convention
               ${MGMT_FLOATING_IP}:${REGISTRY_PORT}/<image-name>
               (e.g. 192.168.204.2:9001/prom/mysqld-exporter)
               to be referenced in the application Helm charts.
        """
        raise exception.KubeAppApplyFailure(
            name=app.name,
            reason="embedded images are not yet supported.")

    def _save_images_list(self, app):
        # Extract the list of images from the charts and overrides where
        # applicable. Save the list to the same location as the armada manifest
        # so it can be sync'ed.
        if app.system_app:
            LOG.info("Generating application overrides...")
            self._helm.generate_helm_application_overrides(
                app.name, cnamespace=None, armada_format=True, combined=True)
            app.charts = self._get_list_of_charts(app.armada_mfile_abs)
            self._save_images_list_by_charts(app)
            # Get the list of images from the updated images overrides
            images_to_download = self._get_image_tags_by_charts(
                app.imgfile_abs, app.armada_mfile_abs)
        else:
            # For custom apps, mine image tags from application path
            images_to_download = self._get_image_tags_by_path(app.path)

        if not images_to_download:
            # TODO(tngo): We may want to support the deployment of apps that
            # set up resources only in the future. In which case, generate
            # an info log and let it advance to the next step.
            raise exception.KubeAppUploadFailure(
                name=app.name,
                reason="charts specify no docker images.")

        with open(app.imgfile_abs, 'ab') as f:
            yaml.safe_dump({"download_images": images_to_download}, f,
                           default_flow_style=False)

    def _save_images_list_by_charts(self, app):
        # Mine the images from values.yaml files in the charts directory.
        # The list of images for each chart are saved to the images file.
        images_by_charts = {}
        for chart in app.charts:
            images = {}
            chart_name = os.path.join(app.charts_dir, chart.name)
            chart_path = os.path.join(chart_name, 'values.yaml')

            if os.path.exists(chart_path):
                with open(chart_path, 'r') as f:
                    try:
                        y = yaml.safe_load(f)
                        images = y["images"]["tags"]
                    except (TypeError, KeyError):
                        LOG.warn("Chart %s has no image tags" % chart_name)
            if images:
                images_by_charts.update({chart.name: images})

        with open(app.imgfile_abs, 'wb') as f:
            yaml.safe_dump(images_by_charts, f, explicit_start=True,
                           default_flow_style=False)

    def _retrieve_images_list(self, app_images_file):
        with open(app_images_file, 'rb') as f:
            images_list = yaml.safe_load(f)
        return images_list

    def _download_images(self, app):
        if os.path.isdir(app.images_dir):
            return self._register_embedded_images(app)

        if app.system_app:
            # Some images could have been overwritten via user overrides
            # between upload and apply, or between applies. Refresh the
            # saved images list.
            saved_images_list = self._retrieve_images_list(app.imgfile_abs)
            saved_download_images_list = list(saved_images_list.get("download_images"))
            images_to_download = self._get_image_tags_by_charts(
                app.imgfile_abs, app.armada_mfile_abs)
            if set(saved_download_images_list) != set(images_to_download):
                saved_images_list.update({"download_images": images_to_download})
                with open(app.imgfile_abs, 'wb') as f:
                    yaml.safe_dump(saved_images_list, f, explicit_start=True,
                                   default_flow_style=False)
        else:
            images_to_download = self._retrieve_images_list(
                app.imgfile_abs).get("download_images")

        total_count = len(images_to_download)
        threads = min(MAX_DOWNLOAD_THREAD, total_count)
        failed_downloads = []

        start = time.time()
        pool = greenpool.GreenPool(size=threads)
        for tag, rc in pool.imap(self._docker.download_an_image,
                                images_to_download):
            if not rc:
                failed_downloads.append(tag)
        elapsed = time.time() - start
        failed_count = len(failed_downloads)
        if failed_count > 0:
            raise exception.KubeAppApplyFailure(
                name=app.name,
                reason="failed to download one or more image(s).")
        else:
            LOG.info("All docker images for application %s were successfully "
                     "downloaded in %d seconds" % (app.name, elapsed))

    def _validate_helm_charts(self, app):
        failed_charts = []
        for r, f in cutils.get_files_matching(app.charts_dir, 'Chart.yaml'):
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
                    name=app.name, reason=str(e))

        if len(failed_charts) > 0:
            raise exception.KubeAppUploadFailure(
                name=app.name, reason="one or more charts failed validation.")

    def _upload_helm_charts(self, app):
        # Set env path for helm-upload execution
        env = os.environ.copy()
        env['PATH'] = '/usr/local/sbin:' + env['PATH']
        charts = [os.path.join(r, f)
                  for r, f in cutils.get_files_matching(app.charts_dir, '.tgz')]

        orig_uid, orig_gid = get_app_install_root_path_ownership()
        try:
            # Temporarily change /scratch group ownership to wrs_protected
            os.chown(constants.APP_INSTALL_ROOT_PATH, orig_uid,
                     grp.getgrnam(constants.SYSINV_WRS_GRPNAME).gr_gid)
            with open(os.devnull, "w") as fnull:
                for chart in charts:
                    subprocess.check_call(['helm-upload', chart], env=env,
                                          stdout=fnull, stderr=fnull)
                    LOG.info("Helm chart %s uploaded" % os.path.basename(chart))
        except Exception as e:
            raise exception.KubeAppUploadFailure(
                name=app.name, reason=str(e))
        finally:
            os.chown(constants.APP_INSTALL_ROOT_PATH, orig_uid, orig_gid)

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
        except exception.K8sNodeNotFound:
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

    def _process_node_labels(self, app, op=constants.LABEL_ASSIGN_OP):
        # Node labels are host personality based and are defined in
        # metadata.yaml file in the following format:
        # labels:
        #   controller: '<label-key1>=<value>, <label-key2>=<value>, ...'
        #   compute: '<label-key1>=<value>, <label-key2>=<value>, ...'

        lfile = os.path.join(app.path, 'metadata.yaml')
        controller_labels = []
        compute_labels = []
        controller_l = compute_l = None
        controller_labels_set = set()
        compute_labels_set = set()

        if os.path.exists(lfile) and os.path.getsize(lfile) > 0:
            with open(lfile, 'r') as f:
                try:
                    y = yaml.safe_load(f)
                    labels = y['labels']
                except KeyError:
                    raise exception.KubeAppUploadFailure(
                        name=app.name,
                        reason="labels file contains no labels.")
            for key, value in labels.items():
                if key == constants.CONTROLLER:
                    controller_l = value
                elif key == constants.WORKER:
                    compute_l = value
        else:
            if not app.system_app:
                LOG.info("Application %s does not require specific node "
                         "labeling." % app.name)
                return

        if controller_l:
            controller_labels =\
                controller_l.replace(',', ' ').split()
            controller_labels_set = set(controller_labels)
            if not self._validate_labels(controller_labels_set):
                raise exception.KubeAppUploadFailure(
                    name=app.name,
                    reason="controller labels are malformed.")

        if compute_l:
            compute_labels =\
                compute_l.replace(',', ' ').split()
            compute_labels_set = set(compute_labels)
            if not self._validate_labels(compute_labels_set):
                raise exception.KubeAppUploadFailure(
                    name=app.name,
                    reason="compute labels are malformed.")

        # Add the default labels for system app. They must exist for
        # the app manifest to be applied successfully. If the nodes have
        # been assigned these labels manually before, these
        # reassignments are simply ignored.
        if app.system_app:
            controller_labels_set.add(constants.CONTROL_PLANE_LABEL)
            compute_labels_set.add(constants.COMPUTE_NODE_LABEL)
            compute_labels_set.add(constants.OPENVSWITCH_LABEL)
            compute_labels_set.add(constants.SRIOV_LABEL)

        # Get controller host(s)
        controller_hosts =\
            self._dbapi.ihost_get_by_personality(constants.CONTROLLER)
        if constants.WORKER in controller_hosts[0].subfunctions:
            # AIO system
            labels = controller_labels_set.union(compute_labels_set)
            if op == constants.LABEL_ASSIGN_OP:
                self._assign_host_labels(controller_hosts, labels)
            elif op == constants.LABEL_REMOVE_OP:
                self._remove_host_labels(controller_hosts, labels)
        else:
            # Standard system
            compute_hosts =\
                self._dbapi.ihost_get_by_personality(constants.WORKER)
            if op == constants.LABEL_ASSIGN_OP:
                self._assign_host_labels(controller_hosts, controller_labels_set)
                self._assign_host_labels(compute_hosts, compute_labels_set)
            elif op == constants.LABEL_REMOVE_OP:
                self._remove_host_labels(controller_hosts, controller_labels_set)
                self._remove_host_labels(compute_hosts, compute_labels_set)

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
                 self._kube.kube_get_secret(DOCKER_REGISTRY_SECRET, ns)):
                # Secret already exist
                continue

            try:
                local_registry_server = self._docker.get_local_docker_registry_server()
                local_registry_auth = get_local_docker_registry_auth()

                auth = '{0}:{1}'.format(local_registry_auth['username'],
                                        local_registry_auth['password'])
                token = '{{\"auths\": {{\"{0}\": {{\"auth\": \"{1}\"}}}}}}'.format(
                    local_registry_server, base64.b64encode(auth))

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
                raise exception.K8sNamespaceDeleteTimeout(name=namespace)
            LOG.info("Namespace %s delete completed." % namespace)
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
        charts = []
        with open(manifest_file, 'r') as f:
            docs = yaml.safe_load_all(f)
            for doc in docs:
                try:
                    if "armada/Chart/" in doc['schema']:
                        charts.append(Chart(
                            name=doc['data']['chart_name'],
                            namespace=doc['data']['namespace']))
                except KeyError:
                    pass
        return charts

    def _get_overrides_files(self, charts):
        """Returns list of override files or None, used in
           application-install and application-delete."""

        missing_overrides = []
        available_overrides = []

        for chart in charts:
            overrides = chart.namespace + '-' + chart.name + '.yaml'
            overrides_file = os.path.join(common.HELM_OVERRIDES_PATH,
                                          overrides)
            if not os.path.exists(overrides_file):
                missing_overrides.append(overrides_file)
            else:
                available_overrides.append(overrides_file)

                # Now handle any meta-overrides files.  These can affect
                # sections of the chart schema other than "values, and can
                # affect the chartgroup or even the manifest.
                if self._helm.generate_meta_overrides(
                        chart.name, chart.namespace):
                    overrides = chart.namespace + '-' + chart.name + \
                                '-meta' + '.yaml'
                    overrides_file = os.path.join(common.HELM_OVERRIDES_PATH,
                                                  overrides)
                    if not os.path.exists(overrides_file):
                        missing_overrides.append(overrides_file)
                    else:
                        available_overrides.append(overrides_file)

        if missing_overrides:
            LOG.error("Missing the following overrides: %s" % missing_overrides)
            return None
        return available_overrides

    def _generate_armada_overrides_str(self, overrides_files):
        return " ".join([' --values /overrides/{0}'.format(os.path.basename(i))
                        for i in overrides_files])

    def _remove_chart_overrides(self, manifest_file):
        charts = self._get_list_of_charts(manifest_file)
        for chart in charts:
            if chart.name in self._helm.chart_operators:
                self._helm.remove_helm_chart_overrides(chart.name,
                                                       chart.namespace)

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
            p1 = subprocess.Popen(['docker', 'exec', ARMADA_CONTAINER_NAME,
                                   'grep', pattern, logfile],
                                   stdout=subprocess.PIPE)
            p2 = subprocess.Popen(['awk', '{print $NF}'], stdin=p1.stdout,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p1.stdout.close()
            result, err = p2.communicate()
            if result:
                # Strip out ANSI color code that might be in the text stream
                r = re.compile("\x1b\[[0-9;]*m")
                result = r.sub('', result)
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
                                    # helm-toolkit doesn't count
                                    percent = \
                                        round(float(num) / (len(app.charts) - 1) * 100)
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

        # Body of the outer method
        mqueue = queue.Queue()
        rc = True
        logfile = app.name + '-' + request + '.log'
        if request == constants.APP_APPLY_OP:
            pattern = APPLY_SEARCH_PATTERN
        else:
            pattern = DELETE_SEARCH_PATTERN

        monitor = greenthread.spawn_after(1, _check_progress, mqueue, app,
                                          pattern, logfile)
        rc = self._docker.make_armada_request(request, app.armada_mfile,
                                              overrides_str, logfile)
        mqueue.put('done')
        monitor.kill()
        return rc

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
        LOG.info("Application (%s) upload started." % app.name)

        try:
            app.tarfile = tarfile

            if cutils.is_url(app.tarfile):
                self._update_app_status(
                    app, new_progress=constants.APP_PROGRESS_TARFILE_DOWNLOAD)
                downloaded_tarfile = self._download_tarfile(app)

                if downloaded_tarfile is None:
                    self._abort_operation(app, constants.APP_UPLOAD_OP)
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
            shutil.copy(app.mfile_abs, app.armada_mfile_abs)

            if not self._docker.make_armada_request('validate', app.armada_mfile):
                return self._abort_operation(app, constants.APP_UPLOAD_OP)

            self._update_app_status(
                app, new_progress=constants.APP_PROGRESS_VALIDATE_UPLOAD_CHARTS)
            if os.path.isdir(app.charts_dir):
                self._validate_helm_charts(app)
                with self._lock:
                    self._upload_helm_charts(app)

            self._save_images_list(app)
            self._update_app_status(app, constants.APP_UPLOAD_SUCCESS)
            LOG.info("Application (%s) upload completed." % app.name)
        except exception.KubeAppUploadFailure as e:
            LOG.exception(e)
            self._abort_operation(app, constants.APP_UPLOAD_OP, str(e))
        except Exception as e:
            LOG.exception(e)
            self._abort_operation(app, constants.APP_UPLOAD_OP)

    def perform_app_apply(self, rpc_app):
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
        :return boolean: whether application apply was successful
        """

        app = AppOperator.Application(rpc_app)
        LOG.info("Application (%s) apply started." % app.name)

        self._process_node_labels(app)

        overrides_str = ''
        ready = True
        try:
            app.charts = self._get_list_of_charts(app.armada_mfile_abs)
            if app.system_app:
                self._create_local_registry_secrets(app.name)
                self._update_app_status(
                    app, new_progress=constants.APP_PROGRESS_GENERATE_OVERRIDES)
                LOG.info("Generating application overrides...")
                self._helm.generate_helm_application_overrides(
                    app.name, cnamespace=None, armada_format=True,
                    combined=True)
                overrides_files = self._get_overrides_files(app.charts)
                if overrides_files:
                    LOG.info("Application overrides generated.")
                    # Ensure all chart overrides are readable by Armada
                    for file in overrides_files:
                        os.chmod(file, 0o644)
                    overrides_str =\
                        self._generate_armada_overrides_str(overrides_files)
                    self._update_app_status(
                        app, new_progress=constants.APP_PROGRESS_DOWNLOAD_IMAGES)
                    self._download_images(app)
                else:
                    ready = False
            else:
                # No support for custom app overrides at this point, just
                # download the needed images.
                self._update_app_status(
                    app, new_progress=constants.APP_PROGRESS_DOWNLOAD_IMAGES)
                self._download_images(app)

            if ready:
                self._update_app_status(
                    app, new_progress=constants.APP_PROGRESS_APPLY_MANIFEST)
                if self._make_armada_request_with_monitor(app,
                                                          constants.APP_APPLY_OP,
                                                          overrides_str):
                    self._update_app_status(app,
                                            constants.APP_APPLY_SUCCESS)
                    LOG.info("Application (%s) apply completed." % app.name)
                    return True
        except Exception as e:
            LOG.exception(e)

        # If it gets here, something went wrong
        self._abort_operation(app, constants.APP_APPLY_OP)
        return False

    def perform_app_remove(self, rpc_app):
        """Process application remove request

        This method invokes Armada to delete the application manifest.
        For system app, it also cleans up old test pods.

        :param rpc_app: application object in the RPC request
        :return boolean: whether application remove was successful
        """

        app = AppOperator.Application(rpc_app)
        LOG.info("Application (%s) remove started." % app.name)

        app.charts = self._get_list_of_charts(app.armada_mfile_abs)
        self._update_app_status(
            app, new_progress=constants.APP_PROGRESS_DELETE_MANIFEST)

        if self._make_armada_request_with_monitor(app, constants.APP_DELETE_OP):
            if app.system_app:

                try:
                    self._delete_local_registry_secrets(app.name)
                    self._delete_persistent_volume_claim(common.HELM_NS_OPENSTACK)
                    self._delete_namespace(common.HELM_NS_OPENSTACK)
                except Exception as e:
                    self._abort_operation(app, constants.APP_REMOVE_OP)
                    LOG.exception(e)
                    return False

            self._update_app_status(app, constants.APP_UPLOAD_SUCCESS)
            LOG.info("Application (%s) remove completed." % app.name)
            return True
        else:
            self._abort_operation(app, constants.APP_REMOVE_OP)

        return False

    def perform_app_delete(self, rpc_app):
        """Process application remove request

        This method removes the application entry from the database and
        performs cleanup which entails removing node labels where applicable
        and purge all application files from the system.

        :param rpc_app: application object in the RPC request
        """

        app = AppOperator.Application(rpc_app)
        try:
            self._dbapi.kube_app_destroy(app.name)
            self._cleanup(app)
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
            self.path = os.path.join(constants.APP_INSTALL_PATH,
                                     self._kube_app.get('name'))
            self.charts_dir = os.path.join(self.path, 'charts')
            self.images_dir = os.path.join(self.path, 'images')
            self.tarfile = None
            self.downloaded_tarfile = False
            self.system_app =\
                (self._kube_app.get('name') == constants.HELM_APP_OPENSTACK)

            self.armada_mfile = generate_armada_manifest_filename(
                self._kube_app.get('name'),
                self._kube_app.get('manifest_file'))
            self.armada_mfile_abs = generate_armada_manifest_filename_abs(
                self._kube_app.get('name'),
                self._kube_app.get('manifest_file'))
            self.mfile_abs = generate_manifest_filename_abs(
                self._kube_app.get('name'),
                self._kube_app.get('manifest_file'))
            self.imgfile_abs = generate_images_filename_abs(
                self._kube_app.get('name'))

            self.charts = []

        @property
        def name(self):
            return self._kube_app.get('name')

        @property
        def status(self):
            return self._kube_app.get('status')

        @property
        def progress(self):
            return self._kube_app.get('progress')

        def update_status(self, new_status, new_progress):
            self._kube_app.status = new_status
            if new_progress:
                self._kube_app.progress = new_progress
            self._kube_app.save()

        def regenerate_manifest_filename(self, new_mname, new_mfile):
            self._kube_app.manifest_name = new_mname
            self._kube_app.manifest_file = new_mfile
            self.armada_mfile = generate_armada_manifest_filename(
                self.name, new_mfile)
            self.armada_mfile_abs = generate_armada_manifest_filename_abs(
                self.name, new_mfile)
            self.mfile_abs = generate_manifest_filename_abs(
                self.name, new_mfile)


class DockerHelper(object):
    """ Utility class to encapsulate Docker related operations """

    def __init__(self, dbapi):
        self._dbapi = dbapi
        self.k8s_registry = None
        self.gcr_registry = None
        self.quay_registry = None
        self.docker_registry = None

    def _get_registry_parameters(self):
        try:
            registry = self._dbapi.service_parameter_get_all(
                service=constants.SERVICE_TYPE_DOCKER,
                section=constants.SERVICE_PARAM_SECTION_DOCKER_REGISTRY,
                        )
            return registry
        except Exception:
            return None

    def _retrieve_specified_registries(self):
        registry_params = self._get_registry_parameters()
        if registry_params:
            for param in registry_params:
                if param.name == \
                        constants.SERVICE_PARAM_NAME_DOCKER_K8S_REGISTRY:
                    self.k8s_registry = str(param.value)
                if param.name == \
                        constants.SERVICE_PARAM_NAME_DOCKER_GCR_REGISTRY:
                    self.gcr_registry = str(param.value)
                if param.name == \
                        constants.SERVICE_PARAM_NAME_DOCKER_QUAY_REGISTRY:
                    self.quay_registry = str(param.value)
                if param.name == \
                        constants.SERVICE_PARAM_NAME_DOCKER_DOCKER_REGISTRY:
                    self.docker_registry = str(param.value)

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
                # First make kubernetes config accessible to Armada. This
                # is a work around the permission issue in Armada container.
                kube_config = os.path.join(constants.APP_SYNCED_DATA_PATH,
                                           'admin.conf')
                shutil.copy('/etc/kubernetes/admin.conf', kube_config)
                os.chown(kube_config, 1000, grp.getgrnam("wrs").gr_gid)

                overrides_dir = common.HELM_OVERRIDES_PATH
                manifests_dir = constants.APP_SYNCED_DATA_PATH
                LOG.info("kube_config=%s, manifests_dir=%s, "
                         "overrides_dir=%s." % (kube_config, manifests_dir,
                                                overrides_dir))
                binds = {
                    kube_config: {'bind': '/armada/.kube/config', 'mode': 'ro'},
                    manifests_dir: {'bind': '/manifests', 'mode': 'ro'},
                    overrides_dir: {'bind': '/overrides', 'mode': 'ro'}}

                container = client.containers.run(
                    CONF.armada_image_tag,
                    name=ARMADA_CONTAINER_NAME,
                    detach=True,
                    volumes=binds,
                    restart_policy={'Name': 'always'},
                    command=None)
                LOG.info("Armada service started!")
                return container
            except OSError as oe:
                LOG.error("Unable to make kubernetes config accessible to "
                          "armada: %s" % oe)
            except Exception as e:
                # Possible docker exceptions are: RuntimeError, ContainerError,
                # ImageNotFound and APIError
                LOG.error("Docker error while launching Armada container: %s", e)
                os.unlink(kube_config)
            return None

    def make_armada_request(self, request, manifest_file, overrides_str='',
                            logfile=None):

        if logfile is None:
            logfile = request + '.log'

        rc = True

        try:
            client = docker.from_env(timeout=INSTALLATION_TIMEOUT)
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
                    cmd = "/bin/bash -c 'armada apply --debug " + manifest_file +\
                          overrides_str + " | tee " + logfile + "'"
                    LOG.info("Armada apply command = %s" % cmd)
                    (exit_code, exec_logs) = armada_svc.exec_run(cmd)
                    if exit_code == 0:
                        if ARMADA_MANIFEST_APPLY_SUCCESS_MSG in exec_logs:
                            LOG.info("Application manifest %s was successfully "
                                     "applied/re-applied." % manifest_file)
                        else:
                            rc = False
                            LOG.error("Received a false positive response from "
                                      "Docker/Armada. Failed to apply application "
                                      "manifest %s: %s." % (manifest_file, exec_logs))
                    else:
                        rc = False
                        if exit_code == CONTAINER_ABNORMAL_EXIT_CODE:
                            LOG.error("Failed to apply application manifest %s. "
                                      "Armada service has exited abnormally." %
                                      manifest_file)
                        else:
                            LOG.error("Failed to apply application manifest %s: "
                                      "%s." % (manifest_file, exec_logs))
                elif request == constants.APP_DELETE_OP:
                    cmd = "/bin/bash -c 'armada delete --debug --manifest " +\
                          manifest_file + " | tee " + logfile + "'"
                    (exit_code, exec_logs) = armada_svc.exec_run(cmd)
                    if exit_code == 0:
                        LOG.info("Application charts were successfully "
                                 "deleted.")
                    else:
                        rc = False
                        if exit_code == CONTAINER_ABNORMAL_EXIT_CODE:
                            LOG.error("Failed to delete application manifest %s. "
                                      "Armada service has exited abnormally." %
                                      manifest_file)
                        else:
                            LOG.error("Failed to delete application manifest %s: "
                                      "%s" % (manifest_file, exec_logs))
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

    def get_local_docker_registry_server(self):
        registry_ip = self._dbapi.address_get_by_name(
            cutils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                   constants.NETWORK_TYPE_MGMT)
        ).address
        registry_server = '{}:{}'.format(registry_ip, DOCKER_REGISTRY_PORT)
        return registry_server

    def _get_img_tag_with_registry(self, pub_img_tag):
        registry_name = pub_img_tag[0:1 + pub_img_tag.find('/')]
        img_name = pub_img_tag[1 + pub_img_tag.find('/'):]
        if registry_name:
            if 'k8s.gcr.io' in registry_name:
                registry = self.k8s_registry
            elif 'gcr.io' in registry_name:
                registry = self.gcr_registry
            elif 'quay.io' in registry_name:
                registry = self.quay_registry
            elif 'docker.io' in registry_name:
                registry = self.docker_registry
            else:
                # try docker.io registry as default
                # if other registries newly added
                # or docker.io repository detected
                LOG.info("Registry %s not recognized or docker.io repository "
                         "detected. Pulling from public/private registry"
                         % registry_name)
                registry = self.docker_registry
                if registry:
                    return str(registry) + '/' + pub_img_tag
                else:
                    return pub_img_tag

            # replace registry
            if registry:
                return str(registry) + '/' + img_name
            else:
                return pub_img_tag
        else:
            # docker.io registry as default
            # if no registries specified in img tag
            registry = self.docker_registry
            if registry:
                return str(registry) + '/' + pub_img_tag
            else:
                return pub_img_tag

    def download_an_image(self, img_tag):

        rc = True
        # retrieve user specified registries first
        self._retrieve_specified_registries()
        local_registry_server = self.get_local_docker_registry_server()

        start = time.time()
        if img_tag.startswith(local_registry_server):
            try:
                LOG.info("Image %s download started from local registry" % img_tag)
                local_registry_auth = get_local_docker_registry_auth()
                client = docker.APIClient(timeout=INSTALLATION_TIMEOUT)
                client.pull(img_tag, auth_config=local_registry_auth)
            except docker.errors.NotFound:
                try:
                    # Pull the image from the public registry
                    LOG.info("Image %s is not available in local registry, "
                             "download started from public/private registry"
                             % img_tag)
                    pub_img_tag = img_tag.replace(local_registry_server + "/", "")
                    target_img_tag = self._get_img_tag_with_registry(pub_img_tag)
                    client.pull(target_img_tag)
                except Exception as e:
                    rc = False
                    LOG.error("Image %s download failed from public/private"
                              "registry: %s" % (target_img_tag, e))
                    return img_tag, rc

                try:
                    # Tag and push the image to the local registry
                    client.tag(target_img_tag, img_tag)
                    client.push(img_tag, auth_config=local_registry_auth)
                except Exception as e:
                    rc = False
                    LOG.error("Image %s push failed to local registry: %s" % (img_tag, e))
            except Exception as e:
                rc = False
                LOG.error("Image %s download failed from local registry: %s" % (img_tag, e))

        else:
            try:
                LOG.info("Image %s download started from public/private registry" % img_tag)
                client = docker.APIClient(timeout=INSTALLATION_TIMEOUT)
                target_img_tag = self._get_img_tag_with_registry(img_tag)
                client.pull(target_img_tag)
                client.tag(target_img_tag, img_tag)
            except Exception as e:
                rc = False
                LOG.error("Image %s download failed from public registry: %s" % (img_tag, e))

        elapsed_time = time.time() - start
        if rc:
            LOG.info("Image %s download succeeded in %d seconds" %
                     (img_tag, elapsed_time))
        return img_tag, rc
