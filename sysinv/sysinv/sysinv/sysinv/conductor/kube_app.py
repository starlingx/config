# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018-2019 Wind River Systems, Inc.
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
from sysinv.api.controllers.v1 import kube_app
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import utils as cutils
from sysinv.common.storage_backend_conf import K8RbdProvisioner
from sysinv.helm import common
from sysinv.helm import helm
from sysinv.helm import utils as helm_utils


# Log and config
LOG = logging.getLogger(__name__)
kube_app_opts = [
    cfg.StrOpt('armada_image_tag',
               default=('quay.io/airshipit/armada:'
                        'dd2e56c473549fd16f94212b553ed58c48d1f51b-ubuntu_bionic'),
               help='Docker image tag of Armada.'),
                ]
CONF = cfg.CONF
CONF.register_opts(kube_app_opts)


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
TARFILE_DOWNLOAD_CONNECTION_TIMEOUT = 60
TARFILE_TRANSFER_CHUNK_SIZE = 1024 * 512
DOCKER_REGISTRY_USER = 'admin'
DOCKER_REGISTRY_SERVICE = 'CGCS'
DOCKER_REGISTRY_SECRET = 'default-registry-key'

ARMADA_HOST_LOG_LOCATION = '/var/log/armada'
ARMADA_CONTAINER_LOG_LOCATION = '/logs'


# Helper functions
def generate_armada_manifest_filename(app_name, app_version, manifest_filename):
    return os.path.join('/manifests', app_name, app_version,
                        app_name + '-' + manifest_filename)


def generate_armada_manifest_dir(app_name, app_version):
    return os.path.join(constants.APP_SYNCED_DATA_PATH, app_name, app_version)


def generate_armada_manifest_filename_abs(armada_mfile_dir, app_name, manifest_filename):
    return os.path.join(armada_mfile_dir, app_name + '-' + manifest_filename)


def generate_manifest_filename_abs(app_name, app_version, manifest_filename):
    return os.path.join(constants.APP_INSTALL_PATH,
                        app_name, app_version, manifest_filename)


def generate_images_filename_abs(armada_mfile_dir, app_name):
    return os.path.join(armada_mfile_dir, app_name + '-images.yaml')


def generate_overrides_dir(app_name, app_version):
    return os.path.join(common.HELM_OVERRIDES_PATH, app_name, app_version)


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


Chart = namedtuple('Chart', 'metadata_name name namespace location release labels sequenced')


class AppOperator(object):
    """Class to encapsulate Kubernetes App operations for System Inventory"""

    APP_OPENSTACK_RESOURCE_CONFIG_MAP = 'ceph-etc'

    def __init__(self, dbapi):
        self._dbapi = dbapi
        self._docker = DockerHelper(self._dbapi)
        self._helm = helm.HelmOperator(self._dbapi)
        self._kube = kubernetes.KubeOperator(self._dbapi)
        self._app = kube_app.KubeAppHelper(self._dbapi)
        self._lock = threading.Lock()

    def _cleanup(self, app, app_dir=True):
        """" Remove application directories and override files """
        try:
            if os.path.exists(app.overrides_dir):
                shutil.rmtree(app.overrides_dir)
                if app_dir:
                    shutil.rmtree(os.path.dirname(
                        app.overrides_dir))

            if os.path.exists(app.armada_mfile_dir):
                shutil.rmtree(app.armada_mfile_dir)
                if app_dir:
                    shutil.rmtree(os.path.dirname(
                        app.armada_mfile_dir))

            if os.path.exists(app.path):
                shutil.rmtree(app.path)
                if app_dir:
                    shutil.rmtree(os.path.dirname(
                        app.path))
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
            if not os.path.isdir(constants.APP_SYNCED_DATA_PATH):
                os.makedirs(constants.APP_SYNCED_DATA_PATH)

            if not os.path.isdir(app.armada_mfile_dir):
                os.makedirs(app.armada_mfile_dir)

            if not os.path.isdir(app.path):
                create_app_path(app.path)

            # Temporarily change /scratch group ownership to sys_protected
            os.chown(constants.APP_INSTALL_ROOT_PATH, orig_uid,
                     grp.getgrnam(constants.SYSINV_SYSADMIN_GRPNAME).gr_gid)

            # Extract the tarfile as sysinv user
            if not cutils.extract_tarfile(app.path, app.tarfile, demote_user=True):
                _handle_extract_failure()

            if app.downloaded_tarfile:
                name, version, patches = self._app._verify_metadata_file(
                    app.path, app.name, app.version)
                if (name != app.name or version != app.version):
                    # Save the official application info. They will be
                    # persisted in the next status update
                    app.regenerate_application_info(name, version, patches)

                if not cutils.verify_checksum(app.path):
                    _handle_extract_failure('checksum validation failed.')
                mname, mfile = self._app._find_manifest_file(app.path)
                # Save the official manifest file info. They will be persisted
                # in the next status update
                app.regenerate_manifest_filename(mname, os.path.basename(mfile))
            else:
                name, version, patches = cutils.find_metadata_file(
                    app.path, constants.APP_METADATA_FILE)
                app.patch_dependencies = patches

            self._app._extract_helm_charts(app.path)

        except exception.SysinvException as e:
            _handle_extract_failure(str(e))
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

    def _get_image_tags_by_charts(self, app_images_file, app_manifest_file, overrides_dir):
        """ Mine the image tags for charts from the images file. Add the
            image tags to the manifest file if the image tags from the charts
            do not exist in both overrides file and manifest file. Convert
            the image tags in the manifest file. Intended for system app.

            The image tagging conversion(local docker registry address prepended):
            ${LOCAL_REGISTRY_SERVER}:${REGISTRY_PORT}/<image-name>
            (ie..registry.local:9001/docker.io/mariadb:10.2.13)
        """

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
                app_overrides_file = os.path.join(overrides_dir, overrides)
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
                                {key: '{}/{}'.format(constants.DOCKER_REGISTRY_SERVER,
                                                     images_manifest[key])})
                            chart_image_tags_updated = True
                        image_tags.append(images_manifest[key])
                    else:
                        if not re.match(r'^.+:.+/', images_overrides[key]):
                            images_overrides.update(
                                {key: '{}/{}'.format(constants.DOCKER_REGISTRY_SERVER,
                                                     images_overrides[key])})
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
        app.charts = self._get_list_of_charts(app.armada_mfile_abs)
        LOG.info("Generating application overrides...")
        self._helm.generate_helm_application_overrides(
            app.overrides_dir, app.name, mode=None, cnamespace=None,
            armada_format=True, armada_chart_info=app.charts, combined=True)
        if app.system_app:
            self._save_images_list_by_charts(app)
            # Get the list of images from the updated images overrides
            images_to_download = self._get_image_tags_by_charts(
                app.imgfile_abs, app.armada_mfile_abs, app.overrides_dir)
        else:
            # For custom apps, mine image tags from application path
            images_to_download = self._get_image_tags_by_path(app.path)

        if not images_to_download:
            # TODO(tngo): We may want to support the deployment of apps that
            # set up resources only in the future. In which case, generate
            # an info log and let it advance to the next step.
            raise exception.KubeAppUploadFailure(
                name=app.name,
                version=app.version,
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
                app.imgfile_abs, app.armada_mfile_abs, app.overrides_dir)
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
                version=app.version,
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
                    name=app.name, version=app.version, reason=str(e))

        if len(failed_charts) > 0:
            raise exception.KubeAppUploadFailure(
                name=app.name, version=app.version, reason="one or more charts failed validation.")

    def _get_helm_repo_from_metadata(self, app):
        """Get helm repo from application metadata

        This extracts the helm repo from the application metadata where the
        chart should be loaded.

        :param app: application
        """
        repo = common.HELM_REPO_FOR_APPS
        lfile = os.path.join(app.path, 'metadata.yaml')

        if os.path.exists(lfile) and os.path.getsize(lfile) > 0:
            with open(lfile, 'r') as f:
                try:
                    y = yaml.safe_load(f)
                    repo = y['helm_repo']
                except KeyError:
                    pass

        LOG.info("Application %s (%s) will load charts to chart repo %s" % (
            app.name, app.version, repo))
        return repo

    def _upload_helm_charts(self, app):
        # Set env path for helm-upload execution
        env = os.environ.copy()
        env['PATH'] = '/usr/local/sbin:' + env['PATH']
        charts = [os.path.join(r, f)
                  for r, f in cutils.get_files_matching(app.charts_dir, '.tgz')]

        orig_uid, orig_gid = get_app_install_root_path_ownership()
        helm_repo = self._get_helm_repo_from_metadata(app)
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

    def _create_storage_provisioner_secrets(self, app_name):
        """ Provide access to the system persistent storage provisioner.

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
                       common.HELM_NS_STORAGE_PROVISIONER] or
                    self._kube.kube_get_secret(pool_secret, ns)):
                # Secret already exist
                continue

            try:
                if not self._kube.kube_get_namespace(ns):
                    self._kube.kube_create_namespace(ns)
                self._kube.kube_copy_secret(
                    pool_secret, common.HELM_NS_STORAGE_PROVISIONER, ns)
            except Exception as e:
                LOG.error(e)
                raise

    def _delete_storage_provisioner_secrets(self, app_name):
        """ Remove access to the system persistent storage provisioner.

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
                    ns == common.HELM_NS_STORAGE_PROVISIONER):
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
                 self._kube.kube_get_secret(DOCKER_REGISTRY_SECRET, ns)):
                # Secret already exist
                continue

            try:
                local_registry_auth = get_local_docker_registry_auth()

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

        missing_overrides = []
        available_overrides = []

        for chart in charts:
            overrides = chart.namespace + '-' + chart.name + '.yaml'
            overrides_file = os.path.join(overrides_dir, overrides)
            if not os.path.exists(overrides_file):
                missing_overrides.append(overrides_file)
            else:
                available_overrides.append(overrides_file)

                # Now handle any meta-overrides files.  These can affect
                # sections of the chart schema other than "values, and can
                # affect the chartgroup or even the manifest.
                if self._helm.generate_meta_overrides(
                        chart.name, chart.namespace, app_name, mode):
                    overrides = chart.namespace + '-' + chart.name + \
                                '-meta' + '.yaml'
                    overrides_file = os.path.join(overrides_dir, overrides)
                    if not os.path.exists(overrides_file):
                        missing_overrides.append(overrides_file)
                    else:
                        available_overrides.append(overrides_file)

        if missing_overrides:
            LOG.error("Missing the following overrides: %s" % missing_overrides)
            return None
        return available_overrides

    def _generate_armada_overrides_str(self, app_name, app_version, overrides_files):
        return " ".join([' --values /overrides/{0}/{1}/{2}'.format(app_name, app_version,
                                                                   os.path.basename(i))
                        for i in overrides_files])

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
        logfile = ARMADA_CONTAINER_LOG_LOCATION + '/' + app.name + '-' + request + '.log'
        if request == constants.APP_APPLY_OP:
            pattern = APPLY_SEARCH_PATTERN
        elif request == constants.APP_DELETE_OP:
            pattern = DELETE_SEARCH_PATTERN
        else:
            pattern = ROLLBACK_SEARCH_PATTERN

        monitor = greenthread.spawn_after(1, _check_progress, mqueue, app,
                                          pattern, logfile)
        rc = self._docker.make_armada_request(request, app.armada_mfile,
                                              overrides_str, app.releases, logfile)
        mqueue.put('done')
        monitor.kill()
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
                    common.HELM_NS_STORAGE_PROVISIONER,
                    common.HELM_NS_OPENSTACK)
            except Exception as e:
                LOG.error(e)
                raise

    def _delete_app_specific_resources(self, app_name):
        """Remove application specific k8s resources.

        Some applications may need resources created outside of the existing
        charts to properly integrate with the current capabilities of the
        system. Remove these resources here.

        :param app_name: Name of the application.
        """

        if app_name == constants.HELM_APP_OPENSTACK:
            self._delete_persistent_volume_claim(common.HELM_NS_OPENSTACK)

            try:
                # Remove the configmap with the ceph monitor information
                # required by the application into the application namespace
                self._kube.kube_delete_config_map(
                    self.APP_OPENSTACK_RESOURCE_CONFIG_MAP,
                    common.HELM_NS_OPENSTACK)
            except Exception as e:
                LOG.error(e)
                raise

            self._delete_namespace(common.HELM_NS_OPENSTACK)

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
            self._app._patch_report_app_dependencies(
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
                old_app.charts = self._get_list_of_charts(old_app.armada_mfile_abs)
                if old_app.system_app:
                    overrides_files = self._get_overrides_files(old_app.overrides_dir,
                                                                old_app.charts,
                                                                old_app.name, mode=None)
                    overrides_str = \
                        self._generate_armada_overrides_str(old_app.name, old_app.version,
                                                            overrides_files)

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

        except Exception as e:
            # ie. patch report error, cleanup application files error
            #     helm release delete failure
            self._update_app_status(
                old_app, constants.APP_APPLY_SUCCESS,
                constants.APP_PROGRESS_UPDATE_ABORTED.format(old_app.version, new_app.version) +
                constants.APP_PROGRESS_RECOVER_COMPLETED.format(old_app.version) +
                constants.APP_PROGRESS_CLEANUP_FAILED.format(new_app.version) +
                'please check logs for detail.')
            LOG.error(e)
            return

        if rc:
            self._update_app_status(
                old_app, constants.APP_APPLY_SUCCESS,
                constants.APP_PROGRESS_UPDATE_ABORTED.format(old_app.version, new_app.version) +
                constants.APP_PROGRESS_RECOVER_COMPLETED.format(old_app.version) +
                'please check logs for detail.')
            LOG.info("Application %s recover to version %s completed."
                     % (old_app.name, old_app.version))
        else:
            self._update_app_status(
                old_app, constants.APP_APPLY_FAILURE,
                constants.APP_PROGRESS_UPDATE_ABORTED.format(old_app.version, new_app.version) +
                constants.APP_PROGRESS_RECOVER_ABORTED.format(old_app.version) +
                'please check logs for detail.')
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

            if self._make_armada_request_with_monitor(to_app,
                                                      constants.APP_ROLLBACK_OP):
                self._update_app_status(to_app, constants.APP_APPLY_SUCCESS,
                                        constants.APP_PROGRESS_COMPLETED)
                LOG.info("Application %s (%s) rollback completed."
                         % (to_app.name, to_app.version))
                return True
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

        app = AppOperator.Application(rpc_app,
            rpc_app.get('name') in self._helm.get_helm_applications())

        LOG.info("Application %s (%s) upload started." % (app.name, app.version))

        try:
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
            shutil.copy(app.mfile_abs, app.armada_mfile_abs)

            if not self._docker.make_armada_request(
                    'validate', manifest_file=app.armada_mfile):
                raise exception.KubeAppUploadFailure(
                    name=app.name,
                    version=app.version,
                    reason="Failed to validate application manifest.")

            self._update_app_status(
                app, new_progress=constants.APP_PROGRESS_VALIDATE_UPLOAD_CHARTS)
            if os.path.isdir(app.charts_dir):
                self._validate_helm_charts(app)
                with self._lock:
                    self._upload_helm_charts(app)

            self._save_images_list(app)
            if app.patch_dependencies:
                self._app._patch_report_app_dependencies(
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

    def perform_app_apply(self, rpc_app, mode):
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
        :return boolean: whether application apply was successful
        """

        app = AppOperator.Application(rpc_app,
            rpc_app.get('name') in self._helm.get_helm_applications())
        LOG.info("Application %s (%s) apply started." % (app.name, app.version))

        overrides_str = ''
        ready = True
        try:
            app.charts = self._get_list_of_charts(app.armada_mfile_abs)
            if app.system_app:
                self._create_local_registry_secrets(app.name)
                self._create_storage_provisioner_secrets(app.name)
                self._create_app_specific_resources(app.name)
            self._update_app_status(
                app, new_progress=constants.APP_PROGRESS_GENERATE_OVERRIDES)
            LOG.info("Generating application overrides...")
            self._helm.generate_helm_application_overrides(
                app.overrides_dir, app.name, mode, cnamespace=None,
                armada_format=True, armada_chart_info=app.charts, combined=True)
            overrides_files = self._get_overrides_files(app.overrides_dir,
                                                        app.charts,
                                                        app.name, mode)
            if overrides_files:
                LOG.info("Application overrides generated.")
                overrides_str = self._generate_armada_overrides_str(
                    app.name, app.version, overrides_files)
                self._update_app_status(
                    app, new_progress=constants.APP_PROGRESS_DOWNLOAD_IMAGES)
                self._download_images(app)
            else:
                ready = False
        except exception.KubeAppApplyFailure as e:
            # ex:Image download failure
            LOG.exception(e)
            self._abort_operation(app, constants.APP_APPLY_OP, str(e))
            raise
        except Exception as e:
            # ex:K8s resource creation failure
            LOG.exception(e)
            self._abort_operation(app, constants.APP_APPLY_OP)
            raise exception.KubeAppApplyFailure(
                name=app.name, version=app.version, reason=e)

        try:
            if ready:
                self._update_app_status(
                    app, new_progress=constants.APP_PROGRESS_APPLY_MANIFEST)
                if self._make_armada_request_with_monitor(app,
                                                          constants.APP_APPLY_OP,
                                                          overrides_str):
                    self._update_app_releases_version(app.name)
                    self._update_app_status(app,
                                            constants.APP_APPLY_SUCCESS,
                                            constants.APP_PROGRESS_COMPLETED)
                    app.update_active(True)
                    LOG.info("Application %s (%s) apply completed." % (app.name, app.version))
                    return True
        except Exception as e:
            # ex: update release version failure
            LOG.exception(e)

        # If it gets here, something went wrong
        self._abort_operation(app, constants.APP_APPLY_OP)
        return False

    def perform_app_update(self, from_rpc_app, to_rpc_app, tarfile, operation):
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
        """

        from_app = AppOperator.Application(from_rpc_app,
            from_rpc_app.get('name') in self._helm.get_helm_applications())
        to_app = AppOperator.Application(to_rpc_app,
            to_rpc_app.get('name') in self._helm.get_helm_applications())
        LOG.info("Start updating Application %s from version %s to version %s ..."
                 % (to_app.name, from_app.version, to_app.version))

        try:
            # Upload new app tarball
            to_app = self.perform_app_upload(to_rpc_app, tarfile)

            self._update_app_status(to_app, constants.APP_UPDATE_IN_PROGRESS)

            result = False
            if operation == constants.APP_APPLY_OP:
                result = self.perform_app_apply(to_rpc_app, mode=None)
            elif operation == constants.APP_ROLLBACK_OP:
                result = self._perform_app_rollback(from_app, to_app)

            if not result:
                LOG.error("Application %s update from version %s to version "
                          "%s aborted." % (to_app.name, from_app.version, to_app.version))
                return self._perform_app_recover(from_app, to_app)

            self._update_app_status(to_app, constants.APP_UPDATE_IN_PROGRESS,
                                    "cleanup application version {}".format(from_app.version))

            # App apply/rollback succeeded
            # Starting cleanup old application
            from_app.charts = self._get_list_of_charts(from_app.armada_mfile_abs)
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
            self._app._patch_report_app_dependencies(
                from_app.name + '-' + from_app.version)

            self._update_app_status(
                to_app, constants.APP_APPLY_SUCCESS,
                constants.APP_PROGRESS_UPDATE_COMPLETED.format(from_app.version,
                                                               to_app.version))
            LOG.info("Application %s update from version %s to version "
                     "%s completed." % (to_app.name, from_app.version, to_app.version))
        except (exception.KubeAppUploadFailure,
                exception.KubeAppApplyFailure):
            # Error occurs during app uploading or applying but before
            # armada apply process...
            # ie.images download/k8s resource creation failure
            # Start recovering without trigger armada process
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
        return True

    def perform_app_remove(self, rpc_app):
        """Process application remove request

        This method invokes Armada to delete the application manifest.
        For system app, it also cleans up old test pods.

        :param rpc_app: application object in the RPC request
        :return boolean: whether application remove was successful
        """

        app = AppOperator.Application(rpc_app,
            rpc_app.get('name') in self._helm.get_helm_applications())
        LOG.info("Application (%s) remove started." % app.name)

        app.charts = self._get_list_of_charts(app.armada_mfile_abs)
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

            if app.system_app:

                try:
                    self._delete_local_registry_secrets(app.name)
                    self._delete_storage_provisioner_secrets(app.name)
                    self._delete_app_specific_resources(app.name)
                except Exception as e:
                    self._abort_operation(app, constants.APP_REMOVE_OP)
                    LOG.exception(e)
                    return False

            self._update_app_status(app, constants.APP_UPLOAD_SUCCESS,
                                    constants.APP_PROGRESS_COMPLETED)
            LOG.info("Application (%s) remove completed." % app.name)
            return True
        else:
            self._abort_operation(app, constants.APP_REMOVE_OP)

        return False

    def activate(self, rpc_app):
        app = AppOperator.Application(
            rpc_app,
            rpc_app.get('name') in self._helm.get_helm_applications())
        with self._lock:
            return app.update_active(True)

    def deactivate(self, rpc_app):
        app = AppOperator.Application(
            rpc_app,
            rpc_app.get('name') in self._helm.get_helm_applications())
        with self._lock:
            return app.update_active(False)

    def get_appname(self, rpc_app):
        app = AppOperator.Application(
            rpc_app,
            rpc_app.get('name') in self._helm.get_helm_applications())
        return app.name

    def is_app_active(self, rpc_app):
        app = AppOperator.Application(
            rpc_app,
            rpc_app.get('name') in self._helm.get_helm_applications())
        return app.active

    def perform_app_delete(self, rpc_app):
        """Process application remove request

        This method removes the application entry from the database and
        performs cleanup which entails removing node labels where applicable
        and purge all application files from the system.

        :param rpc_app: application object in the RPC request
        """

        app = AppOperator.Application(rpc_app,
            rpc_app.get('name') in self._helm.get_helm_applications())
        try:
            self._dbapi.kube_app_destroy(app.name)
            self._cleanup(app)
            self._app._patch_report_app_dependencies(app.name + '-' + app.version)
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

        def __init__(self, rpc_app, is_system_app):
            self._kube_app = rpc_app
            self.path = os.path.join(constants.APP_INSTALL_PATH,
                                     self._kube_app.get('name'),
                                     self._kube_app.get('app_version'))
            self.charts_dir = os.path.join(self.path, 'charts')
            self.images_dir = os.path.join(self.path, 'images')
            self.tarfile = None
            self.downloaded_tarfile = False
            self.system_app = is_system_app
            self.overrides_dir = generate_overrides_dir(
                self._kube_app.get('name'),
                self._kube_app.get('app_version'))
            self.armada_mfile_dir = generate_armada_manifest_dir(
                self._kube_app.get('name'),
                self._kube_app.get('app_version'))
            self.armada_mfile = generate_armada_manifest_filename(
                self._kube_app.get('name'),
                self._kube_app.get('app_version'),
                self._kube_app.get('manifest_file'))
            self.armada_mfile_abs = generate_armada_manifest_filename_abs(
                self.armada_mfile_dir,
                self._kube_app.get('name'),
                self._kube_app.get('manifest_file'))
            self.mfile_abs = generate_manifest_filename_abs(
                self._kube_app.get('name'),
                self._kube_app.get('app_version'),
                self._kube_app.get('manifest_file'))
            self.imgfile_abs = generate_images_filename_abs(
                self.armada_mfile_dir,
                self._kube_app.get('name'))

            self.patch_dependencies = []
            self.charts = []
            self.releases = []

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
            self.armada_mfile = generate_armada_manifest_filename(
                self.name, self.version, new_mfile)
            self.armada_mfile_abs = generate_armada_manifest_filename_abs(
                self.armada_mfile_dir, self.name, new_mfile)
            self.mfile_abs = generate_manifest_filename_abs(
                self.name, self.version, new_mfile)

        def regenerate_application_info(self, new_name, new_version, new_patch_dependencies):
            self._kube_app.name = new_name
            self._kube_app.app_version = new_version
            self.system_app = \
                (self.name == constants.HELM_APP_OPENSTACK)

            new_armada_dir = generate_armada_manifest_dir(
                self.name, self.version)
            shutil.move(self.armada_mfile_dir, new_armada_dir)
            shutil.rmtree(os.path.dirname(self.armada_mfile_dir))
            self.armada_mfile_dir = new_armada_dir

            new_path = os.path.join(
                constants.APP_INSTALL_PATH, self.name, self.version)
            shutil.move(self.path, new_path)
            shutil.rmtree(os.path.dirname(self.path))
            self.path = new_path

            self.charts_dir = os.path.join(self.path, 'charts')
            self.images_dir = os.path.join(self.path, 'images')
            self.imgfile_abs = \
                generate_images_filename_abs(self.armada_mfile_dir, self.name)
            self.overrides_dir = generate_overrides_dir(self.name, self.version)
            self.patch_dependencies = new_patch_dependencies


class DockerHelper(object):
    """ Utility class to encapsulate Docker related operations """

    def __init__(self, dbapi):
        self._dbapi = dbapi
        self._lock = threading.Lock()
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
                # Create the armada log folder if it does not exists
                if not os.path.exists(ARMADA_HOST_LOG_LOCATION):
                    os.mkdir(ARMADA_HOST_LOG_LOCATION)
                    os.chmod(ARMADA_HOST_LOG_LOCATION, 0o755)
                    os.chown(ARMADA_HOST_LOG_LOCATION, 1000, grp.getgrnam("sys_protected").gr_gid)

                # First make kubernetes config accessible to Armada. This
                # is a work around the permission issue in Armada container.
                kube_config = os.path.join(constants.APP_SYNCED_DATA_PATH,
                                           'admin.conf')
                shutil.copy('/etc/kubernetes/admin.conf', kube_config)
                os.chown(kube_config, 1000, grp.getgrnam("sys_protected").gr_gid)

                overrides_dir = common.HELM_OVERRIDES_PATH
                manifests_dir = constants.APP_SYNCED_DATA_PATH
                logs_dir = ARMADA_HOST_LOG_LOCATION
                LOG.info("kube_config=%s, manifests_dir=%s, "
                         "overrides_dir=%s, logs_dir=%s." %
                         (kube_config, manifests_dir, overrides_dir, logs_dir))

                binds = {
                    kube_config: {'bind': '/armada/.kube/config', 'mode': 'ro'},
                    manifests_dir: {'bind': '/manifests', 'mode': 'ro'},
                    overrides_dir: {'bind': '/overrides', 'mode': 'ro'},
                    logs_dir: {'bind': ARMADA_CONTAINER_LOG_LOCATION, 'mode': 'rw'}}

                container = client.containers.run(
                    CONF.armada_image_tag,
                    name=ARMADA_CONTAINER_NAME,
                    detach=True,
                    volumes=binds,
                    restart_policy={'Name': 'always'},
                    network_mode='host',
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

    def make_armada_request(self, request, manifest_file='', overrides_str='',
                            app_releases=[], logfile=None):

        if logfile is None:
            logfile = request + '.log'

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
                    cmd = "/bin/bash -c 'set -o pipefail; armada apply --debug " +\
                          manifest_file + overrides_str + tiller_host + " | tee " +\
                          logfile + "'"
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
                    cmd = "/bin/bash -c 'set -o pipefail; armada delete --debug " +\
                          "--manifest " + manifest_file + tiller_host + " | tee " +\
                          logfile + "'"
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

        start = time.time()
        if img_tag.startswith(constants.DOCKER_REGISTRY_HOST):
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
                    pub_img_tag = img_tag.replace(
                        constants.DOCKER_REGISTRY_SERVER + "/", "")
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
