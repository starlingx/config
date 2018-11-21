# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System Inventory Kubernetes Application Operator."""

import docker
import eventlet
import grp
import os
import re
import shutil
import stat
import subprocess
import threading
import time
import yaml

from collections import namedtuple
from oslo_config import cfg
from oslo_log import log as logging
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import utils as cutils
from sysinv.helm import common
from sysinv.helm import helm


LOG = logging.getLogger(__name__)
kube_app_opts = [
    cfg.StrOpt('armada_image_tag',
               default=('quay.io/airshipit/armada:'
                        'f807c3a1ec727c883c772ffc618f084d960ed5c9'),
               help='Docker image tag of Armada.'),
                ]
CONF = cfg.CONF
CONF.register_opts(kube_app_opts)
ARMADA_CONTAINER_NAME = 'armada_service'
MAX_DOWNLOAD_THREAD = 20


Chart = namedtuple('Chart', 'name namespace')


class AppOperator(object):
    """Class to encapsulate Kubernetes App operations for System Inventory"""

    def __init__(self, dbapi):
        self._dbapi = dbapi
        self._docker = DockerHelper()
        self._helm = helm.HelmOperator(self._dbapi)
        self._kube = kubernetes.KubeOperator(self._dbapi)
        self._lock = threading.Lock()

    def _cleanup(self, app):
        """" Remove application directories and override files """
        try:
            # TODO(tngo): Disable node labeling for system app for now until
            # vim integration with sysinv for container support is ready
            if not app.system_app and app.status != constants.APP_UPLOAD_FAILURE:
                self._process_node_labels(app, op=constants.LABEL_REMOVE_OP)
            if app.system_app and app.status != constants.APP_UPLOAD_FAILURE:
                self._remove_chart_overrides(app.mfile_abs)

            os.unlink(app.armada_mfile_abs)
            shutil.rmtree(app.path)
        except OSError as e:
            LOG.exception(e)

    def _update_app_status(self, app, new_status):
        """ Persist new app status """
        with self._lock:
            app.status = new_status

    def _abort_operation(self, app, operation):
        if (app.status == constants.APP_UPLOAD_IN_PROGRESS):
            self._update_app_status(app, constants.APP_UPLOAD_FAILURE)
        elif (app.status == constants.APP_APPLY_IN_PROGRESS):
            self._update_app_status(app, constants.APP_APPLY_FAILURE)
        elif (app.status == constants.APP_REMOVE_IN_PROGRESS):
            self._update_app_status(app, constants.APP_REMOVE_FAILURE)
        LOG.error("Application %s aborted!." % operation)

    def _extract_tarfile(self, app):
        def _handle_extract_failure():
            raise exception.KubeAppUploadFailure(
                name=app.name,
                reason="failed to extract tarfile content.")
        try:
            if not os.path.isdir(constants.APP_INSTALL_PATH):
                # One time set up
                os.makedirs(constants.APP_INSTALL_PATH)
                os.makedirs(constants.APP_MANIFEST_PATH)

            if not os.path.isdir(app.path):
                os.makedirs(app.path)
            if not cutils.extract_tarfile(app.path, app.tarfile):
                _handle_extract_failure()

            if os.path.isdir(app.charts_dir):
                tar_filelist = cutils.get_files_matching(app.charts_dir,
                                                         '.tgz')
                for p, f in tar_filelist:
                    if not cutils.extract_tarfile(p, os.path.join(p, f)):
                        _handle_extract_failure()
        except OSError as e:
            LOG.error(e)
            _handle_extract_failure()

    def _get_image_tags_by_path(self, path):
        """ Mine the image tags from values.yaml files in the chart directory,
            intended for custom apps. """

        image_tags = []
        ids = []
        for r, f in cutils.get_files_matching(path, 'values.yaml'):
            with open(os.path.join(r, f), 'r') as file:
                try:
                    y = yaml.load(file)
                    ids = y["images"]["tags"].values()
                except (TypeError, KeyError):
                    pass
            image_tags.extend(ids)
        return list(set(image_tags))

    def _get_image_tags_by_charts(self, app_path, charts):
        """ Mine the image tags from both the chart path and the overrides,
            intended for system app. """

        image_tags = []
        for chart in charts:
            tags = []
            overrides = chart.namespace + '-' + chart.name + '.yaml'
            overrides_file = os.path.join(common.HELM_OVERRIDES_PATH,
                                          overrides)
            chart_path = os.path.join(app_path, chart.name)
            if os.path.exists(overrides_file):
                with open(overrides_file, 'r') as file:
                    try:
                        y = yaml.load(file)
                        tags = y["data"]["values"]["images"]["tags"].values()
                    except (TypeError, KeyError):
                        LOG.info("Overrides file %s has no img tags" %
                                  overrides_file)
                if tags:
                    image_tags.extend(tags)
                    continue

            # Either this chart does not have overrides file or image tags are
            # not in its overrides file, walk the chart path to find image tags
            chart_path = os.path.join(app_path, chart.name)
            tags = self._get_image_tags_by_path(chart_path)
            if tags:
                image_tags.extend(tags)

        return list(set(image_tags))

    def _register_embedded_images(self, app):
        """
        TODO(tngo):
        =============
        When we're ready to support air-gapped scenario and private images, the
        following need to be done:
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

    def _download_images(self, app):
        if os.path.isdir(app.images_dir):
            return self._register_embedded_images(app)

        if app.system_app:
            # Grab the image tags from the overrides. If they don't exist
            # then mine them from the chart paths.
            charts = self._get_list_of_charts(app.mfile_abs)
            images_to_download = self._get_image_tags_by_charts(app.charts_dir,
                                                                charts)
        else:
            # For custom apps, mine image tags from application path
            images_to_download = self._get_image_tags_by_path(app.path)

        if images_to_download is None:
            raise exception.KubeAppApplyFailure(
                name=app.name,
                reason="charts specify no docker images.")

        total_count = len(images_to_download)
        threads = min(MAX_DOWNLOAD_THREAD, total_count)
        failed_downloads = []

        start = time.time()
        pool = eventlet.greenpool.GreenPool(size=threads)
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

        with open(os.devnull, "w") as fnull:
            for chart in charts:
                try:
                    subprocess.check_call(['helm-upload', chart], env=env,
                                          stdout=fnull, stderr=fnull)
                    LOG.info("Helm chart %s uploaded" % os.path.basename(chart))
                except Exception as e:
                    raise exception.KubeAppUploadFailure(
                        name=app.name, reason=str(e))

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
        self._kube.kube_patch_node(hostname, body)

    def _assign_host_labels(self, hosts, labels):
        for host in hosts:
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
                    y = yaml.load(f)
                    labels = y['labels']
                except KeyError:
                    raise exception.KubeAppUploadFailure(
                        name=app.name,
                        reason="labels file contains no labels.")
            for key, value in labels.iteritems():
                if key == constants.CONTROLLER:
                    controller_l = value
                elif key == constants.COMPUTE:
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

        # Add the default labels for system app
        if app.system_app:
            controller_labels_set.add(constants.CONTROL_PLANE_LABEL)
            compute_labels_set.add(constants.COMPUTE_NODE_LABEL)
            compute_labels_set.add(constants.OPENVSWITCH_LABEL)

        # Get controller host(s)
        controller_hosts =\
            self._dbapi.ihost_get_by_personality(constants.CONTROLLER)
        if constants.COMPUTE in controller_hosts[0].subfunctions:
            # AIO system
            labels = controller_labels_set.union(compute_labels_set)
            if op == constants.LABEL_ASSIGN_OP:
                self._assign_host_labels(controller_hosts, labels)
            elif op == constants.LABEL_REMOVE_OP:
                self._remove_host_labels(controller_hosts, labels)
        else:
            # Standard system
            compute_hosts =\
                self._dbapi.ihost_get_by_personality(constants.COMPUTE)
            if op == constants.LABEL_ASSIGN_OP:
                self._assign_host_labels(controller_hosts, controller_labels_set)
                self._assign_host_labels(compute_hosts, compute_labels_set)
            elif op == constants.LABEL_REMOVE_OP:
                self._remove_host_labels(controller_hosts, controller_labels_set)
                self._remove_host_labels(compute_hosts, compute_labels_set)

    def _get_list_of_charts(self, manifest_file):
        charts = []
        with open(manifest_file, 'r') as f:
            docs = yaml.load_all(f)
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
        excluded = ['helm-toolkit']

        for chart in charts:
            overrides = chart.namespace + '-' + chart.name + '.yaml'
            if chart.name in excluded:
                LOG.debug("Skipping overrides %s " % overrides)
                continue
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
            if chart.name in constants.SUPPORTED_HELM_CHARTS:
                self._helm.remove_helm_chart_overrides(chart.name,
                                                       chart.namespace)

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
            # Full extraction of application tarball at /scratch/apps.
            # Manifest file is placed under /opt/platform/armada
            # which is managed by drbd-sync and visible to Armada.
            orig_mode = stat.S_IMODE(os.lstat("/scratch").st_mode)
            app.tarfile = tarfile
            self._extract_tarfile(app)
            shutil.copy(app.mfile_abs, app.armada_mfile_abs)

            if not self._docker.make_armada_request('validate', app.armada_mfile):
                return self._abort_operation(app, constants.APP_UPLOAD_OP)
            if os.path.isdir(app.charts_dir):
                self._validate_helm_charts(app)
                # Temporarily allow read and execute access to /scratch so www
                # user can upload helm charts
                os.chmod('/scratch', 0o755)
                self._upload_helm_charts(app)
            self._update_app_status(app, constants.APP_UPLOAD_SUCCESS)
            LOG.info("Application (%s) upload completed." % app.name)
        except Exception as e:
            LOG.exception(e)
            self._abort_operation(app, constants.APP_UPLOAD_OP)
        finally:
            os.chmod('/scratch', orig_mode)

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
        """

        app = AppOperator.Application(rpc_app)
        LOG.info("Application (%s) apply started." % app.name)

        # TODO(tngo): Disable node labeling for system app for now until
        # vim integration with sysinv for container support is ready
        if not app.system_app:
            self._process_node_labels(app)

        overrides_str = ''
        ready = True
        try:
            if app.system_app:
                charts = self._get_list_of_charts(app.mfile_abs)
                LOG.info("Generating application overrides...")
                self._helm.generate_helm_application_overrides(
                    app.name, cnamespace=None, armada_format=True,
                    combined=True)
                overrides_files = self._get_overrides_files(charts)
                if overrides_files:
                    LOG.info("Application overrides generated.")
                    # Ensure all chart overrides are readable by Armada
                    for file in overrides_files:
                        os.chmod(file, 0644)
                    overrides_str =\
                        self._generate_armada_overrides_str(overrides_files)
                    self._download_images(app)
                else:
                    ready = False
            else:
                # No support for custom app overrides at this point, just
                # download the needed images.
                self._download_images(app)

            if ready:
                if self._docker.make_armada_request('apply',
                                                    app.armada_mfile,
                                                    overrides_str):
                    self._update_app_status(app,
                                            constants.APP_APPLY_SUCCESS)
                    LOG.info("Application (%s) apply completed." % app.name)
                    return
        except Exception as e:
            LOG.exception(e)

        # If it gets here, something went wrong
        self._abort_operation(app, constants.APP_APPLY_OP)

    def perform_app_remove(self, rpc_app):
        """Process application remove request

        This method invokes Armada to delete the application manifest.
        For system app, it also cleans up old test pods.

        :param rpc_app: application object in the RPC request
        """

        app = AppOperator.Application(rpc_app)
        LOG.info("Application (%s) remove started." % app.name)

        if self._docker.make_armada_request('delete', app.armada_mfile):
            if app.system_app:
                try:
                    p1 = subprocess.Popen(['kubectl', 'get', 'pods', '-n',
                                          'openstack'],
                                          stdout=subprocess.PIPE)
                    p2 = subprocess.Popen(['awk', '/osh-.*-test/{print $1}'],
                                          stdin=p1.stdout,
                                          stdout=subprocess.PIPE)
                    p3 = subprocess.Popen(['xargs', '-i', 'kubectl',
                                          'delete', 'pods', '-n', 'openstack',
                                          '{}'], stdin=p2.stdout,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)
                    p1.stdout.close()
                    p2.stdout.close()
                    out, err = p3.communicate()
                    if not err:
                        LOG.info("Old test pods cleanup completed.")
                except Exception as e:
                    LOG.exception("Failed to clean up test pods after app "
                                  "removal: %s" % e)
            self._update_app_status(app, constants.APP_UPLOAD_SUCCESS)
            LOG.info("Application (%s) remove completed." % app.name)
        else:
            self._abort_operation(app, constants.APP_REMOVE_OP)

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
            self.system_app =\
                (self._kube_app.get('name') == constants.HELM_APP_OPENSTACK)
            self.armada_mfile =\
                os.path.join('/manifests', self._kube_app.get('name') + "-" +
                             self._kube_app.get('manifest_file'))
            self.armada_mfile_abs =\
                os.path.join(constants.APP_MANIFEST_PATH,
                             self._kube_app.get('name') + "-" +
                             self._kube_app.get('manifest_file'))
            self.mfile_abs =\
                os.path.join(constants.APP_INSTALL_PATH,
                             self._kube_app.get('name'),
                             self._kube_app.get('manifest_file'))

        @property
        def name(self):
            return self._kube_app.get('name')

        @property
        def mfile(self):
            return self._kube_app.get('manifest_file')

        @property
        def status(self):
            return self._kube_app.get('status')

        @status.setter
        def status(self, new_status):
            self._kube_app.status = new_status
            self._kube_app.save()


class DockerHelper(object):
    """ Utility class to encapsulate Docker related operations """

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
                install_dir = constants.APP_INSTALL_PATH
                kube_config = os.path.join(install_dir, 'admin.conf')
                shutil.copy('/etc/kubernetes/admin.conf', kube_config)
                os.chown(kube_config, 1000, grp.getgrnam("wrs").gr_gid)

                overrides_dir = common.HELM_OVERRIDES_PATH
                manifests_dir = constants.APP_MANIFEST_PATH
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

    def make_armada_request(self, request, manifest_file, overrides_str=''):
        rc = True
        try:
            client = docker.from_env()
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
                        LOG.error("Validation of the armada manifest %s "
                                  "failed: %s" % (manifest_file, exec_logs))
                elif request == 'apply':
                    cmd = 'armada apply --debug ' + manifest_file + overrides_str
                    LOG.info("Armada apply command = %s" % cmd)
                    (exit_code, exec_logs) = armada_svc.exec_run(cmd)
                    if exit_code == 0:
                        LOG.info("Application manifest %s was successfully "
                                 "applied/re-applied." % manifest_file)
                    else:
                        rc = False
                        LOG.error("Failed to apply application manifest: %s" %
                                  exec_logs)
                elif request == 'delete':
                    cmd = 'armada delete --debug --manifest ' + manifest_file
                    (exit_code, exec_logs) = armada_svc.exec_run(cmd)
                    if exit_code == 0:
                        LOG.info("Application charts were successfully "
                                 "deleted.")
                    else:
                        rc = False
                        LOG.error("Delete the application manifest failed: %s" %
                                  exec_logs)
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

    def download_an_image(self, img_tag):
        rc = True
        start = time.time()
        try:
            LOG.info("Image %s download started" % img_tag)
            c = docker.from_env()
            c.images.pull(img_tag)
        except Exception as e:
            rc = False
            LOG.error("Image %s download failed: %s" % (img_tag, e))
        elapsed_time = time.time() - start

        LOG.info("Image %s download succeeded in %d seconds" %
                 (img_tag, elapsed_time))
        return img_tag, rc
