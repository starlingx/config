#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

"""Kubernetes operations on a host """

import datetime
import os
import shutil
import subprocess
import sys
import threading
import tsconfig.tsconfig as tsc

from ruamel import yaml

from oslo_log import log as logging
from operator import attrgetter
from sysinv.common import constants
from sysinv.common import containers
from sysinv.common import etcd
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import utils

LOG = logging.getLogger(__name__)

CONTAINERD_CLEANUP_SCRIPT_PATH = '/usr/sbin/k8s-container-cleanup.sh'
CONTAINERD_CLEANUP_FORCE_CLEAN_CMD = 'force-clean'
KUBEADM_UPGRADE_COMMAND_TIMEOUT = 210


class ContainerdOperator(object):
    '''Class to encapsulate containerd operations for Sysinv Agent'''

    def __init__(self):
        pass

    def _get_auth(self):
        """Get auth credentials for crictl
        """
        crictl_auth = None
        hieradata_secure_system = ""
        try:
            with open(constants.TMP_HIERADATA_SECURE_SYSTEM_YAML, 'r') as file:
                hieradata_secure_system = yaml.safe_load(file)
            if hieradata_secure_system:
                username = hieradata_secure_system.get(
                        'platform::dockerdistribution::params::registry_username', None)
                password = hieradata_secure_system.get(
                        'platform::dockerdistribution::params::registry_password', None)
                if username and password:
                    crictl_auth = (f"{username}:{password}")
                else:
                    LOG.error("Registry credentials not found in the hieradata.")
            else:
                LOG.error("Registry credentials not found in the hieradata file.")
        except Exception as ex:
            LOG.error("Failed to fetch registry credentials with error: [%s]" % (ex))
        return crictl_auth

    def stop_all(self):
        """Stop all containers and pods
        """
        try:
            cmd = [CONTAINERD_CLEANUP_SCRIPT_PATH, CONTAINERD_CLEANUP_FORCE_CLEAN_CMD]
            utils.execute(*cmd, check_exit_code=0)
        except Exception as ex:
            raise exception.SysinvException("Failed to stop containerd containers and pods. "
                                            "Error: [%s]" % (ex))

    def pull_images(self, images):
        """ Pull images to crictl

        :param: images: List of images to be downloaded.

        :returns: True if image download succeeds False otherwise
        """
        try:
            crictl_auth = self._get_auth()
            if not crictl_auth:
                return False

            try:
                crictl_images = containers.get_crictl_image_list()
            except Exception as ex:
                # Ignore and proceed
                LOG.warning("Failed to get existing crictl image list. Error: [%s]. "
                            "Proceeding anyways ..." % (ex))
                crictl_images = []

            for image in images:
                image = f"{constants.DOCKER_REGISTRY_SERVER}/{image}"
                if image not in crictl_images:
                    containers.pull_image_to_crictl(image, crictl_auth)
                else:
                    LOG.info("Image [%s] is already present in crictl. "
                             "No need to download. Continuing..." % (image))

        except Exception as ex:
            LOG.exception("Failed to pull kubernetes images: [%s]" % (ex))
            return False
        return True


class KubeHostOperator(object):
    '''Class to abstract kubernetes host operations for Sysinv'''

    def __init__(self, context, host_uuid, host_name):
        self.context = context
        self._host_uuid = host_uuid
        self._host_name = host_name
        self._system_mode = tsc.system_mode
        self._containerd_operator = ContainerdOperator()
        self._kubernetes_operator = kubernetes.KubeOperator()

    def _mask_stop_service(self, service, runtime=False, now=False):
        """Mask and stop services
        """
        try:
            utils.systemctl_mask_service(service, runtime=runtime, now=now)
            utils.pmon_stop_service(service)
        except Exception as ex:
            raise exception.SysinvException("Failed to mask and stop service %s. Error: [%s]"
                                            % (service, ex))

    def _unmask_start_service(self, service, runtime=False, now=False):
        """Unmask and start services
        """
        try:
            utils.systemctl_unmask_service(service, runtime=runtime, now=now)
            utils.pmon_start_service(service)
            if utils.systemctl_is_enabled_service(service) and \
                    not utils.systemctl_is_active_service(service):
                utils.systemctl_start_service(service)
        except Exception as ex:
            raise exception.SysinvException("Failed to unmask and start service %s. Error: [%s]"
                                            % (service, ex))

    def _update_symlink(self, link, to_kube_version):
        """Update symlinks to kubernetes binaries

        :param: link: string. Either a stage1 or stage2 link at /var/lib/kubernetes
        :param: to_kube_version: Kubernetes version to be updated symlinks to...
        """
        try:
            to_kube_version = to_kube_version.strip('v')
            if link == kubernetes.KUBERNETES_SYMLINKS_STAGE_1:
                stage_dir_name = 'stage1'
            else:
                stage_dir_name = 'stage2'
            versioned_stage = \
                    os.path.join(kubernetes.KUBERNETES_VERSIONED_BINARIES_ROOT,
                                    to_kube_version, stage_dir_name)
            # Remove symlink for previous kuberbetes version
            if os.path.islink(link):
                os.remove(link)
            os.symlink(versioned_stage, link)
            LOG.info("Kubernetes symlink [%s] is updated to [%s] "
                     % (link, versioned_stage))
        except Exception as ex:
            raise exception.SysinvException("Failed to update symlink [%s]. Error: [%s]"
                                            % (link, ex))

    def kubeadm_upgrade_node(self, to_kube_version):
        """Runs kubeadm upgrade node command on a host.

        The command "kubeadm upgrade node" is used to upgrade both control plane
        components and kubelet on a kubernetes node.

        :param: to_kube_version: kubernetes version string to be upgraded to.

        :raises: SysinvException in case of failure.
        """
        try:
            process = None
            to_kube_version = to_kube_version.strip('v')
            LOG.info("Running command 'kubeadm upgrade node' on this host ...")

            cmd = [constants.KUBEADM_PATH_FORMAT_STR.format(kubeadm_ver=to_kube_version),
                   "--kubeconfig=%s" % (self._kubeconfig), '-v4', 'upgrade', 'node']

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, bufsize=1)

            def _capture_output():
                for line in process.stdout:
                    LOG.info("[kubeadm-upgrade-node]: %s" % line)
                    # Ensure that the buffer is flushed
                    sys.stdout.flush()

            t = threading.Thread(target=_capture_output)

            t.start()

            return_code = process.wait(timeout=KUBEADM_UPGRADE_COMMAND_TIMEOUT)

            t.join(timeout=KUBEADM_UPGRADE_COMMAND_TIMEOUT)

            if return_code == 0:
                LOG.info("Successfully executed command 'kubeadm upgrade node' on this host.")
            else:
                raise exception.ProcessExecutionError(
                    cmd=cmd, exit_code=return_code, stderr=process.stderr.read())

        except exception.ProcessExecutionError as ex:
            if process:
                process.kill()
            raise exception.SysinvException("Command [%s] execution failed with error: [%s] and "
                                            "return code: [%s]" % (cmd, ex.stderr, ex.exit_code))
        except Exception as ex:
            if process:
                process.kill()
            raise exception.SysinvException("Kubeadm upgrade node operation failed "
                                            "with error: [%s]" % (ex))

    def _update_pause_image_in_containerd(self, current_pause_image, target_pause_image):
        """Update pause image in containerd config file

        :param: current_pause_image: full pause image name with tag currently configured. String
        :param: target_pause_image: full pause image name with tag to be replaced. String

        :return: True if successful, False otherwise
        """
        try:
            stream = ""
            with open(containers.CONTAINERD_CONFIG_FULL_PATH, 'r') as file:
                stream = file.read()
            if stream != "":
                sandbox_image_prefix = \
                        f"sandbox_image = \"{constants.DOCKER_REGISTRY_SERVER}/"
                stream = stream.replace(sandbox_image_prefix + current_pause_image,
                                        sandbox_image_prefix + target_pause_image)
                with open(containers.CONTAINERD_CONFIG_FULL_PATH, 'w') as file:
                    file.write(stream + '\n')
                LOG.info("Successfully updated pause image version in the "
                         "containerd config.")
            else:
                raise exception.SysinvException("Could not properly read containerd config file: "
                                                "[%s]. "
                                                % (containers.CONTAINERD_CONFIG_FULL_PATH))
        except Exception as ex:
            raise exception.SysinvException("Failed to update containerd config file [%s] with the "
                                            "new pause image version [%s], Error: [%s]"
                                            % (containers.CONTAINERD_CONFIG_FULL_PATH,
                                               target_pause_image, ex))

    def upgrade_kubelet(
            self, from_kube_version, to_kube_version, current_pause_image, target_pause_image):
        """Upgrade the kubernetes kubelet on this host

        Common operations for both controller and worker personalities

        :param: from_kube_version: current kubernetes version
        :param: to_kube_version: kubernetes version being upgraded to
        """
        # Update pause image
        if current_pause_image == target_pause_image:
            LOG.info("No need to update 'pause' image inside containerd config. Proceeding...")
        else:
            self._update_pause_image_in_containerd(current_pause_image, target_pause_image)

        # update stage2 symlink.
        self._update_symlink(kubernetes.KUBERNETES_SYMLINKS_STAGE_2, to_kube_version)


class KubeWorkerOperator(KubeHostOperator):
    '''Class for kubernetes worker operations in Sysinv '''

    def __init__(self, context, host_uuid, host_name):
        self._host_personality = constants.WORKER
        self._kubeconfig = kubernetes.KUBERNETES_KUBELET_CONF
        super().__init__(context, host_uuid, host_name)

    def upgrade_kubelet(self, from_kube_version, to_kube_version, is_final_version):
        """Upgrade the kubernetes kubelet on this worker

        Upgrade kubelet on worker hosts.

        :param: from_kube_version: current kubernetes version
        :param: to_kube_version: kubernetes version being upgraded to
        :param: is_final_version: True if to_kube_version is the final version in the
                                  current kubernetes upgrade attempt else False
        """
        try:
            from_kube_version = from_kube_version.strip('v')
            to_kube_version = to_kube_version.strip('v')

            current_images = kubernetes.get_k8s_images(from_kube_version)
            current_pause_image = current_images['pause']

            target_images = kubernetes.get_k8s_images(to_kube_version)
            target_pause_image = target_images['pause']

            # pull pause image if required
            if current_pause_image != target_pause_image:
                if not self._containerd_operator.pull_images([target_pause_image]):
                    raise exception.SysinvException("Failed to pull the pause image required for "
                                                    "the kubelet upgrade.")
            else:
                LOG.info("No need to update the pause image. Skip pulling ...")

            # kubeadm upgrade node
            self.kubeadm_upgrade_node(to_kube_version)

            # update stage1 symlink.
            self._update_symlink(kubernetes.KUBERNETES_SYMLINKS_STAGE_1, to_kube_version)

            super().upgrade_kubelet(
                    from_kube_version, to_kube_version, current_pause_image, target_pause_image)

            utils.pmon_restart_service(kubernetes.KUBELET_SYSTEMD_SERVICE_NAME)

        except Exception as ex:
            raise exception.SysinvException("Error upgrading kubelet: [%s]. " % (ex))


class KubeControllerOperator(KubeHostOperator):
    '''Class for kubernetes controller operations in Sysinv '''

    def __init__(self, context, host_uuid, host_name):
        self._host_personality = constants.CONTROLLER
        self._abort_attempt = 1
        self._etcd_db_path = os.path.join(
                constants.ETCD_PATH, constants.ETCD_DIR_NAME, etcd.ETCD_DB_FILE_NAME)
        self._etcd_bkp_path = os.path.join(
                constants.ETCD_PATH, constants.ETCD_DIR_NAME, etcd.ETCD_BACKUP_FILE_NAME)
        self._kubeconfig = kubernetes.KUBERNETES_ADMIN_CONF
        super().__init__(context, host_uuid, host_name)

    def _backup_kubeconfig_files(self):
        """Backup admin.conf and super-admin.conf
        """
        try:
            os.makedirs(kubernetes.KUBE_CONFIG_BACKUP_PATH, exist_ok=True)
            admin_files = [kubernetes.KUBERNETES_ADMIN_CONF, kubernetes.KUBERNETES_SUPER_ADMIN_CONF]
            for file in admin_files:
                if os.path.exists(file):
                    shutil.copy2(file, kubernetes.KUBE_CONFIG_BACKUP_PATH)
                    LOG.info("File %s copied to %s" % (file, kubernetes.KUBE_CONFIG_BACKUP_PATH))
                else:
                    raise exception.SysinvException("Kubernetes admin file %s not found." % (file))
        except Exception as ex:
            raise exception.SysinvException("Failed to backup kubeconfig files. Error: [%s]" % (ex))

    def _move_control_plane_manifests(self):
        """Move static pod manifests

        Move static pod manifests of current kubernetes version so that they can be restored
        back in case the abort operation is failed.
        """
        try:
            os.makedirs(kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_MANIFESTS_ABORT, exist_ok=True)
            if os.path.exists(kubernetes.KUBE_CONTROL_PLANE_MANIFESTS_PATH):
                manifests = os.listdir(kubernetes.KUBE_CONTROL_PLANE_MANIFESTS_PATH)
                for file_name in manifests:
                    source_file = os.path.join(
                            kubernetes.KUBE_CONTROL_PLANE_MANIFESTS_PATH, file_name)
                    dest_file = os.path.join(
                            kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_MANIFESTS_ABORT, file_name)
                    if not os.path.exists(dest_file):
                        shutil.move(source_file, dest_file)
                        LOG.info("File %s moved to %s" % (source_file, dest_file))
                    else:
                        LOG.info("File %s already saved to %s for the recovery purpose."
                                 % (source_file, dest_file))
                kubernetes.k8s_wait_for_control_plane_terminated()
                LOG.info("All control plane pods are now terminated.")
            else:
                raise exception.SysinvException("Static pod manifests not present at %s."
                            % (kubernetes.KUBE_CONTROL_PLANE_MANIFESTS_PATH))

        except Exception as ex:
            raise exception.SysinvException("Failed to move control plane manifests. "
                                            "Error: [%s]" % (ex))

    def _move_etcd(self):
        """Save etcd for recovery
        """
        try:
            if os.path.exists(self._etcd_bkp_path):
                LOG.info("Etcd was saved already for the recovery purpose, continuing...")
                # In case, if the previous run of the abort failed (all 3 attempts), followed by
                # the recovery also failed *AFTER* recovering etcd, we'd have unintended version of
                # the etcd which will fail the snapshot restore operation. So, remove it here.
                if os.path.exists(self._etcd_db_path):
                    shutil.rmtree(self._etcd_db_path)
                return
            if os.path.exists(self._etcd_db_path):
                shutil.move(self._etcd_db_path, self._etcd_bkp_path)
                LOG.info("Etcd at %s moved to %s" % (self._etcd_db_path, self._etcd_bkp_path))
            else:
                raise exception.SysinvException("Etcd not found at %s" % (self._etcd_db_path))
        except Exception as ex:
            raise exception.SysinvException("Failed to move etcd with error: [%s]" % (ex))

    def restore_etcd_snapshot(self):
        """Restore etcd snapshot

        This method restores the snapshot of the etcd database running before kubernetes upgrade
        was started. The snapshot was taken during kubernetes networking upgrade stage.
        """
        try:
            if os.path.exists(self._etcd_db_path) and self._abort_attempt > 1:
                LOG.info("Etcd already restored in the previous attempt. Continuing...")
                return
            etcd.restore_etcd_snapshot(etcd.ETCD_SNAPSHOT_FULL_FILE_PATH, self._etcd_db_path)
            LOG.info("Etcd snapshot restored successfully to %s" % (self._etcd_db_path))
        except Exception as ex:
            raise exception.SysinvException("Failed to restore etcd snapshot. Error: [%s]" % (ex))

    def restore_backed_up_static_pod_manifests(self):
        """Restore backed up static pod manifests

        This restores static pod manifests of the original kubernetes version
        backed up during networking upgrade.
        """
        try:
            if os.path.exists(kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_BACKUP_PATH):
                if len(os.listdir(kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_BACKUP_PATH)) == 0:
                    raise exception.SysinvException("Static pod manifests not present at the "
                                                    "backup location %s"
                                        % (kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_BACKUP_PATH))
            else:
                raise exception.SysinvException("Static pod manifests backup path %s does not exist"
                                        % (kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_BACKUP_PATH))
            for file in os.listdir(kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_BACKUP_PATH):
                file_path = os.path.join(
                        kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_BACKUP_PATH, file)
                shutil.copy2(file_path, kubernetes.KUBE_CONTROL_PLANE_MANIFESTS_PATH)
            LOG.info("Static pod manifests restored successfully from %s to %s"
                     % (kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_BACKUP_PATH,
                        kubernetes.KUBE_CONTROL_PLANE_MANIFESTS_PATH))
        except Exception as ex:
            raise exception.SysinvException("Failed to restore static pod manifests. "
                                            "Error: [%s]" % (ex))

    def _prepare_for_abort_recovery(self):
        """Save control plane manifests, admin.conf and super-admin.conf and etcd

        These artifacts are saved for recovery in case the abort operation is failed.
        """
        self._backup_kubeconfig_files()
        self._move_control_plane_manifests()
        self._move_etcd()

    def _cleanup_backed_up_artifacts(self):
        """Remove backed up artifacts upon successful abort
        """
        try:
            shutil.rmtree(kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_MANIFESTS_ABORT)
            LOG.info("Removed backed up static pod manifests at %s"
                     % (kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_MANIFESTS_ABORT))
        except Exception as ex:
            LOG.warning("Failed to remove saved file(s) at [%s] after kubernetes upgrade "
                        "abort. Error: [%s]. Please remove manually to save disk space."
                        % (kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_MANIFESTS_ABORT, ex))

        try:
            shutil.rmtree(kubernetes.KUBE_CONFIG_BACKUP_PATH)
            LOG.info("Removed kubeconfig files saved at: [%s]"
                     % (kubernetes.KUBE_CONFIG_BACKUP_PATH))
        except Exception as ex:
            LOG.warning("Failed to remove backed up file(s) at [%s] after kubernetes upgrade "
                        "abort. Error: [%s]. Please remove manually to save disk space."
                        % (kubernetes.KUBE_CONFIG_BACKUP_PATH, ex))

        try:
            shutil.rmtree(self._etcd_bkp_path)
            LOG.info("Removed etcd backed up at [%s]" % (self._etcd_bkp_path))
        except Exception as ex:
            LOG.warning("Failed to remove saved file(s) at [%s] after kubernetes upgrade "
                        "abort. Error: [%s]. Please remove manually to save disk space."
                        % (self._etcd_bkp_path, ex))

    def upgrade_abort(self, current_kube_version, back_to_kube_version):
        """Procedure to abort a kubernetes upgrade

        :param: current_kube_version: current kubernetes version
        :param: back_to_kube_version: kubernetes version to roll back to
        """
        abort = True
        recovery = False
        while self._abort_attempt <= constants.AUTO_RECOVERY_COUNT:
            LOG.info("Trying kubernetes upgrade abort... Attempt %s of %s."
                    % (self._abort_attempt, constants.AUTO_RECOVERY_COUNT))
            try:
                if kubernetes.k8s_health_check(tries=3, try_sleep=1, log=False):
                    if not kubernetes.is_node_cordoned(self._host_name):
                        kubernetes.kube_drain_node_with_options(self._host_name)
                else:
                    if self._abort_attempt == 1:
                        raise exception.SysinvException("Kube-apiserver is not running."
                                                        "Cannot drain the node %s ."
                                                        % (self._host_name))
                    else:
                        LOG.warning("Kube-apisever is not running. This is likely because it was "
                                    "brought down in the previous attempt. Continuing...")

                self._prepare_for_abort_recovery()

                for service in [kubernetes.KUBE_ISOLCPU_PLUGIN_SYSTEMD_SERVICE_NAME,
                                kubernetes.KUBELET_SYSTEMD_SERVICE_NAME]:
                    self._mask_stop_service(service, runtime=True, now=True)

                self._containerd_operator.stop_all()

                LOG.info("All containerd pods and containers stopped successfully.")

                for service in [kubernetes.KUBE_CONTAINERD_SYSTEMD_SERVICE_NAME,
                                kubernetes.KUBE_DOCKER_SYSTEMD_SERVICE_NAME,
                                kubernetes.KUBE_ETCD_SYSTEMD_SERVICE_NAME]:
                    self._mask_stop_service(service, runtime=True, now=True)

                self.restore_etcd_snapshot()

                self.restore_backed_up_static_pod_manifests()

                back_to_kube_version = back_to_kube_version.strip('v')

                for link in [kubernetes.KUBERNETES_SYMLINKS_STAGE_1,
                             kubernetes.KUBERNETES_SYMLINKS_STAGE_2]:
                    self._update_symlink(link, back_to_kube_version)

                kubernetes.enable_kubelet_garbage_collection()

                for service in [kubernetes.KUBE_ETCD_SYSTEMD_SERVICE_NAME,
                                kubernetes.KUBE_DOCKER_SYSTEMD_SERVICE_NAME,
                                kubernetes.KUBE_CONTAINERD_SYSTEMD_SERVICE_NAME,
                                kubernetes.KUBELET_SYSTEMD_SERVICE_NAME,
                                kubernetes.KUBE_ISOLCPU_PLUGIN_SYSTEMD_SERVICE_NAME]:
                    self._unmask_start_service(service, runtime=True, now=True)

                k8s_health = kubernetes.k8s_wait_for_endpoints_health(quiet=True)
                if k8s_health:
                    LOG.info("All control plane pods are back, up and running")
                else:
                    raise exception.SysinvException(
                        "Kubernetes control plane pods not back after kubernetes abort procedure.")

                kubernetes.kube_uncordon_node(self._host_name)

                self._cleanup_backed_up_artifacts()

                abort = True

                break
            except Exception as ex:
                LOG.error("Kubernetes upgrade abort attempt %s of %s failed. Error: [%s]"
                        % (self._abort_attempt, constants.AUTO_RECOVERY_COUNT, ex))
                abort = False
                self._abort_attempt += 1

        # Do best effort to recover to the state just before abort was executed
        if not abort:
            try:
                self.upgrade_abort_recovery(current_kube_version)
                recovery = True
            except Exception as ex:
                LOG.error(ex)
                recovery = False
        return abort, recovery

    def _recover_kubeconfig_files(self):
        """Recover admin.conf and super-admin.conf
        """
        try:
            if os.path.exists(kubernetes.KUBE_CONFIG_BACKUP_PATH):
                files = os.listdir(kubernetes.KUBE_CONFIG_BACKUP_PATH)
                if len(files) == 0:
                    raise exception.SysinvException("Kubeconfig files not found at %s"
                                                    % (kubernetes.KUBE_CONFIG_BACKUP_PATH))
            else:
                raise exception.SysinvException("Path %s does not exists where kubeconfig files "
                                                "were saved for the recovery purpose."
                                    % (kubernetes.KUBE_CONFIG_BACKUP_PATH))
            for file_name in files:
                source_file_path = os.path.join(kubernetes.KUBE_CONFIG_BACKUP_PATH, file_name)
                dest_file_path = os.path.join(kubernetes.KUBERNETES_CONF_DIR, file_name)
                if not os.path.exists(dest_file_path):
                    shutil.move(source_file_path, dest_file_path)
            LOG.info("Kubernetes kubeconfig files recovered successfully from %s to %s."
                     % (kubernetes.KUBE_CONFIG_BACKUP_PATH, kubernetes.KUBERNETES_CONF_DIR))
        except Exception as ex:
            raise exception.SysinvException("Failed to recover kubeconfig files. "
                                            "Error: [%s]" % (ex))

    def _recover_static_pod_manifests(self):
        """Recover static pod manifests
        """
        try:
            if os.path.exists(kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_MANIFESTS_ABORT):
                files = os.listdir(kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_MANIFESTS_ABORT)
                if len(files) == 0:
                    raise exception.SysinvException("Saved static pod manifests not found at %s"
                                    % (kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_MANIFESTS_ABORT))
            else:
                raise exception.SysinvException("Path %s does not exists where static pod manifest "
                                                "were saved for recovery purpose."
                                    % (kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_MANIFESTS_ABORT))

            for file_name in files:
                src_path = os.path.join(kubernetes.KUBE_CONTROL_PLANE_STATIC_PODS_MANIFESTS_ABORT,
                                         file_name)
                dest_path = os.path.join(kubernetes.KUBE_CONTROL_PLANE_MANIFESTS_PATH, file_name)
                if not os.path.exists(dest_path):
                    shutil.move(src_path, dest_path)
                    LOG.info("Kubernetes static pod manifest %s recovered successfully to %s."
                             % (src_path, dest_path))
        except Exception as ex:
            raise exception.SysinvException("Failed to recover static pod manifests. "
                                            "Error: [%s]" % (ex))

    def _recover_etcd(self):
        """Recover etcd
        """
        try:
            if not os.path.exists(self._etcd_db_path):
                shutil.move(self._etcd_bkp_path, self._etcd_db_path)
                LOG.info("Kubernetes: etcd recovered successfully from %s to %s."
                        % (self._etcd_bkp_path, self._etcd_db_path))
        except Exception as ex:
            raise exception.SysinvException("Failed to recover etcd. Error: [%s]" % (ex))

    def upgrade_abort_recovery(self, recover_to_kube_version):
        """Recover a failed abort attempt
        """
        try:
            self._recover_kubeconfig_files()

            self._recover_static_pod_manifests()

            self._recover_etcd()

            recover_to_kube_version = recover_to_kube_version.strip('v')

            for link in [kubernetes.KUBERNETES_SYMLINKS_STAGE_1,
                         kubernetes.KUBERNETES_SYMLINKS_STAGE_2]:
                self._update_symlink(link, recover_to_kube_version)

            for service in [kubernetes.KUBE_ETCD_SYSTEMD_SERVICE_NAME,
                            kubernetes.KUBE_DOCKER_SYSTEMD_SERVICE_NAME,
                            kubernetes.KUBE_CONTAINERD_SYSTEMD_SERVICE_NAME,
                            kubernetes.KUBELET_SYSTEMD_SERVICE_NAME,
                            kubernetes.KUBE_ISOLCPU_PLUGIN_SYSTEMD_SERVICE_NAME]:
                self._unmask_start_service(service, runtime=True, now=True)

            k8s_health = kubernetes.k8s_wait_for_endpoints_health()
            if k8s_health:
                LOG.info("All control plane pods are back, up and running")
            else:
                raise exception.SysinvException(
                        "Kubernetes control plane pods not back after kubernetes abort procedure")

            kubernetes.kube_uncordon_node(self._host_name)

            self._cleanup_backed_up_artifacts()

        except Exception as ex:
            raise exception.SysinvException("Error performing kubernetes upgrade abort recovery: "
                                            "[%s]" % (ex))

    def kubeadm_upgrade_apply(self, to_kube_version):
        """Runs kubeadm upgrade apply command on a controller host.

        The command "kubeadm upgrade apply" is used to upgrade first control plane
        node of the kubernetes cluster.

        :param: to_kube_version: kubernetes version string to be upgraded to.

        :raises: SysinvException in case of failure.
        """
        try:
            process = None

            to_kube_version = to_kube_version.strip('v')

            LOG.info("Running command 'kubeadm upgrade apply' on this host ...")

            cmd = [constants.KUBEADM_PATH_FORMAT_STR.format(kubeadm_ver=to_kube_version),
                   "--kubeconfig=%s" % (self._kubeconfig), '-v4', 'upgrade', 'apply',
                   to_kube_version, '--allow-experimental-upgrades',
                   '--allow-release-candidate-upgrades', '-y']

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, bufsize=1)

            def _capture_output():
                for line in process.stdout:
                    LOG.info("[kubeadm-upgrade-apply]: %s" % line)
                    # Ensure that the buffer is flushed
                    sys.stdout.flush()

            t = threading.Thread(target=_capture_output)

            t.start()

            return_code = process.wait(timeout=KUBEADM_UPGRADE_COMMAND_TIMEOUT)

            t.join(timeout=KUBEADM_UPGRADE_COMMAND_TIMEOUT)

            if return_code == 0:
                LOG.info("Successfully executed command 'kubeadm upgrade apply' on this host.")
            else:
                raise exception.ProcessExecutionError(
                    cmd=cmd, exit_code=return_code, stderr=process.stderr.read())

        except exception.ProcessExecutionError as ex:
            if process:
                process.kill()
            raise exception.SysinvException("Command [%s] execution failed with error: [%s] and "
                                            "return code: [%s]"
                                            % (cmd, ex.stderr, ex.exit_code))
        except Exception as ex:
            if process:
                process.kill()
            raise exception.SysinvException("Kubeadm upgrade apply operation failed "
                                            "with error: [%s]" % (ex))

    def _remove_older_kubelet_config_configmaps(self):
        """Remove all kubelet-config configmaps and just keep the latest one
        """
        try:
            configmaps = self._kubernetes_operator.kube_get_all_configmaps()
            kubelet_confs = [cm for cm in configmaps if 'kubelet-config' in cm.metadata.name]
            configmap_to_keep = max(kubelet_confs, key=attrgetter('metadata.creation_timestamp',
                                                                  'metadata.resource_version'))
            for cm in kubelet_confs:
                if cm.metadata.name != configmap_to_keep.metadata.name:
                    self._kubernetes_operator.kube_delete_config_map(
                        cm.metadata.name, kubernetes.NAMESPACE_KUBE_SYSTEM)
        except Exception as ex:
            raise exception.SysinvException("Failed to remove older kubelet-config configmaps with"
                                            " error: [%s]" % (ex))

    def _update_kube_proxy_service_account(self):
        """Update ImagePullSecrets field in kube-proxy in service account
        """
        try:
            patch_kube_proxy_sa = {
                "imagePullSecrets": [{"name": "registry-local-secret"}]
            }

            self._kubernetes_operator.kube_patch_service_account(
                "kube-proxy", kubernetes.NAMESPACE_KUBE_SYSTEM, body=patch_kube_proxy_sa)
            LOG.info("kube-proxy service account updated successfully.")
        except Exception as ex:
            raise exception.SysinvException("Failed to update image pull secrets in kube-proxy "
                                            "service account with error: [%s]" % (ex))

    def _update_coredns_service_account(self):
        """Update coredns service account labels and ImagePullSecrets
        """
        try:
            patch_coredns_sa = {
                "metadata": {
                    "labels": {
                        "kubernetes.io/cluster-service": "true",
                        "addonmanager.kubernetes.io/mode": "Reconcile"
                    }
                },
                "imagePullSecrets": [{
                    "name": "default-registry-key"
                }]
            }
            self._kubernetes_operator.kube_patch_service_account(
                "coredns", kubernetes.NAMESPACE_KUBE_SYSTEM, body=patch_coredns_sa)
            LOG.info("Coredns service account updated successfully.")
        except Exception as ex:
            raise exception.SysinvException("Failed to update coredns service account "
                                            "with error: [%s]" % (ex))

    def _update_coredns_deployment_with_rollout_restart(self):
        """Update and rollout restart coredns deployment
        """
        try:
            now = datetime.datetime.now()
            now_iso_format = now.isoformat("T") + "Z"
            patch_corens_deployment = {
                "spec": {
                    "template": {
                        "spec": {
                            "nodeSelector": {
                                "node-role.kubernetes.io/control-plane": ""
                            },
                            "affinity": {
                                "podAntiAffinity": {
                                    "requiredDuringSchedulingIgnoredDuringExecution": [{
                                        "labelSelector": {
                                            "matchExpressions": [{
                                                "key": "k8s-app",
                                                "operator": "In",
                                                "values": ["kube-dns"]
                                            }]
                                        },
                                        "topologyKey": "kubernetes.io/hostname"
                                    }]
                                }
                            }
                        },
                        'metadata': {
                            'annotations': {
                                'kubectl.kubernetes.io/restartedAt': now_iso_format
                            }
                        }
                    },
                }
            }

            if self._system_mode == constants.SYSTEM_MODE_SIMPLEX:
                patch_corens_deployment['spec'].update({"replicas": 1})

            self._kubernetes_operator.kube_patch_deployment(
                "coredns", kubernetes.NAMESPACE_KUBE_SYSTEM, body=patch_corens_deployment)
            LOG.info("Coredns deployment updated and rolllout restarted successfully.")
        except Exception as ex:
            raise exception.SysinvException("Failed to update coredns deployment with "
                                            "error: [%s]" % (ex))

    def _rollout_restart_kube_proxy_daemonset(self):
        """Rollout restart kube-proxy daemonset
        """
        try:
            now = datetime.datetime.now()
            now_iso_format = now.isoformat("T") + "Z"
            patch_kube_proxy_daemonset = {
                'spec': {
                    'template': {
                        'metadata': {
                            'annotations': {
                                'kubectl.kubernetes.io/restartedAt': now_iso_format
                            }
                        }
                    }
                }
            }

            self._kubernetes_operator.kube_patch_daemon_set(
                "kube-proxy", kubernetes.NAMESPACE_KUBE_SYSTEM, body=patch_kube_proxy_daemonset)

            LOG.info("Kube-proxy deployment rollout restarted successfully.")

        except Exception as ex:
            raise exception.SysinvException("Failed to update coredns deployment with "
                                            "error: [%s]" % (ex))

    def upgrade_control_plane(self, to_kube_version, is_first_master):
        """Upgrade kubernetes control-plane components on this controller

        :param: to_kube_version: kubernetes version being upgraded to
        :param: is_first_master: True if this is the first controller being upgraded else False
        """
        try:
            if is_first_master:
                self.kubeadm_upgrade_apply(to_kube_version)
            else:
                self.kubeadm_upgrade_node(to_kube_version)

            if self._system_mode == constants.SYSTEM_MODE_SIMPLEX or not is_first_master:

                self._remove_older_kubelet_config_configmaps()

                self._update_coredns_service_account()

                self._update_kube_proxy_service_account()

                self._update_coredns_deployment_with_rollout_restart()

                self._rollout_restart_kube_proxy_daemonset()

            self._update_symlink(kubernetes.KUBERNETES_SYMLINKS_STAGE_1, to_kube_version)

        except Exception as ex:
            raise exception.SysinvException("Error upgrading control plane components: %s" % (ex))

    def upgrade_kubelet(self, from_kube_version, to_kube_version, is_final_version):
        """Upgrade the kubernetes kubelet on this controller

        Upgrade kubelet on controller hosts.
        pause image pull, execution of command 'kubeadm upgrade node' and 'stage1' symlink update
        etc. operations are already done on controller nodes during previous stages of kubernetes
        upgrade.

        :param: from_kube_version: current kubernetes version
        :param: to_kube_version: kubernetes version being upgraded to
        :param: is_final_version: True if to_kube_version is the final version in the
                                  current kubernetes upgrade attempt else False
        """
        try:
            from_kube_version = from_kube_version.strip('v')
            to_kube_version = to_kube_version.strip('v')

            current_images = kubernetes.get_k8s_images(from_kube_version)
            current_pause_image = current_images['pause']

            target_images = kubernetes.get_k8s_images(to_kube_version)
            target_pause_image = target_images['pause']

            super().upgrade_kubelet(
                    from_kube_version, to_kube_version, current_pause_image, target_pause_image)

            # GC was disabled during image download to prevent undesirable image removal before
            # control plane and kubelet upgrade. Reenable if this is the final kubernetes version
            # in upgrade sequence.
            if is_final_version:
                kubernetes.enable_kubelet_garbage_collection()

            utils.pmon_restart_service(kubernetes.KUBELET_SYSTEMD_SERVICE_NAME)

        except Exception as ex:
            raise exception.SysinvException("Error upgrading kubelet: [%s]. " % (ex))
