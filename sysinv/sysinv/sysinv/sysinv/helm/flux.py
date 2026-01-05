#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import subprocess
import yaml

from oslo_log import log as logging

from sysinv.common import kubernetes
from sysinv.common import utils
from sysinv.common.image_download import ContainerImageDownloader
from sysinv.helm import utils as helm_utils

KUBECONFIG = "/etc/kubernetes/admin.conf"
CONFIG_DIR = "/usr/share/ansible/stx-ansible/playbooks/roles/common/fluxcd-controllers/"
CONF_FILE = os.path.join(CONFIG_DIR, 'vars', 'main.yml')
TEMPLATE_PATH = os.path.join(CONFIG_DIR, 'templates')
TEMPLATE_FILENAME = 'values.yaml.j2'
OCI_REPO_CRD = "ocirepositories.source.toolkit.fluxcd.io"

# Log and config
LOG = logging.getLogger(__name__)


class FluxDeploymentManager(object):

    def __init__(self, dbapi):

        self._dbapi = dbapi
        self._image_downloader = ContainerImageDownloader(self._dbapi)

        with open(CONF_FILE) as f:
            self.conf_dict = yaml.safe_load(f)

    def get_image_list(self):
        """ Retrieve list of required images for controllers

        Returns:
            list(str): List containing the images required for controllers.
        """

        image_list = [f"{self.conf_dict['flux_helm_controller_image']}:"
                      f"{self.conf_dict['flux_helm_controller_tag']}",
                      f"{self.conf_dict['flux_source_controller_image']}:"
                      f"{self.conf_dict['flux_source_controller_tag']}"]

        if self.conf_dict['enable_kustomize_controller']:
            image_list.append(f"{self.conf_dict['flux_kustomize_controller_image']}:"
                              f"{self.conf_dict['flux_kustomize_controller_tag']}")
        if self.conf_dict['enable_notification_controller']:
            image_list.append(f"{self.conf_dict['flux_notification_controller_image']}:"
                              f"{self.conf_dict['flux_notification_controller_tag']}")

        return image_list

    def download_images(self):
        """ Download controller images from public/private registries

        Returns:
            bool: True if all images were downloaded. False otherwise.
        """

        image_list = self.get_image_list()
        LOG.info(f"Downloading the following Flux images: {', '.join(image_list)}")

        result = self._image_downloader.download_images_from_upstream_to_local_reg_and_crictl(
            image_list)

        if result:
            LOG.info("Flux images downloaded")
        else:
            LOG.error("Failed to download Flux images.")

        return result

    def deploy_controllers(self):
        """ Deploy Flux controllers from scratch """

        raise NotImplementedError

    def generate_overrides(self):
        """ Generate Helm overrides from Jinja template.

        Returns:
            string: rendered Flux overrides.
        """

        LOG.info("Generating Flux overrides")

        overrides = utils.render_jinja_template_from_file(TEMPLATE_PATH,
                                                          TEMPLATE_FILENAME,
                                                          custom_filters=None,
                                                          values=self.conf_dict)

        LOG.info("Flux overrides generated")

        return overrides

    def upgrade_controllers(self):
        """ Upgrade Flux controllers via Helm

        Returns:
            bool: True if upgrade is sucessful. False otherwise.
        """

        LOG.info("Starting Flux release upgrade")

        success = False
        if self.download_images():

            overrides = self.generate_overrides()

            LOG.info("Upgrading Flux release")

            try:
                subprocess.run(
                    ["helm", "upgrade",
                     "--namespace", self.conf_dict['fluxcd_namespace'],
                     "--kubeconfig", KUBECONFIG,
                     "--install",
                     "--create-namespace",
                     "--wait",
                     "--wait-for-jobs",
                     "--values", "-",
                     self.conf_dict['flux_helm_release_name'],
                     self.conf_dict['flux_charts_path']
                     ],

                    check=True,
                    capture_output=True,
                    input=overrides,
                    text=True
                )

                success = True
                LOG.info("Flux release successfully upgraded")
            except subprocess.CalledProcessError as e:
                LOG.error(f"Error while upgrading flux controllers: {e.stderr}")
            except Exception as e:
                LOG.error(f"Cannot upgrade flux controllers: {e}")

        return success

    @staticmethod
    def is_target_version_installed(history, target_version):
        """ Retrieve the target Helm release revision for rollback

        Args:
            history (list): list of records of the release history.
            target_version (string): target version for rollback.

        Returns:
            bool: True if the target release is installed. False otherwise.
        """

        if len(history) == 0:
            raise Exception("Flux release has an empty history")

        if f"-{target_version}" in history[-1]["chart"] and history[-1]["status"] == 'deployed':
            LOG.warning("Already running target Flux release. Skipping rollback.")
            return True

        return False

    @staticmethod
    def get_target_revision(history, target_version):
        """ Retrieve the target Helm release revision for rollback

        Args:
            history (list): list of records of the release history.
            target_version (string): target version for rollback.

        Returns:
            integer: Revision number.
        """

        for record in reversed(history[:-1]):
            if f"-{target_version}" in record["chart"]:
                return record["revision"]
        return None

    # Workaround for portieris issue when helm-controller is restarting during activate-rollback
    def wait_helm_controller_pod_ready(self):
        """ Wait for helm-controller pod to be Ready
        """

        LOG.info("Waiting for helm-controller pod to be Ready")

        try:
            subprocess.run(
                ["kubectl", "wait", "--for=condition=Ready", "pods",
                 "-l", "app=helm-controller",
                 "-n", self.conf_dict['fluxcd_namespace'],
                 "--timeout=60s",
                 "--kubeconfig", KUBECONFIG],
                check=True
            )
        except Exception as e:
            # Warning and proceeding with the rollback, as the issue might be fixed by it
            LOG.warning(f"Error waiting for helm-controller pod to be Ready: {e}")
        else:
            LOG.info("helm-controller pod is Ready. Proceeding.")

    def delete_oci_repository_crd(self):
        """ Delete ocirepositories.source.toolkit.fluxcd.io CRD as manifests from
        versions 2.15 and 2.17 do not support straightforward rollback.
        """

        kubernetes_operator = kubernetes.KubeOperator()

        LOG.info("Deleting incompatible CRD %s", OCI_REPO_CRD)

        success = False
        try:
            kubernetes_operator.delete_custom_resource_definition(OCI_REPO_CRD)
            success = True
        except Exception as e:
            LOG.error(f"Error deleting CRD {OCI_REPO_CRD}: {e}.")

        LOG.info("Finished CRD deletion")

        return success

    def rollback_controllers(self):
        """ Rollback Flux controllers to the previous version """

        if not self.delete_oci_repository_crd():
            return False

        success = False
        try:
            previous_version = helm_utils.get_chart_version(
                self.conf_dict['flux_legacy_charts_path'])
            history = helm_utils.get_history(self.conf_dict['flux_helm_release_name'],
                                             self.conf_dict['fluxcd_namespace'],
                                             KUBECONFIG)

            # Rollback only if not already in the target version
            if not self.is_target_version_installed(history, previous_version):
                target_revision = self.get_target_revision(history, previous_version)

                if target_revision:
                    self.wait_helm_controller_pod_ready()

                    LOG.info(f"Rolling back Flux release to revision {target_revision}")

                    subprocess.run(
                        ["helm", "rollback",
                         self.conf_dict['flux_helm_release_name'],
                         str(target_revision),
                         "-n", self.conf_dict['fluxcd_namespace'],
                         "--kubeconfig", KUBECONFIG,
                         "--wait",
                         "--wait-for-jobs"],
                        check=True,
                        capture_output=True
                    )

                    success = True
                    LOG.info("Flux release successfully rolled back")
                else:
                    LOG.warning(f"Flux chart version {previous_version} is not available in "
                                "revision history. Skipping rollback.")
                    success = True

        except subprocess.CalledProcessError as e:
            LOG.error(f"Error while rolling back flux controllers: {e.stderr}")
        except Exception as e:
            LOG.error(f"Cannot rollback flux controllers: {e}")

        return success
