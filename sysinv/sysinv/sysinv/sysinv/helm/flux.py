#
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import glob
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
HELM_RELEASE_CRD = "helmreleases.helm.toolkit.fluxcd.io"

# Chart paths
BASE_CHART_DIR = "/usr/local/share/flux2-charts/"
PREVIOUS_VERSION_CHART_DIR = os.path.join("/ostree/2", BASE_CHART_DIR.lstrip('/'))

# Log and config
LOG = logging.getLogger(__name__)


class FluxDeploymentManager(object):

    def __init__(self, dbapi):

        self._dbapi = dbapi
        self._image_downloader = ContainerImageDownloader(self._dbapi)

        with open(CONF_FILE) as f:
            self.conf_dict = yaml.safe_load(f)

    def delete_crd(self, crd_name):
        """Delete a custom resource definition by name using KubeOperator.

        Args:
            crd_name (str): Name of the CRD to delete.

        Returns:
            bool: True if deletion was successful, False otherwise.
        """

        kubernetes_operator = kubernetes.KubeOperator()
        LOG.info(f"Deleting CRD {crd_name}")

        success = False
        try:
            kubernetes_operator.delete_custom_resource_definition(crd_name)
            success = True
        except Exception as e:
            LOG.error(f"Error deleting CRD {crd_name}: {e}.")

        LOG.info("Finished CRD deletion")

        return success

    def delete_oci_repository_crd(self):
        """ Delete ocirepositories.source.toolkit.fluxcd.io CRD as manifests from
        versions 2.15 do not support straightforward rollback and upgrade from/to
        versions 2.17 and 2.18.
        """
        return self.delete_crd(OCI_REPO_CRD)

    def remove_v2beta1_from_helmrelease(self):
        """
            Check if the Helm Release CRD has the v2beta1 version and remove it.
        """
        kubernetes_operator = kubernetes.KubeOperator()
        helm_crd = kubernetes_operator.get_custom_resource_definition(HELM_RELEASE_CRD)

        if not helm_crd:
            LOG.error("Helm Release CRD not found.")
            return

        if "v2beta1" in helm_crd.status.stored_versions:
            LOG.info("Helm Release CRD has v2beta1 version.")
            stored_versions = [
                version for version in helm_crd.status.stored_versions
                if version != "v2beta1"
            ]
            kubernetes_operator.patch_custom_resource_definition_stored_status(
                HELM_RELEASE_CRD,
                stored_versions
            )
            LOG.info("Sucessfully removed v2beta1 version from Helm Release")

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

    @staticmethod
    def get_chart_path(chart_dir):
        """ Find the Flux Helm chart path dynamically in the given directory.

        Args:
            chart_dir (str): Directory to search for the chart.

        Returns:
            str or None: Path to the chart file, or None if not found.
        """
        matches = glob.glob(os.path.join(chart_dir, "flux2-*.tgz"))

        if len(matches) == 0:
            LOG.error(f"No Flux charts found in {chart_dir}")
            return None
        elif len(matches) == 1:
            LOG.info(f"Chart {os.path.basename(matches[0])} found under {chart_dir}")
            return matches[0]
        else:
            LOG.error(f"Multiple Flux charts found in {chart_dir}: {matches}")
            return None

    def upgrade_controllers(self):
        """ Upgrade Flux controllers via Helm

        Returns:
            bool: True if upgrade is sucessful. False otherwise.
        """

        LOG.info("Starting Flux release upgrade")

        chart_path = self.get_chart_path(BASE_CHART_DIR)
        if not chart_path:
            LOG.error("Unable to locate Flux chart for upgrade")
            return False

        self.remove_v2beta1_from_helmrelease()
        self.delete_oci_repository_crd()

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
                     chart_path
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

    def rollback_controllers(self):
        """ Rollback Flux controllers to the previous version """

        previous_version_chart_path = self.get_chart_path(PREVIOUS_VERSION_CHART_DIR)
        if not previous_version_chart_path:
            LOG.error("Unable to locate Flux chart for rollback")
            return False

        # Check if previous and target charts are the same. Covers the scenario where
        # rollback is being executed but Flux hasn't been upversioned.
        if os.path.basename(previous_version_chart_path) == \
                os.path.basename(self.get_chart_path(BASE_CHART_DIR)):
            LOG.info(f"Previous and target chart versions are the same: "
                     f"{previous_version_chart_path}. Skipping rollback.")
            return True

        success = False
        try:
            previous_version = helm_utils.get_chart_version(previous_version_chart_path)
            history = helm_utils.get_history(self.conf_dict['flux_helm_release_name'],
                                             self.conf_dict['fluxcd_namespace'],
                                             KUBECONFIG)

            # Rollback only if not already in the target version
            if self.is_target_version_installed(history, previous_version):
                LOG.info("Skipping Flux rollback since the target version is already installed")
                success = True
            else:
                if self.delete_oci_repository_crd():
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
