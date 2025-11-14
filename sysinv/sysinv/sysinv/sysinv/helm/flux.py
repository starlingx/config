#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import subprocess
import yaml

from oslo_log import log as logging

from sysinv.common import utils
from sysinv.common.image_download import ContainerImageDownloader

KUBECONFIG = "/etc/kubernetes/admin.conf"
CONFIG_DIR = "/usr/share/ansible/stx-ansible/playbooks/roles/common/fluxcd-controllers/"
CONF_FILE = os.path.join(CONFIG_DIR, 'vars', 'main.yml')
TEMPLATE_PATH = os.path.join(CONFIG_DIR, 'templates')
TEMPLATE_FILENAME = 'values.yaml.j2'

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

    def rollback_controllers(self):
        """ Rollback Flux controllers to the previous version """

        raise NotImplementedError
