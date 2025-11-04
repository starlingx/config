#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

""" Helper utilities for downloading container images """

import docker
import requests
from concurrent.futures import as_completed
from concurrent.futures import ThreadPoolExecutor

from oslo_log import log

from sysinv.common import constants
from sysinv.common import containers as containers_util
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.common.retrying import retry
from sysinv.conductor import docker_registry
from sysinv.conductor.kube_app import DockerHelper

LOG = log.getLogger(__name__)


class ContainerImageDownloader(object):

    def __init__(self, dbapi):

        self._dbapi = dbapi
        self._docker = DockerHelper(self._dbapi)

    @retry(retry_on_result=lambda x: x is None,
           stop_max_attempt_number=5,
           wait_fixed=1000)
    def _pull_image_to_docker(self, image, registries_info, docker_client):
        """Pull an image from a registry based on the service parameters

        :param: image: tagged image to download
        :param: registries_info: registries information from service parameters
        :param: docker_client: docker client object

        :returns: None if the image pull failed or the image if it succeeded
        """
        target_image = None
        try:
            LOG.info("Image [%s] download started from upstream registry." % (image))
            target_image, registry_auth = (
                self._docker._get_img_tag_with_registry(image, registries_info)
            )
            docker_client.pull(target_image, auth_config=registry_auth)
            LOG.info("Image [%s] download from upstream public/private registry"
                     " to docker successful" % (image))
        except Exception:
            LOG.error("Failed to download image [%s] from upstream registry." % (image))
            return None
        return target_image

    def docker_registry_image_list(self, filter_out_untagged):
        """List images in the local container registry

        :param: filter_out_untagged: if True does not include untagged images.

        :returns: List of images in the local registry
        """

        try:
            image_list_response = docker_registry.docker_registry_get("_catalog")
        except requests.exceptions.SSLError:
            LOG.exception("Failed to get docker registry catalog")
            raise exception.DockerRegistrySSLException()
        except Exception:
            LOG.exception("Failed to get docker registry catalog")
            raise exception.DockerRegistryAPIException()

        if image_list_response.status_code != 200:
            LOG.error("Bad response from docker registry: %s"
                      % image_list_response.status_code)
            return []

        image_list_response = image_list_response.json()
        images = []
        # responses from the registry looks like this
        # {u'repositories': [u'meliodas/satesatesate', ...]}
        # we need to turn that into what we want to return:
        # [{'name': u'meliodas/satesatesate'}]
        if 'repositories' not in image_list_response:
            return images

        image_list_response = image_list_response['repositories']
        if filter_out_untagged:
            for image in image_list_response:
                image_tags_response = docker_registry.docker_registry_get(
                    "%s/tags/list" % image)
                tags_response = image_tags_response.json()
                tags = tags_response['tags']
                if tags:
                    images.append({'name': image})
        else:
            for image in image_list_response:
                images.append({'name': image})
        return images

    def _pull_image_from_upstream_tag_and_push_to_local_reg(
        self, docker_client, local_registry_auth, registries_info, image
    ):
        """Pull an image from upstream, tags and pushes it to local registry.

        :param: docker_client: docker's client object
        :param: local_registry_auth: authentication for the local registry
        :param: registries_info: registries information from service parameters
        :param: image: image to be pulled, tagged and pushed

        :returns: True if the operation was successful or False otherwise
        """
        local_image = None

        if not image.startswith(constants.DOCKER_REGISTRY_SERVER):
            try:
                # A retry error might be raised when reaching the max attempts
                target_image = self._pull_image_to_docker(image, registries_info, docker_client)
            except Exception as e:
                LOG.error(f"Image pull failed for [{image}] with error {e}")
                return False

            local_image = f"{constants.DOCKER_REGISTRY_SERVER}/{image}"
            try:
                LOG.info("Image tag and push started for [%s]" % (local_image))
                # After pulling the image, it needs to be sent to the system's local
                # registry, so it needs to be tagged to registry.local:9000
                docker_client.tag(target_image, local_image)
                docker_client.push(local_image, auth_config=local_registry_auth)
                # Test inspecting the image. This avoids a scenario where the push command
                # returns a false positive result during docker service restarts.
                docker_client.inspect_distribution(local_image, auth_config=local_registry_auth)
                LOG.info("Image tag and push successful for [%s]" % (local_image))
            except Exception as e:
                LOG.error("Image tag and push failed for [%s] with error [%s]"
                         % (local_image, e))
                return False

            try:
                LOG.info("Removing images [%s] and [%s] after push to local registry ... "
                         % (target_image, local_image))
                docker_client.remove_image(target_image)
                docker_client.remove_image(local_image)
                LOG.info("Removal of images [%s] and [%s] from docker successful."
                         % (target_image, local_image))
            except Exception as e:
                # We need not return False from here as our main purpose of tag
                # and push has been successful but only clean up is failed.
                LOG.warning("Removal of either [%s] or [%s] from docker failed"
                            " with error: [%s]. Use docker commands to manually "
                            "remove them and save disk space."
                            % (target_image, local_image, e))
        return True

    def _pull_image_to_crictl(self, image, crictl_auth):
        """Pull image into crictl

        Private method to pull an image into crictl

        :param: image: image name
        :param: crictl_auth: auth credentials for crictl

        :returns: True if successful else False
        """
        try:
            containers_util.pull_image_to_crictl(image, crictl_auth)
        except exception.SysinvException as e:
            LOG.error("Failed to download image [%s] to crictl with error: [%s]"
                      % (image, e))
            return False
        return True

    def download_images_from_upstream_to_local_reg_and_crictl(self, images):
        """Download images from upstream private/public registry to local
           registry and crictl

        This method retrieves required registry and crictl auth credentials
        and pulls all images to local registry and crictl concurrently.

        :param: images: list of images to be pulled.

        :returns: True if success False otherwise
        """

        # Verify which image needs to be downloaded to docker and crictl
        images = set(images)
        # Create a list of images with the registry server prefix
        images_with_prefix = {
            f"{constants.DOCKER_REGISTRY_SERVER}/{image}"
            for image in images
        }

        try:
            # The list method returns a list of dictionaries in the format
            # [{"name": "<image>"}, {"name": "<image>"}]
            docker_images = {
                image["name"]
                # The context parameter is unused in the method. It is just setup for
                # RPC calls
                for image in self.docker_registry_image_list(False)
            }
        except exception.DockerRegistryAPIException as e:
            LOG.warning(f"An error occurred when retrieving docker image list: {e}")
            docker_images = set()
        except Exception as e:
            LOG.error(f"An error occurred when retrieving docker image list: {e}")
            raise e

        try:
            crictl_images = set(containers_util.get_crictl_image_list())
        except exception.SysinvException as e:
            LOG.warning(f"An error occurred when retrieving crictl image list: {e}")
            crictl_images = set()
        except Exception as e:
            LOG.error(f"An error occurred when retrieving crictl image list: {e}")
            raise e

        docker_images_to_pull = images - docker_images
        crictl_images_to_pull = images_with_prefix - crictl_images

        # Check if there is any image to pull in either crictl or docker registry
        if not (docker_images_to_pull and crictl_images_to_pull):
            LOG.info("All images are already stored in local registry and crictl.")
            return True

        try:
            docker_client = docker.APIClient(
                timeout=constants.IMAGE_DOWNLOAD_TIMEOUT_IN_SECS
            )
            local_registry_auth = cutils.get_local_docker_registry_auth()
            crictl_auth = (
                f"{local_registry_auth['username']}:{local_registry_auth['password']}"
            )
            registries = self._docker.retrieve_specified_registries()
        except Exception as ex:
            # Handle an unexpected and unhandled exception
            LOG.exception(f"An unknown error occured when downloading images: [{ex}]")
            return False

        # Pull all necessary images to docker first
        docker_tasks = []
        with ThreadPoolExecutor() as executor:
            for image in docker_images_to_pull:
                docker_tasks.append(executor.submit(
                    self._pull_image_from_upstream_tag_and_push_to_local_reg,
                    docker_client, local_registry_auth, registries, image
                ))

        # No need to log the results again as we have already logged them inside the
        # worker method. Simply check for any failures.
        if not all([task.result() for task in as_completed(docker_tasks)]):
            return False

        # Pull all necessary images to crictl if docker pull was successfull
        crictl_tasks = []
        with ThreadPoolExecutor() as executor:
            for image in crictl_images_to_pull:
                crictl_tasks.append(executor.submit(
                    self._pull_image_to_crictl, image, crictl_auth
                ))

        # No need to log the results again as we have already logged them inside the
        # worker method. Simply check for any failures.
        return all([task.result() for task in as_completed(crictl_tasks)])
