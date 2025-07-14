#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

"""Kubernetes operations on a host """

from ruamel import yaml

from oslo_log import log as logging
from sysinv.common import constants
from sysinv.common import containers


LOG = logging.getLogger(__name__)


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

    def pull_images(self, images):
        """ Pull images to crictl

        :param: images: List of images to be downloaded.

        :returns: True if image download succeeds False otherwise
        """
        try:
            crictl_auth = self._get_auth()
            if not crictl_auth:
                return False
            crictl_images = containers.get_crictl_image_list()
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
