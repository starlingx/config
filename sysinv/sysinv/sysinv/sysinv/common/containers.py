#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# All Rights Reserved.
#

""" System Inventory containerd utilities and helper functions."""

import json
import time
from oslo_log import log as logging
from sysinv.common import exception
from sysinv.common import utils as cutils

LOG = logging.getLogger(__name__)

CONTAINERD_CONFIG_FULL_PATH = '/etc/containerd/config.toml'


def pull_image_to_crictl(image, crictl_auth, attempts=5, delay_on_retry=True):
    """Helper method to pull an image into crictl

    This method pulls the specified image into containerd cache.

    :param: image: image name
    :param: crictl_auth: auth credentials for containerd
    :param: attempts: Number of retries
    :param: delay_on_retry: delay between attempts in seconds

    :raises: SysinvException upon error
    """
    start = time.time()
    try:
        LOG.info("crictl pull image [%s] started." % (image))

        cmd = ["crictl", "pull", "--creds", crictl_auth, image]
        cutils.execute(*cmd, attempts=attempts,
                       delay_on_retry=delay_on_retry, check_exit_code=0)
    except exception.ProcessExecutionError as e:
        raise exception.SysinvException("crictl pull for image [%s] failed: "
                                        "Error: [%s]" % (image, e))

    elapsed_time = time.time() - start
    LOG.info("crictl pull image [%s] succeeded in %s seconds" % (image, elapsed_time))


def get_crictl_image_list():
    """Helper method to list all crictl images

    This method returns list of all images present in containerd cache

    :raises: SysinvException in case of an error.
    :returns: list of images in containerd cache.
    """
    crictl_image_list = []
    try:
        cmd = ['crictl', 'images', '--output=json']
        stdout, _ = cutils.execute(*cmd, check_exit_code=0)
        crictl_output = json.loads(stdout)
        for img in crictl_output['images']:
            crictl_image_list.extend(img['repoTags'])
    except json.JSONDecodeError as e:
        raise exception.SysinvException("Failed to parse json output of the command: [%s]. "
                                        "Error: [%s]" % (cmd, e))
    except exception.ProcessExecutionError as e:
        raise exception.SysinvException("Failed to run command: [%s]. Error: [%s]" % (cmd, e))
    return crictl_image_list
