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

CONTAINERD_CONFIG_FULL_PATH = "/etc/containerd/config.toml"
IO_CRI_CONTAINERD_PINNED_LABEL_KEY = "io.cri-containerd.pinned"
IO_CRI_CONTAINERD_PINNED_LABEL_VALUE = "pinned"
IO_CRI_CONTAINERD_UNPINNED_LABEL_VALUE = "unpinned"
NAMESPACE_K8S_IO = "k8s.io"


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
        LOG.info("crictl image pull [%s] started." % (image))

        cmd = ["crictl", "pull", "--creds", crictl_auth, image]
        cutils.execute(*cmd, attempts=attempts,
                       delay_on_retry=delay_on_retry, check_exit_code=0)
    except exception.ProcessExecutionError as e:
        raise exception.SysinvException("crictl pull for image [%s] failed: "
                                        "Error: [%s]" % (image, e))

    elapsed_time = time.time() - start
    LOG.info("crictl image pull [%s] succeeded in %s seconds" % (image, elapsed_time))


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


def label_ctr_image(image, label_key, label_value, namespace=NAMESPACE_K8S_IO):
    """Assign a lable to an image

    Assigns a lable to an image using ctr

    :param: image: str. Full image name with tag (name:tag).
    :param: label_key: str. key of the label
    :param: label_value: str. value of the label
    :namespace: namespace name. This will almost always be the default value "k8s.io"

    :raises: SysinvException in case of an error.
    """
    if not isinstance(image, str):
        raise exception.SysinvException("Invalid name for the image to assign a label: %s"
                                        % (image))

    try:
        if not label_key or not label_value:
            LOG.warning("Image %s label may be invalid: %s=%s." % (image, label_key, label_value))

        cmd = ['ctr', '-n', namespace, 'images', 'label', image, "%s=%s" % (label_key, label_value)]

        cutils.execute(*cmd, check_exit_code=0)

    except Exception as ex:
        raise exception.SysinvException("Failed to assign label [%s=%s] to image: [%s] in "
                                        "namespace: [%s]. Error: [%s]"
                                        % (label_key, label_value, image, namespace, ex))


def pin_ctr_image(image, namespace=NAMESPACE_K8S_IO):
    """Pin the image

    :param: image: str. Full image name with tag (name:tag) to be pinned.
    :namespace: namespace name. This will almost always be the default value "k8s.io"

    :raises: SysinvException in case of an error.
    """
    if not isinstance(image, str):
        raise exception.SysinvException("Invalid name for the image to be pinned: %s" % (image))

    try:
        label_ctr_image(image, IO_CRI_CONTAINERD_PINNED_LABEL_KEY,
                        IO_CRI_CONTAINERD_PINNED_LABEL_VALUE, namespace)
        LOG.info("Pinned image %s" % (image))
    except Exception as ex:
        raise exception.SysinvException("Failed to pin the image [%s]: Error: [%s]" % (image, ex))


def unpin_ctr_image(image, namespace=NAMESPACE_K8S_IO):
    """Unpin the image

    :param: image: str. Full image name with tag (name:tag) to be unpinned.
    :namespace: namespace name. This will almost always be the default value "k8s.io"

    :raises: SysinvException in case of an error.
    """
    if not isinstance(image, str):
        raise exception.SysinvException("Invalid name for the image to be unpinned: %s" % (image))

    try:
        label_ctr_image(image, IO_CRI_CONTAINERD_PINNED_LABEL_KEY,
                        IO_CRI_CONTAINERD_UNPINNED_LABEL_VALUE, namespace)
        LOG.info("Unpinned image %s" % (image))
    except Exception as ex:
        raise exception.SysinvException("Failed to unpin the image [%s]. Manually unpin it so that "
                                        "it can be removed by the kubelet garbage collector. "
                                        "Error was: [%s]" % (image, ex))
