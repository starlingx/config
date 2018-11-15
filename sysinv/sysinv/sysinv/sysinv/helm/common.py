#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

""" System Inventory Helm common top level code."""


import os

from sysinv.openstack.common import log as logging
from tsconfig import tsconfig


LOG = logging.getLogger(__name__)

HELM_OVERRIDES_PATH = os.path.join(tsconfig.PLATFORM_PATH, 'helm', tsconfig.SW_VERSION)

# Namespaces
HELM_NS_CEPH = 'ceph'
HELM_NS_DEFAULT = 'default'
HELM_NS_KUBE_SYSTEM = 'kube-system'
HELM_NS_NFS = 'nfs'
HELM_NS_OPENSTACK = 'openstack'

# Services
# Matches configassistant.py value => Should change to STARLINGX
SERVICE_ADMIN = 'CGCS'

# Users
USER_ADMIN = 'admin'
USER_TEST = 'test'
USERS = [USER_ADMIN, USER_TEST]

# Passwords Formatting
PASSWORD_FORMAT_IDENTITY = 'keystone-auth'
PASSWORD_FORMAT_CEPH = 'ceph-auth'

# Node Labels
LABEL_CONTROLLER = 'openstack-control-plane'
LABEL_COMPUTE_LABEL = 'openstack-compute-node'
LABEL_OPENVSWITCH = 'openvswitch'

# Label values
LABEL_VALUE_ENABLED = 'enabled'
LABEL_VALUE_DISABLED = 'disabled'

# Image Tagging
DOCKER_SRC_OSH = 'openstackhelm'
DOCKER_SRC_STX = 'starlingx'
DOCKER_SRC_LOC = 'controller'

# TODO (rchurch): These values and settings are currently provided for early
# integration scenarios. As we formalize delivery mechanisms, these will need to
# be adjusted accordingly.
REGISTRY_OSH = 'docker.io'
REGISTRY_STX = '128.224.186.231:9001'
REGISTRY_LOC = '192.168.204.2:9001'

REPO_OSH = 'openstackhelm'
REPO_STX = 'abailey'
REPO_LOC = 'stx'

IMG_PREFIX_KEY = 'prefix'
IMG_BASE_KEY = 'base'
IMG_TAG_KEY = 'tag'

IMG_PREFIX_OSH = ''
IMG_PREFIX_STX = 'stx-'
IMG_PREFIX_LOC = 'stx-'

TAGS_PIKE = 'pike'
TAGS_LATEST = 'latest'

DOCKER_SRCS = {
    DOCKER_SRC_OSH: {
        IMG_BASE_KEY: '{}/{}'.format(REGISTRY_OSH, REPO_OSH),
        IMG_PREFIX_KEY: IMG_PREFIX_OSH,
        IMG_TAG_KEY: TAGS_PIKE

    },
    DOCKER_SRC_STX: {
        IMG_BASE_KEY: '{}/{}'.format(REGISTRY_STX, REPO_STX),
        IMG_PREFIX_KEY: IMG_PREFIX_STX,
        IMG_TAG_KEY: TAGS_LATEST
    },
    DOCKER_SRC_LOC: {
        IMG_BASE_KEY: '{}/{}'.format(REGISTRY_LOC, REPO_LOC),
        IMG_PREFIX_KEY: IMG_PREFIX_LOC,
        IMG_TAG_KEY: TAGS_LATEST
    }
}
