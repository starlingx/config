#
# Copyright (c) 2018-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

""" System Inventory Helm common top level code."""


import os

from oslo_log import log as logging
from tsconfig import tsconfig


LOG = logging.getLogger(__name__)

HELM_OVERRIDES_PATH = os.path.join(tsconfig.PLATFORM_PATH, 'helm', tsconfig.SW_VERSION)

# Supported chart repositories
HELM_REPO_BASE_PATH = '/var/www/pages/helm_charts'
HELM_REPO_FOR_APPS = 'starlingx'
HELM_REPO_FOR_PLATFORM = 'stx-platform'

# Supported chart attributes:
HELM_CHART_ATTR_ENABLED = 'enabled'
HELM_CHART_ATTRS = [HELM_CHART_ATTR_ENABLED]

# Namespaces
HELM_NS_CEPH = 'ceph'
HELM_NS_DEFAULT = 'default'
HELM_NS_KUBE_SYSTEM = 'kube-system'
HELM_NS_NFS = 'nfs'
HELM_NS_OPENSTACK = 'openstack'
HELM_NS_HELM_TOOLKIT = 'helm-toolkit'
HELM_NS_MONITOR = 'monitor'
HELM_NS_RBD_PROVISIONER = HELM_NS_KUBE_SYSTEM
HELM_NS_STORAGE_PROVISIONER = HELM_NS_KUBE_SYSTEM
HELM_NS_CERT_MANAGER = 'cert-manager'
HELM_NS_VAULT = 'vault'
HELM_NS_NOTIFICATION = 'notification'
HELM_NS_DEPLOYMENT = 'deployment'
HELM_NS_FLUX_HELM = 'flux-helm'

# namespace groups for pod security admission controller
PRIVILEGED_NS = [HELM_NS_CEPH, HELM_NS_NFS, HELM_NS_OPENSTACK, HELM_NS_HELM_TOOLKIT,
               HELM_NS_MONITOR, HELM_NS_RBD_PROVISIONER, HELM_NS_STORAGE_PROVISIONER,
               HELM_NS_CERT_MANAGER, HELM_NS_VAULT, HELM_NS_DEPLOYMENT,
               HELM_NS_KUBE_SYSTEM, HELM_NS_NOTIFICATION, HELM_NS_FLUX_HELM]
POD_SECURITY_VERSION = 'latest'

# Services
# Matches configassistant.py value => Should change to STARLINGX
SERVICE_ADMIN = 'CGCS'

# Users
USER_ADMIN = 'admin'
USER_TEST = 'test'
USER_STX_ADMIN = 'stx_admin'
USERS = [USER_ADMIN, USER_TEST, USER_STX_ADMIN]

# Passwords Formatting
PASSWORD_FORMAT_IDENTITY = 'keystone-auth'
PASSWORD_FORMAT_CEPH = 'ceph-auth'

# Node Labels
LABEL_CONTROLLER = 'openstack-control-plane'
LABEL_COMPUTE_LABEL = 'openstack-compute-node'
LABEL_DISABLE_NOHZ_FULL = 'disable-nohz-full'
LABEL_OPENVSWITCH = 'openvswitch'
LABEL_REMOTE_STORAGE = 'remote-storage'
LABEL_SRIOVDP = 'sriovdp'
LABEL_SRIOVDP_VHOSTNET = 'sriovdp-vhostnet'

# Label values
LABEL_VALUE_ENABLED = 'enabled'
LABEL_VALUE_DISABLED = 'disabled'

# Namespace Labels
COMPONENT_LABEL_KEY = 'app.starlingx.io/component'

# Namespace Label values
COMPONENT_LABEL_VALUE_PLATFORM = 'platform'
