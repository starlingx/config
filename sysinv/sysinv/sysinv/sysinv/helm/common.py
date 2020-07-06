#
# Copyright (c) 2018-2020 Wind River Systems, Inc.
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
HELM_REPO_FOR_APPS = 'starlingx'
HELM_REPO_FOR_PLATFORM = 'stx-platform'

# Supported chart attributes:
HELM_CHART_ATTR_ENABLED = 'enabled'
HELM_CHART_ATTRS = [HELM_CHART_ATTR_ENABLED]

# TODO(rchurch): These are still needed for _check_monitor_labels(). This method
# should migrated to the monitor application with the application framework
# providing a hook to call for app specific label checking.
HELM_CHART_ELASTICSEARCH_MASTER = 'elasticsearch-master'
HELM_CHART_ELASTICSEARCH_DATA = 'elasticsearch-data'
HELM_CHART_ELASTICSEARCH_CLIENT = 'elasticsearch-client'
HELM_CHART_ELASTICSEARCH_CURATOR = 'elasticsearch-curator'
HELM_CHART_LOGSTASH = 'logstash'

# Namespaces
HELM_NS_CEPH = 'ceph'
HELM_NS_DEFAULT = 'default'
HELM_NS_KUBE_SYSTEM = 'kube-system'
HELM_NS_NFS = 'nfs'
HELM_NS_OPENSTACK = 'openstack'
HELM_NS_HELM_TOOLKIT = 'helm-toolkit'
HELM_NS_MONITOR = 'monitor'
HELM_NS_RBD_PROVISIONER = HELM_NS_KUBE_SYSTEM
HELM_NS_CERT_MANAGER = 'cert-manager'
HELM_NS_VAULT = 'vault'

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
LABEL_REMOTE_STORAGE = 'remote-storage'
LABEL_SRIOVDP = 'sriovdp'

LABEL_MONITOR_CONTROLLER = 'elastic-controller'
LABEL_MONITOR_MASTER = 'elastic-master'
LABEL_MONITOR_DATA = 'elastic-data'
LABEL_MONITOR_CLIENT = 'elastic-client'

# Label values
LABEL_VALUE_ENABLED = 'enabled'
LABEL_VALUE_DISABLED = 'disabled'
