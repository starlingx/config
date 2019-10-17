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

# Supported chart repositories
HELM_REPO_FOR_APPS = 'starlingx'
HELM_REPO_FOR_PLATFORM = 'stx-platform'

# Supported chart attributes:
HELM_CHART_ATTR_ENABLED = 'enabled'
HELM_CHART_ATTRS = [HELM_CHART_ATTR_ENABLED]

# Helm: Supported charts:
# These values match the names in the chart package's Chart.yaml
HELM_CHART_AODH = 'aodh'
HELM_CHART_BARBICAN = 'barbican'
HELM_CHART_CEILOMETER = 'ceilometer'
HELM_CHART_CINDER = 'cinder'
HELM_CHART_FM_REST_API = 'fm-rest-api'
HELM_CHART_GARBD = 'garbd'
HELM_CHART_GLANCE = 'glance'
HELM_CHART_GNOCCHI = 'gnocchi'
HELM_CHART_HEAT = 'heat'
HELM_CHART_HORIZON = 'horizon'
HELM_CHART_INGRESS = 'ingress'
HELM_CHART_IRONIC = 'ironic'
HELM_CHART_KEYSTONE = 'keystone'
HELM_CHART_LIBVIRT = 'libvirt'
HELM_CHART_MAGNUM = 'magnum'
HELM_CHART_MARIADB = 'mariadb'
HELM_CHART_MEMCACHED = 'memcached'
HELM_CHART_NEUTRON = 'neutron'
HELM_CHART_NOVA = 'nova'
HELM_CHART_NOVA_API_PROXY = 'nova-api-proxy'
HELM_CHART_OPENVSWITCH = 'openvswitch'
HELM_CHART_PANKO = 'panko'
HELM_CHART_PLACEMENT = 'placement'
HELM_CHART_RABBITMQ = 'rabbitmq'
HELM_CHART_RBD_PROVISIONER = 'rbd-provisioner'
HELM_CHART_CEPH_POOLS_AUDIT = 'ceph-pools-audit'
HELM_CHART_HELM_TOOLKIT = 'helm-toolkit'
HELM_CHART_KEYSTONE_API_PROXY = 'keystone-api-proxy'
HELM_CHART_SWIFT = 'ceph-rgw'
HELM_CHART_NGINX_PORTS_CONTROL = "nginx-ports-control"
HELM_CHART_DCDBSYNC = 'dcdbsync'

HELM_CHART_ELASTICSEARCH_MASTER = 'elasticsearch-master'
HELM_CHART_ELASTICSEARCH_DATA = 'elasticsearch-data'
HELM_CHART_ELASTICSEARCH_CLIENT = 'elasticsearch-client'
HELM_CHART_KIBANA = 'kibana'
HELM_CHART_FILEBEAT = 'filebeat'
HELM_CHART_METRICBEAT = 'metricbeat'
HELM_CHART_KUBESTATEMETRICS = 'kube-state-metrics'
HELM_CHART_NGINX_INGRESS = 'nginx-ingress'
HELM_CHART_LOGSTASH = 'logstash'

# Namespaces
HELM_NS_CEPH = 'ceph'
HELM_NS_DEFAULT = 'default'
HELM_NS_KUBE_SYSTEM = 'kube-system'
HELM_NS_NFS = 'nfs'
HELM_NS_OPENSTACK = 'openstack'
HELM_NS_HELM_TOOLKIT = 'helm-toolkit'
HELM_NS_MONITOR = 'monitor'

# Namespaces: for system functions
HELM_NS_STORAGE_PROVISIONER = HELM_NS_KUBE_SYSTEM

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
