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

# Common Namespaces
HELM_NS_KUBE_SYSTEM = 'kube-system'
HELM_NS_NFS = 'nfs'
HELM_NS_OPENSTACK = 'openstack'
