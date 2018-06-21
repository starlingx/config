#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common import log as logging
from . import common
from . import openstack

LOG = logging.getLogger(__name__)


class NfsProvisionerHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the nfs-provisioner chart"""

    CHART = constants.HELM_CHART_NFS_PROVISIONER
    SUPPORTED_NAMESPACES = [
        common.HELM_NS_NFS
    ]

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_NFS: {
                'storageclass': {
                    'name': 'general'
                }
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
