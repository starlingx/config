#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception

from sysinv.helm import common
from sysinv.helm import openstack


class IronicHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the ironic chart"""

    CHART = constants.HELM_CHART_IRONIC

    SERVICE_NAME = constants.HELM_CHART_IRONIC

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
