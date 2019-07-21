#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception

from sysinv.helm import common
from sysinv.helm import openstack


class MagnumHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the magnum chart"""

    CHART = common.HELM_CHART_MAGNUM

    SERVICE_NAME = common.HELM_CHART_MAGNUM

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'pod': {
                    'replicas': {
                        'api': self._num_controllers(),
                        'conductor': self._num_controllers()
                    }
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
