#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import elastic


class KibanaHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for kibana"""

    CHART = common.HELM_CHART_KIBANA
    SERVICE_NAME = "kibana"
    SERVICE_PORT = 5601

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_MONITOR: {
                "service": {
                    "externalPort": self.SERVICE_PORT,
                    "internalPort": self.SERVICE_PORT,
                    "portName": self.SERVICE_NAME
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
