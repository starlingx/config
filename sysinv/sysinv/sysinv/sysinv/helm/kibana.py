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
                },
                "resources": self._get_resources_overrides(),
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    @staticmethod
    def _get_resources_overrides():

        cpu_requests = "100m"
        memory_size = "256Mi"
        # cpu_limits = "500m"
        cpu_limits = "1"
        memory_limits = "512Mi"

        return {'requests': {
                    'cpu': cpu_requests,
                    'memory': memory_size},
                'limits': {
                    'cpu': cpu_limits,
                    'memory': memory_limits},
                }
