#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import elastic


class KubeStateMetricsHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for kube-state-metrics"""

    CHART = common.HELM_CHART_KUBESTATEMETRICS

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_MONITOR: {
                'resources': self._get_resources_overrides(),
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_resources_overrides(self):

        cpu_request = "50m"
        cpu_limit = "100m"
        memory_size = "256Mi"

        return {'requests': {
                    'cpu': cpu_request},
                'limits': {
                    'cpu': cpu_limit,
                    'memory': memory_size},
                }
