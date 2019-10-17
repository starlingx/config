#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import elastic


class NginxIngressHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for nginx-ingress"""

    CHART = common.HELM_CHART_NGINX_INGRESS

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_MONITOR: {
                "controller": {
                    "resources": self._get_controller_resources_overrides(),
                },
                "defaultBackend": {
                    "resources": self._get_backend_resources_overrides()}
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
    def _get_controller_resources_overrides():

        cpu_limits = "200m"
        memory_limits = "256Mi"

        return {'limits': {
                    'cpu': cpu_limits,
                    'memory': memory_limits},
                }

    @staticmethod
    def _get_backend_resources_overrides():

        cpu_limits = "100m"
        memory_limits = "128Mi"

        return {'limits': {
                    'cpu': cpu_limits,
                    'memory': memory_limits},
                }
