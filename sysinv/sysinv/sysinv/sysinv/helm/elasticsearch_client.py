#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.common import utils
from sysinv.helm import common
from sysinv.helm import elastic


class ElasticsearchClientHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for elasticsearch client"""

    CHART = common.HELM_CHART_ELASTICSEARCH_CLIENT

    def get_overrides(self, namespace=None):
        replicas = 2
        if utils.is_aio_system(self.dbapi):
            if utils.is_aio_simplex_system(self.dbapi):
                replicas = 1

        if (utils.is_aio_system(self.dbapi) and not
                self._is_distributed_cloud_role_system_controller()):
            esJavaOpts = \
                "-Djava.net.preferIPv6Addresses=true -Xmx512m -Xms512m"
        else:
            esJavaOpts = \
                "-Djava.net.preferIPv6Addresses=true -Xmx1024m -Xms1024m"

        overrides = {
            common.HELM_NS_MONITOR: {
                'replicas': replicas,
                'esJavaOpts': esJavaOpts,
                'nodeSelector': {common.LABEL_MONITOR_CLIENT: "enabled"},
                'resources': self._get_client_resources_overrides(),
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_client_resources_overrides(self):
        if (utils.is_aio_system(self.dbapi) and not
                self._is_distributed_cloud_role_system_controller()):
            cpu_requests = "50m"
            cpu_limits = "1"  # high watermark
            memory_size = "1024Mi"
        else:
            cpu_requests = "100m"
            cpu_limits = "1"  # high watermark
            memory_size = "2048Mi"

        resources = {
            'requests': {
                'cpu': cpu_requests,
                'memory': memory_size
            },
            'limits': {
                'cpu': cpu_limits,
                'memory': memory_size
            }
        }
        return resources
