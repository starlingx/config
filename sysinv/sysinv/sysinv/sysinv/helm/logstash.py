#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging
from sysinv.common import exception
from sysinv.common import utils
from sysinv.helm import common
from sysinv.helm import elastic

LOG = logging.getLogger(__name__)


class LogstashHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for logstash"""

    CHART = common.HELM_CHART_LOGSTASH

    def get_overrides(self, namespace=None):
        if utils.is_aio_simplex_system(self.dbapi):
            replicas = 1
        else:
            replicas = 2

        overrides = {
            common.HELM_NS_MONITOR: {
                'replicas': replicas,
                'resources': self._get_resources_overrides(),
            }
        }

        if self._is_distributed_cloud_role_subcloud():
            subcloud_settings = {
                'elasticsearchHosts': "http://%s:%s%s" % (
                    self._system_controller_floating_address(),
                    self.NODE_PORT,
                    self.ELASTICSEARCH_CLIENT_PATH
                ),
                'ingress': {'enabled': False},
            }
            overrides[common.HELM_NS_MONITOR].update(subcloud_settings)

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_resources_overrides(self):
        if (utils.is_aio_system(self.dbapi) and not
                self._is_distributed_cloud_role_system_controller()):
            cpu_limits = "500m"
            memory_limits = "1024Mi"
        else:
            cpu_limits = "500m"
            memory_limits = "2048Mi"

        return {'requests': {
                    'memory': memory_limits},
                'limits': {
                    'cpu': cpu_limits,
                    'memory': memory_limits},
                }
