#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging
from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import elastic

LOG = logging.getLogger(__name__)


class LogstashHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for logstash"""

    CHART = common.HELM_CHART_LOGSTASH

    def get_overrides(self, namespace=None):
        system_fields, system_name_for_index = self.get_system_info_overrides()
        overrides = {
            common.HELM_NS_MONITOR: {
                'replicaCount': self._count_hosts_by_label(
                    common.LABEL_MONITOR_CONTROLLER),
                'persistence': {
                    'storageClass': 'general',
                    'size': "20Gi"},
                'config': {
                    'elasticsearch.path': ""},
                'systemNameForIndex': system_name_for_index
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
