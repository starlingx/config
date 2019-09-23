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
        system_fields, system_name_for_index = self.get_system_info_overrides()
        if utils.is_aio_simplex_system(self.dbapi):
            replicas = 1
        else:
            replicas = 2

        overrides = {
            common.HELM_NS_MONITOR: {
                'replicaCount': replicas,
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
