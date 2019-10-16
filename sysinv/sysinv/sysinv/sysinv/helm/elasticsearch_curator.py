#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import elastic


class ElasticsearchCuratorHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for elasticsearch curator"""

    CHART = common.HELM_CHART_ELASTICSEARCH_CURATOR

    def get_overrides(self, namespace=None):

        # Give 50% of elasticsearch data volume (DATA_VOLUME_SIZE_GB)
        # to filebeat, 40% to metricbeat and 10% to collectd, all
        # subtracting a safety margin due to cronjob running every 6 hours.
        filebeat_limit = str(int(0.5 * self.DATA_VOLUME_SIZE_GB) - 2)
        metricbeat_limit = str(int(0.4 * self.DATA_VOLUME_SIZE_GB) - 2)
        collectd_limit = str(int(0.1 * self.DATA_VOLUME_SIZE_GB) - 1)

        # Expose important overrides.
        overrides = {
            common.HELM_NS_MONITOR: {
                'env': {
                    'FILEBEAT_INDEX_LIMIT_GB': filebeat_limit,
                    'METRICBEAT_INDEX_LIMIT_GB': metricbeat_limit,
                    'COLLECTD_INDEX_LIMIT_GB': collectd_limit,
                },
                # Run job every 6 hours.
                'cronjob': {'schedule': "0 */6 * * *"},
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
