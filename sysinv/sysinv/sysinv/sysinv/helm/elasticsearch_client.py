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
            esJavaOpts = "-Djava.net.preferIPv6Addresses=true -Xmx256m -Xms256m"
            if utils.is_aio_simplex_system(self.dbapi):
                replicas = 1
        else:
            esJavaOpts = "-Djava.net.preferIPv6Addresses=true -Xmx512m -Xms512m"

        overrides = {
            common.HELM_NS_MONITOR: {
                'replicas': replicas,
                'esJavaOpts': esJavaOpts,
                'nodeSelector': {common.LABEL_MONITOR_CLIENT: "enabled"},
                'resources': {
                    'limits': {
                        'cpu': "1"
                    },
                    'requests': {
                        'cpu': "25m",
                        'memory': "512Mi",
                    },
                },
                'persistence': {'enabled': False}
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
