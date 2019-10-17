#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.common import utils
from sysinv.helm import common
from sysinv.helm import elastic


class ElasticsearchMasterHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for elasticsearch master"""

    CHART = common.HELM_CHART_ELASTICSEARCH_MASTER

    def get_overrides(self, namespace=None):

        minimumMasterNodes = 1

        replicas = 3
        if utils.is_aio_system(self.dbapi):
            esJavaOpts = "-Djava.net.preferIPv6Addresses=true -Xmx256m -Xms256m"

            if self._count_hosts_by_label(common.LABEL_MONITOR_MASTER) < 3:
                # For AIO-SX, we will get here by definition, as there will
                # only be 1 master labelled host.
                # For AIO-DX without master labelled worker, we only
                # need 1 elasticsearch master pod, as the 2 data
                # pods will be master capable to form a cluster of 3 masters.
                replicas = 1
        else:
            esJavaOpts = "-Djava.net.preferIPv6Addresses=true -Xmx512m -Xms512m"

        overrides = {
            common.HELM_NS_MONITOR: {
                'nodeGroup': 'master',
                'replicas': replicas,
                'esJavaOpts': esJavaOpts,
                'minimumMasterNodes': minimumMasterNodes,
                'nodeSelector': {common.LABEL_MONITOR_MASTER: "enabled"},
                'resources': self._get_master_resource_overrides(),
                'volumeClaimTemplate': {
                    'accessModes': ["ReadWriteOnce"],
                    'resources': {
                        'requests': {'storage': '4Gi'}
                    },
                    'storageClass': 'general'
                },
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_master_resource_overrides(self):
        if utils.is_aio_system(self.dbapi):
            cpu_requests = "200m"
            memory_size = "256Mi"
        else:
            cpu_requests = "500m"
            memory_size = "512Mi"

        resources = {
            'requests': {
                'cpu': cpu_requests,
                'memory': memory_size
            },
            'limits': {
                'cpu': "1",
                'memory': "1024Mi"
            },
        }
        return resources
