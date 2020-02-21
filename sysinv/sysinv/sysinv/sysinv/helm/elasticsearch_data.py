#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.common import utils
from sysinv.helm import common
from sysinv.helm import elastic


class ElasticsearchDataHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for elasticsearch data"""

    CHART = common.HELM_CHART_ELASTICSEARCH_DATA

    def get_overrides(self, namespace=None):

        combined_data_and_master = False
        replicas = 2
        if utils.is_aio_system(self.dbapi):
            if (utils.is_aio_duplex_system(self.dbapi) and
                    self._count_hosts_by_label(
                        common.LABEL_MONITOR_MASTER) < 3):
                # For AIO-DX without master labelled worker nodes,
                # configure elasticsearch data pods as master capable,
                # so they will form a cluster of 3 masters with the single
                # elasticsearch master pod.
                combined_data_and_master = True

            if utils.is_aio_simplex_system(self.dbapi):
                replicas = 1

        if self._is_ipv6_cluster_service():
            ipv6JavaOpts = "-Djava.net.preferIPv6Addresses=true "
        else:
            ipv6JavaOpts = ""

        if (utils.is_aio_system(self.dbapi) and not
                self._is_distributed_cloud_role_system_controller()):
            esJavaOpts = \
                ipv6JavaOpts + "-Xmx1536m -Xms1536m"
        else:
            esJavaOpts = \
                ipv6JavaOpts + "-Xmx4096m -Xms4096m"

        overrides = {
            common.HELM_NS_MONITOR: {
                'nodeGroup': 'data',
                'replicas': replicas,
                'esJavaOpts': esJavaOpts,
                'resources': self._get_data_resources_overrides(),
                'volumeClaimTemplate': {
                    'accessModes': ["ReadWriteOnce"],
                    'resources': {
                        'requests': {'storage': str(self.DATA_VOLUME_SIZE_GB) + 'Gi'}
                    },
                    'storageClass': 'general'
                },
                'nodeSelector': {common.LABEL_MONITOR_DATA: "enabled"},
                'antiAffinity': "hard",
            }
        }

        if combined_data_and_master:
            overrides[common.HELM_NS_MONITOR]['roles'] = {'master': 'true'}
            overrides[common.HELM_NS_MONITOR]['minimumMasterNodes'] = 1

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_data_resources_overrides(self):
        # Default values based upon AIO+4 and Standard+20 system test

        if (utils.is_aio_system(self.dbapi) and not
                self._is_distributed_cloud_role_system_controller()):
            cpu_requests = "200m"
            cpu_limits = "1"
            memory_size = "4096Mi"
        else:
            cpu_requests = "500m"
            cpu_limits = "2"
            memory_size = "6144Mi"

        resources = {
            'requests': {
                'cpu': cpu_requests,
                'memory': memory_size},
            'limits': {
                'cpu': cpu_limits,
                'memory': memory_size}
        }
        return resources
