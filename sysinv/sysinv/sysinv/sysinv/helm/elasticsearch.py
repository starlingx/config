#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.common import utils
from sysinv.helm import common
from sysinv.helm import elastic


class ElasticsearchHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for elasticsearch"""

    CHART = common.HELM_CHART_ELASTICSEARCH

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_MONITOR: {
                'cluster': self._get_cluster_overrides(),
                'master': self._get_master_overrides(),
                'data': self._get_data_overrides(),
                'client': self._get_client_overrides(),
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_cluster_overrides(self):

        env_vars = {'MINIMUM_MASTER_NODES': "1",
                    'EXPECTED_MASTER_NODES': "1",
                    'RECOVER_AFTER_MASTER_NODES': "1"}

        conf = {
            'env': env_vars,
        }
        return conf

    def _get_master_overrides(self):
        if utils.is_aio_system(self.dbapi):
            heap_size = "256m"
            replicas = 1
        else:
            heap_size = "512m"
            replicas = 3

        conf = {
            'replicas': replicas,
            'heapSize': heap_size,
            'nodeSelector': {common.LABEL_MONITOR_MASTER: "enabled"},
            'antiAffinity': "hard",
        }
        return conf

    def _get_data_overrides(self):
        # Note memory values are to be system engineered.

        combined_data_and_master = False
        replicas = 2
        if utils.is_aio_system(self.dbapi):
            heap_size = "512m"
            memory_size = "512Mi"
            if utils.is_aio_duplex_system(self.dbapi):
                combined_data_and_master = True
            else:
                # AIO simplex, 1 replica
                replicas = 1
        else:
            heap_size = "1536m"
            memory_size = "1536Mi"

        conf = {
            'replicas': replicas,
            'heapSize': heap_size,
            'resources': {
                'limits': {
                    'cpu': "1"
                },
                'requests': {
                    'cpu': "25m",
                    'memory': memory_size,
                }, },
            'persistence': {'storageClass': 'general',
                            'size': "100Gi"},
            'nodeSelector': {common.LABEL_MONITOR_DATA: "enabled"},
            'antiAffinity': "hard",
            'combinedDataAndMaster': combined_data_and_master,
        }
        return conf

    def _get_client_overrides(self):
        replicas = 2
        if utils.is_aio_system(self.dbapi):
            heap_size = "256m"
            if utils.is_aio_simplex_system(self.dbapi):
                replicas = 1
        else:
            heap_size = "512m"

        conf = {
            'replicas': replicas,
            'heapSize': heap_size,
            'nodeSelector': {common.LABEL_MONITOR_CLIENT: "enabled"},
            'antiAffinity': "hard",
        }
        return conf
