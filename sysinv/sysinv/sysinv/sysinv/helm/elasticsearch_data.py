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

        # Note memory values are to be system engineered.

        combined_data_and_master = False
        replicas = 2
        if utils.is_aio_system(self.dbapi):
            esJavaOpts = "-Djava.net.preferIPv6Addresses=true -Xmx512m -Xms512m"
            memory_size = "512Mi"

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
        else:
            esJavaOpts = "-Djava.net.preferIPv6Addresses=true -Xmx1536m -Xms1536m"
            memory_size = "1536Mi"

        overrides = {
            common.HELM_NS_MONITOR: {
                'nodeGroup': 'data',
                'replicas': replicas,
                'esJavaOpts': esJavaOpts,
                'resources': {
                    'limits': {
                        'cpu': "1"
                    },
                    'requests': {
                        'cpu': "25m",
                        'memory': memory_size,
                    },
                },
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
