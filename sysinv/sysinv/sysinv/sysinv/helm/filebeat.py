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


class FilebeatHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for filebeat"""

    CHART = common.HELM_CHART_FILEBEAT

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_MONITOR: {
                'config': self._get_config_overrides(),
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_config_overrides(self):
        conf = {
            'processors': [{'add_kubernetes_metadata': {'in_cluster': True}}],

            'filebeat.inputs': [
                {
                    'enabled': True,
                    'fields': {
                        "hostname": "${NODE_NAME}",
                    },
                    'paths': [
                        "/var/log/*.log",
                        "/var/log/messages",
                        "/var/log/syslog",
                        "/var/log/**/*.log"
                    ],
                    'type': "log"
                }
            ]

        }

        return conf
