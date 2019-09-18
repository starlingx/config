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
        system_fields, system_name_for_index = self.get_system_info_overrides()
        overrides = {
            common.HELM_NS_MONITOR: {
                'config': self._get_config_overrides(system_fields),
                'systemNameForIndex': system_name_for_index,
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_config_overrides(self, system_fields):
        conf = {
            'processors': [{'add_kubernetes_metadata': {'in_cluster': True}}],
            'filebeat.inputs': [
                {
                    'enabled': True,
                    'fields': {
                        "hostname": "${NODE_NAME}",
                        "system": system_fields
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
