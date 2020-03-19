#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import elastic


class FilebeatHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for filebeat"""

    CHART = common.HELM_CHART_FILEBEAT

    def get_overrides(self, namespace=None):
        system_fields = self.get_system_info_overrides()
        overrides = {
            common.HELM_NS_MONITOR: {
                'config': self._get_config_overrides(system_fields),
                'resources': self._get_resources_overrides(),
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
            'name': '${NODE_NAME}',
            'processors': [{'add_kubernetes_metadata': {'in_cluster': True}}],
            'filebeat.inputs': [
                {
                    'enabled': True,
                    'fields_under_root': True,
                    'fields': {
                        "system": system_fields
                    },
                    'paths': [
                        "/var/log/*.log",
                        "/var/log/messages",
                        "/var/log/syslog",
                        "/var/log/**/*.log"
                    ],
                    'type': "log",
                    'close_timeout': "5m"
                }
            ]

        }
        if self._is_distributed_cloud_role_subcloud():
            sc_conf = {
                'setup.dashboards': {'enabled': False},
                'output.elasticsearch': {
                    'hosts': [
                        "%s:%s%s" % (
                            self._system_controller_floating_address(),
                            self.NODE_PORT,
                            self.ELASTICSEARCH_CLIENT_PATH),
                    ]
                }
            }
            conf.update(sc_conf)

        return conf

    @staticmethod
    def _get_resources_overrides():
        cpu_request = "40m"
        cpu_limit = "80m"
        memory_size = "256Mi"

        return {'requests': {
                    'cpu': cpu_request},
                'limits': {
                    'cpu': cpu_limit,
                    'memory': memory_size},
                }
