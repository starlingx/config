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
                'filebeatConfig': {
                    'filebeat.yml': self._get_config_overrides(system_fields),
                },
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
            'processors': [
                {
                    'add_kubernetes_metadata': {
                        'labels.dedot': True,
                        'annotations.dedot': True
                        # If kube_config is not set, KUBECONFIG environment variable will be checked
                        # and if not present it will fall back to InCluster
                    }
                }
            ],
            'fields_under_root': True,
            'fields': {
                "system": system_fields
            },
            'filebeat.inputs': [
                {
                    'enabled': True,
                    'paths': [
                        "/var/log/*.log",
                        "/var/log/messages",
                        "/var/log/syslog",
                        "/var/log/**/*.log"
                    ],
                    'type': "log",
                    'exclude_files': [
                        "^/var/log/containers/",
                        "^/var/log/pods/"
                    ],
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
        cpu_request = "50m"
        cpu_limit = "180m"
        memory_size = "512Mi"

        return {'requests': {
                    'cpu': cpu_request},
                'limits': {
                    'cpu': cpu_limit,
                    'memory': memory_size},
                }
