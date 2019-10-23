#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import elastic


class MetricbeatHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for metricbeat"""

    CHART = common.HELM_CHART_METRICBEAT

    def get_overrides(self, namespace=None):
        system_fields, system_name_for_index = self.get_system_info_overrides()
        overrides = {
            common.HELM_NS_MONITOR: {
                'systemName': '',
                'resources': self._get_resources_overrides(),
                'daemonset': {
                    'modules': {
                        'system': self._get_metric_system(),
                        'kubernetes': self._get_metric_kubernetes(),
                    },
                    'config': self._get_config_overrides(system_fields),
                },
                'deployment': {
                    'modules': {
                        'kubernetes':
                            self._get_metric_deployment_kubernetes()
                    },
                    'config': self._get_config_overrides(system_fields),
                },
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
            'name': '${NODE_NAME}',
            'fields_under_root': True,
            'fields': {
                "system": system_fields
            }
        }
        return conf

    def _get_metric_system(self):
        conf = {
            "enabled": True,
            "config": self._get_metric_module_config()
        }
        return conf

    def _get_metric_module_config(self):
        metricsets = [
            "cpu",
            "load",
            "memory",
            "network",
            "process",
            "process_summary",
            "diskio",
        ]
        period = "15s"

        metricsets_filesystem = [
            "filesystem",
            "fsstat",
        ]
        period_fs = "60s"
        conf = [
            {"module": "system",
             "period": period,
             "metricsets": metricsets,
             "processes": [
                 ".*"],
             "process.include_top_n": {
                 "by_cpu": 15,
                 "by_memory": 15},
             },

            {"module": "system",
             "period": period_fs,
             "metricsets": metricsets_filesystem,
             "processes": [
                 ".*"],
             "processors": [
                 {
                     "drop_event.when.regexp": {
                         "system.filesystem.mount_point":
                             "^/(sys|cgroup|proc|dev|etc|host|lib)($|/)"
                     }
                 }],
             },
        ]
        return conf

    def _get_metric_kubernetes(self):
        metricsets = [
            "node", "system", "pod", "container", "volume"]
        period = "15s"
        conf = {
            "enabled": True,
            "config": [
                {
                    "module": "kubernetes",
                    "in_cluster": True,
                    "add_metadata": True,
                    "metricsets": metricsets,
                    "period": period,
                    "host": "${NODE_NAME}",
                    "hosts": [
                        "https://${HOSTNAME}:10250"
                    ],
                    "bearer_token_file":
                        "/var/run/secrets/kubernetes.io/serviceaccount/token",
                    "ssl.verification_mode": "none",
                    "ssl.certificate_authorities": [
                        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
                    ]
                }
            ]
        }
        return conf

    def _get_metric_deployment_kubernetes(self):
        metricsets_k8s = [
            "state_node",
            "state_deployment",
            "state_replicaset",
            "state_pod",
            "state_container",
            "event"
        ]
        period = "15s"
        conf = {
            "enabled": True,
            "config": [
                {
                    "module": "kubernetes",
                    "in_cluster": True,
                    "add_metadata": True,
                    "metricsets": metricsets_k8s,
                    "period": period,
                    "host": "${NODE_NAME}",
                    "hosts": [
                        "${KUBE_STATE_METRICS_HOST}:8080"
                    ]
                }
            ]
        }
        return conf

    @staticmethod
    def _get_resources_overrides():

        cpu_request = "50m"
        cpu_limit = "180m"   # overload at 150m
        memory_limit = "512Mi"

        return {'requests': {
                    'cpu': cpu_request},
                'limits': {
                    'cpu': cpu_limit,
                    'memory': memory_limit},
                }
