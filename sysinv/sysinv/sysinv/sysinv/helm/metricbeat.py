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
        system_fields = self.get_system_info_overrides()
        overrides = {
            common.HELM_NS_MONITOR: {
                'systemName': '',
                'resources': self._get_resources_overrides(),
                'metricbeatConfig': {
                    'metricbeat.yml': self._get_config_overrides(
                        system_fields,
                        self._get_daemonset_module_config()
                    ),
                    'kube-state-metrics-metricbeat.yml': self._get_config_overrides(
                        system_fields,
                        self._get_deployment_module_config()
                    ),
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

    def _get_config_overrides(self, system_fields, modules):
        conf = {
            'name': '${NODE_NAME}',
            'fields_under_root': True,
            'fields': {
                "system": system_fields
            },
            'metricbeat.modules': modules,
        }

        if self._is_distributed_cloud_role_subcloud():
            sc_conf = {
                 'setup.dashboards': {'enabled': False},
                 'output.elasticsearch': {
                     'hosts': [
                         "%s:%s%s" % (
                             self._system_controller_floating_address(),
                             self.NODE_PORT,
                             self.ELASTICSEARCH_CLIENT_PATH)
                     ]
                 }
            }
            conf.update(sc_conf)

        return conf

    def _get_daemonset_module_config(self):
        modules = [
            self._get_metric_kubernetes(),
        ] + self._get_metric_system()
        return modules

    def _get_deployment_module_config(self):
        modules = [
            self._get_metric_deployment_kubernetes(),
        ]
        return modules

    def _get_metric_system(self):
        conf = [
            {
                "module": "system",
                "enabled": True,
                "period": "60s",
                "metricsets": [
                    "cpu",
                    "diskio",
                    "memory",
                ],
                "cpu.metrics": [
                    "normalized_percentages"
                ]
            },
            {
                "module": "system",
                "enabled": True,
                "period": "60s",
                "metricsets": [
                    "process"
                ],
                "processes": [
                    ".*"],
                "process.include_top_n": {
                    "by_cpu": 15,
                    "by_memory": 15},
                "processors": [
                    {"drop_event.when": {
                        # drop containerized processes
                        "regexp": {
                            "system.process.cgroup.cpu.path":
                            "^/k8s.infra/.*"
                        }
                    }}
                ]
            },
            {
                "module": "system",
                "enabled": True,
                "period": "60s",
                "metricsets": [
                    "network"
                ],
                "processors": [
                    {"drop_event.when": {
                        "or": [
                            # drop container interfaces
                            {"regexp": {
                                "system.network.name":
                                "^(docker0|cali.*)$"
                            }},
                            # drop interfaces with no traffic
                            {"and": [
                                {"equals":
                                    {"system.network.in.packets": 0}
                                 },
                                {"equals":
                                    {"system.network.out.packets": 0}
                                 }]
                             }
                        ]}
                     }
                ]
            },
            {
                "module": "system",
                "enabled": True,
                "period": "5m",
                "metricsets": [
                    "filesystem",
                ],
                "processors": [
                    {"drop_event.when": {
                        "regexp": {
                            "system.filesystem.mount_point":
                            "^/(sys|cgroup|proc|dev|etc|host|lib)($|/)"
                        }
                    }}
                ],
            }
        ]
        return conf

    def _get_metric_kubernetes(self):
        conf = {
            "module": "kubernetes",
            "enabled": True,
            # If kube_config is not set, KUBECONFIG environment variable will be checked
            # and if not present it will fall back to InCluster
            "add_metadata": True,
            "labels.dedot": True,
            "annotations.dedot": True,
            "metricsets": [
                "node",
                "pod",
                "container"
            ],
            "period": "60s",
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
        return conf

    def _get_metric_deployment_kubernetes(self):
        conf = {
            "module": "kubernetes",
            "enabled": True,
            # If kube_config is not set, KUBECONFIG environment variable will be checked
            # and if not present it will fall back to InCluster
            "add_metadata": True,
            "labels.dedot": True,
            "annotations.dedot": True,
            "metricsets": [
                "state_node",
                "state_deployment",
                "state_replicaset",
                "state_pod",
                "state_container",
                "event",
                "state_statefulset"
            ],
            "period": "60s",
            "host": "${NODE_NAME}",
            "hosts": [
                "${KUBE_STATE_METRICS_HOSTS}"
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
