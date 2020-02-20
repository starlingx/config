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
                }
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

    def _get_metric_system(self):
        conf = {
            "enabled": True,
            "config": self._get_metric_module_config()
        }
        return conf

    def _get_metric_module_config(self):
        conf = [
            {
                "module": "system",
                "period": "60s",
                "metricsets": [
                    "cpu",
                    "diskio",
                    "load",
                    "memory",
                    "process_summary",
                ],
                "cpu.metrics": [
                    "percentages",
                    "normalized_percentages"
                ]
            },
            {
                "module": "system",
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
                "period": "5m",
                "metricsets": [
                    "filesystem",
                    "fsstat",
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
            "enabled": True,
            "config": [
                {
                    "module": "kubernetes",
                    "in_cluster": True,
                    "add_metadata": True,
                    "metricsets": [
                        "node",
                        "system",
                        "pod",
                        "container"
                    ],
                    "period": "10s",
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
        conf = {
            "enabled": True,
            "config": [
                {
                    "module": "kubernetes",
                    "in_cluster": True,
                    "add_metadata": True,
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
