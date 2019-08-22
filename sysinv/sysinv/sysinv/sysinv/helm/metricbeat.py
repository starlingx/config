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


class MetricbeatHelm(elastic.ElasticBaseHelm):
    """Class to encapsulate helm operations for metricbeat"""

    CHART = common.HELM_CHART_METRICBEAT

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_MONITOR: {
                'daemonset': {
                    'modules': {
                        'system': self._get_metric_system(),
                        'kubernetes': self._get_metric_kubernetes(),
                    },
                },
                'deployment': {
                    'modules': {
                        'kubernetes':
                            self._get_metric_deployment_kubernetes()
                    }
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
            "core",
            "diskio"]
        period = "60s"
        conf = [
            {"module": "system",
             "period": period,
             "metricsets": metricsets,
             "processes": [
                 ".*"
             ],
             "process.include_top_n": None,
             "by_cpu": 5,
             "by_memory": 5
             }
        ]
        return conf

    def _get_metric_kubernetes(self):
        metricsets = [
            "node", "system", "pod", "container", "volume"]
        period = "60s"
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
        period = "60s"
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
                        "stx-kube-state-metrics.monitor.svc.cluster.local:8080"
                    ]
                }
            ]
        }
        return conf
