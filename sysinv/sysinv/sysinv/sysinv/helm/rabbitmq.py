#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import openstack


class RabbitmqHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the rabbitmq chart"""

    CHART = common.HELM_CHART_RABBITMQ

    def get_overrides(self, namespace=None):
        limit_enabled, limit_cpus, limit_mem_mib = self._get_platform_res_limit()

        # Refer to: https://github.com/rabbitmq/rabbitmq-common/commit/4f9ef33cf9ba52197ff210ffcdf6629c1b7a6e9e
        io_thread_pool_size = limit_cpus * 16
        if io_thread_pool_size < 64:
            io_thread_pool_size = 64
        elif io_thread_pool_size > 1024:
            io_thread_pool_size = 1024

        overrides = {
            common.HELM_NS_OPENSTACK: {
                'pod': {
                    'replicas': {
                        'server': self._num_controllers()
                    },
                    'resources': {
                        'enabled': limit_enabled,
                        'prometheus_rabbitmq_exporter': {
                            'limits': {
                                'cpu': "%d000m" % (limit_cpus),
                                'memory': "%dMi" % (limit_mem_mib)
                            }
                        },
                        'server': {
                            'limits': {
                                'cpu': "%d000m" % (limit_cpus),
                                'memory': "%dMi" % (limit_mem_mib)
                            }
                        }
                    }
                },
                'io_thread_pool': {
                    'enabled': limit_enabled,
                    'size': "%d" % (io_thread_pool_size)
                },
                'endpoints': self._get_endpoints_overrides(),
                'manifests': {
                    'config_ipv6': self._is_ipv6_cluster_service()
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

    def _get_endpoints_overrides(self):
        credentials = self._get_endpoints_oslo_messaging_overrides(
            self.CHART, [])
        overrides = {
            'oslo_messaging': {
                'auth': {
                    'user': credentials['admin']
                }
            },
        }
        return overrides
