#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import base


class IngressHelm(base.BaseHelm):
    """Class to encapsulate helm operations for the ingress chart"""

    CHART = common.HELM_CHART_INGRESS

    SUPPORTED_NAMESPACES = base.BaseHelm.SUPPORTED_NAMESPACES + [
        common.HELM_NS_KUBE_SYSTEM,
        common.HELM_NS_OPENSTACK
    ]
    SUPPORTED_APP_NAMESPACES = {
        constants.HELM_APP_OPENSTACK:
            base.BaseHelm.SUPPORTED_NAMESPACES + [common.HELM_NS_KUBE_SYSTEM,
                                                  common.HELM_NS_OPENSTACK]
    }

    def get_overrides(self, namespace=None):
        limit_enabled, limit_cpus, limit_mem_mib = self._get_platform_res_limit()

        overrides = {
            common.HELM_NS_KUBE_SYSTEM: {
                'pod': {
                    'replicas': {
                        'error_page': self._num_controllers()
                    },
                    'resources': {
                        'enabled': limit_enabled,
                        'ingress': {
                            'limits': {
                                'cpu': "%d000m" % (limit_cpus),
                                'memory': "%dMi" % (limit_mem_mib)
                            }
                        },
                        'error_pages': {
                            'limits': {
                                'cpu': "%d000m" % (limit_cpus),
                                'memory': "%dMi" % (limit_mem_mib)
                            }
                        }
                    }
                },
                'deployment': {
                    'mode': 'cluster',
                    'type': 'DaemonSet'
                },
                'network': {
                    'host_namespace': 'true'
                },
            },
            common.HELM_NS_OPENSTACK: {
                'pod': {
                    'replicas': {
                        'ingress': self._num_controllers(),
                        'error_page': self._num_controllers()
                    },
                    'resources': {
                        'enabled': limit_enabled,
                        'ingress': {
                            'limits': {
                                'cpu': "%d000m" % (limit_cpus),
                                'memory': "%dMi" % (limit_mem_mib)
                            }
                        },
                        'error_pages': {
                            'limits': {
                                'cpu': "%d000m" % (limit_cpus),
                                'memory': "%dMi" % (limit_mem_mib)
                            }
                        }
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
