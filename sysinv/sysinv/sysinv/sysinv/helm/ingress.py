#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common import log as logging
from . import common
from . import openstack

LOG = logging.getLogger(__name__)


class IngressHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the ingress chart"""

    CHART = constants.HELM_CHART_INGRESS
    SUPPORTED_NAMESPACES = [
        common.HELM_NS_KUBE_SYSTEM,
        common.HELM_NS_OPENSTACK
    ]

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def get_overrides(self, namespace=None):
        # Currently have conflicts with ports 80 and 8080, use 8081 for now
        overrides = {
            common.HELM_NS_KUBE_SYSTEM: {
                'deployment': {
                    'mode': 'cluster',
                    'type': 'DaemonSet'
                },
                'network': {
                    'host_namespace': 'true'
                },
                'endpoints': {
                    'ingress': {
                        'port': {
                            'http': {
                                'default': 8081
                            }
                        }
                    }
                }
            },
            common.HELM_NS_OPENSTACK: {
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
