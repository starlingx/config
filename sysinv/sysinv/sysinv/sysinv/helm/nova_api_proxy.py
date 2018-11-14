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


class NovaApiProxyHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the nova chart"""

    CHART = constants.HELM_CHART_NOVA_API_PROXY
    SUPPORTED_NAMESPACES = [
        common.HELM_NS_OPENSTACK
    ]

    SERVICE_NAME = 'nova'
    AUTH_USERS = ['nova']

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def get_overrides(self, namespace=None):

        overrides = {
            common.HELM_NS_OPENSTACK: {
                'pod': {
                    'user': {
                        'nova_api_proxy': {
                            'uid': 0
                        }
                    }
                },
                'conf': {
                    'nova_api_proxy': {
                        'DEFAULT': {
                            'nfvi_compute_listen': self._get_management_address()
                        },
                    }
                },
                'endpoints': self._get_endpoints_overrides(),
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
        return {
            'identity': {
                'auth': self._get_endpoints_identity_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS),
            }
        }
