#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common import log as logging
from sysinv.helm import common
from sysinv.helm import openstack

LOG = logging.getLogger(__name__)


class NovaApiProxyHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the nova chart"""

    CHART = constants.HELM_CHART_NOVA_API_PROXY

    SERVICE_NAME = 'nova-api-proxy'
    AUTH_USERS = ['nova']

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
                'images': self._get_images_overrides(),
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

    def _get_images_overrides(self):
        heat_image = self._operator.chart_operators[
            constants.HELM_CHART_HEAT].docker_image

        return {
            'tags': {
                'nova_api_proxy': self.docker_image,
                'ks_endpoints': heat_image
            }
        }

    def _get_endpoints_overrides(self):
        nova_service_name = self._operator.chart_operators[
            constants.HELM_CHART_NOVA].SERVICE_NAME

        return {
            'identity': {
                'auth': self._get_endpoints_identity_overrides(
                    nova_service_name, self.AUTH_USERS),
            },
            'compute': {
                'host_fqdn_override':
                    self._get_endpoints_host_fqdn_overrides(
                        constants.HELM_CHART_NOVA),
            },
        }
