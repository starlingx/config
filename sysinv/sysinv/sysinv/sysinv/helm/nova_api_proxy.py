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

    @property
    def docker_repo_source(self):
        return common.DOCKER_SRC_LOC

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
        nova_api_proxy_image = "{}:{}/{}/{}{}:{}".format(
            self._get_management_address(), common.REGISTRY_PORT, common.REPO_LOC,
            common.DOCKER_SRCS[self.docker_repo_source][common.IMG_PREFIX_KEY],
            'nova-api-proxy', self.docker_repo_tag)

        heat_image = self._operator.chart_operators[
            constants.HELM_CHART_HEAT].docker_image

        return {
            'tags': {
                'nova_api_proxy': nova_api_proxy_image,
                'ks_endpoints': heat_image
            }
        }

    def _get_endpoints_overrides(self):
        return {
            'identity': {
                'auth': self._get_endpoints_identity_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS),
            }
        }
