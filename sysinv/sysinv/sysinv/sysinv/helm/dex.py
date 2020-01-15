#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception

from sysinv.helm import base
from sysinv.helm import common


class Dex(base.BaseHelm):
    """Class to encapsulate helm operations for the dex chart"""

    CHART = common.HELM_CHART_DEX
    SUPPORTED_NAMESPACES = base.BaseHelm.SUPPORTED_NAMESPACES + \
        [common.HELM_NS_KUBE_SYSTEM]
    SUPPORTED_APP_NAMESPACES = {
        constants.HELM_APP_OIDC_AUTH:
            base.BaseHelm.SUPPORTED_NAMESPACES + [common.HELM_NS_KUBE_SYSTEM],
    }

    SERVICE_NAME = 'dex'
    NODE_PORT = 30556

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def _get_static_clients(self):
        static_clients = []

        # for now we have the example client
        # we will get rid of this in the near future
        # we might also add other clients in the future
        example_client = {
            'id': 'example-app',
            'redirectURIs': ["http://%s:5555/callback" % (self._format_url_address(self._get_oam_address()))],
            'name': 'Example App',
            'secret': 'ZXhhbXBsZS1hcHAtc2VjcmV0'
        }

        static_clients.append(example_client)

        return static_clients

    def get_overrides(self, namespace=None):

        ports = []
        dex_port = {
            'name': 'http',
            'containerPort': 5556,
            'protocol': 'TCP',
            'nodePort': self.NODE_PORT,
        }
        ports.append(dex_port)

        overrides = {
            common.HELM_NS_KUBE_SYSTEM: {
                'config': {
                    'issuer': "https://%s:%s/dex" % (self._format_url_address(self._get_oam_address()), self.NODE_PORT),
                    'staticClients': self._get_static_clients(),
                },
                'ports': ports,
                'replicas': self._num_provisioned_controllers(),
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
