#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception

from sysinv.helm import common
from sysinv.helm.dex_base import DexBaseHelm


class Dex(DexBaseHelm):
    """Class to encapsulate helm operations for the dex chart"""

    CHART = common.HELM_CHART_DEX

    SERVICE_NAME = 'dex'

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def _get_static_clients(self):
        static_clients = []

        oidc_client = {
            'id': self._get_client_id(),
            'redirectURIs': ["https://%s:%s/callback" %
                (self._format_url_address(self._get_oam_address()), self.OIDC_CLIENT_NODE_PORT)],
            'name': 'STX OIDC Client app',
            'secret': self._get_client_secret()
        }

        static_clients.append(oidc_client)

        return static_clients

    def get_overrides(self, namespace=None):

        ports = []
        dex_port = {
            'name': 'http',
            'containerPort': 5556,
            'protocol': 'TCP',
            'nodePort': self.DEX_NODE_PORT,
        }
        ports.append(dex_port)

        overrides = {
            common.HELM_NS_KUBE_SYSTEM: {
                'config': {
                    'issuer': "https://%s:%s/dex" % (self._format_url_address(self._get_oam_address()),
                                                     self.DEX_NODE_PORT),
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
