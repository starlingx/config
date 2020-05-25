#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception

from sysinv.helm import base
from sysinv.helm import common


class CertMgrHelm(base.BaseHelm):
    """Class to encapsulate helm operations for the cert-manager chart"""

    SUPPORTED_NAMESPACES = base.BaseHelm.SUPPORTED_NAMESPACES + \
        [common.HELM_NS_CERT_MANAGER]
    SUPPORTED_APP_NAMESPACES = {
        constants.HELM_APP_CERT_MANAGER:
            base.BaseHelm.SUPPORTED_NAMESPACES + [common.HELM_NS_CERT_MANAGER],
    }

    CHART = common.HELM_CHART_CERT_MANAGER

    SERVICE_NAME = 'cert-manager'

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def get_overrides(self, namespace=None):

        overrides = {
            common.HELM_NS_CERT_MANAGER: {
                'replicaCount': max(1, self._num_provisioned_controllers()),
                'webhook': {
                    'replicaCount': max(1, self._num_provisioned_controllers()),
                },
                'cainjector': {
                    'replicaCount': max(1, self._num_provisioned_controllers()),
                },
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
