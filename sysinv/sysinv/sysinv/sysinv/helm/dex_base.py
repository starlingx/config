#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants

from sysinv.helm import base
from sysinv.helm import common


class DexBaseHelm(base.BaseHelm):
    """Class to encapsulate helm operations for the dex chart"""

    SUPPORTED_NAMESPACES = base.BaseHelm.SUPPORTED_NAMESPACES + \
        [common.HELM_NS_KUBE_SYSTEM]
    SUPPORTED_APP_NAMESPACES = {
        constants.HELM_APP_OIDC_AUTH:
            base.BaseHelm.SUPPORTED_NAMESPACES + [common.HELM_NS_KUBE_SYSTEM],
    }

    # OIDC client and DEX Node ports
    OIDC_CLIENT_NODE_PORT = 30555
    DEX_NODE_PORT = 30556

    @property
    def CHART(self):
        # subclasses must define the property: CHART='name of chart'
        # if an author of a new chart forgets this, NotImplementedError is raised
        raise NotImplementedError

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def _get_client_id(self):
        return 'stx-oidc-client-app'

    def _get_client_secret(self):
        return 'St8rlingX'
