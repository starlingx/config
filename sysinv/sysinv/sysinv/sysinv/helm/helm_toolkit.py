#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import base


class HelmToolkitHelm(base.BaseHelm):
    """Class to encapsulate helm operations for the helm toolkit"""

    CHART = common.HELM_CHART_HELM_TOOLKIT
    SUPPORTED_NAMESPACES = [
        common.HELM_NS_HELM_TOOLKIT,
    ]

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_HELM_TOOLKIT: {}
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
