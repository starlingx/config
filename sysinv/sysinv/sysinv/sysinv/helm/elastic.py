#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.helm import base
from sysinv.helm import common

from sysinv.common import constants


class ElasticBaseHelm(base.BaseHelm):
    """Class to encapsulate Elastic service operations for helm"""

    SUPPORTED_NAMESPACES = \
         base.BaseHelm.SUPPORTED_NAMESPACES + [common.HELM_NS_MONITOR]

    SUPPORTED_APP_NAMESPACES = {
        constants.HELM_APP_MONITOR:
            base.BaseHelm.SUPPORTED_NAMESPACES + [common.HELM_NS_MONITOR]
    }

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES
