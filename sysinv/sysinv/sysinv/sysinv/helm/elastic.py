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

    def _is_enabled(self, app_name, chart_name, namespace):
        """
        Check if the chart is enable at a system level

        :param app_name: Application name
        :param chart_name: Chart supplied with the application
        :param namespace: Namespace where the chart will be executed

        Returns true by default if an exception occurs as most charts are
        enabled.
        """
        return super(ElasticBaseHelm, self)._is_enabled(
            app_name, chart_name, namespace)

    def execute_manifest_updates(self, operator):
        # On application load this chart is enabled. Only disable if specified
        # by the user
        if not self._is_enabled(operator.APP, self.CHART,
                                common.HELM_NS_MONITOR):
            operator.chart_group_chart_delete(
                operator.CHART_GROUPS_LUT[self.CHART],
                operator.CHARTS_LUT[self.CHART])
