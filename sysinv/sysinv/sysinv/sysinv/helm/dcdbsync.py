#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import openstack


class DcdbsyncHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the dcdbsync chart"""

    CHART = common.HELM_CHART_DCDBSYNC
    AUTH_USERS = ['dcdbsync']
    SERVICE_NAME = common.HELM_CHART_DCDBSYNC

    def _is_enabled(self, app_name, chart_name, namespace):
        # First, see if this chart is enabled by the user then adjust based on
        # system conditions
        enabled = super(DcdbsyncHelm, self)._is_enabled(
            app_name, chart_name, namespace)
        if enabled \
                and (self._distributed_cloud_role() !=
                         constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER) \
                and (self._distributed_cloud_role() !=
                         constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
            enabled = False
        return enabled

    def execute_manifest_updates(self, operator):
        if self._is_enabled(operator.APP,
                            self.CHART, common.HELM_NS_OPENSTACK):
            operator.manifest_chart_groups_insert(
                operator.ARMADA_MANIFEST,
                operator.CHART_GROUPS_LUT[self.CHART])

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
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
            },
        }
