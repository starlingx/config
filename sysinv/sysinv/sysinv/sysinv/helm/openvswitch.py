#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils
from sysinv.openstack.common import log as logging
from sysinv.helm import common
from sysinv.helm import openstack

LOG = logging.getLogger(__name__)


class OpenvswitchHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the openvswitch chart"""

    CHART = constants.HELM_CHART_OPENVSWITCH

    def execute_manifest_updates(self, operator, app_name=None):
        if utils.get_vswitch_type(self.dbapi) == constants.VSWITCH_TYPE_NONE:
            # add the openvswitch chart into computekit chart group
            operator.chart_group_chart_insert(
                'openstack-compute-kit',
                'openstack-openvswitch',
                before_chart='openstack-nova')

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {}
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
