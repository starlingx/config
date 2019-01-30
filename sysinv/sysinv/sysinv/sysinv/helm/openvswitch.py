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

    def get_overrides(self, namespace=None):
        # helm has an issue with installing release of no pod
        # https://github.com/helm/helm/issues/4295
        # once this is fixed, we can use 'manifests' instead of 'label' to
        # control ovs enable or not
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'labels': {
                    'ovs': {
                        'node_selector_key': 'openvswitch',
                        'node_selector_value': self._ovs_label_value(),
                    }
                }
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _ovs_label_value(self):
        if utils.get_vswitch_type(self.dbapi) == constants.VSWITCH_TYPE_NONE:
            return "enabled"
        else:
            return "none"
