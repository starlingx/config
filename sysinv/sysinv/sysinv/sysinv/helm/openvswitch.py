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

    # There are already two places at where we generate chartgroup overrides.
    # If more chartgroup overrides are needed in future, it's better to do it
    # at a fixed place. Distributing the overrides in the chart plugins makes
    # it hard to manage chartgroup overrides.
    def get_meta_overrides(self, namespace, app_name=None, mode=None):
        def _meta_overrides():
            if utils.get_vswitch_type(self.dbapi) == \
                    constants.VSWITCH_TYPE_NONE:
                # add the openvswitch chart into computekit chart group
                return {
                    'schema': 'armada/ChartGroup/v1',
                    'metadata': {
                        'schema': 'metadata/Document/v1',
                        'name': 'openstack-compute-kit',
                    },
                    'data': {
                        'chart_group': [
                            'openstack-libvirt',
                            'openstack-openvswitch',
                            'openstack-nova',
                            'openstack-nova-api-proxy',
                            'openstack-neutron',
                            'openstack-placement',
                        ]
                    }
                }
            else:
                return {}

        overrides = {
            common.HELM_NS_OPENSTACK: _meta_overrides()
        }
        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

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
