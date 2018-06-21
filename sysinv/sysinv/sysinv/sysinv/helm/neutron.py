#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common import log as logging
from . import common
from . import openstack

LOG = logging.getLogger(__name__)


class NeutronHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the memcached chart"""

    CHART = constants.HELM_CHART_NEUTRON
    SUPPORTED_NAMESPACES = [
        common.HELM_NS_OPENSTACK
    ]

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'network': {
                    'interface': {
                        'tunnel': 'docker0'
                    }
                },
                'conf': {
                    'neutron': {
                        'DEFAULT': {
                            'l3_ha': 'False',
                            'min_l3_agents_per_router': 1,
                            'max_l3_agents_per_router': 1,
                            'l3_ha_network_type': 'vxlan',
                            'dhcp_agents_per_network': 1
                        }
                    },
                    'plugins': {
                        'ml2_conf': {
                            'ml2_type_flat': {
                                'flat_networks': 'public'
                            }
                        },
                        'openvswitch_agent': {
                            'agent': {
                                'tunnel_types': 'vxlan'
                            },
                            'ovs': {
                                'bridge_mappings': 'public:br-ex'
                            }
                        },
                        'linuxbridge_agent': {
                            'linux_bridge': {
                                'bridge_mappings': 'public:br-ex'
                            }
                        }
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
