#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.openstack.common import log as logging
from sysinv.helm import common
from sysinv.helm import openstack

LOG = logging.getLogger(__name__)


class RabbitmqHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the rabbitmq chart"""

    CHART = common.HELM_CHART_RABBITMQ

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'pod': {
                    'replicas': {
                        'server': self._num_controllers()
                    }
                },
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
        credentials = self._get_endpoints_oslo_messaging_overrides(
            self.CHART, [])
        overrides = {
            'oslo_messaging': {
                'auth': {
                    'user': credentials['admin']
                }
            },
        }
        return overrides
