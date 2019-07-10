#
# Copyright (c) 2018-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common import log as logging
from sysinv.helm import common
from sysinv.helm import openstack

LOG = logging.getLogger(__name__)


class HeatHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the heat chart"""

    CHART = constants.HELM_CHART_HEAT

    SERVICE_NAME = constants.HELM_CHART_HEAT
    AUTH_USERS = ['heat', 'heat_trustee', 'heat_stack_user']

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'pod': self._get_pod_overrides(),
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

    def _get_pod_overrides(self):
        return {
            'replicas': {
                'api': self._num_controllers(),
                'cfn': self._num_controllers(),
                'cloudwatch': self._num_controllers(),
                'engine': self._num_controllers()
            }
        }

    def _get_endpoints_overrides(self):
        return {
            'identity': {
                'auth': self._get_endpoints_identity_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS),
            },
            'cloudformation': {
                'host_fqdn_override':
                    self._get_endpoints_host_fqdn_overrides(
                        'cloudformation'),
                'port': self._get_endpoints_port_api_public_overrides(),
                'scheme': self._get_endpoints_scheme_public_overrides(),
            },
            'orchestration': {
                'host_fqdn_override':
                    self._get_endpoints_host_fqdn_overrides(
                        self.SERVICE_NAME),
                'port': self._get_endpoints_port_api_public_overrides(),
                'scheme': self._get_endpoints_scheme_public_overrides(),
            },
            'oslo_db': {
                'auth': self._get_endpoints_oslo_db_overrides(
                    self.SERVICE_NAME, [self.SERVICE_NAME])
            },
            'oslo_messaging': {
                'auth': self._get_endpoints_oslo_messaging_overrides(
                    self.SERVICE_NAME, [self.SERVICE_NAME])
            },
        }

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)
