#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.helm import common
from sysinv.helm import openstack


class MariadbHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the mariadb chart"""

    CHART = common.HELM_CHART_MARIADB

    def _num_server_replicas(self):
        return self._num_controllers()

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'pod': {
                    'replicas': {
                        'server': self._num_server_replicas(),
                        'ingress': self._num_controllers()
                    }
                },
                'endpoints': self._get_endpoints_overrides(),
            }
        }

        if not cutils.is_std_system(self.dbapi):
            config_override = {
                'conf': {
                    'database': {
                        'config_override': ''
                    }
                }
            }
            overrides[common.HELM_NS_OPENSTACK].update(config_override)

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_endpoints_overrides(self):
        return {
            'oslo_db': {
                'auth': self._get_endpoints_oslo_db_overrides(
                    self.CHART, [])
            }
        }
