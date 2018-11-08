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


class MariadbHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the mariadb chart"""

    CHART = constants.HELM_CHART_MARIADB
    SUPPORTED_NAMESPACES = [
        common.HELM_NS_OPENSTACK
    ]

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def get_overrides(self, namespace=None):
        # NOTE: there is an intentional typo in "force_recovey" to match
        # a typo in the upstream helm chart.  This will eventually go away
        # when we upgrade to the latest chart.
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'pod': {
                    'replicas': {
                        'server': 1
                    }
                },
                'endpoints': self._get_endpoints_overrides(),
                'force_recovey': 'mariadb-server-0',
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
            'oslo_db': {
                'auth': self._get_endpoints_oslo_db_overrides(
                    self.CHART, [])
            }
        }
