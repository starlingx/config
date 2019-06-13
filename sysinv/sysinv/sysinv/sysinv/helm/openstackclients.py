#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.helm import common
from sysinv.openstack.common import log as logging
from sysinv.helm import openstack

LOG = logging.getLogger(__name__)


class OpenstackClientsHelm(openstack.OpenstackBaseHelm):

    CHART = constants.HELM_CHART_CLIENTS
    SERVICE_NAME = constants.HELM_CHART_CLIENTS

    def get_overrides(self, namespace=None):

        overrides = {
            common.HELM_NS_OPENSTACK: {
                "endpoints": self._get_endpoints_overrides()
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
        overrides = self._get_common_users_overrides(
                    common.SERVICE_ADMIN)
        overrides['admin'].update({
            'project_name': self._get_admin_project_name(),
            'project_domain_name': self._get_admin_project_domain(),
            'user_domain_name': self._get_admin_user_domain(),
        })
        return {
            'identity': {
                'auth': overrides
            },
        }
