#
# Copyright (c) 2018-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils
from sysinv.openstack.common import log as logging
from sysinv.helm import common
from sysinv.helm import base

LOG = logging.getLogger(__name__)


class GarbdHelm(base.BaseHelm):
    """Class to encapsulate helm operations for the galera arbitrator chart"""

    # The service name is used to build the standard docker image location.
    # It is intentionally "mariadb" and not "garbd" as they both use the
    # same docker image.
    SERVICE_NAME = 'mariadb'

    CHART = constants.HELM_CHART_GARBD
    SUPPORTED_NAMESPACES = \
        base.BaseHelm.SUPPORTED_NAMESPACES + [common.HELM_NS_OPENSTACK]
    SUPPORTED_APP_NAMESPACES = {
        constants.HELM_APP_OPENSTACK:
            base.BaseHelm.SUPPORTED_NAMESPACES + [common.HELM_NS_OPENSTACK]
    }

    def execute_manifest_updates(self, operator, app_name=None):
        if app_name == constants.HELM_APP_OPENSTACK:
            if (self._num_controllers() < 2 or
                    utils.is_aio_duplex_system(self.dbapi) or
                    (self._distributed_cloud_role() ==
                        constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER)):
                # If there are fewer than 2 controllers or we're on AIO-DX
                # or we are on distributed cloud system controller
                # we'll use a single mariadb server and so we don't want to
                # run garbd.  This will remove "openstack-garbd" from the
                # charts in the openstack-mariadb chartgroup.
                operator.chart_group_chart_delete('openstack-mariadb',
                                                  'openstack-garbd')

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
