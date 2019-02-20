#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common import log as logging
from sysinv.helm import common
from sysinv.helm import openstack

LOG = logging.getLogger(__name__)


class MariadbHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the mariadb chart"""

    CHART = constants.HELM_CHART_MARIADB

    def _num_server_replicas(self):
        # For now we want to run with a single mariadb server pod for the
        # AIO-DX case.
        if utils.is_aio_duplex_system(self.dbapi):
            return 1
        else:
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
                'images': self._get_images_overrides(),
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

    def _get_images_overrides(self):
        heat_image = self._operator.chart_operators[
            constants.HELM_CHART_HEAT].docker_image

        return {
            'tags': {
                'prometheus_mysql_exporter_helm_tests': heat_image
            }
        }

    def _get_endpoints_overrides(self):
        return {
            'oslo_db': {
                'auth': self._get_endpoints_oslo_db_overrides(
                    self.CHART, [])
            }
        }
