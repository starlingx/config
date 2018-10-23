#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception

from . import common
from . import openstack


class IronicHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the ironic chart"""

    CHART = constants.HELM_CHART_IRONIC
    SUPPORTED_NAMESPACES = [
        common.HELM_NS_OPENSTACK
    ]

    SERVICE_NAME = constants.HELM_CHART_IRONIC

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'images': self._get_images_overrides(),
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
                'bootstrap': heat_image,
                'db_init': heat_image,
                'ironic_api': self.docker_image,
                'ironic_conductor': self.docker_image,
                'ironic_db_sync': self.docker_image,
                'ironic_manage_cleaning_network': heat_image,
                'ironic_pxe': self.docker_image,
                'ironic_pxe_init': self.docker_image,
                'ironic_retrive_cleaning_network': heat_image,
                'ironic_retrive_swift_config': heat_image,
                'ks_endpoints': heat_image,
                'ks_service': heat_image,
                'ks_user': heat_image,
            }
        }
