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


class HeatHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the heat chart"""

    CHART = constants.HELM_CHART_HEAT
    SUPPORTED_NAMESPACES = [
        common.HELM_NS_OPENSTACK
    ]

    SERVICE_NAME = constants.HELM_CHART_HEAT
    AUTH_USERS = ['heat', 'heat_trustee', 'heat_stack_user']

    @property
    def docker_repo_source(self):
        return common.DOCKER_SRC_STX

    @property
    def docker_repo_tag(self):
        return common.DOCKER_SRCS[self.docker_repo_source][common.IMG_TAG_KEY]

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'pod': self._get_pod_overrides(),
                'endpoints': self._get_endpoints_overrides(),
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
        return {
            'tags': {
                'bootstrap': self.docker_image,
                'db_drop': self.docker_image,
                'db_init': self.docker_image,
                'heat_api': self.docker_image,
                'heat_cfn': self.docker_image,
                'heat_cloudwatch': self.docker_image,
                'heat_db_sync': self.docker_image,
                'heat_engine': self.docker_image,
                'heat_engine_cleaner': self.docker_image,
                'ks_endpoints': self.docker_image,
                'ks_service': self.docker_image,
                'ks_user': self.docker_image,
            }
        }

    def _get_pod_overrides(self):
        return {
            'replicas': {
                'api': self._num_controllers(),
                'cnf': self._num_controllers(),
                'cloudwatch': self._num_controllers(),
                'engine': self._num_controllers()
            }
        }

    def _get_endpoints_identity_users_overrides(self):
        overrides = {}
        overrides.update(self._get_common_users_overrides(self.SERVICE_NAME))

        for user in self.AUTH_USERS:
            overrides.update({
                user: {
                    'region_name': self._region_name(),
                    'password': self._get_keyring_password(self.SERVICE_NAME, user)
                }
            })
        return overrides

    def _get_endpoints_identity_overrides(self):
        return {'auth': self._get_endpoints_identity_users_overrides()}

    def _get_endpoints_overrides(self):
        return {
            'identity': self._get_endpoints_identity_overrides(),
        }
