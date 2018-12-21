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


class AodhHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the aodh chart"""

    CHART = constants.HELM_CHART_AODH
    SUPPORTED_NAMESPACES = [
        common.HELM_NS_OPENSTACK
    ]

    SERVICE_NAME = 'aodh'
    AUTH_USERS = ['aodh']

    @property
    def docker_repo_source(self):
        return common.DOCKER_SRC_LOC

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'images': self._get_images_overrides(),
                'conf': self._get_conf_overrides(),
                'endpoints': self._get_endpoints_overrides()
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
                'db_drop': heat_image,
                'db_init': self.docker_image,
                'aodh_api': self.docker_image,
                'aodh_alarms_cleaner': self.docker_image,
                'aodh_db_sync': self.docker_image,
                'aodh_evaluator': self.docker_image,
                'aodh_listener': self.docker_image,
                'aodh_notifier': self.docker_image,
                'ks_endpoints': heat_image,
                'ks_service': heat_image,
                'ks_user': heat_image,
            }
        }

    def _get_conf_overrides(self):
        return {
            'aodh': {
                'service_credentials': {
                    'region_name': self._region_name()
                }
            }
        }

    def _get_endpoints_overrides(self):
        return {
            'identity': {
                'auth': self._get_endpoints_identity_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS),
            },
            'oslo_cache': {
                'auth': {
                    'memcached_secret_key':
                        self._get_common_password('auth_memcache_key')
                }
            },
            'oslo_db': {
                'auth': self._get_endpoints_oslo_db_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS)
            },
            'oslo_messaging': {
                'auth': self._get_endpoints_oslo_messaging_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS)
            },
        }
