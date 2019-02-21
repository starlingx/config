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
from sysinv.helm import openstack

LOG = logging.getLogger(__name__)


class CeilometerHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the ceilometer chart"""

    CHART = constants.HELM_CHART_CEILOMETER

    SERVICE_NAME = 'ceilometer'
    AUTH_USERS = ['ceilometer']

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'images': self._get_images_overrides(),
                'pod': self._get_pod_overrides(),
                'conf': self._get_conf_overrides(),
                'manifests': self._get_manifests_overrides(),
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
                'ks_service': heat_image,
                'ks_user': heat_image,
                'ks_endpoints': heat_image,
                'db_init': self.docker_image,
                'db_init_mongodb': self.docker_image,
                'ceilometer_db_sync': self.docker_image,
                'ceilometer_central': self.docker_image,
                'ceilometer_compute': self.docker_image,
                'ceilometer_ipmi': self.docker_image,
                'ceilometer_notification': self.docker_image,
                'ceilometer_collector': self.docker_image,
                'ceilometer_api': self.docker_image,
                'test': self.docker_image
            }
        }

    def _get_pod_overrides(self):
        return {
            'replicas': {
                'central': self._num_controllers()
            }
        }

    def _get_manifests_overrides(self):
        manifests_overrides = {}
        if utils.is_virtual():
            manifests_overrides.update({'daemonset_ipmi': False})
        return manifests_overrides

    def _get_conf_overrides(self):
        return {
            'ceilometer': {
                'DEFAULT': self._get_conf_ceilometer_default_overrides(),
                'notification': {
                    'messaging_urls': {
                        'values': self._get_notification_messaging_urls()
                    }
                },
                'meter': {
                    'meter_definitions_dirs': '/etc/ceilometer/meters.d'
                }
            }
        }

    def _get_conf_ceilometer_default_overrides(self):
        default_overrides = {
            'region_name_for_services': self._get_service_region_name(self.SERVICE_NAME)
        }

        if self._region_config():
            region_1_name = self._get_service_region_name(constants.SERVICE_TYPE_KEYSTONE)
            shared_services_types = self._get_shared_services_types()
            default_overrides.update(
                {'region_name_for_shared_services': region_1_name,
                 'shared_services_types': shared_services_types})

        return default_overrides

    def _get_shared_services_types(self):
        shared_services_types = []

        shared_services = self._get_shared_services()
        if constants.SERVICE_TYPE_IMAGE in shared_services:
            shared_services_types += [constants.SERVICE_TYPE_IMAGE]

        if constants.SERVICE_TYPE_VOLUME in shared_services:
            shared_services_types += [constants.SERVICE_TYPE_VOLUME,
                                      constants.SERVICE_TYPE_VOLUME + 'v2',
                                      constants.SERVICE_TYPE_VOLUME + 'v3']

        return shared_services_types

    def _get_notification_messaging_urls(self):
        rabbit_user = 'rabbitmq-admin'
        rabbit_pass = self._get_common_password(rabbit_user)
        rabbit_paths = ['/ceilometer', '/cinder', '/glance', '/nova', '/keystone', '/neutron', '/heat']

        messaging_urls = []
        for rabbit_path in rabbit_paths:
            messaging_urls += \
                ['rabbit://%s:%s@rabbitmq.openstack.svc.cluster.local:5672%s' % (rabbit_user, rabbit_pass, rabbit_path)]

        return messaging_urls

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
            'oslo_messaging': {
                'auth': self._get_endpoints_oslo_messaging_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS)
            },
        }

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)
