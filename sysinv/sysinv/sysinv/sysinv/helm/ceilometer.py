#
# Copyright (c) 2018-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.common import utils
from sysinv.helm import common
from sysinv.helm import openstack


class CeilometerHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the ceilometer chart"""

    CHART = common.HELM_CHART_CEILOMETER

    SERVICE_NAME = common.HELM_CHART_CEILOMETER
    AUTH_USERS = ['ceilometer']

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
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

    def _get_pod_overrides(self):
        return {
            'replicas': {
                'central': self._num_controllers(),
                'notification': self._num_controllers()
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

    def _get_notification_messaging_urls(self):
        rabbit_user = 'rabbitmq-admin'
        rabbit_pass = self._get_common_password(rabbit_user)
        rabbit_paths = ['/ceilometer', '/cinder', '/glance', '/nova', '/keystone', '/neutron', '/heat']

        messaging_urls = []
        for rabbit_path in rabbit_paths:
            messaging_urls += \
                ['rabbit://%s:%s@rabbitmq.openstack.svc.cluster.local:5672%s' %
                 (rabbit_user, rabbit_pass, rabbit_path)]

        return messaging_urls

    def _get_endpoints_overrides(self):
        return {
            'identity': {
                'auth': self._get_endpoints_identity_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS),
            },
            'oslo_cache': {
                'auth': {
                    'memcache_secret_key':
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
