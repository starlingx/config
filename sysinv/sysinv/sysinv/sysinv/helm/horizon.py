#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common import log as logging
from sysinv.helm import common
from sysinv.helm import openstack

LOG = logging.getLogger(__name__)


class HorizonHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the horizon chart"""

    CHART = constants.HELM_CHART_HORIZON

    SERVICE_NAME = 'horizon'

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'images': self._get_images_overrides(),
                'network': {
                    'node_port': {
                        'enabled': 'true',
                        'port': 31000
                    }
                },
                'conf': {
                    'horizon': {
                        'local_settings': {
                            'config': self._get_local_settings_config_overrides(),
                        }
                    }
                },
                'pod': {
                    'mounts': {
                        'horizon': {
                            'horizon': {
                                # Branding directory mount
                                'volumeMounts': [{
                                    'name': 'horizon-branding',
                                    'mountPath': '/opt/branding',
                                }],
                                'volumes': [{
                                    'name': 'horizon-branding',
                                    'hostPath':
                                        {
                                            'path': '/opt/branding',
                                            'type': 'Directory'
                                        },
                                }],
                            }
                        }
                    }
                },
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

    def _get_endpoints_overrides(self):
        return {
            'oslo_db': {
                'auth': self._get_endpoints_oslo_db_overrides(
                    self.SERVICE_NAME, [self.SERVICE_NAME])
            },
        }

    def _get_images_overrides(self):
        heat_image = self._operator.chart_operators[
            constants.HELM_CHART_HEAT].docker_image
        return {
            'tags': {
                'db_drop': heat_image,
                'db_init': heat_image,
                'horizon': self.docker_image,
                'horizon_db_sync': self.docker_image,
            }
        }

    def _get_local_settings_config_overrides(self):
        local_settings_config = {
            # Region Modes
            'ss_enabled': 'False',
            'dc_mode': 'False',

            # Security
            'https_enabled': 'False',
            'lockout_period_sec': '300',
            'lockout_retries_num': '3',
            'horizon_secret_key': self._get_or_generate_password(
                self.SERVICE_NAME, common.HELM_NS_OPENSTACK,
                'horizon_secret_key'),

            # Optional Services
            'enable_murano': 'False',
            'enable_magnum': 'False',

            # Turn off domain support as we aren't using it
            'keystone_multidomain_support': 'False',
        }

        local_settings_config.update({'system_region_name': self._region_name()})

        # Basic region config additions
        if self._region_config():
            openstack_host = 'controller'  # TODO(tsmith) must evaluate region functionality
            region_name = self._region_name()

            local_settings_config.update({
                'openstack_keystone_url': "http://%s:5000/v3" % openstack_host,
                'region_name': region_name,
                'available_regions': [("http://%s:5000/v3" % openstack_host, region_name), ],
                'ss_enabled': 'True',
            })

        # Distributed cloud additions
        if self._distributed_cloud_role() in [
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD,
                constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER]:

            local_settings_config.update({
                'dc_mode': 'True',
            })

        # Https & security settings
        if self._https_enabled():
            local_settings_config.update({
                'https_enabled': 'True',
            })

        lockout_retries = self._get_service_parameter('horizon', 'auth', 'lockout_retries')
        lockout_seconds = self._get_service_parameter('horizon', 'auth', 'lockout_seconds')
        if lockout_retries is not None and lockout_seconds is not None:
            local_settings_config.update({
                'lockout_retries_num': str(lockout_retries.value),
                'lockout_period_sec': str(lockout_seconds.value),
            })

        # Optional services settings
        service_config = self._get_service_config('murano')
        if service_config is not None and service_config.enabled:
            local_settings_config.update({
                'enable_murano': 'True',
            })

        service_config = self._get_service_config('magnum')
        if service_config is not None and service_config.enabled:
            local_settings_config.update({
                'enable_magnum': 'True',
            })

        return local_settings_config

    def _region_config(self):
        # A wrapper over the Base region_config check.
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
            return False
        else:
            return super(HorizonHelm, self)._region_config()
