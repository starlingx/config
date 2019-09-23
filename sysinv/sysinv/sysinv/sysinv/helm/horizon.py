#
# Copyright (c) 2018-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception
from sysinv.helm import common
from sysinv.helm import openstack


class HorizonHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the horizon chart"""

    CHART = common.HELM_CHART_HORIZON

    SERVICE_NAME = common.HELM_CHART_HORIZON

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'conf': {
                    'horizon': {
                        'local_settings': {
                            'config': self._get_local_settings_config_overrides(),
                        }
                    }
                },
                'endpoints': self._get_endpoints_overrides(),
                'network': {
                    'node_port': {
                        'enabled': self._get_network_node_port_overrides()
                    }
                }
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
            'dashboard': {
                'host_fqdn_override':
                    self._get_endpoints_host_fqdn_overrides(
                        common.HELM_CHART_HORIZON),
                'port': self._get_endpoints_port_api_public_overrides(),
                'scheme': self._get_endpoints_scheme_public_overrides(),
            },
            'oslo_db': {
                'auth': self._get_endpoints_oslo_db_overrides(
                    self.SERVICE_NAME, [self.SERVICE_NAME])
            },
        }

    def _get_local_settings_config_overrides(self):
        local_settings_config = {
            'horizon_secret_key': self._get_or_generate_password(
                self.SERVICE_NAME, common.HELM_NS_OPENSTACK,
                'horizon_secret_key'),

            'system_region_name': self._region_name()
        }

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

        return local_settings_config

    def _region_config(self):
        # A wrapper over the Base region_config check.
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
            return False
        else:
            return super(HorizonHelm, self)._region_config()

    def _get_network_node_port_overrides(self):
        # If openstack endpoint FQDN is configured, disable node_port 31000
        # which will enable the Ingress for the horizon service
        endpoint_fqdn = self._get_service_parameter(
            constants.SERVICE_TYPE_OPENSTACK,
            constants.SERVICE_PARAM_SECTION_OPENSTACK_HELM,
            constants.SERVICE_PARAM_NAME_ENDPOINT_DOMAIN)
        if endpoint_fqdn:
            return False
        else:
            return True
