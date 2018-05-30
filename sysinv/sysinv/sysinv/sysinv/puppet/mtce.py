#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from tsconfig.tsconfig import KEYRING_PATH
from sysinv.common import constants
from . import openstack


class MtcePuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for mtce configuration"""

    SERVICE_NAME = 'mtce'

    def get_static_config(self):
        return {
            'platform::mtce::params::auth_username': self.SERVICE_NAME,
        }

    def get_secure_static_config(self):
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'platform::mtce::params::auth_pw': kspass,
        }

    def get_system_config(self):
        multicast_address = self._get_address_by_name(
            constants.MTCE_MULTICAST_MGMT_IP_NAME,
            constants.NETWORK_TYPE_MULTICAST)

        config = {
            'platform::mtce::params::auth_host':
                self._keystone_auth_address(),
            'platform::mtce::params::auth_port':
                self._keystone_auth_port(),
            'platform::mtce::params::auth_uri':
                self._keystone_auth_uri(),
            'platform::mtce::params::auth_username':
                self._get_service_user_name(self.SERVICE_NAME),
            'platform::mtce::params::auth_user_domain':
                self._get_service_user_domain_name(),
            'platform::mtce::params::auth_project_domain':
                self._get_service_project_domain_name(),
            'platform::mtce::params::auth_project':
                self._get_service_tenant_name(),
            'platform::mtce::params::auth_region':
                self._keystone_region_name(),

            'platform::mtce::params::keyring_directory': KEYRING_PATH,
            'platform::mtce::params::ceilometer_port':
                self._get_ceilometer_port(),
            'platform::mtce::params::mtce_multicast':
                multicast_address.address,
        }
        return config

    def _get_ceilometer_port(self):
        return self._operator.ceilometer.SERVICE_PORT

    def get_public_url(self):
        # not an openstack service
        raise NotImplementedError()

    def get_internal_url(self):
        # not an openstack service
        raise NotImplementedError()

    def get_admin_url(self):
        # not an openstack service
        raise NotImplementedError()
