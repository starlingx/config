#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from . import openstack


class SmPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for sm configuration"""

    SERVICE_NAME = 'smapi'
    SERVICE_PORT = 7777

    def get_static_config(self):
        config = {
            'platform::smapi::params::auth_username': self.SERVICE_NAME,
        }
        return config

    def get_secure_static_config(self):
        kspass = self._get_service_password(self.SERVICE_NAME)

        config = {
            'smapi::keystone::auth::password': kspass,
            'smapi::keystone::authtoken::password': kspass,
            'smapi::auth::auth_password': kspass,
            'platform::smapi::params::keystone_password': kspass,
        }
        return config

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)

        config = {
            'smapi::keystone::authtoken::username': ksuser,
            'smapi::keystone::authtoken::auth_url': self._keystone_identity_uri(),
            'smapi::keystone::auth::auth_name': ksuser,
            'smapi::keystone::auth::public_url': self.get_public_url(),
            'smapi::keystone::auth::region': self._region_name(),
            'smapi::keystone::auth::admin_url': self.get_admin_url(),
            'smapi::keystone::auth::internal_url': self.get_internal_url(),

            'platform::smapi::params::admin_url': self.get_admin_url(),
            'platform::smapi::params::internal_url': self.get_internal_url(),
            'platform::smapi::params::keystone_auth_url': self._keystone_identity_uri(),
            'platform::smapi::params::keystone_username': ksuser,
            'platform::smapi::params::public_url': self.get_public_url(),
            'platform::smapi::params::port': self.SERVICE_PORT,
            'platform::smapi::params::region': self._region_name(),
        }

        return config

    def get_host_config(self, host):
        config = {
            'platform::smapi::params::bind_ip': host.mgmt_ip,
        }

        return config

    def get_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT)

    def get_internal_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)

    def get_admin_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)
