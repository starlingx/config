#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


from sysinv.puppet import openstack


class SwiftPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for Swift configuration"""

    SERVICE_NAME = 'swift'
    SERVICE_PORT = 8080
    SERVICE_PATH = 'v1/AUTH_%(tenant_id)s'

    def get_secure_static_config(self):
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'swift::keystone::auth::password': kspass,
            'swift::proxy::authtoken::password': kspass,
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)

        config = {
            'openstack::swift::params::api_host':
                self._get_management_address(),
            'swift::keystone::auth::region':
                self._get_service_region_name(self.SERVICE_NAME),
            'swift::keystone::auth::auth_name': ksuser,
            'swift::keystone::auth::tenant': self._get_service_tenant_name(),
            'swift::keystone::auth::public_url': self.get_public_url(),
            'swift::keystone::auth::internal_url': self.get_internal_url(),
            'swift::keystone::auth::admin_url': self.get_admin_url(),
            'swift::proxy::authtoken::auth_uri': self._keystone_auth_uri(),
            'swift::proxy::authtoken::auth_url': self._keystone_identity_uri(),
            'swift::proxy::authtoken::project_name':
                self._get_service_tenant_name(),
            'swift::proxy::authtoken::username': ksuser,
        }
        return config

    def get_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT,
                                            path=self.SERVICE_PATH)

    def get_internal_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT,
                                             path=self.SERVICE_PATH)

    def get_admin_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)
