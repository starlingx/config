#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from . import openstack


class MuranoPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for murano configuration"""

    SERVICE_NAME = 'murano'
    SERVICE_PORT = 8082

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)

        return {
            'murano::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'murano::admin_password': kspass,

            'murano::db::postgresql::password': dbpass,

            'murano::keystone::auth::password': kspass,
            'openstack::murano::params::auth_password':
                self. _generate_random_password(),
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME) \
                 + self._region_name()
        config = {
            'openstack::murano::params::service_enabled':
                self._get_service_enabled(),

            'murano::admin_user': ksuser,
            'murano::auth_uri': self._keystone_auth_uri(),
            'murano::identity_uri': self._keystone_identity_uri(),
            'murano::admin_tenant_name': self._get_service_tenant_name(),

        }
        if self._get_service_enabled():
            config.update({
                'murano::keystone::auth::public_url': self.get_public_url(),
                'murano::keystone::auth::internal_url': self.get_internal_url(),
                'murano::keystone::auth::admin_url': self.get_admin_url(),
                'murano::keystone::auth::auth_name': ksuser,
                'murano::keystone::auth::region': self._region_name(),
                'murano::keystone::auth::tenant':
                    self._get_service_tenant_name(),})

        return config

    def get_secure_system_config(self):
        config = {
            'murano::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
        }

        return config

    def _get_service_enabled(self):
        service_config = self._get_service_config(self.SERVICE_NAME)
        if service_config:
            return service_config.enabled
        else:
            return False

    def get_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT)

    def get_internal_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)

    def get_admin_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)
