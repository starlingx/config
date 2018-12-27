#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.puppet import openstack


class MagnumPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for magnum configuration"""

    SERVICE_NAME = 'magnum'
    SERVICE_PORT = 9511
    SERVICE_NAME_DOMAIN = 'magnum-domain'

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)

        return {
            'magnum::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)
        dkspass = self._get_service_password(self.SERVICE_NAME_DOMAIN)

        return {
            'magnum::db::postgresql::password': dbpass,

            'magnum::keystone::auth::password': kspass,
            'magnum::keystone::authtoken::password': kspass,

            'magnum::keystone::domain::domain_password': dkspass,
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME) \
                 + self._region_name()

        config = {
            'magnum::clients::region_name':
                self._region_name(),
            'openstack::magnum::params::service_enabled':
                self._get_service_enabled(),
        }
        if self._get_service_enabled():
            config.update({
                'magnum::keystone::auth::region':
                    self._region_name(),
                'magnum::keystone::auth::auth_name': ksuser,
                'magnum::keystone::auth::public_url':
                    self.get_public_url(),
                'magnum::keystone::auth::internal_url':
                    self.get_internal_url(),
                'magnum::keystone::auth::admin_url':
                    self.get_admin_url(),
                'magnum::keystone::auth::tenant':
                    self._get_service_tenant_name(),

                'magnum::keystone::authtoken::username': ksuser,
                'magnum::keystone::authtoken::project_name':
                    self._get_service_tenant_name(),
                'magnum::keystone::authtoken::auth_url':
                    self._keystone_identity_uri(),
                # unlike all other services, magnum wants a /v3 at the end
                # of auth uri in config, which caused a lot of grief
                # at one point
                'magnum::keystone::authtoken::auth_uri':
                    self._keystone_auth_uri() + '/v3',
                'magnum::keystone::authtoken::region':
                    self._keystone_region_name(),
                'magnum::keystone::authtoken::user_domain_name':
                    self._get_service_user_domain_name(),
                'magnum::keystone::authtoken::project_domain_name':
                    self._get_service_project_domain_name(), })
        return config

    def get_secure_system_config(self):
        config = {
            'magnum::db::database_connection':
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

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)
