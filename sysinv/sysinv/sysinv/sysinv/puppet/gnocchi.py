#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants

from . import openstack


class GnocchiPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for gnocchi configuration"""

    SERVICE_NAME = 'gnocchi'
    SERVICE_PORT = 8041

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)

        return {
            'gnocchi::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'gnocchi::db::postgresql::password': dbpass,

            'gnocchi::keystone::auth::password': kspass,
            'gnocchi::keystone::authtoken::password': kspass,
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)

        config = {
            'gnocchi::api::enabled': self._enable_gnocchi_api(),
            'gnocchi::keystone::auth::region':
                self._get_service_region_name(self.SERVICE_NAME),
            'gnocchi::keystone::auth::public_url': self.get_public_url(),
            'gnocchi::keystone::auth::internal_url': self.get_internal_url(),
            'gnocchi::keystone::auth::admin_url': self.get_admin_url(),
            'gnocchi::keystone::auth::auth_name': ksuser,
            'gnocchi::keystone::auth::tenant': self._get_service_tenant_name(),

            'gnocchi::keystone::authtoken::auth_url':
                self._keystone_identity_uri(),
            'gnocchi::keystone::authtoken::auth_uri':
                self._keystone_auth_uri(),
            'gnocchi::keystone::authtoken::user_domain_name':
                self._get_service_user_domain_name(),
            'gnocchi::keystone::authtoken::project_domain_name':
                self._get_service_project_domain_name(),
            'gnocchi::keystone::authtoken::project_name':
                self._get_service_tenant_name(),
            'gnocchi::keystone::authtoken::region_name':
                self._keystone_region_name(),
            'gnocchi::keystone::authtoken::username': ksuser,

            'openstack::gnocchi::params::region_name':
                self._get_service_region_name(self.SERVICE_NAME),
            'openstack::gnocchi::params::service_create':
                self._to_create_services(),
        }
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
            config.update({'openstack::gnocchi::params::service_enabled': False,
                           'gnocchi::keystone::auth::configure_endpoint': False})

        return config

    def get_secure_system_config(self):
        config = {
            'gnocchi::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
        }

        return config

    def get_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT)

    def get_internal_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)

    def get_admin_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)

    def _enable_gnocchi_api(self):
        if self._kubernetes_enabled():
            return False
        else:
            return True
