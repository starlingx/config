#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.puppet import openstack


class IronicPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for ironic configuration"""
    SERVICE_NAME = 'ironic'
    SERVICE_PORT = 6485
    SERVICE_TYPE = 'baremetal'

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)

        return {
            'ironic::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'ironic::db::postgresql::password': dbpass,
            'ironic::keystone::auth::password': kspass,
            'ironic::api::authtoken::password': kspass,
            'ironic::neutron::password': self._get_neutron_password(),
            'ironic::glance::password': self._get_glance_password(),
            'nova::ironic::common::password': kspass,

        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME) \
                + self._region_name()
        config = {
            'openstack::ironic::params::service_enabled':
                self._get_service_enabled(),

            'ironic::api::authtoken::username': ksuser,
            'ironic::api::authtoken::auth_url': self._keystone_identity_uri(),
            'ironic::api::authtoken::auth_uri': self._keystone_auth_uri(),
            'ironic::neutron::username': self._get_neutron_username(),
            'ironic::glance::username': self._get_glance_username(),
        }
        if self._get_service_enabled():
            config.update({
                'ironic::keystone::auth::public_url': self.get_public_url(),
                'ironic::keystone::auth::internal_url': self.get_internal_url(),
                'ironic::keystone::auth::admin_url': self.get_admin_url(),
                'ironic::keystone::auth::auth_name': ksuser,
                'ironic::keystone::auth::region': self._region_name(),
                'ironic::keystone::auth::tenant': self._get_service_tenant_name(),
                'ironic::keystone::auth::service_type': self.SERVICE_TYPE,
                'ironic::api::authtoken::project_name': self._get_service_tenant_name(),
                'ironic::api::authtoken::user_domain_name': self._get_service_user_domain_name(),
                'ironic::api::authtoken::project_domain_name': self._get_service_project_domain_name(),
                'ironic::api::authtoken::region_name': self._keystone_region_name(),
                # Populate Neutron credentials
                'ironic::neutron::api_endpoint': self._operator.neutron.get_internal_url(),
                'ironic::neutron::auth_url': self._keystone_auth_uri(),
                'ironic::neutron::project_name': self._get_service_tenant_name(),
                'ironic::neutron::user_domain_name': self._get_service_user_domain_name(),
                'ironic::neutron::project_domain_name': self._get_service_project_domain_name(),
                # Populate Glance credentials
                'ironic::glance::auth_url': self._keystone_auth_uri(),
                # 'ironic::glance::api_servers': self._format_url_address(self._operator.glance.get_glance_url()),
                'ironic::glance::user_domain_name': self._get_service_user_domain_name(),
                'ironic::glance::project_domain_name': self._get_service_project_domain_name(),
                'ironic::glance::api_servers': self._operator.glance.get_glance_url(),
                'nova::ironic::common::username': ksuser,
                'nova::ironic::common::auth_url': self._keystone_identity_uri(),
                'nova::ironic::common::api_endpoint': self.get_internal_url(),
                'nova::ironic::common::project_name': self._get_service_tenant_name(),
            })
        return config

    def get_secure_system_config(self):
        config = {
            'ironic::database_connection':
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

    def _get_neutron_username(self):
        return self._get_service_user_name(self._operator.neutron.SERVICE_NAME)

    def _get_neutron_password(self):
        return self._get_service_password(self._operator.neutron.SERVICE_NAME)

    def _get_glance_username(self):
        return self._get_service_user_name(self._operator.glance.SERVICE_NAME)

    def _get_glance_password(self):
        return self._get_service_password(self._operator.glance.SERVICE_NAME)
