#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants

from . import openstack


class AodhPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for aodh configuration"""

    SERVICE_NAME = 'aodh'
    SERVICE_PORT = 8042

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'aodh::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'aodh::db::postgresql::password': dbpass,

            'aodh::keystone::auth::password': kspass,
            'aodh::keystone::authtoken::password': kspass,
            'aodh::auth::auth_password': kspass,
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)

        config = {
            'aodh::keystone::auth::public_url': self.get_public_url(),
            'aodh::keystone::auth::internal_url': self.get_internal_url(),
            'aodh::keystone::auth::admin_url': self.get_admin_url(),
            'aodh::keystone::auth::auth_name': ksuser,
            'aodh::keystone::auth::region': self._region_name(),
            'aodh::keystone::auth::tenant': self._get_service_tenant_name(),

            'aodh::keystone::authtoken::auth_url':
                self._keystone_identity_uri(),
            'aodh::keystone::authtoken::auth_uri':
                self._keystone_auth_uri(),

            'aodh::keystone::authtoken::user_domain_name':
                self._get_service_user_domain_name(),
            'aodh::keystone::authtoken::project_domain_name':
                self._get_service_project_domain_name(),
            'aodh::keystone::authtoken::project_name':
                self._get_service_tenant_name(),
            'aodh::keystone::authtoken::region_name':
                self._keystone_region_name(),
            'aodh::keystone::authtoken::username': ksuser,

            'aodh::auth::auth_url':
                self._keystone_auth_uri(),
            'aodh::auth::auth_tenant_name':
                self._get_service_tenant_name(),
            # auth_region needs to be where ceilometer client queries data
            'aodh::auth::auth_region':
                self._region_name(),
            'aodh::auth::auth_user': ksuser,

            'openstack::aodh::params::region_name':
                self._get_service_region_name(self.SERVICE_NAME),
            'openstack::aodh::params::service_create':
                self._to_create_services(),
        }
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
            config.update({'openstack::aodh::params::service_enabled': False,
                           'aodh::keystone::auth::configure_endpoint': False})

        return config

    def get_secure_system_config(self):
        config = {
            'aodh::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
        }

        return config

    def get_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT)

    def get_internal_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)

    def get_admin_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)

    def _get_neutron_url(self):
        return self._operator.neutron.get_internal_url()
