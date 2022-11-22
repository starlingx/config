#
# Copyright (c) 2018-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.puppet import openstack


class BarbicanPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for barbican configuration"""

    SERVICE_NAME = 'barbican'
    SERVICE_PORT = 9311

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)

        return {
            'barbican::db::postgresql::user': dbuser,
            'barbican::keystone::authtoken::region_name':
                self._keystone_region_name(),
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        # initial bootstrap is bound to localhost
        dburl = self._format_database_connection(self.SERVICE_NAME,
                                                 constants.LOCALHOST_HOSTNAME)

        return {
            'barbican::db::database_connection': dburl,
            'barbican::db::postgresql::password': dbpass,

            'barbican::keystone::auth::password': kspass,
            'barbican::keystone::authtoken::password': kspass,
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)

        config = {
            'barbican::keystone::auth::public_url': self.get_public_url(),
            'barbican::keystone::auth::internal_url': self.get_internal_url(),
            'barbican::keystone::auth::admin_url': self.get_admin_url(),
            'barbican::keystone::auth::auth_name': ksuser,
            'barbican::keystone::auth::region': self._region_name(),
            'barbican::keystone::auth::tenant': self._get_service_tenant_name(),
            'barbican::keystone::auth::configure_user_role': False,

            'barbican::keystone::authtoken::auth_url':
                self._keystone_identity_uri(),
            'barbican::keystone::authtoken::auth_uri':
                self._keystone_auth_uri(),

            'barbican::keystone::authtoken::user_domain_name':
                self._get_service_user_domain_name(),
            'barbican::keystone::authtoken::project_domain_name':
                self._get_service_project_domain_name(),
            'barbican::keystone::authtoken::project_name':
                self._get_service_project_name(),
            'barbican::keystone::authtoken::region_name':
                self._keystone_region_name(),
            'barbican::keystone::authtoken::username': ksuser,

            'openstack::barbican::params::region_name':
                self._get_service_region_name(self.SERVICE_NAME),
            'openstack::barbican::params::service_create':
                self._to_create_services(),
        }

        return config

    def get_secure_system_config(self):
        config = {
            'barbican::db::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
        }

        return config

    def get_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT)

    def get_internal_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)

    def get_admin_url(self):
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
            return self._format_admin_endpoint(
                self.SERVICE_PORT,
                address=self._get_subcloud_endpoint_address())
        else:
            return self._format_admin_endpoint(self.SERVICE_PORT)

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)
