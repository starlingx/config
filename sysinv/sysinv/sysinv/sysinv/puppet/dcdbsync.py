#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.puppet import openstack


class DCDBsyncPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for dcdbsync
     configuration"""

    SERVICE_NAME = 'dcdbsync'
    SERVICE_PORT = 8219
    SERVICE_PATH = 'v1.0'
    IDENTITY_SERVICE_NAME = 'keystone'
    IDENTITY_SERVICE_DB = 'keystone'

    def get_static_config(self):
        dbuser = self._get_database_username(self.IDENTITY_SERVICE_NAME)

        return {
            'dcdbsync::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.IDENTITY_SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        # initial bootstrap is bound to localhost
        dburl = self._format_database_connection(self.IDENTITY_SERVICE_NAME,
                                                 constants.LOCALHOST_HOSTNAME,
                                                 database=self.IDENTITY_SERVICE_DB)
        return {
            'dcdbsync::database_connection': dburl,
            'dcdbsync::db::postgresql::password': dbpass,
            'dcdbsync::keystone::auth::password': kspass,
            'dcdbsync::api::keystone_password': kspass,
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)

        return {
            # The region in which the identity server can be found
            'dcdbsync::region_name': self._keystone_region_name(),

            'dcdbsync::keystone::auth::public_url': self.get_public_url(),
            'dcdbsync::keystone::auth::internal_url': self.get_internal_url(),
            'dcdbsync::keystone::auth::admin_url': self.get_admin_url(),
            'dcdbsync::keystone::auth::region': self._region_name(),
            'dcdbsync::keystone::auth::auth_name': ksuser,
            'dcdbsync::keystone::auth::auth_domain':
                self._get_service_user_domain_name(),
            'dcdbsync::keystone::auth::service_name': self.SERVICE_NAME,
            'dcdbsync::keystone::auth::tenant': self._get_service_tenant_name(),
            'dcdbsync::api::bind_host': self._get_management_address(),
            'dcdbsync::api::keystone_auth_uri': self._keystone_auth_uri(),
            'dcdbsync::api::keystone_identity_uri':
                self._keystone_identity_uri(),
            'dcdbsync::api::keystone_tenant': self._get_service_project_name(),
            'dcdbsync::api::keystone_user_domain':
                self._get_service_user_domain_name(),
            'dcdbsync::api::keystone_project_domain':
                self._get_service_project_domain_name(),
            'dcdbsync::api::keystone_user': ksuser,
            'platform::dcdbsync::params::region_name': self.get_region_name(),
            'platform::dcdbsync::params::service_create':
                self._to_create_services(),
        }

    def get_secure_system_config(self):
        dbpass = self._get_database_password(self.IDENTITY_SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'dcdbsync::database_connection':
                self._format_database_connection(
                    self.IDENTITY_SERVICE_NAME,
                    database=self.IDENTITY_SERVICE_DB),
            'dcdbsync::db::postgresql::password': dbpass,
            'dcdbsync::keystone::auth::password': kspass,
            'dcdbsync::api::keystone_password': kspass,
        }

    def get_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT,
                                            path=self.SERVICE_PATH)

    def get_internal_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT,
                                             path=self.SERVICE_PATH)

    def get_admin_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT,
                                             path=self.SERVICE_PATH)

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)
