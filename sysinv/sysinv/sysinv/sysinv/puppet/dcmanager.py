#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from . import openstack

from sysinv.common import constants


class DCManagerPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for dcmanager configuration"""

    SERVICE_NAME = 'dcmanager'
    SERVICE_PORT = 8119
    SERVICE_PATH = 'v1.0'

    ADMIN_SERVICE = 'CGCS'
    ADMIN_TENANT = 'admin'
    ADMIN_USER = 'admin'

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)

        return {
            'dcmanager::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)
        admin_password = self._get_keyring_password(self.ADMIN_SERVICE,
                                                    self.ADMIN_USER)
        # initial bootstrap is bound to localhost
        dburl = self._format_database_connection(self.SERVICE_NAME,
                                                 constants.LOCALHOST_HOSTNAME)

        return {
            'dcmanager::database_connection': dburl,

            'dcmanager::db::postgresql::password': dbpass,

            'dcmanager::keystone::auth::password': kspass,

            'dcmanager::api::keystone_password': kspass,

            'dcmanager::api::keystone_admin_password': admin_password,
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)

        return {
            # The region in which the identity server can be found
            'dcmanager::region_name': self._keystone_region_name(),

            'dcmanager::keystone::auth::public_url': self.get_public_url(),
            'dcmanager::keystone::auth::internal_url': self.get_internal_url(),
            'dcmanager::keystone::auth::admin_url': self.get_admin_url(),
            'dcmanager::keystone::auth::region': constants.SYSTEM_CONTROLLER_REGION,
            'dcmanager::keystone::auth::auth_name': ksuser,
            'dcmanager::keystone::auth::auth_domain':
                self._get_service_user_domain_name(),
            'dcmanager::keystone::auth::service_name': self.SERVICE_NAME,
            'dcmanager::keystone::auth::tenant': self._get_service_tenant_name(),
            'dcmanager::keystone::auth::admin_project_name':
                self._operator.keystone.get_admin_project_name(),
            'dcmanager::keystone::auth::admin_project_domain':
                self._operator.keystone.get_admin_project_domain(),
            'dcmanager::api::bind_host': self._get_management_address(),
            'dcmanager::api::keystone_auth_uri': self._keystone_auth_uri(),
            'dcmanager::api::keystone_identity_uri':
                self._keystone_identity_uri(),
            'dcmanager::api::keystone_tenant': self._get_service_project_name(),
            'dcmanager::api::keystone_user_domain':
                self._get_service_user_domain_name(),
            'dcmanager::api::keystone_project_domain':
                self._get_service_project_domain_name(),
            'dcmanager::api::keystone_user': ksuser,
            'dcmanager::api::keystone_admin_user': self.ADMIN_USER,
            'dcmanager::api::keystone_admin_tenant': self.ADMIN_TENANT,
            'openstack::dcmanager::params::region_name': self.get_region_name(),
            'platform::dcmanager::params::service_create':
                self._to_create_services(),
        }

    def get_secure_system_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)
        admin_password = self._get_keyring_password(self.ADMIN_SERVICE,
                                                    self.ADMIN_USER)
        return {
            'dcmanager::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
            'dcmanager::db::postgresql::password': dbpass,

            'dcmanager::keystone::auth::password': kspass,

            'dcmanager::api::keystone_password': kspass,

            'dcmanager::api::keystone_admin_password': admin_password,
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
