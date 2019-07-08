#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.puppet import openstack

from sysinv.common import constants


class SystemInventoryPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for sysinv configuration"""

    SERVICE_NAME = 'sysinv'
    SERVICE_PORT = 6385
    SERVICE_PATH = 'v1'

    OPENSTACK_KEYRING_SERVICE = 'CGCS'

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)

        return {
            'sysinv::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        # initial bootstrap is bound to localhost
        dburl = self._format_database_connection(self.SERVICE_NAME,
                                                 constants.LOCALHOST_HOSTNAME)

        return {
            'sysinv::database_connection': dburl,

            'sysinv::db::postgresql::password': dbpass,

            'sysinv::keystone::auth::password': kspass,

            'sysinv::api::keystone_password': kspass,
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)
        neutron_region_name = self._operator.neutron.get_region_name()
        nova_region_name = self._operator.nova.get_region_name()
        barbican_region_name = self._operator.barbican.get_region_name()

        return {
            # The region in which the identity server can be found
            'sysinv::region_name': self._keystone_region_name(),
            'sysinv::neutron_region_name': neutron_region_name,
            'sysinv::nova_region_name': nova_region_name,
            'sysinv::barbican_region_name': barbican_region_name,

            'sysinv::keystone::auth::public_url': self.get_public_url(),
            'sysinv::keystone::auth::internal_url': self.get_internal_url(),
            'sysinv::keystone::auth::admin_url': self.get_admin_url(),
            'sysinv::keystone::auth::region': self._region_name(),
            'sysinv::keystone::auth::auth_name': ksuser,
            'sysinv::keystone::auth::service_name': self.SERVICE_NAME,
            'sysinv::keystone::auth::tenant': self._get_service_tenant_name(),

            'sysinv::api::bind_host': self._get_management_address(),
            'sysinv::api::pxeboot_host': self._get_pxeboot_address(),
            'sysinv::api::keystone_auth_uri': self._keystone_auth_uri(),
            'sysinv::api::keystone_identity_uri':
                self._keystone_identity_uri(),
            'sysinv::api::keystone_tenant': self._get_service_project_name(),
            'sysinv::api::keystone_user_domain':
                self._get_service_user_domain_name(),
            'sysinv::api::keystone_project_domain':
                self._get_service_project_domain_name(),
            'sysinv::api::keystone_user': ksuser,

            'openstack::sysinv::params::region_name': self.get_region_name(),
            'platform::sysinv::params::service_create':
                self._to_create_services(),

            'sysinv::api::openstack_keystone_auth_uri':
                self._keystone_auth_uri(),
            'sysinv::api::openstack_keystone_identity_uri':
                self._keystone_identity_uri(),
            'sysinv::api::openstack_keystone_user_domain':
                self._operator.keystone.get_admin_user_domain(),
            'sysinv::api::openstack_keystone_project_domain':
                self._operator.keystone.get_admin_project_domain(),
            'sysinv::api::openstack_keystone_user':
                self._operator.keystone.get_admin_user_name(),
            'sysinv::api::openstack_keystone_tenant':
                self._operator.keystone.get_admin_project_name(),
            'sysinv::api::openstack_keyring_service':
                self.OPENSTACK_KEYRING_SERVICE
        }

    def get_secure_system_config(self):
        return {
            'sysinv::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
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
