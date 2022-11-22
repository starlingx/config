#
# Copyright (c) 2017-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants

from sysinv.puppet import openstack


class PatchingPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for patching configuration"""

    SERVICE_NAME = 'patching'
    SERVICE_PORT = 5491
    SERVICE_PUBLIC_PORT = 15491
    SERVICE_KS_USERNAME = 'patching'

    def get_static_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)

        return {
            'patching::api::keystone_user': ksuser,
        }

    def get_secure_static_config(self):
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'patching::api::keystone_password': kspass,
            'patching::keystone::auth::password': kspass,
            'patching::keystone::authtoken::password': kspass,
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)
        patch_keystone_auth_uri = self._keystone_auth_uri()
        patch_keystone_identity_uri = self._keystone_identity_uri()
        controller_multicast = self._get_address_by_name(
            constants.PATCH_CONTROLLER_MULTICAST_MGMT_IP_NAME,
            constants.NETWORK_TYPE_MULTICAST)
        agent_multicast = self._get_address_by_name(
            constants.PATCH_AGENT_MULTICAST_MGMT_IP_NAME,
            constants.NETWORK_TYPE_MULTICAST)

        return {
            'patching::api::keystone_user': ksuser,
            'patching::api::keystone_tenant': self._get_service_tenant_name(),
            'patching::api::keystone_auth_uri': patch_keystone_auth_uri,
            'patching::api::keystone_identity_uri': patch_keystone_identity_uri,
            'patching::api::keystone_region_name':
                self._get_service_region_name(self.SERVICE_NAME),

            'patching::api::keystone_user_domain':
                self._get_service_user_domain_name(),
            'patching::api::keystone_project_domain':
                self._get_service_project_domain_name(),
            'patching::api::bind_host':
                self._get_management_address(),

            'patching::keystone::auth::public_url': self.get_public_url(),
            'patching::keystone::auth::internal_url': self.get_internal_url(),
            'patching::keystone::auth::admin_url': self.get_admin_url(),
            'patching::keystone::auth::auth_name': ksuser,
            'patching::keystone::auth::service_name': self.SERVICE_NAME,
            'patching::keystone::auth::region':
                self._get_service_region_name(self.SERVICE_NAME),
            'patching::keystone::auth::tenant': self._get_service_tenant_name(),

            'patching::keystone::authtoken::auth_url':
                self._keystone_identity_uri(),
            'patching::keystone::authtoken::auth_uri':
                self._keystone_auth_uri(),

            'patching::controller_multicast': controller_multicast.address,
            'patching::agent_multicast': agent_multicast.address,

            'openstack::patching::params::region_name': self.get_region_name(),
            'platform::patching::params::service_create':
                self._to_create_services(),
        }

    def get_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PUBLIC_PORT)

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
