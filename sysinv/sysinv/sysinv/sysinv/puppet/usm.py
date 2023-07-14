#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from sysinv.common import constants
from sysinv.puppet import openstack


class UnifiedSoftwareManagementPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for Unified Software Management
       (USM) configuration"""

    SERVICE_NAME = 'usm'
    SERVICE_PORT = 5497
    SERVICE_PUBLIC_PORT = 15497
    SERVICE_KS_USERNAME = 'usm'

    def get_static_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)

        return {
            'usm::api::keystone_user': ksuser,
        }

    def get_secure_static_config(self):
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'usm::api::keystone_password': kspass,
            'usm::keystone::auth::password': kspass,
            'usm::keystone::authtoken::password': kspass,
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)
        usm_keystone_auth_uri = self._keystone_auth_uri()
        usm_keystone_identity_uri = self._keystone_identity_uri()
        controller_multicast = self._get_address_by_name(
            constants.PATCH_CONTROLLER_MULTICAST_MGMT_IP_NAME,
            constants.NETWORK_TYPE_MULTICAST)
        agent_multicast = self._get_address_by_name(
            constants.PATCH_AGENT_MULTICAST_MGMT_IP_NAME,
            constants.NETWORK_TYPE_MULTICAST)

        return {
            'usm::api::keystone_user': ksuser,
            'usm::api::keystone_tenant': self._get_service_tenant_name(),
            'usm::api::keystone_auth_uri': usm_keystone_auth_uri,
            'usm::api::keystone_identity_uri': usm_keystone_identity_uri,
            'usm::api::keystone_region_name':
                self._get_service_region_name(self.SERVICE_NAME),

            'usm::api::keystone_user_domain':
                self._get_service_user_domain_name(),
            'usm::api::keystone_project_domain':
                self._get_service_project_domain_name(),
            'usm::api::bind_host':
                self._get_management_address(),

            'usm::keystone::auth::public_url': self.get_public_url(),
            'usm::keystone::auth::internal_url': self.get_internal_url(),
            'usm::keystone::auth::admin_url': self.get_admin_url(),
            'usm::keystone::auth::auth_name': ksuser,
            'usm::keystone::auth::service_name': self.SERVICE_NAME,
            'usm::keystone::auth::region':
                self._get_service_region_name(self.SERVICE_NAME),
            'usm::keystone::auth::tenant': self._get_service_tenant_name(),

            'usm::keystone::authtoken::auth_url':
                self._keystone_identity_uri(),
            'usm::keystone::authtoken::auth_uri':
                self._keystone_auth_uri(),

            'usm::controller_multicast': controller_multicast.address,
            'usm::agent_multicast': agent_multicast.address,

            'openstack::usm::params::region_name': self.get_region_name(),
            'platform::usm::params::service_create':
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
