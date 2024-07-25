#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.puppet import openstack


class DCAgentPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for dcagent configuration"""

    SERVICE_NAME = "dcagent"
    SERVICE_PORT = 8325
    SERVICE_PATH = "v1"
    IDENTITY_SERVICE_NAME = "keystone"
    IDENTITY_SERVICE_DB = "keystone"

    def get_static_config(self):
        return {}

    def get_secure_static_config(self):
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            "dcagent::keystone::auth::password": kspass,
            "dcagent::api::keystone_password": kspass,
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)
        bind_host, host = self._get_bind_host()

        config = {
            # The region in which the identity server can be found
            "dcagent::region_name": self._keystone_region_name(),
            "dcagent::keystone::auth::public_url": self.get_public_url(),
            "dcagent::keystone::auth::internal_url": self.get_internal_url(),
            "dcagent::keystone::auth::admin_url": self.get_admin_url(),
            "dcagent::keystone::auth::region": self._region_name(),
            "dcagent::keystone::auth::auth_name": ksuser,
            "dcagent::keystone::auth::auth_domain": self._get_service_user_domain_name(),
            "dcagent::keystone::auth::service_name": self.SERVICE_NAME,
            "dcagent::keystone::auth::tenant": self._get_service_tenant_name(),
            "dcagent::keystone::auth::distributed_cloud_role": self._distributed_cloud_role(),
            "dcagent::api::bind_host": bind_host,
            "dcagent::api::keystone_auth_uri": self._keystone_auth_uri(host),
            "dcagent::api::keystone_identity_uri": self._keystone_identity_uri(host),
            "dcagent::api::keystone_tenant": self._get_service_project_name(),
            "dcagent::api::keystone_user_domain": self._get_service_user_domain_name(),
            "dcagent::api::keystone_project_domain": self._get_service_project_domain_name(),
            "dcagent::api::keystone_user": ksuser,
            "platform::dcagent::params::region_name": self.get_region_name(),
            "platform::dcagent::params::service_create": self._to_create_services(),
        }

        return config

    def get_secure_system_config(self):
        kspass = self._get_service_password(self.SERVICE_NAME)

        config = {
            "dcagent::keystone::auth::password": kspass,
            "dcagent::api::keystone_password": kspass,
        }

        return config

    def get_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT, path=self.SERVICE_PATH)

    def get_internal_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT, path=self.SERVICE_PATH)

    def get_admin_url(self):
        return self._format_admin_endpoint(
            self.SERVICE_PORT,
            address=self._get_subcloud_endpoint_address(),
            path=self.SERVICE_PATH,
        )

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)
