#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.puppet import openstack
from sysinv.common import constants


class HeatPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for heat configuration"""

    SERVICE_NAME = 'heat'
    SERVICE_PORT = 8004
    SERVICE_PORT_CFN = 8000
    SERVICE_PORT_CLOUDWATCH = 8003
    SERVICE_PATH = 'v1/%(tenant_id)s'
    SERVICE_PATH_WAITCONDITION = 'v1/waitcondition'

    DEFAULT_DOMAIN_NAME = 'heat'
    DEFAULT_STACK_ADMIN = 'heat_admin'
    SERVICE_NAME_DOMAIN = 'heat-domain'

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)

        return {
            'heat::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)
        dkspass = self._get_service_password(self.SERVICE_NAME_DOMAIN)

        return {
            'heat::db::postgresql::password': dbpass,

            'heat::keystone::auth::password': kspass,

            'heat::keystone::auth_cfn::password': kspass,
            'heat::keystone::authtoken::password': kspass,

            'heat::keystone::domain::domain_password': dkspass,

            'heat::engine::auth_encryption_key':
                self._generate_random_password(length=32),

            'openstack::heat::params::domain_pwd': dkspass,
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)
        config = {
            'heat::keystone_ec2_uri': self._operator.keystone.get_auth_url(),
            'heat::region_name': self.get_region_name(),

            'heat::engine::heat_metadata_server_url':
                self._get_metadata_url(),
            'heat::engine::heat_waitcondition_server_url':
                self._get_waitcondition_url(),
            'heat::engine::heat_watch_server_url':
                self._get_cloudwatch_url(),

            'heat::keystone::domain::domain_name': self._get_stack_domain(),
            'heat::keystone::domain::domain_admin': self._get_stack_admin(),

            'heat::keystone::auth::region': self.get_region_name(),
            'heat::keystone::auth::public_url': self.get_public_url(),
            'heat::keystone::auth::internal_url': self.get_internal_url(),
            'heat::keystone::auth::admin_url': self.get_admin_url(),
            'heat::keystone::auth::auth_name': ksuser,
            'heat::keystone::auth::tenant': self._get_service_tenant_name(),

            'heat::keystone::auth_cfn::region':
                self.get_region_name(),
            'heat::keystone::auth_cfn::public_url':
                self.get_public_url_cfn(),
            'heat::keystone::auth_cfn::internal_url':
                self.get_internal_url_cfn(),
            'heat::keystone::auth_cfn::admin_url':
                self.get_admin_url_cfn(),
            'heat::keystone::auth_cfn::auth_name': ksuser,
            'heat::keystone::auth_cfn::tenant':
                self._get_service_tenant_name(),

            'heat::keystone::authtoken::auth_url':
                self._keystone_identity_uri(),
            'heat::keystone::authtoken::auth_uri':
                self._keystone_auth_uri(),
            'heat::keystone::authtoken::user_domain_name':
                self._get_service_user_domain_name(),
            'heat::keystone::authtoken::project_domain_name':
                self._get_service_project_domain_name(),
            'heat::keystone::authtoken::project_name':
                self._get_service_tenant_name(),
            'heat::keystone::authtoken::username': ksuser,

            'openstack::heat::params::domain_name': self._get_stack_domain(),
            'openstack::heat::params::domain_admin': self._get_stack_admin(),
            'openstack::heat::params::region_name': self.get_region_name(),
            'openstack::heat::params::domain_pwd':
                self._get_service_password(self.SERVICE_NAME_DOMAIN),
            'openstack::heat::params::service_tenant':
                self._get_service_tenant_name(),
            'openstack::heat::params::service_create':
                self._to_create_services(),
        }

        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
            config.update({'openstack::heat::params::service_enabled': False,
                           'heat::keystone::auth::configure_endpoint': False,
                           'heat::keystone::auth_cfn::configure_endpoint':
                               False})

        return config

    def get_secure_system_config(self):
        config = {
            'heat::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
        }

        return config

    def get_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT,
                                            path=self.SERVICE_PATH)

    def get_internal_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT,
                                             path=self.SERVICE_PATH)

    def get_admin_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT,
                                             path=self.SERVICE_PATH)

    def get_public_url_cfn(self):
        return self._format_public_endpoint(self.SERVICE_PORT_CFN,
                                            path=self.SERVICE_PATH)

    def get_internal_url_cfn(self):
        return self._format_private_endpoint(self.SERVICE_PORT_CFN,
                                             path=self.SERVICE_PATH)

    def get_admin_url_cfn(self):
        return self._format_private_endpoint(self.SERVICE_PORT_CFN,
                                             path=self.SERVICE_PATH)

    def _get_metadata_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT_CFN)

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)

    def _get_waitcondition_url(self):
        return self._format_public_endpoint(
            self.SERVICE_PORT_CFN, path=self.SERVICE_PATH_WAITCONDITION)

    def _get_cloudwatch_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT_CLOUDWATCH)

    def _get_stack_domain(self):
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)
            if service_config is not None:
                return service_config.capabilities.get('admin_domain_name')
        return self.DEFAULT_DOMAIN_NAME

    def _get_stack_admin(self):
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)
            if service_config is not None:
                return service_config.capabilities.get('admin_user_name')
        return self.DEFAULT_STACK_ADMIN
