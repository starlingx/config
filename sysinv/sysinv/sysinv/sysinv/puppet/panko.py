#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import subprocess

from sysinv.common import exception
from sysinv.common import constants

from . import openstack


class PankoPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for panko configuration"""

    SERVICE_NAME = 'panko'
    SERVICE_PORT = 8977

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'panko::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'panko::db::postgresql::password': dbpass,

            'panko::keystone::auth::password': kspass,
            'panko::keystone::authtoken::password': kspass,
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)

        config = {
            'panko::keystone::auth::region':
                self._get_service_region_name(self.SERVICE_NAME),
            'panko::keystone::auth::public_url': self.get_public_url(),
            'panko::keystone::auth::internal_url': self.get_internal_url(),
            'panko::keystone::auth::admin_url': self.get_admin_url(),
            'panko::keystone::auth::auth_name': ksuser,
            'panko::keystone::auth::tenant': self._get_service_tenant_name(),

            'panko::keystone::authtoken::auth_url':
                self._keystone_identity_uri(),
            'panko::keystone::authtoken::auth_uri':
                self._keystone_auth_uri(),
            'panko::keystone::authtoken::user_domain_name':
                self._get_service_user_domain_name(),
            'panko::keystone::authtoken::project_domain_name':
                self._get_service_project_domain_name(),
            'panko::keystone::authtoken::project_name':
                self._get_service_tenant_name(),
            'panko::keystone::authtoken::region_name':
                self._keystone_region_name(),
            'panko::keystone::authtoken::username': ksuser,

            'openstack::panko::params::region_name':
                self._get_service_region_name(self.SERVICE_NAME),
            'openstack::panko::params::service_create':
                self._to_create_services(),
        }
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
            config.update({'openstack::panko::params::service_enabled': False,
                           'panko::keystone::auth::configure_endpoint': False})

        return config

    def get_secure_system_config(self):
        config = {
            'panko::db::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
        }

        return config

    def get_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT)

    def get_internal_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)

    def get_admin_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)
