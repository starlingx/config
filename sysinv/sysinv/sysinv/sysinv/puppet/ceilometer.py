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


class CeilometerPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for ceilometer configuration"""

    SERVICE_NAME = 'ceilometer'
    SERVICE_PORT = 8777

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)

        return {
            'ceilometer::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'ceilometer::db::postgresql::password': dbpass,

            'ceilometer::keystone::auth::password': kspass,
            'ceilometer::keystone::authtoken::password': kspass,

            'ceilometer::agent::auth::auth_password': kspass,
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)

        config = {
            'ceilometer::keystone::auth::public_url': self.get_public_url(),
            'ceilometer::keystone::auth::internal_url': self.get_internal_url(),
            'ceilometer::keystone::auth::admin_url': self.get_admin_url(),
            'ceilometer::keystone::auth::auth_name': ksuser,
            'ceilometer::keystone::auth::region': self._region_name(),
            'ceilometer::keystone::auth::tenant': self._get_service_tenant_name(),

            'ceilometer::keystone::authtoken::auth_url':
                self._keystone_identity_uri(),
            'ceilometer::keystone::authtoken::auth_uri':
                self._keystone_auth_uri(),
            'ceilometer::keystone::authtoken::user_domain_name':
                self._get_service_user_domain_name(),
            'ceilometer::keystone::authtoken::project_domain_name':
                self._get_service_project_domain_name(),
            'ceilometer::keystone::authtoken::project_name':
                self._get_service_tenant_name(),
            'ceilometer::keystone::authtoken::region_name':
                self._keystone_region_name(),
            'ceilometer::keystone::authtoken::username': ksuser,

            'ceilometer::agent::auth::auth_url':
                self._keystone_auth_uri(),
            'ceilometer::agent::auth::auth_user': ksuser,
            'ceilometer::agent::auth::auth_user_domain_name':
                self._get_service_user_domain_name(),
            'ceilometer::agent::auth::auth_project_domain_name':
                self._get_service_project_domain_name(),
            'ceilometer::agent::auth::auth_tenant_name':
                self._get_service_tenant_name(),
            'ceilometer::agent::auth::auth_region':
                self._keystone_region_name(),

            'openstack::ceilometer::params::region_name':
                self.get_region_name(),
            'openstack::ceilometer::params::service_create':
                self._to_create_services(),
        }
        return config

    def get_secure_system_config(self):
        config = {
            'ceilometer::db::database_connection':
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

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)
