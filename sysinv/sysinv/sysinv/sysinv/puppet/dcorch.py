#
# Copyright (c) 2018-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import utils

from sysinv.helm import helm
from sysinv.puppet import openstack


class DCOrchPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for dcorch configuration"""

    SERVICE_NAME = 'dcorch'
    SERVICE_PORT = 8118
    SERVICE_PATH = 'v1.0'

    ADMIN_SERVICE = 'CGCS'
    ADMIN_TENANT = 'admin'
    ADMIN_USER = 'admin'

    COMPUTE_SERVICE_PORT = 28774
    COMPUTE_SERVICE_PATH = 'v2.1/%(tenant_id)s'
    NETWORKING_SERVICE_PORT = 29696
    NETWORKING_SERVICE_PATH = ''
    PLATFORM_SERVICE_PORT = 26385
    PLATFORM_SERVICE_PATH = 'v1'
    CINDER_SERVICE_PATH_V2 = 'v2/%(tenant_id)s'
    CINDER_SERVICE_PATH_V3 = 'v3/%(tenant_id)s'
    CINDER_SERVICE_PORT = 28776
    PATCHING_SERVICE_PORT = 25491
    PATCHING_SERVICE_PATH = ''
    NFV_SERVICE_PORT = 4545
    NFV_SERVICE_PATH = ''
    IDENTITY_SERVICE_PORT = 25000
    IDENTITY_SERVICE_PATH = 'v3'

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)

        return {
            'dcorch::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)
        admin_password = self._get_keyring_password(self.ADMIN_SERVICE,
                                                    self.ADMIN_USER)
        dm_kspass = self._operator.dcmanager.get_ks_user_password()

        # initial bootstrap is bound to localhost
        dburl = self._format_database_connection(self.SERVICE_NAME,
                                                 constants.LOCALHOST_HOSTNAME)

        return {
            'dcorch::database_connection': dburl,

            'dcorch::db::postgresql::password': dbpass,

            'dcorch::keystone::auth::password': kspass,

            'dcorch::api_proxy::keystone_password': kspass,

            'dcorch::api_proxy::keystone_admin_password': admin_password,

            'dcorch::api_proxy::dcmanager_keystone_password': dm_kspass,
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)
        dm_ksuser = self._operator.dcmanager.get_ks_user_name()

        config = {
            # The region in which the identity server can be found
            'dcorch::region_name': self._keystone_region_name(),
            'dcorch::keystone::auth::neutron_proxy_internal_url':
                self.get_proxy_internal_url(self.NETWORKING_SERVICE_PORT,
                                            self.NETWORKING_SERVICE_PATH),
            'dcorch::keystone::auth::nova_proxy_internal_url':
                self.get_proxy_internal_url(self.COMPUTE_SERVICE_PORT,
                                            self.COMPUTE_SERVICE_PATH),
            'dcorch::keystone::auth::sysinv_proxy_internal_url':
                self.get_proxy_internal_url(self.PLATFORM_SERVICE_PORT,
                                            self.PLATFORM_SERVICE_PATH),
            'dcorch::keystone::auth::cinder_proxy_internal_url_v2':
                self.get_proxy_internal_url(self.CINDER_SERVICE_PORT,
                                            self.CINDER_SERVICE_PATH_V2),
            'dcorch::keystone::auth::cinder_proxy_internal_url_v3':
                self.get_proxy_internal_url(self.CINDER_SERVICE_PORT,
                                            self.CINDER_SERVICE_PATH_V3),
            'dcorch::keystone::auth::patching_proxy_internal_url':
                self.get_proxy_internal_url(self.PATCHING_SERVICE_PORT,
                                            self.PATCHING_SERVICE_PATH),
            'dcorch::keystone::auth::identity_proxy_internal_url':
                self.get_proxy_internal_url(self.IDENTITY_SERVICE_PORT,
                                            self.IDENTITY_SERVICE_PATH),
            'dcorch::keystone::auth::neutron_proxy_public_url':
                self.get_proxy_public_url(self.NETWORKING_SERVICE_PORT,
                                          self.NETWORKING_SERVICE_PATH),
            'dcorch::keystone::auth::nova_proxy_public_url':
                self.get_proxy_public_url(self.COMPUTE_SERVICE_PORT,
                                          self.COMPUTE_SERVICE_PATH),
            'dcorch::keystone::auth::sysinv_proxy_public_url':
                self.get_proxy_public_url(self.PLATFORM_SERVICE_PORT,
                                          self.PLATFORM_SERVICE_PATH),
            'dcorch::keystone::auth::cinder_proxy_public_url_v2':
                self.get_proxy_public_url(self.CINDER_SERVICE_PORT,
                                          self.CINDER_SERVICE_PATH_V2),
            'dcorch::keystone::auth::cinder_proxy_public_url_v3':
                self.get_proxy_public_url(self.CINDER_SERVICE_PORT,
                                          self.CINDER_SERVICE_PATH_V3),
            'dcorch::keystone::auth::patching_proxy_public_url':
                self.get_proxy_public_url(self.PATCHING_SERVICE_PORT,
                                          self.PATCHING_SERVICE_PATH),
            'dcorch::keystone::auth::nfv_proxy_public_url':
                self.get_proxy_public_url(self.NFV_SERVICE_PORT,
                                          self.NFV_SERVICE_PATH),
            'dcorch::keystone::auth::identity_proxy_public_url':
                self.get_proxy_public_url(self.IDENTITY_SERVICE_PORT,
                                          self.IDENTITY_SERVICE_PATH),

            'dcorch::keystone::auth::sysinv_proxy_admin_url':
                self.get_proxy_admin_url(self.PLATFORM_SERVICE_PORT,
                                         self.PLATFORM_SERVICE_PATH),
            'dcorch::keystone::auth::identity_proxy_admin_url':
                self.get_proxy_admin_url(self.IDENTITY_SERVICE_PORT,
                                         self.IDENTITY_SERVICE_PATH),
            'dcorch::keystone::auth::patching_proxy_admin_url':
                self.get_proxy_admin_url(self.PATCHING_SERVICE_PORT,
                                         self.PATCHING_SERVICE_PATH),

            'dcorch::keystone::auth::region': self.get_region_name(),
            'dcorch::keystone::auth::auth_name': ksuser,
            'dcorch::keystone::auth::service_name': self.SERVICE_NAME,
            'dcorch::keystone::auth::tenant': self._get_service_tenant_name(),

            'dcorch::api_proxy::bind_host': self._get_management_address(),
            'dcorch::api_proxy::keystone_auth_uri': self._keystone_auth_uri(),
            'dcorch::api_proxy::keystone_identity_uri':
                self._keystone_identity_uri(),
            'dcorch::api_proxy::keystone_tenant': self._get_service_project_name(),
            'dcorch::api_proxy::keystone_user_domain':
                self._get_service_user_domain_name(),
            'dcorch::api_proxy::keystone_project_domain':
                self._get_service_project_domain_name(),
            'dcorch::api_proxy::keystone_user': ksuser,
            'dcorch::api_proxy::dcmanager_keystone_user': dm_ksuser,
            'dcorch::api_proxy::keystone_admin_user': self.ADMIN_USER,
            'dcorch::api_proxy::keystone_admin_tenant': self.ADMIN_TENANT,
            'openstack::dcorch::params::region_name': self.get_region_name(),
            'platform::dcorch::params::service_create':
                self._to_create_services(),
        }

        if utils.is_openstack_applied(self.dbapi):
            is_upgrading, upgrade = utils.is_upgrade_in_progress(self.dbapi)
            if is_upgrading:
                old_config = self._operator.read_system_config(upgrade.from_release)
                keys_to_copy = [
                    'dcorch::stx_openstack::keystone_identity_uri',
                    'dcorch::stx_openstack::keystone_admin_user',
                    'dcorch::stx_openstack::keystone_admin_tenant',
                ]
                for key in keys_to_copy:
                    config[key] = old_config.get(key)
            else:
                helm_data = helm.HelmOperatorData(self.dbapi)
                endpoints_data = helm_data.get_keystone_endpoint_data()
                auth_data = helm_data.get_keystone_auth_data()

                app_config = {
                    'dcorch::stx_openstack::'
                    'keystone_identity_uri':
                        endpoints_data['endpoint_override'],
                    'dcorch::stx_openstack::'
                    'keystone_admin_user':
                        auth_data['admin_user_name'],
                    'dcorch::stx_openstack::'
                    'keystone_admin_tenant':
                        auth_data['admin_project_name'],
                }
                config.update(app_config)

        return config

    def get_secure_system_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)
        admin_password = self._get_keyring_password(self.ADMIN_SERVICE,
                                                    self.ADMIN_USER)
        dm_kspass = self._operator.dcmanager.get_ks_user_password()

        config = {
            'dcorch::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
            'dcorch::db::postgresql::password': dbpass,
            'dcorch::keystone::auth::password': kspass,
            'dcorch::api_proxy::keystone_password': kspass,
            'dcorch::api_proxy::keystone_admin_password': admin_password,
            'dcorch::api_proxy::dcmanager_keystone_password': dm_kspass,
        }

        if utils.is_openstack_applied(self.dbapi):
            is_upgrading, upgrade = utils.is_upgrade_in_progress(self.dbapi)
            if is_upgrading:
                old_config = self._operator.read_secure_system_config(upgrade.from_release)
                keys_to_copy = [
                    'dcorch::stx_openstack::keystone_admin_password'
                ]
                for key in keys_to_copy:
                    config[key] = old_config.get(key)
            else:
                helm_data = helm.HelmOperatorData(self.dbapi)
                auth_data = helm_data.get_keystone_auth_data()
                app_auth_config = {
                    'dcorch::stx_openstack::'
                    'keystone_admin_password':
                        auth_data['admin_password'],
                }
                config.update(app_auth_config)

        return config

    def get_public_url(self):
        pass

    def get_internal_url(self):
        pass

    def get_admin_url(self):
        pass

    def get_proxy_internal_url(self, port, service_path):
        return self._format_private_endpoint(port, path=service_path)

    def get_proxy_public_url(self, port, service_path):
        return self._format_public_endpoint(port, path=service_path)

    def get_proxy_admin_url(self, port, service_path):
        return self._format_admin_endpoint(port, path=service_path)

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)
