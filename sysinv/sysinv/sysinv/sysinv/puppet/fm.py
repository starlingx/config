#
# Copyright (c) 2018-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


import yaml

from sysinv.common import constants
from sysinv.common import utils
from sysinv.puppet import openstack


class FmPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for fm configuration"""

    SERVICE_NAME = 'fm'
    SERVICE_PORT = 18002
    BOOTSTRAP_MGMT_IP = '127.0.0.1'
    TRAP_SERVER_DEFAULT_PORT = 162
    TRAP_SERVER_PORT_CONFIG_KEY = 'trap-server-port'
    SNMP_CHART_NAME = 'snmp'
    SNMP_NAME_SPACE = 'kube-system'

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)
        return {
            'fm::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'fm::db::postgresql::password': dbpass,
            'fm::keystone::auth::password': kspass,
            'fm::keystone::authtoken::password': kspass,
            'fm::auth::auth_password': kspass,
            'fm::database_connection':
                self._format_database_connection(self.SERVICE_NAME,
                                                 self.BOOTSTRAP_MGMT_IP),
        }

    def get_system_config(self):
        ksuser = self._get_service_user_name(self.SERVICE_NAME)
        system = self.dbapi.isystem_get_one()
        if utils.is_app_applied(self.dbapi, constants.HELM_APP_SNMP):
            snmp_enabled_value = 1    # True
            snmp_trap_server_port = self.get_snmp_trap_port()
        else:
            snmp_enabled_value = 0    # False
            snmp_trap_server_port = self.TRAP_SERVER_DEFAULT_PORT

        config = {
            'fm::keystone::auth::public_url': self.get_public_url(),
            'fm::keystone::auth::internal_url': self.get_internal_url(),
            'fm::keystone::auth::admin_url': self.get_admin_url(),
            'fm::keystone::auth::auth_name': ksuser,
            'fm::keystone::auth::region': self.get_region_name(),
            'fm::keystone::auth::tenant': self._get_service_tenant_name(),

            'fm::keystone::authtoken::auth_url':
                self._keystone_identity_uri(),
            'fm::keystone::authtoken::auth_uri':
                self._keystone_auth_uri(),

            'fm::keystone::authtoken::user_domain_name':
                self._get_service_user_domain_name(),
            'fm::keystone::authtoken::project_domain_name':
                self._get_service_project_domain_name(),
            'fm::keystone::authtoken::project_name':
                self._get_service_tenant_name(),
            'fm::keystone::authtoken::region_name':
                self._keystone_region_name(),
            'fm::keystone::authtoken::username': ksuser,

            'fm::auth::auth_url':
                self._keystone_auth_uri(),
            'fm::auth::auth_tenant_name':
                self._get_service_tenant_name(),

            'platform::fm::params::region_name': self._region_name(),
            'platform::fm::params::snmp_enabled': snmp_enabled_value,
            'platform::fm::params::snmp_trap_server_port':
                snmp_trap_server_port,
            'platform::fm::params::system_name': system.name,

            'platform::fm::params::service_create':
                self._to_create_services(),
        }

        return config

    def get_secure_system_config(self):
        config = {
            'fm::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
        }

        return config

    def get_host_config(self, host):
        config = {
            'platform::fm::params::api_host': host.mgmt_ip
        }
        return config

    def get_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT)

    def get_internal_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)

    def get_admin_url(self):
        return self._format_admin_endpoint(self.SERVICE_PORT)

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)

    def get_snmp_trap_port(self):
        """Obtain snmp trap server port from user helm override.
           If it is not configured, use the default port 162.
        """
        snmp_trap_port = self.TRAP_SERVER_DEFAULT_PORT

        db_app = self.dbapi.kube_app_get(constants.HELM_APP_SNMP)
        db_chart = self.dbapi.helm_override_get(db_app.id,
                                                self.SNMP_CHART_NAME,
                                                self.SNMP_NAME_SPACE)
        if db_chart is not None and db_chart.user_overrides is not None:
            user_overrides = yaml.load(db_chart.user_overrides)
            if self.TRAP_SERVER_PORT_CONFIG_KEY in user_overrides:
                snmp_trap_port = user_overrides[
                    self.TRAP_SERVER_PORT_CONFIG_KEY]
        return snmp_trap_port
