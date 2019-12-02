#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from six.moves import configparser
import os

from sysinv.common import utils
from sysinv.common import constants

from tsconfig import tsconfig
from six.moves.urllib.parse import urlparse

from sysinv.puppet import openstack


OPENSTACK_PASSWORD_RULES_FILE = '/etc/keystone/password-rules.conf'


class KeystonePuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for keystone configuration"""

    SERVICE_NAME = 'keystone'
    SERVICE_TYPE = 'identity'
    SERVICE_PORT = 5000
    SERVICE_PATH = 'v3'

    ADMIN_SERVICE = 'CGCS'
    ADMIN_USER = 'admin'

    DEFAULT_DOMAIN_NAME = 'Default'

    def _region_config(self):
        # A wrapper over the Base region_config check.
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
            return False
        else:
            return super(KeystonePuppet, self)._region_config()

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)
        admin_username = self.get_admin_user_name()

        return {
            'keystone::db::postgresql::user': dbuser,
            'keystone::cache_enabled': True,
            'keystone::cache_backend': 'dogpile.cache.memcached',

            'platform::client::params::admin_username': admin_username,

            'platform::client::credentials::params::keyring_base':
                os.path.dirname(tsconfig.KEYRING_PATH),
            'platform::client::credentials::params::keyring_directory':
                tsconfig.KEYRING_PATH,
            'platform::client::credentials::params::keyring_file':
                os.path.join(tsconfig.KEYRING_PATH, '.CREDENTIAL'),
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)

        admin_password = self._get_keyring_password(self.ADMIN_SERVICE,
                                                    self.ADMIN_USER)
        admin_token = self._generate_random_password(length=32)

        # initial bootstrap is bound to localhost
        dburl = self._format_database_connection(self.SERVICE_NAME,
                                                 constants.LOCALHOST_HOSTNAME)

        return {
            'keystone::database_connection': dburl,

            'keystone::admin_password': admin_password,
            'keystone::admin_token': admin_token,

            'keystone::db::postgresql::password': dbpass,

            'keystone::roles::admin::password': admin_password,
            'platform::client::params::admin_password': admin_password,
        }

    def get_system_config(self):
        admin_username = self.get_admin_user_name()
        admin_project = self.get_admin_project_name()

        config = {
            'keystone::public_bind_host': self._get_management_address(),
            'keystone::admin_bind_host': self._get_management_address(),

            'keystone::endpoint::public_url': self.get_public_url(),
            'keystone::endpoint::internal_url': self.get_internal_url(),
            'keystone::endpoint::admin_url': self.get_admin_url(),
            'keystone::endpoint::region': self._region_name(),

            'keystone::roles::admin::admin': admin_username,

            'platform::client::params::admin_username': admin_username,
            'platform::client::params::admin_project_name': admin_project,
            'platform::client::params::admin_user_domain':
                self.get_admin_user_domain(),
            'platform::client::params::admin_project_domain':
                self.get_admin_project_domain(),
            'platform::client::params::identity_region': self._region_name(),
            'platform::client::params::identity_auth_url': self.get_auth_url(),
            'platform::client::params::keystone_identity_region':
                self._identity_specific_region_name(),
            'platform::client::params::auth_region':
                self._identity_specific_region_name(),
            'openstack::keystone::params::api_version': self.SERVICE_PATH,
            'openstack::keystone::params::identity_uri':
                self.get_identity_uri(),
            'openstack::keystone::params::auth_uri':
                self.get_auth_uri(),
            'openstack::keystone::params::host_url':
                self._format_url_address(self._get_management_address()),
            # The region in which the identity server can be found
            # and it could be different than the region where the
            # system resides
            'openstack::keystone::params::region_name':
                self._identity_specific_region_name(),
            'openstack::keystone::params::system_controller_region':
                constants.SYSTEM_CONTROLLER_REGION,
            'openstack::keystone::params::service_create':
                self._to_create_services(),

            'CONFIG_KEYSTONE_ADMIN_USERNAME': self.get_admin_user_name(),
        }

        if utils.is_openstack_applied(self.dbapi):
            config['openstack::keystone::params::openstack_auth_uri'] = \
                self.get_openstack_auth_uri()

        config.update(self._get_service_parameter_config())
        config.update(self._get_password_rule())
        return config

    def get_secure_system_config(self):
        # the admin password may have been updated since initial
        # configuration. Retrieve the password from keyring and
        # update the hiera records
        admin_password = self._get_keyring_password(self.ADMIN_SERVICE,
                                                    self.ADMIN_USER)
        db_connection = self._format_database_connection(self.SERVICE_NAME)
        config = {
            'keystone::admin_password': admin_password,
            'keystone::roles::admin::password': admin_password,
            'keystone::database_connection': db_connection,
            'platform::client::params::admin_password': admin_password,
        }
        return config

    def get_host_config(self, host):
        # The valid format for IPv6 addresses is: inet6:[<ip_v6>]:port
        # Although, for IPv4, the "inet" part is not mandatory, we
        # specify if anyway, for consistency purposes.
        if self._get_address_by_name(
                constants.CONTROLLER_PLATFORM_NFS,
                constants.NETWORK_TYPE_MGMT).family == constants.IPV6_FAMILY:
            argument = "url:inet6:[%s]:11211" % host.mgmt_ip
        else:
            argument = "url:inet:%s:11211" % host.mgmt_ip

        config = {
            'keystone::cache_backend_argument': argument
        }
        return config

    def _get_service_parameter_config(self):
        service_parameters = self._get_service_parameter_configs(
            constants.SERVICE_TYPE_IDENTITY)

        if service_parameters is None:
            return {}

        config = {
            'openstack::keystone::params::token_expiration':
                self._service_parameter_lookup_one(
                    service_parameters,
                    constants.SERVICE_PARAM_SECTION_IDENTITY_CONFIG,
                    constants.SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION,
                    constants.SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION_DEFAULT),
        }

        return config

    @staticmethod
    def _get_password_rule():
        password_rule = {}
        if os.path.isfile(OPENSTACK_PASSWORD_RULES_FILE):
            try:
                passwd_rules = \
                    KeystonePuppet._extract_openstack_password_rules_from_file(
                        OPENSTACK_PASSWORD_RULES_FILE)
                password_rule.update({
                    'keystone::security_compliance::unique_last_password_count':
                        passwd_rules['unique_last_password_count'],
                    'keystone::security_compliance::password_regex':
                        passwd_rules['password_regex'],
                    'keystone::security_compliance::password_regex_description':
                        passwd_rules['password_regex_description']
                })
            except Exception:
                pass
        return password_rule

    def _identity_specific_region_name(self):
        """
        Returns the Identity Region name based on the System mode:
            If Multi-Region then Keystone is shared: return Primary Region
            Else: Local Region
        """
        if (self._region_config()):
            return self.get_region_name()
        else:
            return self._region_name()

    def get_public_url(self):
        if (self._region_config() and
                    self.SERVICE_TYPE in self._get_shared_services()):
            return self._get_public_url_from_service_config(self.SERVICE_NAME)
        else:
            return self._format_public_endpoint(self.SERVICE_PORT)

    def get_internal_url(self):
        if (self._region_config() and
                    self.SERVICE_TYPE in self._get_shared_services()):
            return self._get_internal_url_from_service_config(self.SERVICE_NAME)
        else:
            return self._format_private_endpoint(self.SERVICE_PORT)

    def get_admin_url(self):
        if (self._region_config() and
                    self.SERVICE_TYPE in self._get_shared_services()):
            return self._get_admin_url_from_service_config(self.SERVICE_NAME)
        else:
            return self._format_private_endpoint(self.SERVICE_PORT)

    def get_auth_address(self):
        if self._region_config():
            url = urlparse(self.get_identity_uri())
            return url.hostname
        else:
            return self._get_management_address()

    def get_auth_host(self):
        return self._format_url_address(self.get_auth_address())

    def get_auth_port(self):
        return self.SERVICE_PORT

    def get_auth_uri(self):
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)
            return service_config.capabilities.get('auth_uri')
        else:
            return "http://%s:5000" % self._format_url_address(
                self._get_management_address())

    def get_openstack_auth_uri(self):
        location = self._get_service_default_dns_name(
            self.SERVICE_NAME)

        url = "%s://%s:80" % (self._get_public_protocol(),
                              location)
        return url

    def get_identity_uri(self):
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)
            return service_config.capabilities.get('auth_url')
        else:
            return "http://%s:%s" % (self._format_url_address(
                self._get_management_address()), self.SERVICE_PORT)

    def get_auth_url(self):
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)
            return service_config.capabilities.get('auth_uri') + '/v3'
        else:
            return self._format_private_endpoint(self.SERVICE_PORT,
                                                 path=self.SERVICE_PATH)

    def get_region_name(self):
        """This is a wrapper to get the service region name,
           each puppet operator provides this wrap to get the region name
           of the service it owns
        """
        return self._get_service_region_name(self.SERVICE_NAME)

    def get_admin_user_name(self):
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)
            if service_config is not None:
                return service_config.capabilities.get('admin_user_name')
        return self.ADMIN_USER

    def get_admin_user_domain(self):
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)
            if service_config is not None:
                return service_config.capabilities.get('admin_user_domain')
        return self.DEFAULT_DOMAIN_NAME

    def get_admin_project_name(self):
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)
            if service_config is not None:
                return service_config.capabilities.get('admin_project_name')
        return self.ADMIN_USER

    def get_admin_project_domain(self):
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)
            if service_config is not None:
                return service_config.capabilities.get('admin_project_domain')
        return self.DEFAULT_DOMAIN_NAME

    def get_service_user_domain(self):
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)
            if service_config is not None:
                return service_config.capabilities.get('service_user_domain')
        return self.DEFAULT_DOMAIN_NAME

    def get_service_project_domain(self):
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)
            if service_config is not None:
                return service_config.capabilities.get('service_project_domain')
        return self.DEFAULT_DOMAIN_NAME

    def get_service_name(self):
        return self._get_configured_service_name(self.SERVICE_NAME)

    def get_service_type(self):
        service_type = self._get_configured_service_type(self.SERVICE_NAME)
        if service_type is None:
            return self.SERVICE_TYPE
        else:
            return service_type

    @staticmethod
    def _extract_openstack_password_rules_from_file(
            rules_file, section="security_compliance"):
        try:
            config = configparser.RawConfigParser()
            parsed_config = config.read(rules_file)
            if not parsed_config:
                msg = ("Cannot parse rules file: %s" % rules_file)
                raise Exception(msg)
            if not config.has_section(section):
                msg = ("Required section '%s' not found in rules file" % section)
                raise Exception(msg)

            rules = config.items(section)
            if not rules:
                msg = ("section '%s' contains no configuration options" % section)
                raise Exception(msg)
            return dict(rules)
        except Exception:
            raise Exception("Failed to extract password rules from file")
