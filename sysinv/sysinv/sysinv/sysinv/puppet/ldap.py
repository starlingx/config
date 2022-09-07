#
# Copyright (c) 2017-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import keyring
import os

from passlib.hash import ldap_salted_sha1 as hash

from sysinv.common import constants
from sysinv.common import utils

from sysinv.puppet import base


class LdapPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for ldap configuration"""
    SERVICE_NAME = 'open-ldap'

    def get_secure_static_config(self):
        password = self._generate_random_password()
        passhash = hash.encrypt(password)

        # Store the ldapadmin password for client (such as sssd)
        keyring.set_password('ldap', 'ldapadmin', password)

        return {
            'platform::ldap::params::admin_pw': password,
            'platform::ldap::params::admin_hashed_pw': passhash,
        }

    def get_static_config(self):
        # default values for bootstrap manifest
        ldapserver_remote = False
        ldapserver_host = constants.CONTROLLER
        bind_anonymous = False

        return {
            'platform::ldap::params::ldapserver_remote': ldapserver_remote,
            'platform::ldap::params::ldapserver_host': ldapserver_host,
            'platform::ldap::params::bind_anonymous': bind_anonymous,
        }

    def get_secure_system_config(self):
        config = {}
        bootstrap_completed = \
            os.path.isfile(constants.ANSIBLE_BOOTSTRAP_COMPLETED_FLAG)
        is_subcloud = \
            self._distributed_cloud_role() == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD
        is_upgrading, _ = utils.is_upgrade_in_progress(self.dbapi)
        # Checking for upgrade is a temporary fix to allow the upgrade to run.
        # A subsequent code change is needed to create the openldap certificate
        # during the upgrade and then remove this check.
        if bootstrap_completed and not is_subcloud and not is_upgrading:
            ldap_cert, ldap_key = utils.get_certificate_from_secret(
                constants.OPENLDAP_CERT_SECRET_NAME,
                constants.CERT_NAMESPACE_PLATFORM_CERTS)

            config.update({
                'platform::ldap::params::secure_cert': ldap_cert,
                'platform::ldap::params::secure_key': ldap_key,
            })

        return config

    def get_host_config(self, host):
        ldapserver_remote = False
        ldapserver_host = constants.CONTROLLER
        bind_anonymous = False
        if self._distributed_cloud_role() == \
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            # Note: During bootstrap, sysinv db is not yet populated
            # and hence local ldapserver will be configured.
            # It will be then disabled when controller manifests are applied.
            sys_controller_network = self.dbapi.network_get_by_type(
                constants.NETWORK_TYPE_SYSTEM_CONTROLLER)
            sys_controller_network_addr_pool = self.dbapi.address_pool_get(
                sys_controller_network.pool_uuid)
            ldapserver_remote = True
            ldapserver_addr = sys_controller_network_addr_pool.floating_address
            ldapserver_host = self._format_url_address(ldapserver_addr)
            bind_anonymous = True

        elif self._region_config():
            service_config = self.get_service_config(self.SERVICE_NAME)
            if service_config is not None:
                ldapserver_remote = True
                ldapserver_uri = service_config.capabilities.get('service_uri')
                addr_index = ldapserver_uri.rfind('/')
                ldapserver_host = ldapserver_uri[addr_index + 1:]
                bind_anonymous = True

        if host.personality != constants.CONTROLLER:
            # if storage/worker, use bind anonymously
            bind_anonymous = True
            return {
                'platform::ldap::params::ldapserver_remote': ldapserver_remote,
                'platform::ldap::params::ldapserver_host': ldapserver_host,
                'platform::ldap::params::bind_anonymous': bind_anonymous,
            }

        # Rest of the configuration is required only for controller hosts
        if host.hostname == constants.CONTROLLER_0_HOSTNAME:
            server_id = '001'
            provider_uri = 'ldap://%s' % constants.CONTROLLER_1_HOSTNAME
        elif host.hostname == constants.CONTROLLER_1_HOSTNAME:
            server_id = '002'
            provider_uri = 'ldap://%s' % constants.CONTROLLER_0_HOSTNAME
        else:
            raise Exception("unknown controller hostname {}".format(
                host.hostname))

        return {
            'platform::ldap::params::server_id': server_id,
            'platform::ldap::params::provider_uri': provider_uri,
            'platform::ldap::params::ldapserver_remote': ldapserver_remote,
            'platform::ldap::params::ldapserver_host': ldapserver_host,
            'platform::ldap::params::bind_anonymous': bind_anonymous,
        }

    def get_service_config(self, service):
        configs = self.context.setdefault('_service_configs', {})
        if service not in configs:
            configs[service] = self._get_service(service)
        return configs[service]
