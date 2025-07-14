#
# Copyright (c) 2022-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging
from sysinv.puppet import base
from sysinv.common import constants
from sysinv.common import exception

LOG = logging.getLogger(__name__)


class SssdPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for sssd configuration"""

    SERVICE_NAME = 'ldap'
    SERVICE_USER = 'ldapadmin'
    identity_service_parameters = []

    def get_secure_system_config(self):
        config = {}
        domains = {}
        nss = self._get_nss_parameters()
        pam = self._get_pam_parameters()

        # update local domain
        domains.update({'controller': self._get_local_domain()})

        # retrieve service parameters for service identity
        self.identity_service_parameters = self._get_service_parameters(
            constants.SERVICE_TYPE_IDENTITY)

        if self.identity_service_parameters is not None:
            LOG.info('UPDATE Remote LDAP Domains')
            # update remote domains
            remote_domains = [constants.SERVICE_PARAM_SECTION_IDENTITY_LDAP_DOMAIN1,
                              constants.SERVICE_PARAM_SECTION_IDENTITY_LDAP_DOMAIN2,
                              constants.SERVICE_PARAM_SECTION_IDENTITY_LDAP_DOMAIN3]
            for domain in remote_domains:
                domain_name = self._get_service_parameter_domain_name(domain)
                if domain_name != "undef":
                    ldap_domain_parameters = self._get_ldap_domain(domain)
                    if ldap_domain_parameters is not None:
                        domains.update({domain_name: ldap_domain_parameters})

        config.update(
            {
                'platform::sssd::params::domains': domains,
                'platform::sssd::params::nss_options': nss,
                'platform::sssd::params::pam_options': pam,
            })

        return config

    def _get_ldap_domain_service_parameter_value(self, domain,
            parameter_name,
            default):
        for param in self.identity_service_parameters:
            if param['section'] == domain and param['name'] == parameter_name:
                return param['value']
        return default

    def _get_service_parameter_domain_name(self, domain):

        domain_name = self._get_ldap_domain_service_parameter_value(
            domain,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_DOMAIN,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_DOMAIN_DEFAULT,
        )
        return domain_name

    def _get_service_parameter_ldap_uri(self, domain):

        ldap_uri = self._get_ldap_domain_service_parameter_value(
            domain,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_URI,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_DOMAIN_DEFAULT,
        )

        return ldap_uri

    def _get_service_parameter_access_filter(self, domain):

        access_filter = self._get_ldap_domain_service_parameter_value(
            domain,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_ACCESS_FILTER,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_DOMAIN_DEFAULT,
        )

        return access_filter

    def _get_service_parameter_search_base(self, domain):

        search_base = self._get_ldap_domain_service_parameter_value(
            domain,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_SEARCH_BASE,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_DOMAIN_DEFAULT,
        )

        return search_base

    def _get_service_parameter_user_search_base(self, domain):

        user_search_base = self._get_ldap_domain_service_parameter_value(
            domain,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_USER_SEARCH_BASE,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_DOMAIN_DEFAULT,
        )

        return user_search_base

    def _get_service_parameter_group_search_base(self, domain):

        group_search_base = self._get_ldap_domain_service_parameter_value(
            domain,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_GROUP_SEARCH_BASE,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_DOMAIN_DEFAULT,
        )

        return group_search_base

    def _get_service_parameter_default_bind_dn(self, domain):

        bind_dn = self._get_ldap_domain_service_parameter_value(
            domain,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_DEFAULT_BIND_DN,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_DOMAIN_DEFAULT,
        )

        return bind_dn

    def _get_service_parameter_default_authtok(self, domain):

        authtok = self._get_ldap_domain_service_parameter_value(
            domain,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_DEFAULT_AUTH_TOK,
            constants.SERVICE_PARAM_NAME_IDENTITY_LDAP_DOMAIN_DEFAULT,
        )

        return authtok

    def _get_mandatory_parameter(self, parameter_name,
            get_parameter_value, domain):
        # check if the mandatory service parameter has been added
        parameter_value = get_parameter_value(domain)
        if parameter_value != "undef":
            return parameter_value
        else:
            LOG.warn('Parameter %s is mandatory and is not found'
                    % parameter_name)
            return None

    def _get_network_type(self, network_type):
        return self.dbapi.network_get_by_type(network_type)

    def _is_host_address_ipv6(self):
        try:
            # Subclouds may be using the optional admin network
            network = self._get_network_type(constants.NETWORK_TYPE_ADMIN)
        except exception.NetworkTypeNotFound:
            network = self._get_network_type(constants.NETWORK_TYPE_MGMT)
            pass

        addr_pool = self.dbapi.address_pool_get(network.pool_uuid)
        if addr_pool.family == constants.IPV6_FAMILY:
            return True
        else:
            return False

    def _get_local_domain(self):
        binding_pass = self._get_keyring_password(self.SERVICE_NAME,
                                                  self.SERVICE_USER)
        ldap_uri = self._get_local_domain_uri()

        # sssd supports the debug levels (from sssd.conf manual page):
        # 0, 0x0010: Fatal failures. Anything that would prevent SSSD
        #            from starting up or causes it to cease running.
        # 1, 0x0020: Critical failures. An error that doesn't kill
        #            SSSD, but one that indicates that at least one
        #            major feature is not going to work properly.
        # 2, 0x0040: Serious failures. An error announcing that a
        #            particular request or operation has failed.
        # 3, 0x0080: Minor failures. These are the errors that would
        #            percolate down to cause the operation failure
        #            of 2.
        # 4, 0x0100: Configuration settings.
        # 5, 0x0200: Function data.
        # 6, 0x0400: Trace messages for operation functions.
        # 7, 0x1000: Trace messages for internal control functions.
        # 8, 0x2000: Contents of function-internal variables that may
        #            be interesting.
        # 9, 0x4000: Extremely low-level tracing information.
        # 10, 0x10000: Even more low-level libldb tracing information.
        #              Almost never really required.
        #
        # Debug level: 0x0270, includes fatal failures, critical failures,
        # serious failures and function data.

        # Default is to bind anonymously.
        domain_parameters = {
            'cache_credentials': 'true',
            'debug_level': '0x0270',
            'id_provider': 'ldap',
            'enumerate': 'true',
            'access_provider': 'ldap',
            'auth_provider': 'ldap',
            'ldap_pwd_policy': 'shadow',
            'pwd_expiration_warning': '7',
            'ldap_access_order': 'pwd_expire_policy_renew',
            'ldap_chpass_update_last_change': 'true',
            'ldap_access_filter': '(& (objectclass=posixAccount))',
            'ldap_search_base': 'dc=cgcs,dc=local',
            'ldap_user_home_directory': '/home/$cn',
            'ldap_user_shell': '/bin/bash',
            'ldap_uri': ldap_uri,
            'ldap_tls_cacert': '/etc/ssl/certs/ca-certificates.crt',
            'fallback_homedir': '/home/%u',
            'timeout': '20',
        }

        # bind to 'CN=ldapadmin,DC=cgcs,DC=local' using password if
        # this is not a DC Subcloud.
        if self._distributed_cloud_role() != \
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            domain_parameters.update({
                'ldap_default_bind_dn': 'CN=ldapadmin,DC=cgcs,DC=local',
                'ldap_default_authtok_type': 'password',
                'ldap_default_authtok': binding_pass,
            })

        return domain_parameters

    def _get_ldap_domain(self, domain):

        domain_parameters = {
            'cache_credentials': 'true',
            'debug_level': '0x0270',
            'id_provider': 'ldap',
            'access_provider': 'ldap',
            'ldap_id_mapping': 'true',
            'ldap_schema': 'rfc2307bis',
            'ldap_user_object_class': 'user',
            'ldap_group_member': 'member',
            'ldap_group_object_class': 'group',
            'override_homedir': '/home/%d/%u',
            'ldap_user_principal': 'userPrincipalName',
            'ldap_user_name': 'sAMAccountName',
            'ldap_group_name': 'sAMAccountName',
            'ldap_user_primary_group': 'primaryGroupID',
            'ldap_user_objectsid': 'objectSid',
            'ldap_group_objectsid': 'objectSid',
            'case_sensitive': 'false',
            'default_shell': '/bin/bash',
            'fallback_homedir': '/home/%d/%u',
            'use_fully_qualified_names': 'true',
            'ldap_tls_cacert': '/etc/ssl/certs/ca-certificates.crt',
            'timeout': '20',
        }

        # add mandatory parameters
        uri = self._get_mandatory_parameter("ldap_uri",
                self._get_service_parameter_ldap_uri,
                domain)
        access_filter = self._get_mandatory_parameter("ldap_access_filter",
                self._get_service_parameter_access_filter,
                domain)
        search_base = self._get_mandatory_parameter("ldap_search_base",
                self._get_service_parameter_search_base,
                domain)
        default_bind_dn = self._get_mandatory_parameter("ldap_default_bind_dn",
                self._get_service_parameter_default_bind_dn,
                domain)
        default_authtok = self._get_mandatory_parameter("ldap_default_authtok",
                self._get_service_parameter_default_authtok,
                domain)

        if uri is not None and \
                access_filter is not None and \
                search_base is not None and \
                default_bind_dn is not None and \
                default_authtok is not None:
                    domain_parameters['ldap_uri'] = uri
                    domain_parameters['ldap_access_filter'] = access_filter
                    domain_parameters['ldap_search_base'] = search_base
                    domain_parameters['ldap_default_bind_dn'] = default_bind_dn
                    domain_parameters['ldap_default_authtok'] = default_authtok
        else:
            msg = 'Apply for %s failed, mandatory parameters are missing:' % domain
            if uri is None:
                msg += ' ldap_uri'
            if access_filter is None:
                msg += ' ldap_access_filter'
            if search_base is None:
                msg += ' ldap_search_base'
            if default_bind_dn is None:
                msg += ' ldap_default_bind_dn'
            if default_authtok is None:
                msg += ' ldap_default_authtok'
            raise exception.SysinvException(msg)

        # add optional parameters
        user_search_base = self._get_service_parameter_user_search_base(domain)
        if user_search_base != "undef":
            domain_parameters['ldap_user_search_base'] = user_search_base

        group_search_base = self._get_service_parameter_group_search_base(domain)
        if group_search_base != "undef":
            domain_parameters['ldap_group_search_base'] = group_search_base

        if self._is_host_address_ipv6():
            domain_parameters['lookup_family_order'] = 'ipv6_first'

        return domain_parameters

    def _get_nss_parameters(self):
        # reconnection_retries = 3 Number of times services should
        # attempt to reconnect in the event of a Data Provider crash
        # or restart before they give up
        # debug_level = 0x0070 Log fatal failures, critical failures,
        # serious failures

        nss_parameters = {
            'reconnection_retries': '3',
            'debug_level': '0x0070',
        }

        return nss_parameters

    def _get_pam_parameters(self):
        # reconnection_retries = 3 Number of times services should
        # attempt to reconnect in the event of a Data Provider crash
        # or restart before they give up
        # debug_level = 0x0070 Log fatal failures, critical failures,
        # serious failures

        pam_parameters = {
            'reconnection_retries': '3',
            'debug_level': '0x0070',
            'pam_pwd_expiration_warning': '7',
        }

        return pam_parameters

    def _get_local_domain_uri(self):
        ldapserver_host = constants.CONTROLLER
        if self._distributed_cloud_role() == \
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            sys_controller_network = self.dbapi.network_get_by_type(
                constants.NETWORK_TYPE_SYSTEM_CONTROLLER)
            sys_controller_network_addr_pool = self.dbapi.address_pool_get(
                sys_controller_network.pool_uuid)
            ldapserver_addr = sys_controller_network_addr_pool.floating_address
            ldapserver_host = self._format_url_address(ldapserver_addr)

        ldapserver_uri = 'ldaps://%s' % ldapserver_host

        return ldapserver_uri
