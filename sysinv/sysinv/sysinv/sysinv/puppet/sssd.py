#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.puppet import base


class SssdPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for sssd configuration"""

    SERVICE_NAME = 'ldap'
    SERVICE_USER = 'ldapadmin'

    def get_secure_system_config(self):
        config = {}
        domains = {}

        domains.update({'local': self._get_local_domain()})

        config.update(
            {
                'platform::sssd::params::domains': domains,
            })

        return config

    def _get_local_domain(self):
        binding_pass = self._get_keyring_password(self.SERVICE_NAME,
                self.SERVICE_USER)

        # sssd support the debug levels (from sssd.conf manual page):
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
        # Example: 0x3ff0, debug log includes level 0 to 8 messages.

        domain_settings = {
            'id_provider': 'ldap',
            'ldap_uri': 'ldaps://controller/',
            'ldap_tls_cacert': '/etc/ssl/certs/ca-certificates.crt',
            'ldap_search_base': 'dc=cgcs,dc=local',
            'ldap_default_bind_dn': 'CN=ldapadmin,DC=cgcs,DC=local',
            'ldap_default_authtok_type': 'password',
            'ldap_default_authtok': binding_pass,
            'debug_level': '0x3ff0',
        }

        return domain_settings
