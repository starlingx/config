#
# Copyright (c) 2017-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import keyring
import os

from oslo_log import log
from passlib.hash import ldap_salted_sha1 as hash

from sysinv.common import constants
from sysinv.common import utils
from sysinv.common.retrying import retry

from sysinv.puppet import base

LOG = log.getLogger(__name__)


class LdapPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for ldap configuration"""
    SERVICE_NAME = 'open-ldap'

    # olcTLSProtocolMin: 3.3 = TLS 1.2, 3.4 = TLS 1.3
    TLS_PROTOCOL_MIN_MAP = {
        'VersionTLS12': '3.3',
        'VersionTLS13': '3.4',
    }

    # All GnuTLS cipher algorithms used by our 9 supported ciphers.
    # Maps IANA cipher name to the GnuTLS cipher algorithm component.
    IANA_TO_GNUTLS_CIPHER_ALGO = {
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384': 'AES-256-GCM',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256': 'AES-128-GCM',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384': 'AES-256-GCM',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256': 'AES-128-GCM',
        'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256':
            'CHACHA20-POLY1305',
        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256':
            'CHACHA20-POLY1305',
        'TLS_AES_256_GCM_SHA384': 'AES-256-GCM',
        'TLS_AES_128_GCM_SHA256': 'AES-128-GCM',
        'TLS_CHACHA20_POLY1305_SHA256': 'CHACHA20-POLY1305',
    }

    # Complete set of GnuTLS cipher algorithms covered by SECURE256
    # and SECURE128 keywords that we may need to exclude.
    ALL_GNUTLS_CIPHER_ALGOS = {
        'AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305',
    }

    # IANA to GnuTLS priority string components (Bullseye slapd)
    IANA_TO_GNUTLS_CIPHER_MAP = {
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384':
            '+ECDHE-RSA:+AES-256-GCM:+AEAD',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256':
            '+ECDHE-RSA:+AES-128-GCM:+AEAD',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384':
            '+ECDHE-ECDSA:+AES-256-GCM:+AEAD',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256':
            '+ECDHE-ECDSA:+AES-128-GCM:+AEAD',
        'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256':
            '+ECDHE-RSA:+CHACHA20-POLY1305:+AEAD',
        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256':
            '+ECDHE-ECDSA:+CHACHA20-POLY1305:+AEAD',
    }

    GNUTLS_TLS13_CIPHERS = {
        'TLS_AES_256_GCM_SHA384': '+AES-256-GCM',
        'TLS_AES_128_GCM_SHA256': '+AES-128-GCM',
        'TLS_CHACHA20_POLY1305_SHA256': '+CHACHA20-POLY1305',
    }

    # IANA to OpenSSL cipher names (Trixie slapd)
    IANA_TO_OPENSSL_CIPHER_MAP = {
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384':
            'ECDHE-RSA-AES256-GCM-SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256':
            'ECDHE-RSA-AES128-GCM-SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384':
            'ECDHE-ECDSA-AES256-GCM-SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256':
            'ECDHE-ECDSA-AES128-GCM-SHA256',
        'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256':
            'ECDHE-RSA-CHACHA20-POLY1305',
        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256':
            'ECDHE-ECDSA-CHACHA20-POLY1305',
    }

    OPENSSL_TLS13_CIPHERS = [
        'TLS_AES_256_GCM_SHA384',
        'TLS_AES_128_GCM_SHA256',
        'TLS_CHACHA20_POLY1305_SHA256',
    ]

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

    def _is_openldap_certificate_created(self):
        """ Returns True when it's safe to read the openldap certificate.
        """
        # TODO(fcorream): Remove OLD_ANSIBLE_BOOTSTRAP_COMPLETED_FLAG
        # just needed for upgrade to R9 ( 24.09 )
        is_upgrading = self.is_upgrade_in_progress_cached()[0]

        bootstrap_completed = \
            os.path.isfile(constants.ANSIBLE_BOOTSTRAP_COMPLETED_FLAG) or \
            (is_upgrading and
             os.path.isfile(constants.OLD_ANSIBLE_BOOTSTRAP_COMPLETED_FLAG))

        return bootstrap_completed

    @retry(stop_max_attempt_number=3, wait_fixed=2 * 1000)
    def get_secure_system_config(self):
        config = {}

        # Retrieve openldap CA certificate, and server certificate/key.
        # For subcloud, only CA certificate is needed.
        # Subcloud secret can be Opaque or TLS.
        if self._is_openldap_certificate_created():
            is_subcloud = \
                self._distributed_cloud_role() == \
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD

            ldap_ca_secret_type = utils.get_secret_type(
                constants.OPENLDAP_CA_CERT_SECRET_NAME,
                constants.CERT_NAMESPACE_PLATFORM_CA_CERTS)

            if is_subcloud and ldap_ca_secret_type == constants.K8S_SECRET_TYPE_OPAQUE.lower():
                ldap_ca_cert = utils.get_ca_certificate_from_opaque_secret(
                    constants.OPENLDAP_CA_CERT_SECRET_NAME,
                    constants.CERT_NAMESPACE_PLATFORM_CA_CERTS)
            else:
                ldap_ca_cert, _, _ = utils.get_certificate_from_secret(
                    constants.OPENLDAP_CA_CERT_SECRET_NAME,
                    constants.CERT_NAMESPACE_PLATFORM_CA_CERTS)

            if is_subcloud:
                config.update({
                    'platform::ldap::params::ca_cert': ldap_ca_cert,
                })
            else:
                ldap_cert, ldap_key, _ = utils.get_certificate_from_secret(
                    constants.OPENLDAP_CERT_SECRET_NAME,
                    constants.CERT_NAMESPACE_PLATFORM_CERTS)

                config.update({
                    'platform::ldap::params::secure_cert': ldap_cert,
                    'platform::ldap::params::secure_key': ldap_key,
                    'platform::ldap::params::ca_cert': ldap_ca_cert,
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
        provider_prot = 'ldaps'
        if utils.is_centos():
            provider_prot = 'ldap'

        if host.hostname == constants.CONTROLLER_0_HOSTNAME:
            server_id = '001'
            provider_uri = '%s://%s' % (provider_prot, constants.CONTROLLER_1_HOSTNAME)
        elif host.hostname == constants.CONTROLLER_1_HOSTNAME:
            server_id = '002'
            provider_uri = '%s://%s' % (provider_prot, constants.CONTROLLER_0_HOSTNAME)
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

    def get_system_config(self):
        config = {}
        config.update(self._get_openldap_tls_config())
        return config

    def _get_openldap_tls_config(self):
        """Get OpenLDAP TLS config from platform service parameters.

        Reads platform config TLS service parameters and converts
        to slapd's olcTLSProtocolMin and olcTLSCipherSuite format.
        Bullseye slapd uses GnuTLS, Trixie uses OpenSSL.
        """
        tls_min_version = \
            constants.SERVICE_PARAM_PLATFORM_TLS_MIN_VERSION_DEFAULT
        tls_cipher_suite = \
            constants.SERVICE_PARAM_PLATFORM_TLS_CIPHER_SUITE_DEFAULT

        try:
            parms = self.dbapi.service_parameter_get_all(
                service=constants.SERVICE_TYPE_PLATFORM,
                section=constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG)
            for p in parms:
                if p.name == \
                        constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION:
                    tls_min_version = p.value
                elif p.name == \
                        constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE:
                    tls_cipher_suite = p.value
        except Exception:
            LOG.warning("Failed to read TLS service parameters, "
                        "using defaults")

        protocol_min = self.TLS_PROTOCOL_MIN_MAP.get(
            tls_min_version, '3.3')

        is_bullseye = (utils.get_debian_release_codename() == 'bullseye')
        if is_bullseye:
            cipher_suite = self._build_gnutls_cipher_suite(
                tls_cipher_suite)
        else:
            cipher_suite = self._build_openssl_cipher_suite(
                tls_cipher_suite)

        return {
            'platform::ldap::params::tls_protocol_min': protocol_min,
            'platform::ldap::params::tls_cipher_suite': cipher_suite,
        }

    def _build_gnutls_cipher_suite(self, tls_cipher_suite):
        """Build GnuTLS priority string for Bullseye slapd.

        slapd 2.4 with GnuTLS 3.7 does NOT accept individual cipher
        components (NONE:+ECDHE-RSA:+AES-256-GCM:+AEAD). It requires
        high-level keywords like SECURE256:+SECURE128.

        To provide per-cipher-algorithm exclusion, we start with the
        SECURE256:+SECURE128 base and use GnuTLS '-' exclusion syntax
        to remove cipher algorithms not in the configured list.

        Note: exclusion operates at the cipher algorithm level, not
        the full cipher suite level. Excluding AES-256-GCM removes it
        from all key exchange methods (both ECDHE-RSA and ECDHE-ECDSA).
        """
        # Collect GnuTLS cipher algorithms needed by configured ciphers
        needed_algos = set()
        for iana_name in tls_cipher_suite.split(','):
            iana_name = iana_name.strip()
            if not iana_name:
                continue
            algo = self.IANA_TO_GNUTLS_CIPHER_ALGO.get(iana_name)
            if algo:
                needed_algos.add(algo)

        # Build exclusion list for algorithms not needed
        exclusions = []
        for algo in sorted(self.ALL_GNUTLS_CIPHER_ALGOS):
            if algo not in needed_algos:
                exclusions.append('-%s' % algo)

        base = 'SECURE256:+SECURE128:-VERS-TLS-ALL:' \
               '+VERS-TLS1.2:+VERS-TLS1.3:-SHA1'

        if exclusions:
            return '%s:%s' % (base, ':'.join(exclusions))
        return base

    def _build_openssl_cipher_suite(self, tls_cipher_suite):
        """Build OpenSSL cipher string for Trixie slapd."""
        ciphers = []
        for iana_name in tls_cipher_suite.split(','):
            iana_name = iana_name.strip()
            if not iana_name:
                continue
            if iana_name in self.OPENSSL_TLS13_CIPHERS:
                ciphers.append(iana_name)
            else:
                openssl_name = self.IANA_TO_OPENSSL_CIPHER_MAP.get(
                    iana_name)
                if openssl_name:
                    ciphers.append(openssl_name)
                else:
                    LOG.warning("Unknown IANA cipher for OpenSSL: %s" %
                                iana_name)
        return ':'.join(ciphers)
