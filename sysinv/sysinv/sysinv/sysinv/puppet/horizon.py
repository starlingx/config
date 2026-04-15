#
# Copyright (c) 2017-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging

from sysinv.puppet import openstack

from sysinv.common import constants
from sysinv.common import exception

LOG = logging.getLogger(__name__)

# IANA to OpenSSL cipher name mapping for lighttpd (same as HAProxy)
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

TLS13_CIPHERS = [
    'TLS_AES_256_GCM_SHA384',
    'TLS_AES_128_GCM_SHA256',
    'TLS_CHACHA20_POLY1305_SHA256',
]


class HorizonPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for horizon configuration"""

    def get_secure_static_config(self):
        return {
            'openstack::horizon::params::secret_key':
                self._generate_random_password(length=32),
        }

    def get_system_config(self):
        config = {
            'openstack::horizon::params::enable_https':
                self._https_enabled(),
            'openstack::horizon::params::openstack_host':
                self._keystone_auth_host(),

        }
        tpm_config = self._get_tpm_config()
        if tpm_config is not None:
            config.update(tpm_config)
        config.update(self._get_lighttpd_tls_config())
        return config

    def _get_lighttpd_tls_config(self):
        """Get lighttpd TLS configuration from platform service parameters.

        Reads platform config TLS service parameters and converts
        them to OpenSSL cipher list format for lighttpd.
        lighttpd uses OpenSSL cipher names (same format as HAProxy).
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

        # Convert IANA cipher names to OpenSSL format for lighttpd
        # Note: On Bullseye (lighttpd 1.4.55), ssl.cipher-list only
        # controls TLS 1.2 ciphers. TLS 1.3 ciphers are always
        # enabled by OpenSSL 1.1.1 and cannot be controlled via
        # ssl.cipher-list. TLS 1.3 cipher names in ssl.cipher-list
        # cause lighttpd to crash. Therefore, TLS 1.3-only cipher
        # names are never included in the cipher list.
        # On Trixie (lighttpd 1.4.79), ssl.openssl.ssl-conf-cmd
        # handles MinProtocol enforcement directly.
        openssl_ciphers = []
        for iana_name in tls_cipher_suite.split(','):
            iana_name = iana_name.strip()
            if not iana_name:
                continue
            if iana_name in TLS13_CIPHERS:
                # Skip TLS 1.3 ciphers — they are always enabled
                # by OpenSSL and cannot be in ssl.cipher-list
                continue
            openssl_name = IANA_TO_OPENSSL_CIPHER_MAP.get(iana_name)
            if openssl_name:
                openssl_ciphers.append(openssl_name)
            else:
                LOG.warning("Unknown IANA cipher: %s, skipping"
                            % iana_name)

        return {
            'openstack::horizon::params::tls_min_version': tls_min_version,
            'openstack::horizon::params::tls_cipher_list':
                ':'.join(openssl_ciphers) if openssl_ciphers else None,
        }

    def _get_tpm_config(self):
        try:
            tpmconfig = self.dbapi.tpmconfig_get_one()
            if tpmconfig.tpm_path:
                return {
                    'openstack::horizon::params::tpm_object':
                        tpmconfig.tpm_path
                }
        except exception.NotFound:
            pass

        return None

    def get_public_url(self):
        # not an openstack service
        raise NotImplementedError()

    def get_internal_url(self):
        # not an openstack service
        raise NotImplementedError()

    def get_admin_url(self):
        # not an openstack service
        raise NotImplementedError()
