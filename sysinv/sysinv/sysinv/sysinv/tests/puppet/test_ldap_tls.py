# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
from collections import namedtuple
from unittest import TestCase

from sysinv.common import constants
from sysinv.puppet.ldap import LdapPuppet


_Param = namedtuple('_Param', ['name', 'value'])

_KEY_PROTO = 'platform::ldap::params::tls_protocol_min'
_KEY_CIPHER = 'platform::ldap::params::tls_cipher_suite'


def _make_puppet(params=None):
    """Create a LdapPuppet with a mocked operator/dbapi."""
    operator = mock.MagicMock()
    operator.dbapi.service_parameter_get_all.return_value = params or []
    puppet = LdapPuppet(operator)
    return puppet


class TestTlsProtocolMinMap(TestCase):
    """Tests for TLS version to olcTLSProtocolMin mapping."""

    def test_tls12_maps_to_3_3(self):
        self.assertEqual(
            LdapPuppet.TLS_PROTOCOL_MIN_MAP['VersionTLS12'], '3.3')

    def test_tls13_maps_to_3_4(self):
        self.assertEqual(
            LdapPuppet.TLS_PROTOCOL_MIN_MAP['VersionTLS13'], '3.4')


class TestBuildGnutlsCipherSuite(TestCase):
    """Tests for GnuTLS priority string generation (Bullseye).

    Uses SECURE256:+SECURE128 base with -ALGO exclusions for ciphers
    not in the configured list.
    """

    def test_all_ciphers_no_exclusion(self):
        """When all 3 cipher algos are needed, no exclusions appended."""
        puppet = _make_puppet()
        result = puppet._build_gnutls_cipher_suite(
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,'
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,'
            'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256')
        self.assertEqual(
            result,
            'SECURE256:+SECURE128:-VERS-TLS-ALL:'
            '+VERS-TLS1.2:+VERS-TLS1.3:-SHA1')

    def test_single_cipher_excludes_others(self):
        """When only AES-256 is configured, AES-128 and CHACHA20 excluded."""
        puppet = _make_puppet()
        result = puppet._build_gnutls_cipher_suite(
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')
        self.assertIn('-AES-128-GCM', result)
        self.assertIn('-CHACHA20-POLY1305', result)
        self.assertNotIn('-AES-256-GCM', result)

    def test_different_inputs_different_outputs(self):
        """Different cipher lists produce different exclusions."""
        puppet = _make_puppet()
        result1 = puppet._build_gnutls_cipher_suite(
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')
        result2 = puppet._build_gnutls_cipher_suite(
            'TLS_AES_128_GCM_SHA256')
        self.assertNotEqual(result1, result2)


class TestBuildOpensslCipherSuite(TestCase):
    """Tests for OpenSSL cipher string generation (Trixie)."""

    def test_single_tls12_cipher(self):
        puppet = _make_puppet()
        result = puppet._build_openssl_cipher_suite(
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')
        self.assertEqual(result, 'ECDHE-RSA-AES256-GCM-SHA384')

    def test_tls13_cipher_passthrough(self):
        puppet = _make_puppet()
        result = puppet._build_openssl_cipher_suite(
            'TLS_AES_256_GCM_SHA384')
        self.assertEqual(result, 'TLS_AES_256_GCM_SHA384')

    def test_multiple_ciphers_colon_separated(self):
        puppet = _make_puppet()
        result = puppet._build_openssl_cipher_suite(
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,'
            'TLS_AES_128_GCM_SHA256')
        self.assertEqual(
            result,
            'ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256')

    def test_unknown_cipher_skipped(self):
        puppet = _make_puppet()
        result = puppet._build_openssl_cipher_suite(
            'UNKNOWN,TLS_AES_256_GCM_SHA384')
        self.assertEqual(result, 'TLS_AES_256_GCM_SHA384')


class TestGetOpenldapTlsConfig(TestCase):
    """Tests for _get_openldap_tls_config() hieradata generation."""

    @mock.patch(
        'sysinv.puppet.ldap.utils.get_debian_release_codename',
        return_value='bullseye')
    def test_defaults_bullseye(self, _mock_codename):
        puppet = _make_puppet()
        config = puppet._get_openldap_tls_config()
        self.assertEqual(config[_KEY_PROTO], '3.3')
        self.assertIn('SECURE256', config[_KEY_CIPHER])

    @mock.patch(
        'sysinv.puppet.ldap.utils.get_debian_release_codename',
        return_value='trixie')
    def test_defaults_trixie(self, _mock_codename):
        puppet = _make_puppet()
        config = puppet._get_openldap_tls_config()
        self.assertEqual(config[_KEY_PROTO], '3.3')
        # Trixie uses OpenSSL format, no NONE: prefix
        self.assertNotIn('NONE:', config[_KEY_CIPHER])
        self.assertIn('ECDHE-RSA-AES', config[_KEY_CIPHER])

    @mock.patch(
        'sysinv.puppet.ldap.utils.get_debian_release_codename',
        return_value='bullseye')
    def test_tls13_version(self, _mock_codename):
        params = [
            _Param(
                constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
                'VersionTLS13'),
        ]
        puppet = _make_puppet(params)
        config = puppet._get_openldap_tls_config()
        self.assertEqual(config[_KEY_PROTO], '3.4')

    @mock.patch(
        'sysinv.puppet.ldap.utils.get_debian_release_codename',
        return_value='trixie')
    def test_custom_ciphers_trixie(self, _mock_codename):
        params = [
            _Param(
                constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
                'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,'
                'TLS_AES_256_GCM_SHA384'),
        ]
        puppet = _make_puppet(params)
        config = puppet._get_openldap_tls_config()
        self.assertEqual(
            config[_KEY_CIPHER],
            'ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_256_GCM_SHA384')

    @mock.patch(
        'sysinv.puppet.ldap.utils.get_debian_release_codename',
        return_value='bullseye')
    def test_db_failure_uses_defaults(self, _mock_codename):
        """DB read failure should fall back to defaults."""
        operator = mock.MagicMock()
        operator.dbapi.service_parameter_get_all.side_effect = \
            Exception("DB error")
        puppet = LdapPuppet(operator)
        config = puppet._get_openldap_tls_config()
        self.assertEqual(config[_KEY_PROTO], '3.3')
        self.assertIn('SECURE256', config[_KEY_CIPHER])
