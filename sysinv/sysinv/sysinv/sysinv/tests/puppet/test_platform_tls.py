# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
from collections import namedtuple
from unittest import TestCase

from sysinv.common import constants
from sysinv.puppet.platform import PlatformPuppet


# Lightweight stand-in for a service_parameter DB row
_Param = namedtuple('_Param', ['name', 'value'])

# Hieradata key shortcuts
_KEY_OPTS = 'platform::haproxy::params::ssl_bind_options'
_KEY_CIPHERS = 'platform::haproxy::params::ssl_ciphers'
_KEY_SUITES = 'platform::haproxy::params::ssl_ciphersuites'
_KEY_CURVES = 'platform::haproxy::params::ssl_bind_curves'


def _make_puppet(params=None):
    """Create a PlatformPuppet with a mocked operator/dbapi."""
    operator = mock.MagicMock()
    operator.dbapi.service_parameter_get_all.return_value = params or []
    puppet = PlatformPuppet(operator)
    return puppet


class TestIanaToOpensslCipher(TestCase):
    """Tests for IANA to OpenSSL cipher name conversion."""

    def test_tls12_ecdhe_rsa_aes256(self):
        result = PlatformPuppet._iana_to_openssl_cipher(
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')
        self.assertEqual(result, 'ECDHE-RSA-AES256-GCM-SHA384')

    def test_tls12_ecdhe_rsa_aes128(self):
        result = PlatformPuppet._iana_to_openssl_cipher(
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256')
        self.assertEqual(result, 'ECDHE-RSA-AES128-GCM-SHA256')

    def test_tls12_ecdhe_ecdsa_aes256(self):
        result = PlatformPuppet._iana_to_openssl_cipher(
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384')
        self.assertEqual(result, 'ECDHE-ECDSA-AES256-GCM-SHA384')

    def test_tls12_ecdhe_ecdsa_aes128(self):
        result = PlatformPuppet._iana_to_openssl_cipher(
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256')
        self.assertEqual(result, 'ECDHE-ECDSA-AES128-GCM-SHA256')

    def test_tls12_ecdhe_rsa_chacha20(self):
        result = PlatformPuppet._iana_to_openssl_cipher(
            'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256')
        self.assertEqual(result, 'ECDHE-RSA-CHACHA20-POLY1305')

    def test_tls12_ecdhe_ecdsa_chacha20(self):
        result = PlatformPuppet._iana_to_openssl_cipher(
            'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256')
        self.assertEqual(result, 'ECDHE-ECDSA-CHACHA20-POLY1305')

    def test_tls13_aes256_passthrough(self):
        result = PlatformPuppet._iana_to_openssl_cipher(
            'TLS_AES_256_GCM_SHA384')
        self.assertEqual(result, 'TLS_AES_256_GCM_SHA384')

    def test_tls13_aes128_passthrough(self):
        result = PlatformPuppet._iana_to_openssl_cipher(
            'TLS_AES_128_GCM_SHA256')
        self.assertEqual(result, 'TLS_AES_128_GCM_SHA256')

    def test_tls13_chacha20_passthrough(self):
        result = PlatformPuppet._iana_to_openssl_cipher(
            'TLS_CHACHA20_POLY1305_SHA256')
        self.assertEqual(result, 'TLS_CHACHA20_POLY1305_SHA256')

    def test_unknown_cipher_returns_none(self):
        result = PlatformPuppet._iana_to_openssl_cipher(
            'TLS_UNKNOWN_CIPHER')
        self.assertIsNone(result)

    def test_all_valid_ciphers_mapped(self):
        """Every cipher in IANA_TO_OPENSSL_CIPHER_MAP + TLS13 is convertible."""
        all_ciphers = list(PlatformPuppet.IANA_TO_OPENSSL_CIPHER_MAP.keys()) + \
            PlatformPuppet.TLS13_CIPHERS
        for cipher in all_ciphers:
            result = PlatformPuppet._iana_to_openssl_cipher(cipher)
            self.assertIsNotNone(result,
                                 "Cipher %s returned None" % cipher)


class TestGetHaproxyTlsConfig(TestCase):
    """Tests for _get_haproxy_tls_config() hieradata generation."""

    @mock.patch('sysinv.puppet.platform.utils.get_debian_release_codename',
                return_value='bullseye')
    def test_defaults_tls12_bind_options(self, _mock_codename):
        """Default TLS12 min version produces correct bind-options."""
        config = _make_puppet()._get_haproxy_tls_config()
        self.assertEqual(config[_KEY_OPTS],
                         'no-sslv3 no-tlsv10 no-tlsv11')

    @mock.patch('sysinv.puppet.platform.utils.get_debian_release_codename',
                return_value='bullseye')
    def test_tls13_bind_options(self, _mock_codename):
        """TLS13 min version adds no-tlsv12 to bind-options."""
        params = [_Param(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            constants.SERVICE_PARAM_PLATFORM_TLS_VERSION_TLS13)]
        config = _make_puppet(params)._get_haproxy_tls_config()
        self.assertEqual(config[_KEY_OPTS],
                         'no-sslv3 no-tlsv10 no-tlsv11 no-tlsv12')

    @mock.patch('sysinv.puppet.platform.utils.get_debian_release_codename',
                return_value='bullseye')
    def test_default_ciphers_split(self, _mock_codename):
        """Default cipher suite splits into TLS 1.2 and TLS 1.3 keys."""
        config = _make_puppet()._get_haproxy_tls_config()
        # TLS 1.2 ciphers in OpenSSL format
        self.assertIn(_KEY_CIPHERS, config)
        for name in ['ECDHE-RSA-AES256-GCM-SHA384',
                      'ECDHE-RSA-AES128-GCM-SHA256']:
            self.assertIn(name, config[_KEY_CIPHERS])
        # TLS 1.3 ciphersuites
        self.assertIn(_KEY_SUITES, config)
        for name in ['TLS_AES_256_GCM_SHA384',
                      'TLS_AES_128_GCM_SHA256']:
            self.assertIn(name, config[_KEY_SUITES])

    @mock.patch('sysinv.puppet.platform.utils.get_debian_release_codename',
                return_value='bullseye')
    def test_tls13_only_ciphers_no_ssl_ciphers_key(self, _mock_codename):
        """When only TLS 1.3 ciphers configured, ssl_ciphers key absent."""
        params = [_Param(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            'TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256')]
        config = _make_puppet(params)._get_haproxy_tls_config()
        self.assertNotIn(_KEY_CIPHERS, config)
        self.assertIn(_KEY_SUITES, config)

    @mock.patch('sysinv.puppet.platform.utils.get_debian_release_codename',
                return_value='bullseye')
    def test_bullseye_no_curves(self, _mock_codename):
        """On Bullseye (HAProxy 2.2), ssl_bind_curves must NOT be set."""
        config = _make_puppet()._get_haproxy_tls_config()
        self.assertNotIn(_KEY_CURVES, config)

    @mock.patch('sysinv.puppet.platform.utils.get_debian_release_codename',
                return_value='trixie')
    def test_trixie_has_curves(self, _mock_codename):
        """On Trixie (HAProxy 2.8+), ssl_bind_curves must be set."""
        config = _make_puppet()._get_haproxy_tls_config()
        self.assertIn(_KEY_CURVES, config)
        self.assertEqual(config[_KEY_CURVES],
                         'secp256r1:secp384r1:secp521r1')

    @mock.patch('sysinv.puppet.platform.utils.get_debian_release_codename',
                return_value='bullseye')
    def test_db_failure_uses_defaults(self, _mock_codename):
        """DB read failure falls back to default TLS config."""
        puppet = _make_puppet()
        puppet.dbapi.service_parameter_get_all.side_effect = Exception('DB down')
        config = puppet._get_haproxy_tls_config()
        self.assertEqual(config[_KEY_OPTS],
                         'no-sslv3 no-tlsv10 no-tlsv11')
        self.assertIn(_KEY_CIPHERS, config)
        self.assertIn(_KEY_SUITES, config)
