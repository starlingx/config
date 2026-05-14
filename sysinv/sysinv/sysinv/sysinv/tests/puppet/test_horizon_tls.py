# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
from collections import namedtuple
from unittest import TestCase

from sysinv.common import constants
from sysinv.puppet.horizon import HorizonPuppet
from sysinv.puppet.horizon import IANA_TO_OPENSSL_CIPHER_MAP
from sysinv.puppet.horizon import TLS13_CIPHERS


# Lightweight stand-in for a service_parameter DB row
_Param = namedtuple('_Param', ['name', 'value'])

# Hieradata key shortcuts
_KEY_MIN_VER = 'openstack::horizon::params::tls_min_version'
_KEY_CIPHER = 'openstack::horizon::params::tls_cipher_list'


def _make_puppet(params=None):
    """Create a HorizonPuppet with a mocked operator/dbapi."""
    operator = mock.MagicMock()
    operator.dbapi.service_parameter_get_all.return_value = params or []
    puppet = HorizonPuppet(operator)
    return puppet


class TestLighttpdTlsConfig(TestCase):
    """Tests for _get_lighttpd_tls_config() hieradata generation."""

    def test_defaults_when_no_params(self):
        """No DB params -> defaults (TLS12, all 9 ciphers)."""
        puppet = _make_puppet()
        config = puppet._get_lighttpd_tls_config()
        self.assertEqual(config[_KEY_MIN_VER], 'VersionTLS12')
        # Only 6 TLS 1.2 ciphers (TLS 1.3 never in ssl.cipher-list)
        cipher_list = config[_KEY_CIPHER]
        self.assertEqual(len(cipher_list.split(':')), 6)

    def test_tls13_min_version(self):
        """VersionTLS13 from DB is passed through."""
        params = [_Param(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            'VersionTLS13')]
        puppet = _make_puppet(params)
        config = puppet._get_lighttpd_tls_config()
        self.assertEqual(config[_KEY_MIN_VER], 'VersionTLS13')

    def test_tls12_ciphers_converted_to_openssl(self):
        """TLS 1.2 IANA ciphers are converted to OpenSSL names."""
        params = [_Param(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')]
        puppet = _make_puppet(params)
        config = puppet._get_lighttpd_tls_config()
        self.assertEqual(config[_KEY_CIPHER],
                         'ECDHE-RSA-AES256-GCM-SHA384')

    def test_tls13_cipher_only_returns_none(self):
        """TLS 1.3 only cipher -> None (skipped from cipher list)."""
        params = [_Param(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            'TLS_AES_256_GCM_SHA384')]
        puppet = _make_puppet(params)
        config = puppet._get_lighttpd_tls_config()
        self.assertIsNone(config[_KEY_CIPHER])

    def test_mixed_tls12_and_tls13_only_tls12_in_list(self):
        """Mixed TLS 1.2 + 1.3: only TLS 1.2 in cipher list."""
        params = [_Param(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,'
            'TLS_AES_256_GCM_SHA384')]
        puppet = _make_puppet(params)
        config = puppet._get_lighttpd_tls_config()
        self.assertEqual(
            config[_KEY_CIPHER],
            'ECDHE-RSA-AES256-GCM-SHA384')

    def test_unknown_cipher_skipped(self):
        """Unknown cipher names are skipped."""
        params = [_Param(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,UNKNOWN_CIPHER')]
        puppet = _make_puppet(params)
        config = puppet._get_lighttpd_tls_config()
        self.assertEqual(config[_KEY_CIPHER], 'ECDHE-RSA-AES256-GCM-SHA384')

    def test_db_failure_falls_back_to_defaults(self):
        """DB exception -> defaults used."""
        operator = mock.MagicMock()
        operator.dbapi.service_parameter_get_all.side_effect = \
            Exception("DB error")
        puppet = HorizonPuppet(operator)
        config = puppet._get_lighttpd_tls_config()
        self.assertEqual(config[_KEY_MIN_VER], 'VersionTLS12')
        self.assertIsNotNone(config[_KEY_CIPHER])

    def test_all_default_ciphers_in_output(self):
        """All 6 default TLS 1.2 ciphers produce valid OpenSSL names."""
        puppet = _make_puppet()
        config = puppet._get_lighttpd_tls_config()
        ciphers = config[_KEY_CIPHER].split(':')
        # Only 6 TLS 1.2 ciphers (TLS 1.3 never in ssl.cipher-list)
        self.assertEqual(len(ciphers), 6)
        for c in ciphers:
            self.assertTrue(len(c) > 0, "Empty cipher in list")

    def test_cipher_map_covers_all_tls12(self):
        """IANA_TO_OPENSSL_CIPHER_MAP has all 6 TLS 1.2 ciphers."""
        self.assertEqual(len(IANA_TO_OPENSSL_CIPHER_MAP), 6)

    def test_tls13_ciphers_list_has_three(self):
        """TLS13_CIPHERS has exactly 3 entries."""
        self.assertEqual(len(TLS13_CIPHERS), 3)

    def test_tls13_ciphers_never_in_cipher_list(self):
        """TLS 1.3 cipher names are never in ssl.cipher-list.

        lighttpd 1.4.55 on Bullseye crashes if TLS 1.3 cipher names
        appear in ssl.cipher-list. OpenSSL 1.1.1 always enables TLS
        1.3 ciphers regardless of ssl.cipher-list.
        """
        params = [
            _Param(constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
                   constants.SERVICE_PARAM_PLATFORM_TLS_CIPHER_SUITE_DEFAULT)]
        puppet = _make_puppet(params)
        config = puppet._get_lighttpd_tls_config()
        ciphers = config[_KEY_CIPHER].split(':')
        # Only TLS 1.2 OpenSSL ciphers, no TLS 1.3 names
        self.assertEqual(len(ciphers), 6)
        for c in ciphers:
            self.assertNotIn(c, TLS13_CIPHERS)

    def test_tls13_min_cipher_list_unchanged(self):
        """When min=TLS13, cipher list still has TLS 1.2 ciphers.

        On Bullseye, lighttpd 1.4.55 has no MinProtocol support.
        TLS 1.3 enforcement is a known limitation. Cipher list
        always contains TLS 1.2 ciphers for lighttpd stability.
        """
        params = [
            _Param(constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
                   'VersionTLS13'),
            _Param(constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
                   constants.SERVICE_PARAM_PLATFORM_TLS_CIPHER_SUITE_DEFAULT)]
        puppet = _make_puppet(params)
        config = puppet._get_lighttpd_tls_config()
        ciphers = config[_KEY_CIPHER].split(':')
        self.assertEqual(len(ciphers), 6)
        for c in ciphers:
            self.assertNotIn(c, TLS13_CIPHERS)
