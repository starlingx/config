#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for TLS service parameter constants and validation.
"""

import unittest

import wsme.exc

from sysinv.common import constants
from sysinv.common import service_parameter


class TestTLSConstants(unittest.TestCase):
    """Verify TLS constants are defined correctly."""

    def test_tls_parameter_names(self):
        self.assertEqual(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            'tls-min-version')
        self.assertEqual(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            'tls-cipher-suite')

    def test_tls_version_values(self):
        self.assertEqual(
            constants.SERVICE_PARAM_PLATFORM_TLS_VERSION_TLS12,
            'VersionTLS12')
        self.assertEqual(
            constants.SERVICE_PARAM_PLATFORM_TLS_VERSION_TLS13,
            'VersionTLS13')
        self.assertEqual(
            len(constants.SERVICE_PARAM_PLATFORM_TLS_VERSIONS), 2)

    def test_tls_default_version(self):
        self.assertEqual(
            constants.SERVICE_PARAM_PLATFORM_TLS_MIN_VERSION_DEFAULT,
            'VersionTLS12')

    def test_tls_valid_ciphers_count(self):
        self.assertEqual(
            len(constants.SERVICE_PARAM_PLATFORM_TLS_CIPHERS_VALID), 9)

    def test_tls_valid_ciphers_contain_tls12(self):
        tls12_ciphers = [
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
        ]
        for cipher in tls12_ciphers:
            self.assertIn(
                cipher,
                constants.SERVICE_PARAM_PLATFORM_TLS_CIPHERS_VALID)

    def test_tls_valid_ciphers_contain_tls13(self):
        tls13_ciphers = [
            'TLS_AES_256_GCM_SHA384',
            'TLS_AES_128_GCM_SHA256',
            'TLS_CHACHA20_POLY1305_SHA256',
        ]
        for cipher in tls13_ciphers:
            self.assertIn(
                cipher,
                constants.SERVICE_PARAM_PLATFORM_TLS_CIPHERS_VALID)

    def test_tls_default_cipher_suite_contains_all_valid(self):
        default = constants.SERVICE_PARAM_PLATFORM_TLS_CIPHER_SUITE_DEFAULT
        for cipher in constants.SERVICE_PARAM_PLATFORM_TLS_CIPHERS_VALID:
            self.assertIn(cipher, default)

    def test_tls_params_in_platform_config_optional(self):
        self.assertIn(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            service_parameter.PLATFORM_CONFIG_PARAMETER_OPTIONAL)
        self.assertIn(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            service_parameter.PLATFORM_CONFIG_PARAMETER_OPTIONAL)

    def test_tls_params_have_validators(self):
        validators = service_parameter.PLATFORM_CONFIG_PARAMETER_VALIDATOR
        self.assertIn(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            validators)
        self.assertIn(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            validators)


class TestValidateTLSMinVersion(unittest.TestCase):
    """Test _validate_tls_min_version()."""

    def test_valid_tls12(self):
        # Should not raise
        service_parameter._validate_tls_min_version(
            'tls-min-version', 'VersionTLS12')

    def test_valid_tls13(self):
        # Should not raise
        service_parameter._validate_tls_min_version(
            'tls-min-version', 'VersionTLS13')

    def test_invalid_tls11(self):
        self.assertRaises(
            wsme.exc.ClientSideError,
            service_parameter._validate_tls_min_version,
            'tls-min-version', 'VersionTLS11')

    def test_invalid_tls10(self):
        self.assertRaises(
            wsme.exc.ClientSideError,
            service_parameter._validate_tls_min_version,
            'tls-min-version', 'VersionTLS10')

    def test_invalid_empty(self):
        self.assertRaises(
            wsme.exc.ClientSideError,
            service_parameter._validate_tls_min_version,
            'tls-min-version', '')

    def test_invalid_random_string(self):
        self.assertRaises(
            wsme.exc.ClientSideError,
            service_parameter._validate_tls_min_version,
            'tls-min-version', 'TLSv1.2')

    def test_invalid_lowercase(self):
        self.assertRaises(
            wsme.exc.ClientSideError,
            service_parameter._validate_tls_min_version,
            'tls-min-version', 'versiontls12')

    def test_error_message_lists_valid_values(self):
        try:
            service_parameter._validate_tls_min_version(
                'tls-min-version', 'bad')
            self.fail("Expected ClientSideError")
        except wsme.exc.ClientSideError as e:
            self.assertIn('VersionTLS12', str(e))
            self.assertIn('VersionTLS13', str(e))


class TestValidateTLSCipherSuite(unittest.TestCase):
    """Test _validate_tls_cipher_suite()."""

    def test_valid_single_cipher(self):
        service_parameter._validate_tls_cipher_suite(
            'tls-cipher-suite',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')

    def test_valid_multiple_ciphers(self):
        value = ','.join([
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
        ])
        service_parameter._validate_tls_cipher_suite(
            'tls-cipher-suite', value)

    def test_valid_all_ciphers(self):
        value = ','.join(
            constants.SERVICE_PARAM_PLATFORM_TLS_CIPHERS_VALID)
        service_parameter._validate_tls_cipher_suite(
            'tls-cipher-suite', value)

    def test_invalid_single_cipher(self):
        self.assertRaises(
            wsme.exc.ClientSideError,
            service_parameter._validate_tls_cipher_suite,
            'tls-cipher-suite', 'TLS_RSA_WITH_AES_128_CBC_SHA')

    def test_invalid_mixed_with_valid(self):
        value = 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,INVALID_CIPHER'
        self.assertRaises(
            wsme.exc.ClientSideError,
            service_parameter._validate_tls_cipher_suite,
            'tls-cipher-suite', value)

    def test_invalid_openssl_format(self):
        # OpenSSL names should be rejected (only IANA accepted)
        self.assertRaises(
            wsme.exc.ClientSideError,
            service_parameter._validate_tls_cipher_suite,
            'tls-cipher-suite', 'ECDHE-RSA-AES256-GCM-SHA384')

    def test_invalid_empty_string(self):
        self.assertRaises(
            wsme.exc.ClientSideError,
            service_parameter._validate_tls_cipher_suite,
            'tls-cipher-suite', '')

    def test_valid_with_whitespace(self):
        # Spaces around commas should be handled
        value = ('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 , '
                 'TLS_AES_256_GCM_SHA384')
        service_parameter._validate_tls_cipher_suite(
            'tls-cipher-suite', value)

    def test_error_message_lists_invalid_ciphers(self):
        try:
            service_parameter._validate_tls_cipher_suite(
                'tls-cipher-suite', 'BAD_CIPHER_1,BAD_CIPHER_2')
            self.fail("Expected ClientSideError")
        except wsme.exc.ClientSideError as e:
            self.assertIn('BAD_CIPHER_1', str(e))
            self.assertIn('BAD_CIPHER_2', str(e))

    def test_error_message_lists_valid_ciphers(self):
        try:
            service_parameter._validate_tls_cipher_suite(
                'tls-cipher-suite', 'INVALID')
            self.fail("Expected ClientSideError")
        except wsme.exc.ClientSideError as e:
            self.assertIn('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                          str(e))
