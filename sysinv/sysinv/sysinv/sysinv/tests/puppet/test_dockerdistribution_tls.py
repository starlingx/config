# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
from collections import namedtuple
from unittest import TestCase

from sysinv.common import constants
from sysinv.puppet.dockerdistribution import DockerDistributionPuppet
from sysinv.puppet.dockerdistribution import GO_TLS_VERSION_MAP

_Param = namedtuple('_Param', ['name', 'value'])

_KEY_MIN_VER = 'platform::dockerdistribution::params::tls_min_version'
_KEY_CIPHERS = 'platform::dockerdistribution::params::tls_cipher_suites'


def _make_puppet(params=None):
    operator = mock.MagicMock()
    operator.dbapi.service_parameter_get_all.return_value = params or []
    return DockerDistributionPuppet(operator)


class TestGoTlsVersionMap(TestCase):
    """Tests for VersionTLS* to Go tls format mapping."""

    def test_tls12_maps_to_go_format(self):
        self.assertEqual(GO_TLS_VERSION_MAP[
            constants.SERVICE_PARAM_PLATFORM_TLS_VERSION_TLS12], 'tls1.2')

    def test_tls13_maps_to_go_format(self):
        self.assertEqual(GO_TLS_VERSION_MAP[
            constants.SERVICE_PARAM_PLATFORM_TLS_VERSION_TLS13], 'tls1.3')


class TestGetDockerRegistryTlsConfig(TestCase):
    """Tests for _get_docker_registry_tls_config() hieradata generation."""

    def test_defaults_tls12(self):
        config = _make_puppet()._get_docker_registry_tls_config()
        self.assertEqual(config[_KEY_MIN_VER], 'tls1.2')

    def test_defaults_cipher_list(self):
        config = _make_puppet()._get_docker_registry_tls_config()
        self.assertIsInstance(config[_KEY_CIPHERS], list)
        self.assertTrue(len(config[_KEY_CIPHERS]) > 0)

    def test_tls13_version(self):
        params = [_Param(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            constants.SERVICE_PARAM_PLATFORM_TLS_VERSION_TLS13)]
        config = _make_puppet(params)._get_docker_registry_tls_config()
        self.assertEqual(config[_KEY_MIN_VER], 'tls1.3')

    def test_custom_ciphers(self):
        params = [_Param(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            'TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256')]
        config = _make_puppet(params)._get_docker_registry_tls_config()
        self.assertEqual(config[_KEY_CIPHERS],
                         ['TLS_AES_256_GCM_SHA384',
                          'TLS_AES_128_GCM_SHA256'])

    def test_ciphers_are_iana_format(self):
        """Docker Registry uses IANA names natively, no conversion."""
        config = _make_puppet()._get_docker_registry_tls_config()
        for cipher in config[_KEY_CIPHERS]:
            self.assertTrue(cipher.startswith('TLS_'),
                            "Cipher %s not in IANA format" % cipher)

    def test_db_failure_uses_defaults(self):
        puppet = _make_puppet()
        puppet.dbapi.service_parameter_get_all.side_effect = \
            Exception('DB down')
        config = puppet._get_docker_registry_tls_config()
        self.assertEqual(config[_KEY_MIN_VER], 'tls1.2')
        self.assertIsInstance(config[_KEY_CIPHERS], list)
