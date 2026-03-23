#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
API-level tests for TLS service parameters.
Tests POST/PATCH/DELETE through the service_parameter API endpoint.
"""

from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.api.test_service_parameters import \
    ApiServiceParameterTestCaseMixin
from sysinv.tests.db import base as dbbase


class TLSServiceParameterTestMixin(ApiServiceParameterTestCaseMixin):
    """TLS-specific service parameter API tests."""

    def _tls_post(self, name, value, expect_errors=False,
                  error_message=None):
        data = {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            'name': name,
            'value': value,
        }
        return self.post(data, expect_errors=expect_errors,
                         error_message=error_message)

    # --- tls-min-version POST tests ---

    def test_tls_min_version_valid_tls12(self):
        response = self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            'VersionTLS12')
        self.assertEqual(response['value'], 'VersionTLS12')

    def test_tls_min_version_valid_tls13(self):
        response = self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            'VersionTLS13')
        self.assertEqual(response['value'], 'VersionTLS13')

    def test_tls_min_version_invalid_tls11(self):
        self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            'VersionTLS11',
            expect_errors=True,
            error_message="Invalid TLS version")

    def test_tls_min_version_invalid_empty(self):
        self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            '',
            expect_errors=True,
            error_message="The service parameter value is mandatory")

    def test_tls_min_version_invalid_random(self):
        self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            'TLSv1.2',
            expect_errors=True,
            error_message="Invalid TLS version")

    # --- tls-cipher-suite POST tests ---

    def test_tls_cipher_suite_valid_single(self):
        response = self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')
        self.assertEqual(response['value'],
                         'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')

    def test_tls_cipher_suite_valid_multiple(self):
        value = ('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,'
                 'TLS_AES_256_GCM_SHA384')
        response = self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            value)
        self.assertEqual(response['value'], value)

    def test_tls_cipher_suite_valid_all_defaults(self):
        value = constants.SERVICE_PARAM_PLATFORM_TLS_CIPHER_SUITE_DEFAULT
        response = self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            value)
        self.assertEqual(response['value'], value)

    def test_tls_cipher_suite_invalid_cipher(self):
        self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            'TLS_RSA_WITH_AES_128_CBC_SHA',
            expect_errors=True,
            error_message="Invalid cipher suite")

    def test_tls_cipher_suite_invalid_openssl_name(self):
        self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            'ECDHE-RSA-AES256-GCM-SHA384',
            expect_errors=True,
            error_message="Invalid cipher suite")

    def test_tls_cipher_suite_invalid_mixed(self):
        value = 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,BOGUS_CIPHER'
        self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            value,
            expect_errors=True,
            error_message="Invalid cipher suite")

    # --- PATCH tests ---

    def test_tls_min_version_patch_valid(self):
        # Create with TLS12, then patch to TLS13
        response = self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            'VersionTLS12')
        uuid = response['uuid']
        patched = self.patch(uuid, {'value': 'VersionTLS13'})
        self.assertEqual(patched['value'], 'VersionTLS13')

    def test_tls_min_version_patch_invalid(self):
        response = self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            'VersionTLS12')
        uuid = response['uuid']
        self.patch(uuid, {'value': 'VersionTLS11'},
                   expect_errors=True,
                   error_message="Invalid TLS version")

    def test_tls_cipher_suite_patch_valid(self):
        response = self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')
        uuid = response['uuid']
        patched = self.patch(uuid, {'value': 'TLS_AES_256_GCM_SHA384'})
        self.assertEqual(patched['value'], 'TLS_AES_256_GCM_SHA384')

    def test_tls_cipher_suite_patch_invalid(self):
        response = self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')
        uuid = response['uuid']
        self.patch(uuid, {'value': 'INVALID_CIPHER'},
                   expect_errors=True,
                   error_message="Invalid cipher suite")

    # --- DELETE tests ---

    def test_tls_min_version_delete(self):
        response = self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            'VersionTLS12')
        uuid = response['uuid']
        del_response = self.delete(self.get_single_url(uuid),
                                   headers=self.API_HEADERS)
        self.assertEqual(del_response.status_code, 204)

    def test_tls_cipher_suite_delete(self):
        response = self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')
        uuid = response['uuid']
        del_response = self.delete(self.get_single_url(uuid),
                                   headers=self.API_HEADERS)
        self.assertEqual(del_response.status_code, 204)

    def test_tls_min_version_delete_then_recreate(self):
        response = self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            'VersionTLS12')
        self.delete(self.get_single_url(response['uuid']),
                    headers=self.API_HEADERS)
        response = self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
            'VersionTLS13')
        self.assertEqual(response['value'], 'VersionTLS13')

    def test_tls_cipher_suite_delete_then_recreate(self):
        response = self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')
        self.delete(self.get_single_url(response['uuid']),
                    headers=self.API_HEADERS)
        response = self._tls_post(
            constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
            'TLS_AES_256_GCM_SHA384')
        self.assertEqual(response['value'], 'TLS_AES_256_GCM_SHA384')


class PlatformIPv4ControllerTLSServiceParameterTestCase(
        TLSServiceParameterTestMixin,
        base.FunctionalTest,
        dbbase.ProvisionedControllerHostTestCase):
    pass
