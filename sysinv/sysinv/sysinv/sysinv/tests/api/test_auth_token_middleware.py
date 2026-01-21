#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the OIDC AuthTokenMiddleware
"""

import json
import mock
import unittest

from sysinv.api.middleware import auth_token
from sysinv.common import exception
from sysinv.tests.db import base as dbbase


class MockApp(object):
    def __call__(self, env, start_response):
        return "mock_app_response"


class MockConf(object):
    def get(self, key, default=None):
        config_map = {
            'oidc_default_domain': 'TestDomain',
            'oidc_default_project': 'TestProject'
        }
        return config_map.get(key, default)

    def __getitem__(self, key):
        return self.get(key)


class AuthTokenMiddlewareTestCase(dbbase.DbTestCase):

    def setUp(self):
        super(AuthTokenMiddlewareTestCase, self).setUp()
        self.mock_app = MockApp()
        self.mock_conf = MockConf()

        # Mock the parent class initialization
        with mock.patch('keystonemiddleware.auth_token.AuthProtocol.__init__'):
            self.middleware = auth_token.AuthTokenMiddleware(
                self.mock_app, self.mock_conf, ['/v1/public']
            )
            # Set the required attributes that would be set by parent init
            self.middleware._sysinv_app = self.mock_app
            self.middleware.default_domain = 'TestDomain'
            self.middleware.default_project = 'TestProject'
            self.middleware._oidc_token_cache = {}
            # Manually set the compiled regex patterns for testing
            import re
            self.middleware.public_api_routes = [re.compile('/v1/public(\.json|\.xml)?$')]

    @mock.patch('platform_util.oidc.oidc_utils.get_oidc_token_claims')
    @mock.patch('platform_util.oidc.oidc_utils.parse_oidc_token_claims')
    def test_oidc_auth_success(self, mock_parse, mock_get_claims):
        # Setup mocks
        mock_get_claims.return_value = {'sub': 'testuser', 'groups': ['admin']}
        mock_parse.return_value = {'username': 'testuser', 'roles': ['admin', 'user']}

        # Test
        result = self.middleware.oidc_middleware._oidc_auth('test-token')

        # Verify result
        self.assertEqual(result['username'], 'testuser')
        self.assertEqual(result['roles'], ['admin', 'user'])
        mock_get_claims.assert_called_once_with('test-token', self.middleware.oidc_middleware._oidc_token_cache)
        mock_parse.assert_called_once()

    def test_oidc_auth_missing_token(self):
        # Test with no token
        self.assertRaises(exception.NotAuthorized, self.middleware.oidc_middleware._oidc_auth, None)

    @mock.patch('platform_util.oidc.oidc_utils.get_oidc_token_claims')
    def test_oidc_auth_claims_exception(self, mock_get_claims):
        # Setup mock to raise exception
        mock_get_claims.side_effect = Exception('Claims error')

        # Test
        self.assertRaises(exception.NotAuthorized, self.middleware.oidc_middleware._oidc_auth, 'test-token')

    @mock.patch('platform_util.oidc.oidc_utils.get_oidc_token_claims')
    @mock.patch('platform_util.oidc.oidc_utils.parse_oidc_token_claims')
    def test_oidc_auth_parse_exception(self, mock_parse, mock_get_claims):
        # Setup mocks
        mock_get_claims.return_value = {'sub': 'testuser'}
        mock_parse.side_effect = Exception('Parse error')

        # Test
        self.assertRaises(exception.NotAuthorized, self.middleware.oidc_middleware._oidc_auth, 'test-token')

    def test_call_public_api(self):
        # Test public API bypass
        env = {'PATH_INFO': '/v1/public'}
        start_response = mock.Mock()

        with mock.patch.object(self.middleware.oidc_middleware, '_oidc_auth') as mock_oidc_auth:
            self.middleware(env, start_response)

            # Verify OIDC auth is not called for public API
            mock_oidc_auth.assert_not_called()
            self.assertTrue(env['is_public_api'])

    def test_call_with_keystone_token(self):
        # Test with Keystone token present
        env = {
            'PATH_INFO': '/v1/private/test',
            'HTTP_X_AUTH_TOKEN': 'keystone-token'
        }
        start_response = mock.Mock()

        with mock.patch.object(self.middleware.oidc_middleware, '_oidc_auth') as mock_oidc_auth:
            with mock.patch('keystonemiddleware.auth_token.AuthProtocol.__call__') as mock_super:
                mock_super.return_value = 'keystone_response'
                self.middleware(env, start_response)

            # Verify OIDC auth is not called when Keystone token exists
            mock_oidc_auth.assert_not_called()
            mock_super.assert_called_once()

    def test_call_with_oidc_token(self):
        # Test with OIDC token in headers
        env = {
            'PATH_INFO': '/v1/private/test',
            'HTTP_OIDC_TOKEN': 'oidc-token'
        }
        start_response = mock.Mock()

        with mock.patch.object(self.middleware.oidc_middleware, '_oidc_auth') as mock_oidc_auth:
            mock_oidc_auth.return_value = {'username': 'test', 'roles': ['admin']}
            self.middleware(env, start_response)

            # Verify OIDC auth is called
            mock_oidc_auth.assert_called_once_with('oidc-token')

    def test_call_with_headers_raw(self):
        # Test with OIDC token in headers_raw
        env = {
            'PATH_INFO': '/v1/private/test',
            'headers_raw': [('OIDC-Token', 'oidc-token')]
        }
        start_response = mock.Mock()

        with mock.patch.object(self.middleware.oidc_middleware, '_oidc_auth') as mock_oidc_auth:
            mock_oidc_auth.return_value = {'username': 'test', 'roles': ['admin']}
            self.middleware(env, start_response)

            # Verify OIDC auth is called with token from headers_raw
            mock_oidc_auth.assert_called_once_with('oidc-token')

    def test_call_malformed_headers_raw(self):
        # Test with malformed headers_raw
        env = {
            'PATH_INFO': '/v1/private/test',
            'headers_raw': 'invalid_format'
        }
        start_response = mock.Mock()

        with mock.patch.object(self.middleware.oidc_middleware, '_oidc_auth') as mock_oidc_auth:
            mock_oidc_auth.return_value = {'username': 'test', 'roles': ['admin']}
            self.middleware(env, start_response)

            # Should handle malformed headers_raw gracefully
            mock_oidc_auth.assert_called_once_with(None)

    def test_call_no_token(self):
        # Test with no token at all
        env = {'PATH_INFO': '/v1/private/test'}
        start_response = mock.Mock()

        with mock.patch.object(self.middleware.oidc_middleware, '_oidc_auth') as mock_oidc_auth:
            mock_oidc_auth.side_effect = exception.NotAuthorized('No token')
            result = self.middleware(env, start_response)

            # Should return 401 error response with new format
            start_response.assert_called_once_with('401 Unauthorized', mock.ANY)
            self.assertIsInstance(result, list)
            # Verify the response body contains the new error format
            response_body = result[0].decode('utf-8')
            error_data = json.loads(response_body)
            self.assertIn('error_message', error_data)

    def test_call_with_x_auth_token_header(self):
        # Test with X-Auth-Token in headers_raw
        env = {
            'PATH_INFO': '/v1/private/test',
            'headers_raw': [('X-Auth-Token', 'keystone-token')]
        }
        start_response = mock.Mock()

        with mock.patch.object(self.middleware.oidc_middleware, '_oidc_auth') as mock_oidc_auth:
            with mock.patch('keystonemiddleware.auth_token.AuthProtocol.__call__') as mock_super:
                mock_super.return_value = 'keystone_response'
                self.middleware(env, start_response)

            # Verify OIDC auth is not called when X-Auth-Token exists in headers_raw
            mock_oidc_auth.assert_not_called()
            mock_super.assert_called_once()


if __name__ == '__main__':
    unittest.main()
