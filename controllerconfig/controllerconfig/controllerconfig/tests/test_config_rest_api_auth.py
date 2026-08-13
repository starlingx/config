#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Extended coverage tests for rest_api_utils module."""

import unittest
from unittest import mock

from controllerconfig.common import rest_api_utils


class TestRestApiExtended(unittest.TestCase):
    """Extended tests for rest_api_utils helper functions."""

    def _make_token(self):
        token = mock.MagicMock()
        token.get_id.return_value = "tok-123"
        return token

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_delete_endpoint(self, mock_req):
        """delete_endpoint calls DELETE on /endpoints/<id>."""
        mock_req.return_value = {"endpoint": {}}
        token = self._make_token()
        rest_api_utils.delete_endpoint(token, "http://api/v3", "e1")
        mock_req.assert_called_once_with(
            token, "DELETE", "http://api/v3/endpoints/e1"
        )

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_create_domain_user(self, mock_req):
        """create_domain_user calls POST on /users."""
        mock_req.return_value = {"user": {"id": "u1"}}
        token = self._make_token()
        result = rest_api_utils.create_domain_user(
            token, "http://api/v3", "admin", "pass",
            "admin@test.com", "d1"
        )
        self.assertEqual(result.get_user_id(), "u1")

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_delete_user(self, mock_req):
        """delete_user calls DELETE on /users/<id>."""
        mock_req.return_value = {"user": {}}
        token = self._make_token()
        rest_api_utils.delete_user(token, "http://api/v3", "u1")
        mock_req.assert_called_once_with(
            token, "DELETE", "http://api/v3/users/u1"
        )

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_add_role_on_domain(self, mock_req):
        """add_role_on_domain calls PUT on correct URL."""
        mock_req.return_value = {}
        token = self._make_token()
        rest_api_utils.add_role_on_domain(
            token, "http://api/v3", "d1", "u1", "r1"
        )
        expected = "http://api/v3/domains/d1/users/u1/roles/r1"
        mock_req.assert_called_once_with(token, "PUT", expected)

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_create_domain(self, mock_req):
        """create_domain calls POST on /domains."""
        mock_req.return_value = {"domain": {"id": "d1"}}
        token = self._make_token()
        result = rest_api_utils.create_domain(
            token, "http://api/v3", "test", "Test domain"
        )
        self.assertEqual(result.get_domain_id(), "d1")

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_disable_domain(self, mock_req):
        """disable_domain calls PATCH on /domains/<id>."""
        mock_req.return_value = {"domain": {"id": "d1"}}
        token = self._make_token()
        rest_api_utils.disable_domain(token, "http://api/v3", "d1")
        call_args = mock_req.call_args
        self.assertEqual(call_args[0][1], "PATCH")

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_delete_domain(self, mock_req):
        """delete_domain calls DELETE on /domains/<id>."""
        mock_req.return_value = {"domain": {}}
        token = self._make_token()
        rest_api_utils.delete_domain(token, "http://api/v3", "d1")
        mock_req.assert_called_once_with(
            token, "DELETE", "http://api/v3/domains/d1"
        )

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_delete_project(self, mock_req):
        """delete_project calls DELETE on /projects/<id>."""
        mock_req.return_value = {"project": {}}
        token = self._make_token()
        rest_api_utils.delete_project(token, "http://api/v3", "p1")
        mock_req.assert_called_once_with(
            token, "DELETE", "http://api/v3/projects/p1"
        )


if __name__ == "__main__":
    unittest.main()
