#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for controllerconfig.common.rest_api_utils module."""

import json
import unittest
from unittest import mock

from controllerconfig.common.exceptions import KeystoneFail
from controllerconfig.common import rest_api_utils
import io
from six.moves.urllib.error import HTTPError
from six.moves.urllib.error import URLError


class TestRestApiRequest(unittest.TestCase):
    """Tests for rest_api_request function."""

    def _make_token(self):
        token = mock.MagicMock()
        token.get_id.return_value = "tok-123"
        return token

    @mock.patch("controllerconfig.common.rest_api_utils.urlrequest")
    def test_get_request_success(self, mock_urlrequest):
        """Successful GET request returns parsed JSON."""
        mock_response = mock.MagicMock()
        mock_response.read.return_value = json.dumps({"result": "ok"})
        mock_urlrequest.urlopen.return_value = mock_response

        token = self._make_token()
        result = rest_api_utils.rest_api_request(
            token, "GET", "http://api/test"
        )
        self.assertEqual(result, {"result": "ok"})
        mock_response.close.assert_called_once()

    @mock.patch("controllerconfig.common.rest_api_utils.urlrequest")
    def test_empty_response(self, mock_urlrequest):
        """Empty response returns empty dict."""
        mock_response = mock.MagicMock()
        mock_response.read.return_value = ""
        mock_urlrequest.urlopen.return_value = mock_response

        token = self._make_token()
        result = rest_api_utils.rest_api_request(
            token, "GET", "http://api/test"
        )
        self.assertEqual(result, {})

    @mock.patch("controllerconfig.common.rest_api_utils.urlrequest")
    def test_post_with_payload(self, mock_urlrequest):
        """POST request with payload sets Content-type header."""
        mock_response = mock.MagicMock()
        mock_response.read.return_value = json.dumps({"id": "new"})
        mock_urlrequest.urlopen.return_value = mock_response
        mock_urlrequest.Request.return_value = mock.MagicMock()

        token = self._make_token()
        payload = json.dumps({"name": "test"})
        result = rest_api_utils.rest_api_request(
            token, "POST", "http://api/test",
            api_cmd_payload=payload
        )
        self.assertEqual(result, {"id": "new"})

    @mock.patch("controllerconfig.common.rest_api_utils.urlrequest")
    def test_http_401_sets_token_expired(self, mock_urlrequest):
        """HTTP 401 sets token as expired and raises KeystoneFail."""
        error = HTTPError("http://api/test", 401, "Unauthorized",
                          {}, None)
        mock_urlrequest.urlopen.side_effect = error
        mock_urlrequest.Request.return_value = mock.MagicMock()

        token = self._make_token()
        with self.assertRaises(KeystoneFail):
            rest_api_utils.rest_api_request(
                token, "GET", "http://api/test"
            )
        token.set_expired.assert_called_once()

    @mock.patch("controllerconfig.common.rest_api_utils.urlrequest")
    def test_http_500_raises_keystone_fail(self, mock_urlrequest):
        """HTTP 500 raises KeystoneFail."""
        error = HTTPError("http://api/test", 500, "Server Error",
                          {}, None)
        mock_urlrequest.urlopen.side_effect = error
        mock_urlrequest.Request.return_value = mock.MagicMock()

        token = self._make_token()
        with self.assertRaises(KeystoneFail):
            rest_api_utils.rest_api_request(
                token, "GET", "http://api/test"
            )

    @mock.patch("controllerconfig.common.rest_api_utils.urlrequest")
    def test_url_error_raises_keystone_fail(self, mock_urlrequest):
        """URLError raises KeystoneFail."""
        mock_urlrequest.urlopen.side_effect = (
            URLError("connection refused")
        )
        mock_urlrequest.Request.return_value = mock.MagicMock()

        token = self._make_token()
        with self.assertRaises(KeystoneFail):
            rest_api_utils.rest_api_request(
                token, "GET", "http://api/test"
            )


class TestGetToken(unittest.TestCase):
    """Tests for get_token function."""

    @mock.patch("controllerconfig.common.rest_api_utils.urlrequest")
    def test_get_token_success(self, mock_urlrequest):
        """Successful token request returns Token object."""
        mock_response = mock.MagicMock()
        mock_response.read.return_value = json.dumps({
            "token": {
                "expires_at": "2099-01-01T00:00:00Z",
                "catalog": []
            }
        })
        mock_response.info.return_value.getheader.return_value = (
            "tok-abc"
        )
        mock_urlrequest.urlopen.return_value = mock_response
        mock_urlrequest.Request.return_value = mock.MagicMock()

        result = rest_api_utils.get_token(
            "http://keystone:5000/v3", "admin", "admin",
            "password", "Default", "Default"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.get_id(), "tok-abc")

    @mock.patch("controllerconfig.common.rest_api_utils.urlrequest")
    def test_get_token_http_error(self, mock_urlrequest):
        """HTTP error returns None."""
        fp = io.BytesIO(b"Unauthorized")
        mock_urlrequest.urlopen.side_effect = HTTPError(
            "http://keystone", 401, "Unauthorized", {}, fp
        )
        mock_urlrequest.Request.return_value = mock.MagicMock()

        result = rest_api_utils.get_token(
            "http://keystone:5000/v3", "admin", "admin",
            "password", "Default", "Default"
        )
        self.assertIsNone(result)

    @mock.patch("controllerconfig.common.rest_api_utils.urlrequest")
    def test_get_token_url_error(self, mock_urlrequest):
        """URL error returns None."""
        mock_urlrequest.urlopen.side_effect = URLError("refused")
        mock_urlrequest.Request.return_value = mock.MagicMock()

        result = rest_api_utils.get_token(
            "http://keystone:5000/v3", "admin", "admin",
            "password", "Default", "Default"
        )
        self.assertIsNone(result)


class TestApiHelpers(unittest.TestCase):
    """Tests for high-level API helper functions."""

    def _make_token(self):
        token = mock.MagicMock()
        token.get_id.return_value = "tok-123"
        return token

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_get_services(self, mock_req):
        """get_services calls GET on /services."""
        mock_req.return_value = {"services": []}
        token = self._make_token()
        rest_api_utils.get_services(token, "http://api/v3")
        mock_req.assert_called_once_with(
            token,
            "GET",
            "http://api/v3/services"
        )

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_create_service(self, mock_req):
        """create_service calls POST on /services."""
        mock_req.return_value = {"service": {"id": "s1"}}
        token = self._make_token()
        result = rest_api_utils.create_service(
            token, "http://api/v3", "nova", "compute", "Compute"
        )
        self.assertEqual(result.get_id(), "s1")

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_delete_service(self, mock_req):
        """delete_service calls DELETE on /services/<id>."""
        mock_req.return_value = {"service": {}}
        token = self._make_token()
        rest_api_utils.delete_service(token, "http://api/v3", "s1")
        mock_req.assert_called_once_with(
            token, "DELETE", "http://api/v3/services/s1"
        )

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_get_endpoints(self, mock_req):
        """get_endpoints calls GET on /endpoints."""
        mock_req.return_value = {"endpoints": []}
        token = self._make_token()
        rest_api_utils.get_endpoints(token, "http://api/v3")
        mock_req.assert_called_once_with(
            token, "GET", "http://api/v3/endpoints"
        )

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_create_endpoint(self, mock_req):
        """create_endpoint calls POST on /endpoints."""
        mock_req.return_value = {"endpoint": {"id": "e1"}}
        token = self._make_token()
        result = rest_api_utils.create_endpoint(
            token, "http://api/v3", "s1", "R1", "public", "http://svc"
        )
        self.assertEqual(result.get_id(), "e1")

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_get_users(self, mock_req):
        """get_users calls GET on /users."""
        mock_req.return_value = {"users": []}
        token = self._make_token()
        rest_api_utils.get_users(token, "http://api/v3")
        mock_req.assert_called_once_with(
            token, "GET", "http://api/v3/users"
        )

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_create_user(self, mock_req):
        """create_user calls POST on /users."""
        mock_req.return_value = {"user": {"id": "u1"}}
        token = self._make_token()
        result = rest_api_utils.create_user(
            token, "http://api/v3", "admin", "pass",
            "admin@test.com", "p1", "d1"
        )
        self.assertEqual(result.get_user_id(), "u1")

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_get_roles(self, mock_req):
        """get_roles calls GET on /roles."""
        mock_req.return_value = {"roles": []}
        token = self._make_token()
        rest_api_utils.get_roles(token, "http://api/v3")
        mock_req.assert_called_once_with(
            token, "GET", "http://api/v3/roles"
        )

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_get_projects(self, mock_req):
        """get_projects calls GET on /projects."""
        mock_req.return_value = {"projects": []}
        token = self._make_token()
        rest_api_utils.get_projects(token, "http://api/v3")
        mock_req.assert_called_once_with(
            token, "GET", "http://api/v3/projects"
        )

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_create_project(self, mock_req):
        """create_project calls POST on /projects."""
        mock_req.return_value = {"project": {"id": "p1"}}
        token = self._make_token()
        result = rest_api_utils.create_project(
            token, "http://api/v3", "test", "Test project", "d1"
        )
        self.assertEqual(result.get_id(), "p1")

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_get_domains(self, mock_req):
        """get_domains calls GET on /domains."""
        mock_req.return_value = {"domains": []}
        token = self._make_token()
        rest_api_utils.get_domains(token, "http://api/v3")
        mock_req.assert_called_once_with(
            token, "GET", "http://api/v3/domains"
        )

    @mock.patch.object(rest_api_utils, "rest_api_request")
    def test_add_role(self, mock_req):
        """add_role calls PUT on correct URL."""
        mock_req.return_value = {}
        token = self._make_token()
        rest_api_utils.add_role(
            token,
            "http://api/v3",
            "p1",
            "u1",
            "r1"
        )
        expected_url = "http://api/v3/projects/p1/users/u1/roles/r1"
        mock_req.assert_called_once_with(token, "PUT", expected_url)


if __name__ == "__main__":
    unittest.main()
