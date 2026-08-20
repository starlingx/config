#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for cgtsclient.common.http module."""
import json
import unittest
from unittest import mock

from cgtsclient.common import http
from cgtsclient import exc


class TestServiceCatalog(unittest.TestCase):
    """Test ServiceCatalog class."""

    def _make_catalog(self,
                      services=None,
                      token_id='tok',
                      expires='2099-01-01'
                      ):
        if services is None:
            services = []
        return http.ServiceCatalog({
            'access': {
                'token': {'id': token_id, 'expires': expires,
                          'tenant': {'id': 'tid'}},
                'user': {'id': 'uid'},
                'serviceCatalog': services,
            }
        })

    def test_get_token(self):
        sc = self._make_catalog()
        tok = sc.get_token()
        self.assertEqual(tok['id'], 'tok')
        self.assertEqual(tok['user_id'], 'uid')
        self.assertEqual(tok['tenant_id'], 'tid')

    def test_get_token_no_user(self):
        sc = http.ServiceCatalog({
            'access': {'token': {'id': 't1', 'expires': 'e1'}}
        })
        tok = sc.get_token()
        self.assertEqual(tok['id'], 't1')
        self.assertNotIn('user_id', tok)

    def test_url_for_success(self):
        services = [{'type': 'platform',
                     'endpoints': [
                         {'publicURL':
                          'http://host:6385/v1'}
                     ]}]
        sc = self._make_catalog(services=services)
        url = sc.url_for()
        self.assertEqual(url, 'http://host:6385/v1')

    def test_url_for_not_found(self):
        sc = self._make_catalog(services=[])
        self.assertRaises(exc.EndpointNotFound, sc.url_for)

    def test_url_for_ambiguous(self):
        services = [
            {'type': 'platform',
             'endpoints': [
                 {'publicURL': 'a'},
                 {'publicURL': 'b'}
             ]}
        ]
        sc = self._make_catalog(services=services)
        self.assertRaises(exc.AmbiguousEndpoints, sc.url_for)

    def test_url_for_type_not_found(self):
        services = [{'type': 'platform',
                     'endpoints': [{'internalURL': 'http://x'}]}]
        sc = self._make_catalog(services=services)
        self.assertRaises(exc.EndpointTypeNotFound, sc.url_for)

    def test_url_for_with_filter(self):
        services = [{'type': 'platform',
                     'endpoints': [
                         {'region': 'r1',
                          'publicURL': 'http://r1'},
                         {'region': 'r2',
                          'publicURL': 'http://r2'},
                     ]}]
        sc = self._make_catalog(services=services)
        url = sc.url_for(attr='region', filter_value='r1')
        self.assertEqual(url, 'http://r1')


class TestExtractErrorJson(unittest.TestCase):
    """Test _extract_error_json and _extract_error_json_text."""

    def _mock_resp(self,
                   content_type='application/json',
                   json_data=None,
                   status=400
                   ):
        resp = mock.MagicMock()
        resp.headers = {'Content-Type': content_type}
        resp.status_code = status
        if json_data is not None:
            resp.json.return_value = json_data
        return resp

    def test_error_message_key(self):
        body_json = {
            'error_message':
            '{"faultstring": "bad",'
            ' "debuginfo": "d"}'
        }
        result = http._extract_error_json_text(body_json)
        self.assertEqual(result['faultstring'], 'bad')

    def test_error_key(self):
        body_json = {'error': {'title': 'Not Found', 'message': 'gone'}}
        result = http._extract_error_json_text(body_json)
        self.assertEqual(result['faultstring'], 'Not Found')
        self.assertEqual(result['debuginfo'], 'gone')

    def test_errors_key_with_detail(self):
        body_json = {'errors': [{'title': 'err', 'detail': 'det'}]}
        result = http._extract_error_json_text(body_json)
        self.assertEqual(result['faultstring'], 'err')
        self.assertEqual(result['debuginfo'], 'det')

    def test_errors_key_with_description(self):
        body_json = (
            {'errors': [{'title': 'err', 'description': 'desc'}]}
        )
        result = http._extract_error_json_text(body_json)
        self.assertEqual(result['debuginfo'], 'desc')

    def test_extract_error_json_json_content(self):
        resp = self._mock_resp(
            json_data={'error': {'title': 'T', 'message': 'M'}}
        )
        result = http._extract_error_json('body', resp)
        self.assertEqual(result['faultstring'], 'T')

    def test_extract_error_json_non_json_content(self):
        resp = self._mock_resp(content_type='text/plain')
        result = http._extract_error_json('not json', resp)
        self.assertEqual(result, {})

    def test_extract_error_json_non_json_valid_body(self):
        resp = self._mock_resp(content_type='text/plain')
        body = json.dumps({'error': {'title': 'X', 'message': 'Y'}})
        result = http._extract_error_json(body, resp)
        self.assertEqual(result['faultstring'], 'X')

    def test_extract_error_json_no_headers(self):
        resp = object()  # no headers attr
        result = http._extract_error_json('bad', resp)
        self.assertEqual(result, {})

    def test_nested_error_message(self):
        inner = json.dumps(
            {'faultstring': 'inner_fault', 'debuginfo': 'dbg'}
        )
        outer = json.dumps({'error_message': inner})
        body_json = {'error_message': outer}
        result = http._extract_error_json_text(body_json)
        self.assertEqual(result['faultstring'], 'inner_fault')

    def test_extract_json_value_error(self):
        resp = self._mock_resp(json_data=None)
        resp.json.side_effect = ValueError("bad json")
        result = http._extract_error_json('body', resp)
        self.assertEqual(result, {})


class TestSessionClient(unittest.TestCase):
    """Test SessionClient methods."""

    def _make_client(self):
        session = mock.MagicMock()
        auth = mock.MagicMock()
        client = http.SessionClient(
            session=session, auth=auth,
            endpoint_override='http://host:6385/v1')
        return client

    def test_get_connection_url_both_v1(self):
        client = self._make_client()
        url = client._get_connection_url('/v1/ihosts')
        self.assertEqual(url, 'http://host:6385/v1/ihosts')

    def test_get_connection_url_no_v1(self):
        client = self._make_client()
        client.endpoint_override = 'http://host:6385'
        url = client._get_connection_url('ihosts')
        self.assertEqual(url, 'http://host:6385/v1/ihosts')

    def test_json_request_204(self):
        client = self._make_client()
        resp = mock.MagicMock()
        resp.status_code = 204
        resp.content = ''
        resp.headers = {'content-type': 'application/json'}
        client._http_request = mock.MagicMock(return_value=resp)
        r, body = client.json_request('GET', '/v1/test')
        self.assertEqual(body, [])

    def test_json_request_json_body(self):
        client = self._make_client()
        resp = mock.MagicMock()
        resp.status_code = 200
        resp.content = '{"key": "val"}'
        resp.headers = {'content-type': 'application/json'}
        resp.json.return_value = {'key': 'val'}
        client._http_request = mock.MagicMock(return_value=resp)
        r, body = client.json_request('GET', '/v1/test')
        self.assertEqual(body, {'key': 'val'})

    def test_json_request_non_json(self):
        client = self._make_client()
        resp = mock.MagicMock()
        resp.status_code = 200
        resp.content = 'text'
        resp.headers = {'content-type': 'text/plain'}
        client._http_request = mock.MagicMock(return_value=resp)
        r, body = client.json_request('GET', '/v1/test')
        self.assertIsNone(body)

    def test_raw_request(self):
        client = self._make_client()
        resp = mock.MagicMock()
        resp.status_code = 200
        client._http_request = mock.MagicMock(return_value=resp)
        r = client.raw_request('DELETE', '/v1/test')
        self.assertEqual(r.status_code, 200)

    def test_http_request_400_error(self):
        client = self._make_client()
        resp = mock.MagicMock()
        resp.status_code = 400
        resp.content = b''
        resp.headers = {'Content-Type': 'text/plain'}
        client.session.request = mock.MagicMock(return_value=resp)
        self.assertRaises(Exception,  # noqa: H202
                          client._http_request,
                          '/test',
                          'GET')

    def test_http_request_redirect(self):
        client = self._make_client()
        resp1 = mock.MagicMock()
        resp1.status_code = 302
        resp1.headers = {'location': '/new'}
        resp2 = mock.MagicMock()
        resp2.status_code = 200
        client.session.request = (
            mock.MagicMock(side_effect=[resp1, resp2])
        )
        r = client._http_request('/old', 'GET')
        self.assertEqual(r.status_code, 200)

    def test_http_request_300(self):
        client = self._make_client()
        resp = mock.MagicMock()
        resp.status_code = 300
        client.session.request = mock.MagicMock(return_value=resp)
        self.assertRaises(Exception,  # noqa: H202
                          client._http_request,
                          '/test',
                          'GET')

    def test_http_request_strips_v1(self):
        client = self._make_client()
        resp = mock.MagicMock()
        resp.status_code = 200
        client.session.request = mock.MagicMock(return_value=resp)
        client._http_request('/v1/ihosts', 'GET')
        call_args = client.session.request.call_args
        self.assertEqual(call_args[0][0], '/ihosts')

    def test_upload_request_with_data(self):
        client = self._make_client()
        client.session.get_token = mock.MagicMock(return_value='tok')
        with mock.patch('requests.post') as mock_post:
            mock_post.return_value.json.return_value = {'success': True}
            result = client.upload_request_with_data(
                'POST', '/v1/upload', body=b'data')
            self.assertTrue(result['success'])

    def test_upload_request_with_multipart(self):
        client = self._make_client()
        client.session.get_token = mock.MagicMock(return_value='tok')
        with mock.patch('requests.post') as mock_post, \
            mock.patch('builtins.open',
                       mock.mock_open(read_data=b'file_data')
                       ), \
            mock.patch(
            'cgtsclient.common.http.MultipartEncoder'
        ) as mock_enc:
            mock_enc_inst = mock.MagicMock()
            mock_enc_inst.content_type = (
                'multipart/form-data; boundary=xxx'
            )
            mock_enc.return_value = mock_enc_inst
            mock_post.return_value.json.return_value = {'ok': True}
            mock_post.return_value.status_code = 200
            result = client.upload_request_with_multipart(
                'POST', '/v1/upload',
                body={'file1': '/tmp/test.tar'},
                data={'key': 'val'})
            self.assertTrue(result['ok'])

    def test_upload_multipart_check_exceptions_error(self):
        client = self._make_client()
        client.session.get_token = mock.MagicMock(return_value='tok')
        with mock.patch('requests.post') as mock_post, \
            mock.patch('builtins.open',
                       mock.mock_open(read_data=b'data')
                       ), \
            mock.patch(
            'cgtsclient.common.http.MultipartEncoder'
        ) as mock_enc:
            mock_enc_inst = mock.MagicMock()
            mock_enc_inst.content_type = (
                'multipart/form-data; boundary=xxx'
            )
            mock_enc.return_value = mock_enc_inst
            mock_post.return_value.status_code = 400
            mock_post.return_value.text = (
                '{"error": {"title": "Bad", "message": "req"}}'
            )
            mock_post.return_value.headers = (
                {'Content-Type': 'application/json'}
            )
            mock_post.return_value.json.return_value = (
                {'error': {'title': 'Bad', 'message': 'req'}}
            )
            self.assertRaises(
                exc.HTTPBadRequest,
                client.upload_request_with_multipart,
                'POST', '/v1/upload',
                body={'f': '/tmp/t'}, check_exceptions=True)


if __name__ == '__main__':
    unittest.main()
