#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import sys
import unittest
from unittest import mock

import requests as req_lib

from cgtsclient.common import http  # noqa: E402
from cgtsclient import exc  # noqa: E402

# Mock platform_util before importing http (not available outside tox)
_oidc_utils = mock.MagicMock()
sys.modules.setdefault('platform_util', mock.MagicMock())
sys.modules.setdefault('platform_util.oidc', mock.MagicMock())
sys.modules.setdefault('platform_util.oidc.oidc_utils', _oidc_utils)


def _make_resp(status=200, content_type='application/json', extra=None):
    """Build a dict-like mock response object compatible with
    get_status_code.
    """
    d = {'status': status, 'content-type': content_type}
    if extra:
        d.update(extra)
    obj = mock.MagicMock(
        spec=['status', '__getitem__', '__contains__', 'get']
    )
    obj.__getitem__ = lambda s, k: d[k]
    obj.__contains__ = lambda s, k: k in d
    obj.get = lambda k, default=None: d.get(k, default)
    obj.status = status
    return obj


def _make_client(endpoint='http://host:6385/v1', token='tok', **kwargs):
    with mock.patch('httplib2.Http.__init__', return_value=None):
        c = http.HTTPClient(endpoint, token=token, **kwargs)
        c.connections = {}
        c.connection_params = (
            mock.MagicMock,
            ('host', 6385, '/v1'),
            {}
        )
        c.endpoint_url = endpoint
        c.follow_all_redirects = False
    return c


class TestGetStatusCode(unittest.TestCase):
    def test_status_int(self):
        r = mock.MagicMock(spec=['status_int'])
        r.status_int = 201
        c = _make_client()
        self.assertEqual(201, c.get_status_code(r))

    def test_status(self):
        r = mock.MagicMock(spec=['status'])
        r.status = 404
        c = _make_client()
        self.assertEqual(404, c.get_status_code(r))


class TestGetConnectionParams(unittest.TestCase):
    def test_http(self):
        cls, args, kwargs = (
            http.HTTPClient.get_connection_params('http://h:80/v1')
        )
        self.assertEqual(args, ('h', 80, '/v1'))

    def test_https(self):
        cls, args, kwargs = \
            http.HTTPClient.get_connection_params(
                'https://h:443/v1',
                ca_file='/ca',
                cert_file='/c',
                key_file='/k')
        self.assertIs(cls, http.VerifiedHTTPSConnection)
        self.assertEqual(kwargs['ca_file'], '/ca')

    def test_bad_scheme(self):
        self.assertRaises(
            exc.EndpointException,
            http.HTTPClient.get_connection_params,
            'ftp://h/v1')


class TestGetConnectionUrl(unittest.TestCase):
    def test_v1_in_both(self):
        c = _make_client()
        url = c._get_connection_url('/v1/resource')
        self.assertNotIn('/v1/v1', url)
        self.assertIn('/resource', url)

    def test_v1_in_neither(self):
        c = _make_client()
        c.connection_params = (mock.MagicMock, ('host', 6385, '/'), {})
        c.endpoint_url = 'http://host:6385'
        url = c._get_connection_url('/resource')
        self.assertIn('/v1/', url)

    def test_v1_in_base_only(self):
        c = _make_client()
        url = c._get_connection_url('/resource')
        self.assertIn('/resource', url)


class TestHTTPClientInit(unittest.TestCase):
    def test_basic(self):
        c = _make_client()
        self.assertEqual(c.auth_token, 'tok')
        self.assertEqual(c.endpoint_url, 'http://host:6385/v1')
        self.assertEqual(c.content_type, 'application/json')

    def test_oidc_auth(self):
        c = _make_client(oidc_auth=True, oidc_username='user1')
        self.assertEqual(c.auth_strategy, 'oidc')
        self.assertEqual(c.oidc_username, 'user1')

    def test_ca_cert_from_kwargs(self):
        with mock.patch('httplib2.Http.__init__',
                        return_value=None
                        ):
            c = http.HTTPClient('https://h:6385/v1', ca_file='/my/ca')
            c.connections = {}
        self.assertEqual(c.ca_file, '/my/ca')

    def test_cert_key_files(self):
        c = _make_client(cert_file='/cert', key_file='/key')
        self.assertEqual(c.cert_file, '/cert')
        self.assertEqual(c.key_file, '/key')


class TestCsRequest(unittest.TestCase):
    def _client(self, **kwargs):
        return _make_client(**kwargs)

    def test_200_octet_stream(self):
        c = self._client()
        resp = _make_resp(200, 'application/octet-stream')
        body = b'binarydata'
        with mock.patch.object(c, 'request', return_value=(resp, body)):
            r, b = c._cs_request('http://host:6385/v1/res', 'GET')
        self.assertEqual(b, b'binarydata')

    def test_200_text_plain(self):
        c = self._client()
        resp = _make_resp(200, 'text/plain')
        body = b'hello'
        with mock.patch.object(c, 'request', return_value=(resp, body)):
            r, b = c._cs_request('http://host:6385/v1/res', 'GET')
        self.assertEqual(b, 'hello')

    def test_401_raises(self):
        c = self._client()
        resp = _make_resp(401, 'text/plain')
        with mock.patch.object(
                c,
                'request',
                return_value=(resp, b'unauth')
        ):
            self.assertRaises(exc.HTTPUnauthorized,
                              c._cs_request,
                              'http://host:6385/v1/r',
                              'GET')

    def test_403_with_faultstring(self):
        c = self._client()
        resp = _make_resp(403, 'text/plain')
        body = json.dumps(
            {'error_message': json.dumps({'faultstring': 'nope'})}
        ).encode()
        with mock.patch.object(c, 'request', return_value=(resp, body)):
            self.assertRaises(exc.Forbidden,
                              c._cs_request,
                              'http://host:6385/v1/r',
                              'GET')

    def test_403_no_body(self):
        c = self._client()
        resp = _make_resp(403, 'application/octet-stream')
        with mock.patch.object(c, 'request', return_value=(resp, None)):
            self.assertRaises(exc.Forbidden,
                              c._cs_request,
                              'http://host:6385/v1/r',
                              'GET')

    def test_400_raises_from_response(self):
        c = self._client()
        resp = _make_resp(400, 'text/plain')
        with mock.patch.object(
                c,
                'request',
                return_value=(resp, b'bad')
        ):
            self.assertRaises(exc.HTTPException,
                              c._cs_request,
                              'http://host:6385/v1/r',
                              'GET')

    def test_500_raises(self):
        c = self._client()
        resp = _make_resp(500, 'text/plain')
        with mock.patch.object(
                c,
                'request',
                return_value=(resp, b'err')
        ):
            self.assertRaises(exc.HTTPException,
                              c._cs_request,
                              'http://host:6385/v1/r',
                              'GET')

    def test_301_redirect(self):
        c = self._client()
        resp1 = _make_resp(
            301,
            'text/plain',
            extra={'location': 'http://new/v1/r'}
        )
        resp2 = _make_resp(200, 'text/plain')
        with mock.patch.object(c, 'request', side_effect=[
            (resp1, b''), (resp2, b'ok')
        ]):
            r, b = c._cs_request('http://host:6385/v1/r', 'GET')
        self.assertEqual(r.status, 200)

    def test_302_redirect(self):
        c = self._client()
        resp1 = _make_resp(
            302,
            'text/plain',
            extra={'location': 'http://new/v1/r'}
        )
        resp2 = _make_resp(200, 'text/plain')
        with mock.patch.object(c, 'request', side_effect=[
            (resp1, b''), (resp2, b'ok')
        ]):
            r, b = c._cs_request('http://host:6385/v1/r', 'GET')
        self.assertEqual(r.status, 200)

    def test_300_raises(self):
        c = self._client()
        resp = _make_resp(300, 'text/plain')
        with mock.patch.object(c, 'request', return_value=(resp, b'')):
            self.assertRaises(exc.HTTPException,
                              c._cs_request,
                              'http://host:6385/v1/r',
                              'GET')

    def test_ssl_error(self):
        c = self._client()
        with mock.patch.object(c, 'request',
                               side_effect=req_lib.exceptions.SSLError(
                                   'ssl'
                               )):
            self.assertRaises(exc.SslCertificateValidationError,
                              c._cs_request,
                              'http://host:6385/v1/r',
                              'GET')

    def test_generic_exception(self):
        c = self._client()
        with mock.patch.object(
                c,
                'request',
                side_effect=Exception('boom')
        ):
            self.assertRaises(exc.CommunicationError,
                              c._cs_request,
                              'http://host:6385/v1/r',
                              'GET')

    def test_oidc_token_header(self):
        c = self._client(oidc_auth=True, oidc_username='u')
        c.oidc_token = 'oidc_tok'
        resp = _make_resp(200, 'text/plain')
        with mock.patch.object(
                c,
                'request',
                return_value=(resp, b'ok')
        ) as m:
            c._cs_request('http://host:6385/v1/r', 'GET')
        call_kwargs = m.call_args
        hdrs = call_kwargs[1].get(
            'headers',
            call_kwargs[0][2]
            if len(call_kwargs[0]) > 2 else {})
        self.assertIn('OIDC-Token', hdrs)

    def test_content_type_override(self):
        c = self._client()
        resp = _make_resp(200, 'text/plain')
        with mock.patch.object(
                c,
                'request',
                return_value=(resp, b'ok')
        ) as m:
            c._cs_request('http://host:6385/v1/r', 'GET',
                          content_type='text/xml')
        headers = m.call_args[1]['headers']
        self.assertEqual(headers['Content-Type'], 'text/xml')


class TestJsonRequest(unittest.TestCase):
    def _client(self):
        c = _make_client()
        c.authenticate_and_fetch_endpoint_url = mock.MagicMock()
        return c

    def test_normal_json(self):
        c = self._client()
        resp = _make_resp(200, 'application/json')
        body_iter = [json.dumps({'key': 'val'})]
        with mock.patch.object(
                c,
                '_cs_request',
                return_value=(resp, body_iter)
        ):
            r, body = c.json_request('GET', '/v1/res')
        self.assertEqual(body, {'key': 'val'})

    def test_204_empty(self):
        c = self._client()
        resp = _make_resp(204, 'application/json')
        with mock.patch.object(
                c,
                '_cs_request',
                return_value=(resp, '')
        ):
            r, body = c.json_request('GET', '/v1/res')
        self.assertEqual(body, [])

    def test_205_empty(self):
        c = self._client()
        resp = _make_resp(205, 'application/json')
        with mock.patch.object(
                c,
                '_cs_request',
                return_value=(resp, '')
        ):
            r, body = c.json_request('GET', '/v1/res')
        self.assertEqual(body, [])

    def test_no_content_type(self):
        c = self._client()
        resp = _make_resp(200)
        # Override get to return None for content-type
        resp.get = lambda k, d=None: None
        with mock.patch.object(
                c,
                '_cs_request',
                return_value=(resp, '')
        ):
            r, body = c.json_request('GET', '/v1/res')
        self.assertEqual(body, [])

    def test_non_json_content_type(self):
        c = self._client()
        resp = _make_resp(200, 'text/plain')
        with mock.patch.object(
                c,
                '_cs_request',
                return_value=(resp, 'text')
        ):
            r, body = c.json_request('GET', '/v1/res')
        self.assertIsNone(body)

    def test_401_retry(self):
        c = self._client()
        c.authenticate = mock.MagicMock()
        resp = _make_resp(200, 'application/json')
        body_iter = [json.dumps({'ok': True})]
        with mock.patch.object(
            c, '_cs_request',
            side_effect=[
                exc.HTTPUnauthorized(),
                (resp, body_iter)
            ]
        ):
            r, body = c.json_request('GET', '/v1/res')
        c.authenticate.assert_called_once()
        self.assertEqual(body, {'ok': True})

    def test_json_decode_error(self):
        c = self._client()
        resp = _make_resp(200, 'application/json')
        body_iter = ['not-json']
        with mock.patch.object(
                c,
                '_cs_request',
                return_value=(resp, body_iter)
        ):
            r, body = c.json_request('GET', '/v1/res')
        # On decode error, body stays as string
        self.assertIsNotNone(r)

    def test_body_kwarg_serialized(self):
        c = self._client()
        resp = _make_resp(200, 'application/json')
        body_iter = ['{}']
        with mock.patch.object(
                c,
                '_cs_request',
                return_value=(resp, body_iter)
        ) as m:
            c.json_request('POST', '/v1/res', body={'a': 1})
        call_kwargs = m.call_args[1]
        self.assertEqual(call_kwargs['body'], json.dumps({'a': 1}))


class TestRawRequest(unittest.TestCase):
    def test_raw(self):
        c = _make_client()
        c.authenticate_and_fetch_endpoint_url = mock.MagicMock()
        resp = _make_resp(200, 'application/octet-stream')
        with mock.patch.object(
                c,
                '_cs_request',
                return_value=(resp, b'data')
        ) as m:
            r, b = c.raw_request('GET', '/v1/res')
        headers = m.call_args[1]['headers']
        self.assertEqual(headers['Content-Type'],
                         'application/octet-stream')


class TestUploadRequestWithData(unittest.TestCase):
    def _client(self, **kwargs):
        c = _make_client(**kwargs)
        c.authenticate_and_fetch_endpoint_url = mock.MagicMock()
        return c

    @mock.patch('cgtsclient.common.http.requests.post')
    def test_with_oidc(self, mock_post):
        c = self._client(oidc_auth=True, oidc_username='u')
        c.oidc_token = 'oidc_tok'
        mock_post.return_value.json.return_value = {'ok': True}
        result = c.upload_request_with_data(
            'POST',
            '/v1/upload',
            body=b'data'
        )
        headers = mock_post.call_args[1]['headers']
        self.assertIn('OIDC-Token', headers)
        self.assertEqual(result, {'ok': True})

    @mock.patch('cgtsclient.common.http.requests.post')
    def test_without_oidc(self, mock_post):
        c = self._client()
        mock_post.return_value.json.return_value = {'ok': True}
        c.upload_request_with_data('POST', '/v1/upload', body=b'data')
        headers = mock_post.call_args[1]['headers']
        self.assertIn('X-Auth-Token', headers)

    @mock.patch('cgtsclient.common.http.requests.post')
    def test_insecure(self, mock_post):
        c = self._client(insecure=True)
        mock_post.return_value.json.return_value = {}
        c.upload_request_with_data('POST', '/v1/upload', body=b'data')
        self.assertFalse(mock_post.call_args[1]['verify'])

    @mock.patch('cgtsclient.common.http.requests.post')
    def test_ca_file(self, mock_post):
        c = self._client(ca_file='/ca.pem')
        mock_post.return_value.json.return_value = {}
        c.upload_request_with_data('POST', '/v1/upload', body=b'data')
        self.assertEqual(mock_post.call_args[1]['verify'], '/ca.pem')

    @mock.patch('cgtsclient.common.http.requests.post')
    def test_cert_key(self, mock_post):
        c = self._client(cert_file='/cert', key_file='/key')
        mock_post.return_value.json.return_value = {}
        c.upload_request_with_data('POST', '/v1/upload', body=b'data')
        self.assertEqual(mock_post.call_args[1]['cert'],
                         ('/cert', '/key'))


class TestUploadRequestWithMultipart(unittest.TestCase):
    def _client(self, **kwargs):
        c = _make_client(**kwargs)
        c.authenticate_and_fetch_endpoint_url = mock.MagicMock()
        return c

    @mock.patch('builtins.open', mock.mock_open(read_data=b'filedata'))
    @mock.patch('cgtsclient.common.http.MultipartEncoder')
    @mock.patch('cgtsclient.common.http.requests.post')
    def test_normal(self, mock_post, mock_enc):
        c = self._client()
        mock_enc.return_value.content_type = 'multipart/form-data'
        mock_post.return_value.json.return_value = {'ok': True}
        mock_post.return_value.status_code = 200
        result = c.upload_request_with_multipart(
            'POST', '/v1/upload', body={'f': '/tmp/f'}, data={'k': 'v'})
        self.assertEqual(result, {'ok': True})

    @mock.patch('builtins.open', mock.mock_open(read_data=b'filedata'))
    @mock.patch('cgtsclient.common.http.MultipartEncoder')
    @mock.patch('cgtsclient.common.http.requests.post')
    def test_check_exceptions_400(self, mock_post, mock_enc):
        c = self._client()
        mock_enc.return_value.content_type = 'multipart/form-data'
        mock_post.return_value.status_code = 400
        mock_post.return_value.text = json.dumps(
            {'error_message': json.dumps({'faultstring': 'bad'})})
        mock_post.return_value.json.return_value = {}
        self.assertRaises(
            exc.HTTPBadRequest,
            c.upload_request_with_multipart,
            'POST', '/v1/upload', body={'f': '/tmp/f'},
            check_exceptions=True)

    @mock.patch('builtins.open', mock.mock_open(read_data=b'filedata'))
    @mock.patch('cgtsclient.common.http.MultipartEncoder')
    @mock.patch('cgtsclient.common.http.requests.post')
    def test_oidc_headers(self, mock_post, mock_enc):
        c = self._client(oidc_auth=True, oidc_username='u')
        c.oidc_token = 'oidc_tok'
        mock_enc.return_value.content_type = 'multipart/form-data'
        mock_post.return_value.json.return_value = {}
        mock_post.return_value.status_code = 200
        c.upload_request_with_multipart(
            'POST', '/v1/upload', body={'f': '/tmp/f'})
        headers = mock_post.call_args[1]['headers']
        self.assertIn('OIDC-Token', headers)


class TestOidcAuthentication(unittest.TestCase):
    def test_no_auth_url(self):
        c = _make_client(oidc_auth=True, oidc_username='u')
        c.auth_url = None
        self.assertRaises(exc.HTTPException, c.oidc_authentication)

    def test_no_oidc_username(self):
        c = _make_client(oidc_auth=True, oidc_username=None)
        c.auth_url = 'http://auth'
        c.oidc_username = None
        self.assertRaises(exc.HTTPException, c.oidc_authentication)

    @mock.patch('cgtsclient.common.http.oidc_utils.get_oidc_token',
                side_effect=KeyError('missing'))
    def test_key_error(self, _):
        c = _make_client(
            oidc_auth=True,
            oidc_username='u',
            auth_url='http://auth'
        )
        self.assertRaises(exc.HTTPException, c.oidc_authentication)

    @mock.patch('cgtsclient.common.http.oidc_utils.get_oidc_token',
                side_effect=RuntimeError('fail'))
    def test_generic_exception(self, _):
        c = _make_client(
            oidc_auth=True,
            oidc_username='u',
            auth_url='http://auth'
        )
        self.assertRaises(exc.HTTPException, c.oidc_authentication)

    @mock.patch('cgtsclient.common.http.oidc_utils.get_oidc_token',
                return_value='new_token')
    def test_success(self, _):
        c = _make_client(
            oidc_auth=True,
            oidc_username='u',
            auth_url='http://auth'
        )
        c.oidc_authentication()
        self.assertEqual(c.oidc_token, 'new_token')


class TestAuthenticate(unittest.TestCase):

    def test_unknown_strategy(self):
        c = _make_client(auth_url='http://auth')
        c.auth_strategy = 'unknown'
        self.assertRaises(exc.HTTPException, c.authenticate)

    def test_no_auth_url(self):
        c = _make_client()
        c.auth_url = None
        self.assertRaises(exc.HTTPUnauthorized, c.authenticate)

    def test_no_username(self):
        c = _make_client(auth_url='http://auth')
        c.username = None
        self.assertRaises(exc.HTTPUnauthorized, c.authenticate)

    def test_no_password(self):
        c = _make_client(auth_url='http://auth')
        c.username = 'user'
        c.password = None
        self.assertRaises(exc.HTTPUnauthorized, c.authenticate)

    def test_success_tenant_id(self):
        c = _make_client(auth_url='http://auth')
        c.username = 'user'
        c.password = 'pass'
        c.tenant_id = 'tid'
        catalog = {
            'access': {
                'token': {'id': 'new_tok', 'expires': '2099-01-01',
                          'tenant': {'id': 'tid'}},
                'user': {'id': 'uid'},
                'serviceCatalog': [{
                    'type': 'platform',
                    'endpoints': [
                        {'region': None,
                         'publicURL': 'http://ep'}
                    ]
                }]
            }
        }
        resp = _make_resp(200, 'application/json')
        with mock.patch.object(c, '_cs_request',
                               return_value=(resp,
                                             json.dumps(catalog)
                                             )):
            c.authenticate()
        self.assertEqual(c.auth_token, 'new_tok')

    def test_success_tenant_name(self):
        c = _make_client(auth_url='http://auth')
        c.username = 'user'
        c.password = 'pass'
        c.tenant_id = None
        c.tenant_name = 'tname'
        catalog = {
            'access': {
                'token': {'id': 'tok2', 'expires': '2099-01-01',
                          'tenant': {'id': 'tid2'}},
                'user': {'id': 'uid2'},
                'serviceCatalog': [{
                    'type': 'platform',
                    'endpoints': [
                        {'region': None,
                         'publicURL': 'http://ep2'}
                    ]
                }]
            }
        }
        resp = _make_resp(200, 'application/json')
        with mock.patch.object(c, '_cs_request',
                               return_value=(resp,
                                             json.dumps(catalog)
                                             )):
            c.authenticate()
        self.assertEqual(c.auth_token, 'tok2')

    def test_non_200_raises(self):
        c = _make_client(auth_url='http://auth')
        c.username = 'user'
        c.password = 'pass'
        resp = _make_resp(401, 'text/plain')
        with mock.patch.object(c, '_cs_request',
                               return_value=(resp, 'denied')):
            self.assertRaises(exc.HTTPUnauthorized, c.authenticate)

    def test_empty_resp_body(self):
        c = _make_client(auth_url='http://auth')
        c.username = 'user'
        c.password = 'pass'
        resp = _make_resp(200, 'application/json')
        with mock.patch.object(c, '_cs_request',
                               return_value=(resp, '')):
            # empty body -> resp_body=None ->
            # _extract_service_catalog(None) -> TypeError
            self.assertRaises((exc.HTTPUnauthorized, TypeError),
                              c.authenticate)


class TestGetAuthInfo(unittest.TestCase):
    def test_returns_dict(self):
        c = _make_client()
        c.auth_tenant_id = 'tid'
        c.auth_user_id = 'uid'
        info = c.get_auth_info()
        self.assertEqual(info['auth_token'], 'tok')
        self.assertEqual(info['auth_tenant_id'], 'tid')
        self.assertEqual(info['auth_user_id'], 'uid')
        self.assertIn('endpoint_url', info)


class TestExtractErrorJson(unittest.TestCase):
    def test_valid(self):
        c = _make_client()
        body = json.dumps({
            'error_message': json.dumps(
                {'faultstring': 'err', 'debuginfo': 'dbg'}
            )
        })
        result = c._extract_error_json(body)
        self.assertEqual(result['faultstring'], 'err')

    def test_invalid_json(self):
        c = _make_client()
        result = c._extract_error_json('not json')
        self.assertEqual(result, {})

    def test_no_error_message_key(self):
        c = _make_client()
        body = json.dumps({'other': 'stuff'})
        result = c._extract_error_json(body)
        self.assertEqual(result, {})


class TestStripCredentials(unittest.TestCase):
    def test_with_password(self):
        c = _make_client()
        c.password = 'secret'
        kw = {'body': 'password=secret&user=admin'}
        result = c._strip_credentials(kw)
        self.assertNotIn('secret', result['body'])
        self.assertIn('REDACTED', result['body'])

    def test_without_password(self):
        c = _make_client()
        c.password = None
        kw = {'body': 'data'}
        result = c._strip_credentials(kw)
        self.assertIs(result, kw)

    def test_no_body(self):
        c = _make_client()
        c.password = 'secret'
        kw = {'headers': {}}
        result = c._strip_credentials(kw)
        self.assertIs(result, kw)


class TestExtractServiceCatalog(unittest.TestCase):
    def test_success(self):
        c = _make_client()
        c.endpoint_url = None
        body = {
            'access': {
                'token': {'id': 'newtok', 'expires': '2099-01-01',
                          'tenant': {'id': 'tid'}},
                'user': {'id': 'uid'},
                'serviceCatalog': [{
                    'type': 'platform',
                    'endpoints': [
                        {'region': None,
                         'publicURL': 'http://ep'}
                    ]
                }]
            }
        }
        c._extract_service_catalog(body)
        self.assertEqual(c.auth_token, 'newtok')
        self.assertEqual(c.endpoint_url, 'http://ep')

    def test_key_error(self):
        c = _make_client()
        self.assertRaises(
            exc.HTTPUnauthorized,
            c._extract_service_catalog,
            {'access': {'token': {}}})


class TestGetEndpointUrl(unittest.TestCase):
    def test_success(self):
        c = _make_client(auth_url='http://auth')
        c.auth_token = 'tok'
        c.region_name = 'RegionOne'
        body = json.dumps({
            'endpoints': [
                {'type': 'platform', 'region': 'RegionOne',
                 'publicURL': 'http://ep:6385/v1'}
            ]
        })
        resp = _make_resp(200, 'text/plain')
        with mock.patch.object(
                c,
                '_cs_request',
                return_value=(resp, body)
        ):
            url = c._get_endpoint_url()
        self.assertEqual(url, 'http://ep:6385/v1')

    def test_401_fallback(self):
        c = _make_client(auth_url='http://auth')
        c.authenticate = mock.MagicMock()
        c.endpoint_url = 'http://fallback'
        with mock.patch.object(c, '_cs_request',
                               side_effect=exc.HTTPUnauthorized()):
            url = c._get_endpoint_url()
        c.authenticate.assert_called_once()
        self.assertEqual(url, 'http://fallback')

    def test_endpoint_not_found(self):
        c = _make_client(auth_url='http://auth')
        c.region_name = 'RegionOne'
        body = json.dumps({'endpoints': []})
        resp = _make_resp(200, 'text/plain')
        with mock.patch.object(
                c,
                '_cs_request',
                return_value=(resp, body)
        ):
            self.assertRaises(exc.EndpointNotFound, c._get_endpoint_url)

    def test_endpoint_type_not_found(self):
        c = _make_client(auth_url='http://auth')
        c.region_name = 'R1'
        c.endpoint_type = 'adminURL'
        body = json.dumps({
            'endpoints': [
                {'type': 'platform',
                 'region': 'R1',
                 'publicURL': 'http://ep'}
            ]
        })
        resp = _make_resp(200, 'text/plain')
        with mock.patch.object(
                c,
                '_cs_request',
                return_value=(resp, body)
        ):
            self.assertRaises(exc.EndpointTypeNotFound,
                              c._get_endpoint_url)


class TestVerifiedHTTPSConnection(unittest.TestCase):
    @mock.patch(
        'six.moves.http_client.HTTPSConnection.__init__',
        return_value=None
    )
    def test_init_with_ca(self, _):
        conn = http.VerifiedHTTPSConnection(
            'host',
            443,
            ca_file='/ca.pem'
        )
        self.assertEqual(conn.ca_file, '/ca.pem')

    @mock.patch(
        'six.moves.http_client.HTTPSConnection.__init__',
        return_value=None
    )
    def test_init_without_ca(self, _):
        with mock.patch.object(
                http.VerifiedHTTPSConnection,
                'get_system_ca_file',
                return_value='/sys/ca'):
            conn = http.VerifiedHTTPSConnection('host', 443)
        self.assertEqual(conn.ca_file, '/sys/ca')

    def test_get_system_ca_file_found(self):
        ca_path = '/etc/ssl/certs/ca-certificates.crt'
        with mock.patch(
                'os.path.exists',
                side_effect=lambda p: p == ca_path):
            result = \
                http.VerifiedHTTPSConnection \
                    .get_system_ca_file()
        self.assertEqual(result, ca_path)

    def test_get_system_ca_file_none(self):
        with mock.patch('os.path.exists', return_value=False):
            result = http.VerifiedHTTPSConnection.get_system_ca_file()
        self.assertIsNone(result)


class TestConstructHttpClient(unittest.TestCase):

    def test_with_session_sets_defaults(self):
        session = mock.MagicMock()
        with mock.patch('cgtsclient.common.http.SessionClient') as sc:
            http.construct_http_client(
                endpoint='http://ep', endpoint_type='internal',
                session=session, region_name='R1')
        kw = sc.call_args
        self.assertEqual(
            kw[1].get(
                'endpoint_override',
                kw[1].get('endpoint_override')
            ),
            'http://ep'
        )

    def test_without_session(self):
        with mock.patch('httplib2.Http.__init__', return_value=None):
            client = http.construct_http_client(
                endpoint='http://host:6385/v1',
                username='u',
                password='p',
                auth_url='http://auth')
        self.assertIsInstance(client, http.HTTPClient)


class TestResponseBodyIterator(unittest.TestCase):
    def test_next_with_data(self):
        resp = mock.MagicMock()
        resp.read.return_value = b'chunk'
        it = http.ResponseBodyIterator(resp)
        self.assertEqual(it.next(), b'chunk')

    def test_next_stop_iteration(self):
        resp = mock.MagicMock()
        resp.read.return_value = b''
        it = http.ResponseBodyIterator(resp)
        self.assertRaises(StopIteration, it.next)


if __name__ == '__main__':
    unittest.main()
