# Copyright 2013, 2017 Wind River, Inc.
# Copyright 2012 Openstack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import logging
import os
import requests
import socket

import httplib2

import six
from six.moves.urllib.parse import urlparse

try:
    import ssl
except ImportError:
    # TODO(bcwaldon): Handle this failure more gracefully
    pass

try:
    import json
except ImportError:
    import simplejson as json

from cgtsclient import exc as exceptions
from neutronclient.common import utils

_logger = logging.getLogger(__name__)

CHUNKSIZE = 1024 * 64  # 64kB

# httplib2 retries requests on socket.timeout which
# is not idempotent and can lead to orhan objects.
# See: https://code.google.com/p/httplib2/issues/detail?id=124
httplib2.RETRIES = 1

if os.environ.get('CGTSCLIENT_DEBUG'):
    ch = logging.StreamHandler()
    _logger.setLevel(logging.DEBUG)
    _logger.addHandler(ch)


class ServiceCatalog(object):
    """Helper methods for dealing with a Keystone Service Catalog."""

    def __init__(self, resource_dict):
        self.catalog = resource_dict

    def get_token(self):
        """Fetch token details fron service catalog."""
        token = {'id': self.catalog['access']['token']['id'],
                 'expires': self.catalog['access']['token']['expires'], }
        try:
            token['user_id'] = self.catalog['access']['user']['id']
            token['tenant_id'] = (
                self.catalog['access']['token']['tenant']['id'])
        except Exception:
            # just leave the tenant and user out if it doesn't exist
            pass
        return token

    def url_for(self, attr=None, filter_value=None,
                service_type='platform', endpoint_type='publicURL'):
        """Fetch the URL from the Neutron service for
        a particular endpoint type. If none given, return
        publicURL.
        """

        catalog = self.catalog['access'].get('serviceCatalog', [])
        matching_endpoints = []
        for service in catalog:
            if service['type'] != service_type:
                continue

            endpoints = service['endpoints']
            for endpoint in endpoints:
                if not filter_value or endpoint.get(attr) == filter_value:
                    matching_endpoints.append(endpoint)

        if not matching_endpoints:
            raise exceptions.EndpointNotFound()
        elif len(matching_endpoints) > 1:
            raise exceptions.AmbiguousEndpoints(reason=matching_endpoints)
        else:
            if endpoint_type not in matching_endpoints[0]:
                raise exceptions.EndpointTypeNotFound(reason=endpoint_type)

        return matching_endpoints[0][endpoint_type]


class HTTPClient(httplib2.Http):
    """Handles the REST calls and responses, include authn."""

    #################
    # INIT
    #################
    def __init__(self, endpoint,
                 username=None, tenant_name=None, tenant_id=None,
                 password=None, auth_url=None,
                 token=None, region_name=None, timeout=None,
                 endpoint_url=None, insecure=False,
                 endpoint_type='publicURL',
                 auth_strategy='keystone', ca_cert=None, log_credentials=False,
                 **kwargs):
        if 'ca_file' in kwargs:
            ca_cert = kwargs['ca_file']

        super(HTTPClient, self).__init__(timeout=timeout, ca_certs=ca_cert)

        self.username = username
        self.tenant_name = tenant_name
        self.tenant_id = tenant_id
        self.password = password
        self.auth_url = auth_url.rstrip('/') if auth_url else None
        self.endpoint_type = endpoint_type
        self.region_name = region_name
        self.auth_token = token
        self.auth_tenant_id = None
        self.auth_user_id = None
        self.content_type = 'application/json'
        self.endpoint_url = endpoint
        self.auth_strategy = auth_strategy
        self.log_credentials = log_credentials
        self.connection_params = self.get_connection_params(self.endpoint_url, **kwargs)

        # httplib2 overrides
        self.disable_ssl_certificate_validation = insecure

    #################
    # REQUEST
    #################

    @staticmethod
    def http_log_resp(_logger, resp, body=None):
        if not _logger.isEnabledFor(logging.DEBUG):
            return

        resp_status_code = resp.get('status_code') or ""
        resp_headers = resp.get('headers') or ""
        _logger.debug("RESP:%(code)s %(headers)s %(body)s\n",
                      {'code': resp_status_code,
                       'headers': resp_headers,
                       'body': body})

    def _cs_request(self, *args, **kwargs):
        kargs = {}
        kargs.setdefault('headers', kwargs.get('headers', {}))

        if 'content_type' in kwargs:
            kargs['headers']['Content-Type'] = kwargs['content_type']
            kargs['headers']['Accept'] = kwargs['content_type']
        else:
            kargs['headers']['Content-Type'] = self.content_type
            kargs['headers']['Accept'] = self.content_type

        if self.auth_token:
            kargs['headers']['X-Auth-Token'] = self.auth_token

        if 'body' in kwargs:
            kargs['body'] = kwargs['body']
        args = utils.safe_encode_list(args)
        kargs = utils.safe_encode_dict(kargs)
        if self.log_credentials:
            log_kargs = kargs
        else:
            log_kargs = self._strip_credentials(kargs)

        utils.http_log_req(_logger, args, log_kargs)
        try:
            resp, body = self.request(*args, **kargs)
        except httplib2.SSLHandshakeError as e:
            raise exceptions.SslCertificateValidationError(reason=e)
        except Exception as e:
            # Wrap the low-level connection error (socket timeout, redirect
            # limit, decompression error, etc) into our custom high-level
            # connection exception (it is excepted in the upper layers of code)
            _logger.debug("throwing ConnectionFailed : %s", e)
            raise exceptions.CommunicationError(e)
        finally:
            # Temporary Fix for gate failures. RPC calls and HTTP requests
            # seem to be stepping on each other resulting in bogus fd's being
            # picked up for making http requests
            self.connections.clear()

        # Read body into string if it isn't obviously image data
        body_str = None
        if 'content-type' in resp and resp['content-type'] != 'application/octet-stream':
            body_str = ''.join([chunk for chunk in body])
            self.http_log_resp(_logger, resp, body_str)
            body = body_str
        else:
            self.http_log_resp(_logger, resp, body)

        status_code = self.get_status_code(resp)
        if status_code == 401:
            raise exceptions.HTTPUnauthorized(body)
        elif status_code == 403:
            error_json = self._extract_error_json(body_str)
            raise exceptions.Forbidden(error_json.get('faultstring'))
        elif 400 <= status_code < 600:
            _logger.warn("Request returned failure status.")
            error_json = self._extract_error_json(body_str)
            raise exceptions.from_response(
                resp, error_json.get('faultstring'),
                error_json.get('debuginfo'), *args)
        elif status_code in (301, 302, 305):
            # Redirected. Reissue the request to the new location.
            return self._cs_request(resp['location'], args[1], **kwargs)
        elif status_code == 300:
            raise exceptions.from_response(resp, *args)

        return resp, body

    def json_request(self, method, url, **kwargs):
        self.authenticate_and_fetch_endpoint_url()
        # Perform the request once. If we get a 401 back then it
        # might be because the auth token expired, so try to
        # re-authenticate and try again. If it still fails, bail.
        kwargs.setdefault('headers', {})
        kwargs['headers'].setdefault('Content-Type', 'application/json')
        kwargs['headers'].setdefault('Accept', 'application/json')

        if 'body' in kwargs:
            kwargs['body'] = json.dumps(kwargs['body'])

        connection_url = self._get_connection_url(url)
        try:
            resp, body_iter = self._cs_request(connection_url,
                                               method, **kwargs)
        except exceptions.HTTPUnauthorized:
            self.authenticate()
            resp, body_iter = self._cs_request(
                connection_url, method, **kwargs)

        content_type = resp['content-type'] \
            if resp.get('content-type', None) else None

        if resp.status == 204 or resp.status == 205 or content_type is None:
            return resp, list()

        if 'application/json' in content_type:
            body = ''.join([chunk for chunk in body_iter])
            try:
                body = json.loads(body)
            except ValueError:
                _logger.error('Could not decode response body as JSON')
        else:
            body = None

        return resp, body

    def raw_request(self, method, url, **kwargs):
        self.authenticate_and_fetch_endpoint_url()
        kwargs.setdefault('headers', {})
        kwargs['headers'].setdefault('Content-Type',
                                     'application/octet-stream')
        connection_url = self._get_connection_url(url)
        return self._cs_request(connection_url, method, **kwargs)

    def upload_request(self, method, url, **kwargs):
        self.authenticate_and_fetch_endpoint_url()
        connection_url = self._get_connection_url(url)
        headers = {"X-Auth-Token": self.auth_token}
        files = {'file': ("for_upload",
                          kwargs['body'],
                          )}
        req = requests.post(connection_url, headers=headers, files=files)
        return req.json()

    def upload_request_with_data(self, method, url, **kwargs):
        self.authenticate_and_fetch_endpoint_url()
        connection_url = self._get_connection_url(url)
        headers = {"X-Auth-Token": self.auth_token}
        files = {'file': ("for_upload",
                          kwargs['body'],
                          )}
        data = kwargs.get('data')
        req = requests.post(connection_url, headers=headers, files=files,
                            data=data)
        return req.json()

    #################
    # AUTHENTICATE
    #################

    def authenticate_and_fetch_endpoint_url(self):
        if not self.auth_token:
            self.authenticate()
        if not self.endpoint_url:
            self._get_endpoint_url()

    def authenticate(self):
        if self.auth_strategy != 'keystone':
            raise exceptions.HTTPUnauthorized('Unknown auth strategy')
        if self.tenant_id:
            body = {'auth': {'passwordCredentials':
                             {'username': self.username,
                              'password': self.password, },
                             'tenantId': self.tenant_id, }, }
        else:
            body = {'auth': {'passwordCredentials':
                             {'username': self.username,
                              'password': self.password, },
                             'tenantName': self.tenant_name, }, }

        token_url = self.auth_url + "/tokens"

        # Make sure we follow redirects when trying to reach Keystone
        tmp_follow_all_redirects = self.follow_all_redirects
        self.follow_all_redirects = True
        try:
            resp, resp_body = self._cs_request(token_url, "POST",
                                               body=json.dumps(body),
                                               content_type="application/json")
        finally:
            self.follow_all_redirects = tmp_follow_all_redirects
        status_code = self.get_status_code(resp)
        if status_code != 200:
            raise exceptions.HTTPUnauthorized(resp_body)
        if resp_body:
            try:
                resp_body = json.loads(resp_body)
            except ValueError:
                pass
        else:
            resp_body = None
        self._extract_service_catalog(resp_body)

        _logger.debug("Authenticated user %s" % self.username)

    def get_auth_info(self):
        return {'auth_token': self.auth_token,
                'auth_tenant_id': self.auth_tenant_id,
                'auth_user_id': self.auth_user_id,
                'endpoint_url': self.endpoint_url}

    #################
    # UTILS
    #################
    def _extract_error_json(self, body):
        error_json = {}
        try:
            body_json = json.loads(body)
            if 'error_message' in body_json:
                raw_msg = body_json['error_message']
                error_json = json.loads(raw_msg)
        except ValueError:
            return {}

        return error_json

    def _strip_credentials(self, kwargs):
        if kwargs.get('body') and self.password:
            log_kwargs = kwargs.copy()
            log_kwargs['body'] = kwargs['body'].replace(self.password,
                                                        'REDACTED')
            return log_kwargs
        else:
            return kwargs

    def _extract_service_catalog(self, body):
        """Set the client's service catalog from the response data."""
        self.service_catalog = ServiceCatalog(body)
        try:
            sc = self.service_catalog.get_token()
            self.auth_token = sc['id']
            self.auth_tenant_id = sc.get('tenant_id')
            self.auth_user_id = sc.get('user_id')
        except KeyError:
            raise exceptions.HTTPUnauthorized()
        if not self.endpoint_url:
            self.endpoint_url = self.service_catalog.url_for(
                attr='region', filter_value=self.region_name,
                endpoint_type=self.endpoint_type)

    def _get_endpoint_url(self):
        url = self.auth_url + '/tokens/%s/endpoints' % self.auth_token
        try:
            resp, body = self._cs_request(url, "GET")
        except exceptions.HTTPUnauthorized:
            # rollback to authenticate() to handle case when neutron client
            # is initialized just before the token is expired
            self.authenticate()
            return self.endpoint_url

        body = json.loads(body)
        for endpoint in body.get('endpoints', []):
            if (endpoint['type'] == 'platform' and endpoint.get('region') == self.region_name):
                if self.endpoint_type not in endpoint:
                    raise exceptions.EndpointTypeNotFound(
                        reason=self.endpoint_type)
                return endpoint[self.endpoint_type]

        raise exceptions.EndpointNotFound()

    def _get_connection_url(self, url):
        (_class, _args, _kwargs) = self.connection_params
        base_url = _args[2]
        # Since some packages send sysinv endpoint with 'v1' and some don't,
        # the postprocessing for both options will be done here
        # Instead of doing a fix in each of these packages
        endpoint = self.endpoint_url
        # if 'v1 in both, remove 'v1' from endpoint
        if 'v1' in base_url and 'v1' in url:
            endpoint = endpoint.replace('/v1', '', 1)
        # if 'v1 not in both, add 'v1' to endpoint
        elif 'v1' not in base_url and 'v1' not in url:
            endpoint = endpoint.rstrip('/') + '/v1'

        return endpoint.rstrip('/') + '/' + url.lstrip('/')

    @staticmethod
    def get_connection_params(endpoint, **kwargs):
        parts = urlparse(endpoint)

        _args = (parts.hostname, parts.port, parts.path)
        _kwargs = {'timeout': (float(kwargs.get('timeout'))
                               if kwargs.get('timeout') else 600)}

        if parts.scheme == 'https':
            _class = VerifiedHTTPSConnection
            _kwargs['ca_file'] = kwargs.get('ca_file', None)
            _kwargs['cert_file'] = kwargs.get('cert_file', None)
            _kwargs['key_file'] = kwargs.get('key_file', None)
            _kwargs['insecure'] = kwargs.get('insecure', False)
        elif parts.scheme == 'http':
            _class = six.moves.http_client.HTTPConnection
        else:
            msg = 'Unsupported scheme: %s' % parts.scheme
            raise exceptions.EndpointException(reason=msg)

        return (_class, _args, _kwargs)

    def get_status_code(self, response):
        """Returns the integer status code from the response.

        Either a Webob.Response (used in testing) or httplib.Response
        is returned.
        """
        if hasattr(response, 'status_int'):
            return response.status_int
        else:
            return response.status


class VerifiedHTTPSConnection(six.moves.http_client.HTTPSConnection):
    """httplib-compatibile connection using client-side SSL authentication

    :see http://code.activestate.com/recipes/
            577548-https-httplib-client-connection-with-certificate-v/
    """

    def __init__(self, host, port, key_file=None, cert_file=None,
                 ca_file=None, timeout=None, insecure=False):
        six.moves.http_client.HTTPSConnection.__init__(self, host, port,
                                                       key_file=key_file,
                                                       cert_file=cert_file)
        self.key_file = key_file
        self.cert_file = cert_file
        if ca_file is not None:
            self.ca_file = ca_file
        else:
            self.ca_file = self.get_system_ca_file()
        self.timeout = timeout
        self.insecure = insecure

    def connect(self):
        """Connect to a host on a given (SSL) port.
        If ca_file is pointing somewhere, use it to check Server Certificate.

        Redefined/copied and extended from httplib.py:1105 (Python 2.6.x).
        This is needed to pass cert_reqs=ssl.CERT_REQUIRED as parameter to
        ssl.wrap_socket(), which forces SSL to check server certificate against
        our client certificate.
        """
        sock = socket.create_connection((self.host, self.port), self.timeout)

        if self._tunnel_host:
            self.sock = sock
            self._tunnel()

        if self.insecure is True:
            kwargs = {'cert_reqs': ssl.CERT_NONE}
        else:
            kwargs = {'cert_reqs': ssl.CERT_REQUIRED, 'ca_certs': self.ca_file}

        if self.cert_file:
            kwargs['certfile'] = self.cert_file
            if self.key_file:
                kwargs['keyfile'] = self.key_file

        self.sock = ssl.wrap_socket(sock, **kwargs)

    @staticmethod
    def get_system_ca_file():
        """Return path to system default CA file."""
        # Standard CA file locations for Debian/Ubuntu, RedHat/Fedora,
        # Suse, FreeBSD/OpenBSD
        ca_path = ['/etc/ssl/certs/ca-certificates.crt',
                   '/etc/pki/tls/certs/ca-bundle.crt',
                   '/etc/ssl/ca-bundle.pem',
                   '/etc/ssl/cert.pem']
        for ca in ca_path:
            if os.path.exists(ca):
                return ca
        return None


class ResponseBodyIterator(object):
    """A class that acts as an iterator over an HTTP response."""

    def __init__(self, resp):
        self.resp = resp

    def __iter__(self):
        while True:
            yield six.next()

    def next(self):
        chunk = self.resp.read(CHUNKSIZE)
        if chunk:
            return chunk
        else:
            raise StopIteration()
