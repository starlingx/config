# Copyright (c) 2020-2025 Wind River Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import json
import os
import tempfile

import requests
from oslo_config import cfg
from oslo_log import log
from oslo_utils import encodeutils
from six.moves.urllib.request import Request
from six.moves.urllib.error import HTTPError
from six.moves.urllib.error import URLError
from six.moves.urllib.request import urlopen

from sysinv.common import constants
from sysinv.openstack.common.keystone_objects import Token

DC_ROLE_UNDETECTED = 'unknown'

CERT_INSTALL_LOCK_NAME = "sysinv-certs"

LOG = log.getLogger(__name__)
CONF = cfg.CONF

dc_role = DC_ROLE_UNDETECTED

internal_token_cache = None


def rest_api_request(token, method, api_cmd,
                     api_cmd_payload=None, timeout=45):
    """
    Make a rest-api request
    Returns: response as a dictionary
    """
    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "cert-mon/1.0"

    try:
        request_info = Request(api_cmd)
        request_info.get_method = lambda: method
        if token:
            request_info.add_header("X-Auth-Token", token.get_id())
        request_info.add_header("Accept", "application/json")

        if api_cmd_headers is not None:
            for header_type, header_value in api_cmd_headers.items():
                request_info.add_header(header_type, header_value)

        if api_cmd_payload is not None:
            request_info.data = encodeutils.safe_encode(api_cmd_payload)

        request = None
        try:
            request = urlopen(request_info, timeout=timeout)
            response = request.read()
        finally:
            if request:
                request.close()

        if response == "":
            response = json.loads("{}")
        else:
            response = json.loads(response)

    except HTTPError as e:
        if 401 == e.code:
            if token:
                token.set_expired()
        raise

    except URLError:
        LOG.error("Cannot access %s" % api_cmd)
        raise

    return response


def get_system(token, method, api_cmd, api_cmd_headers=None,
                     api_cmd_payload=None, timeout=10):
    """
    Make a rest-api request
    Returns: response as a dictionary
    """
    LOG.debug("%s cmd:%s hdr:%s payload:%s" % (method,
             api_cmd, api_cmd_headers, api_cmd_payload))

    response = None
    try:
        request_info = Request(api_cmd)
        request_info.get_method = lambda: method
        if token:
            request_info.add_header("X-Auth-Token", token.get_id())
        request_info.add_header("Accept", "application/json")

        if api_cmd_headers is not None:
            for header_type, header_value in api_cmd_headers.items():
                request_info.add_header(header_type, header_value)

        if api_cmd_payload is not None:
            request_info.data = encodeutils.safe_encode(api_cmd_payload)

        request = urlopen(request_info, timeout=timeout)
        response = request.read()

        if response == "":
            response = json.loads("{}")
        else:
            response = json.loads(response)
        request.close()

    except HTTPError as e:
        if 401 == e.code:
            if token:
                token.set_expired()
        LOG.warn("HTTP Error e.code=%s e=%s" % (e.code, e))
        if hasattr(e, 'msg') and e.msg:
            response = json.loads(e.msg)
        else:
            response = json.loads("{}")
        raise

    except URLError:
        LOG.error("Cannot access %s" % api_cmd)
        raise

    finally:
        return response


def get_token():
    """Get token for the sysinv user."""

    keystone_conf = CONF.get('KEYSTONE_AUTHTOKEN')

    token = _get_token(
        keystone_conf.auth_url + '/v3/auth/tokens',
        keystone_conf.project_name,
        keystone_conf.username,
        keystone_conf.password,
        keystone_conf.user_domain_name,
        keystone_conf.project_domain_name,
        keystone_conf.region_name)

    return token


def _get_token(auth_url,
               auth_project,
               username,
               password,
               user_domain,
               project_domain,
               region_name,
               timeout=60):
    """
    Ask OpenStack Keystone for a token
    Returns: token object or None on failure
    """
    try:
        request_info = Request(auth_url)
        request_info.add_header("Content-type", "application/json")
        request_info.add_header("Accept", "application/json")
        payload = json.dumps(
            {"auth": {
                "identity": {
                    "methods": [
                        "password"
                    ],
                    "password": {
                        "user": {
                            "name": username,
                            "password": password,
                            "domain": {"name": user_domain}
                        }
                    }
                },
                "scope": {
                    "project": {
                        "name": auth_project,
                        "domain": {"name": project_domain}
                    }}}})

        request_info.data = encodeutils.safe_encode(payload)

        request = urlopen(request_info, timeout=timeout)
        # Identity API v3 returns token id in X-Subject-Token
        # response header.
        token_id = request.headers.get('X-Subject-Token')
        json_response = request.read()
        response = json.loads(json_response)
        request.close()

        # save the region name for service url lookup
        return Token(response, token_id, region_name)

    except HTTPError as e:
        LOG.error("%s, %s" % (e.code, e.read()))
        return None

    except URLError as e:
        LOG.error(e)
        return None


def init_keystone_auth_opts():
    keystone_opts = [
        cfg.StrOpt('username',
                   help='Username of account'),
        cfg.StrOpt('auth_uri',
                   help='authentication uri'),
        cfg.StrOpt('password',
                   help='Password of account'),
        cfg.StrOpt('project_name',
                   help='Tenant name of account'),
        cfg.StrOpt('user_domain_name',
                   default='Default',
                   help='User domain name of account'),
        cfg.StrOpt('project_domain_name',
                   default='Default',
                   help='Project domain name of account'),
        cfg.StrOpt('region_name',
                   default='',
                   help='Region name'),
        cfg.StrOpt('auth_url',
                   default='',
                   help='Authorization url')
    ]

    keystone_opt_group = cfg.OptGroup(name='KEYSTONE_AUTHTOKEN',
                                      title='Keystone options')
    cfg.CONF.register_opts(keystone_opts, group=keystone_opt_group.name)

    endpoint_opts = keystone_opts[:]
    endpoint_opts.append(
        cfg.StrOpt('http_connect_timeout',
                   default=10,
                   help='HTTP connection timeout')
    )
    endpoint_cache_group = cfg.OptGroup(name='endpoint_cache',
                                        title='Endpoint cache')
    cfg.CONF.register_opts(endpoint_opts, group=endpoint_cache_group.name)


def get_dc_role():
    global dc_role
    if dc_role == DC_ROLE_UNDETECTED:
        token = get_cached_token()
        if not token:
            raise Exception('Failed to obtain keystone token')
        service_type = 'platform'
        service_name = 'sysinv'
        sysinv_url = token.get_service_internal_url(service_type,
                                                    service_name)
        api_cmd = sysinv_url + '/isystems'
        res = rest_api_request(token, "GET", api_cmd)['isystems']
        if len(res) == 1:
            system = res[0]
            dc_role = system['distributed_cloud_role']
            LOG.debug('DC role: %s' % system)
        else:
            raise Exception('Failed to access system data')

    return dc_role


def upload_request_with_data(token, url, **kwargs):
    headers = {"X-Auth-Token": token.get_id()}
    files = {'file': ("for_upload",
                    kwargs['body'],)}
    data = kwargs.get('data')
    timeout = kwargs.get('timeout')
    try:
        req = requests.post(url, headers=headers, files=files,
                            data=data, timeout=timeout)
        req.raise_for_status()
    except requests.exceptions.HTTPError as e:
        if 401 == e.response.status_code:
            if token:
                token.set_expired()
        raise
    except requests.exceptions.InvalidURL:
        LOG.error("Cannot access %s" % url)
        raise

    LOG.info('response from upload API = %s' % req.json())
    return req.json()


def rest_api_upload(token, filepath, url, data=None, timeout=30):
    """
    Make a rest-api upload call
    """
    LOG.info('rest_api_upload called. filepath=%s, url=%s, data=%s, timeout=%s'
            % (filepath, url, data, timeout))
    try:
        file_to_upload = open(filepath, 'rb')
    except Exception as e:
        LOG.exception(e)

    return upload_request_with_data(token, url, body=file_to_upload, data=data,
                                    timeout=timeout)


def update_pemfile(tls_crt, tls_key):
    LOG.info('Updating temporary pemfile')
    try:
        fd, tmppath = tempfile.mkstemp(suffix='.pem')
        with open(tmppath, 'w+') as f:
            f.write(tls_crt)
            f.write("\n")
            f.write(tls_key)
    except Exception as e:
        LOG.exception(e)
        raise
    finally:
        if fd is not None:
            os.close(fd)
    return tmppath


def list_platform_certificates(token):
    """Lists platform certificates using the sysinv API
    :param token: the token to access the sysinv API
    """
    sysinv_url = token.get_service_internal_url(
        constants.SERVICE_TYPE_PLATFORM, constants.SYSINV_USERNAME)
    api_cmd = sysinv_url + "/certificate"
    return rest_api_request(token, "GET", api_cmd)


def update_platform_cert(token, cert_type, pem_file_path, force=False):
    """Update a platform certificate using the sysinv API
    :param token: the token to access the sysinv API
    :param cert_type: the type of the certificate that is being updated
    :param pem_file_path: path to the certificate file in PEM format
    :param force: whether to bypass semantic checks and force the update,
        defaults to False
    """
    LOG.info('Updating %s certificate. pem_file_path=%s' % (cert_type, pem_file_path))
    sysinv_url = token.get_service_internal_url(constants.SERVICE_TYPE_PLATFORM, constants.SYSINV_USERNAME)
    api_cmd = sysinv_url + '/certificate/certificate_install'

    data = {'mode': cert_type,
            'force': str(force).lower()}

    response = rest_api_upload(token, pem_file_path, api_cmd, data, timeout=60)
    error = response.get('error')
    if error:
        LOG.info('Failed. Certificate not installed. Error=%s' % error)
    else:
        LOG.info('Certificate successfully installed')

    # cleanup
    try:
        os.remove(pem_file_path)
    except OSError:
        LOG.exception('Failed to remove temp pem file %s' % pem_file_path)


class TokenCache(object):
    """Simple token cache. This class holds one keystone token.
    """
    def __init__(self, token_type):
        self._token = None
        self._token_type = token_type

    def get_token(self):
        """Get a new token if required; otherwise use the cached token"""
        if not self._token or self._token.is_expired():
            LOG.debug("TokenCache %s, Acquiring new token, previous token: %s",
                      self._token_type, self._token)
            self._token = get_token()
        else:
            LOG.debug("TokenCache %s, Token is still valid, reusing token: %s",
                      self._token_type, self._token)
        return self._token


def get_internal_token_cache():
    global internal_token_cache
    if not internal_token_cache:
        internal_token_cache = TokenCache("internal")
    return internal_token_cache


def get_cached_token():
    return get_internal_token_cache().get_token()
