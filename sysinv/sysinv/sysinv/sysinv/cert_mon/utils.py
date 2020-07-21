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
# Copyright (c) 2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
import json
from oslo_config import cfg
from oslo_log import log
from six.moves.urllib.request import Request
from six.moves.urllib.error import HTTPError
from six.moves.urllib.error import URLError
from six.moves.urllib.request import urlopen

from sysinv.common import constants
from sysinv.openstack.common.keystone_objects import Token

LOG = log.getLogger(__name__)
CONF = cfg.CONF


def update_admin_ep_cert(token, ca_crt, tls_crt, tls_key):
    service_type = constants.SERVICE_TYPE_PLATFORM
    service_name = 'sysinv'
    sysinv_url = token.get_service_internal_url(service_type, service_name)
    api_cmd = sysinv_url + '/certificate/certificate_renew'
    api_cmd_payload = dict()
    api_cmd_payload['certtype'] = 'admin-endpoint-cert'
    resp = rest_api_request(token, "POST", api_cmd, json.dumps(api_cmd_payload))

    if 'result' in resp and resp['result'] == 'OK':
        LOG.info('Request succeed')
    else:
        LOG.error('Request response %s' % resp)


def rest_api_request(token, method, api_cmd,
                     api_cmd_payload=None, timeout=10):
    """
    Make a rest-api request
    Returns: response as a dictionary
    """
    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "cert-mon/1.0"

    LOG.debug("%s cmd:%s hdr:%s payload:%s" % (method,
             api_cmd, api_cmd_headers, api_cmd_payload))

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
            request_info.add_data(api_cmd_payload)

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
            request_info.add_data(api_cmd_payload)

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
    token = _get_token(
        CONF.keystone_authtoken.auth_url,
        CONF.keystone_authtoken.project_name,
        CONF.keystone_authtoken.username,
        CONF.keystone_authtoken.password,
        CONF.keystone_authtoken.user_domain_name,
        CONF.keystone_authtoken.project_domain_name,
        CONF.keystone_authtoken.region_name)

    return token


def _get_token(auth_url, auth_project, username, password, user_domain,
               project_domain, region_name):
    """
    Ask OpenStack Keystone for a token
    Returns: token object or None on failure
    """
    try:
        url = auth_url + "/v3/auth/tokens"
        request_info = Request(url)
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

        request_info.add_data(payload)

        request = urlopen(request_info)
        # Identity API v3 returns token id in X-Subject-Token
        # response header.
        token_id = request.info().getheader('X-Subject-Token')
        response = json.loads(request.read())
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
                   help='authorization url'),
    ]

    keystone_opt_group = cfg.OptGroup(name='keystone_authtoken',
                                      title='Keystone options')
    cfg.CONF.register_opts(keystone_opts, group=keystone_opt_group.name)
