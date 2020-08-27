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
import base64
import json
import re
from keystoneclient.v3 import client as keystone_client
from keystoneauth1 import session
from keystoneclient.auth.identity import v3
from oslo_config import cfg
from oslo_log import log
from six.moves.urllib.request import Request
from six.moves.urllib.error import HTTPError
from six.moves.urllib.error import URLError
from six.moves.urllib.request import urlopen

from sysinv.common import constants
from sysinv.openstack.common.keystone_objects import Token
from sysinv.common import kubernetes as sys_kube

# Subcloud sync status
ENDPOINT_TYPE_DC_CERT = 'dc-cert'

SYNC_STATUS_UNKNOWN = "unknown"
SYNC_STATUS_IN_SYNC = "in-sync"
SYNC_STATUS_OUT_OF_SYNC = "out-of-sync"

DEPLOY_STATE_DONE = 'complete'

MANAGEMENT_UNMANAGED = "unmanaged"
MANAGEMENT_MANAGED = "managed"

AVAILABILITY_OFFLINE = "offline"
AVAILABILITY_ONLINE = "online"

CERT_NAMESPACE_SYS_CONTROLLER = 'dc-cert'
CERT_NAMESPACE_SUBCLOUD_CONTROLLER = 'sc-cert'
DC_ROLE_UNDETECTED = 'unknown'

LOG = log.getLogger(__name__)
CONF = cfg.CONF

dc_role = DC_ROLE_UNDETECTED


def update_admin_ep_cert(token, ca_crt, tls_crt, tls_key):
    service_type = 'platform'
    service_name = 'sysinv'
    sysinv_url = token.get_service_internal_url(service_type, service_name)
    api_cmd = sysinv_url + '/certificate/certificate_renew'
    api_cmd_payload = dict()
    api_cmd_payload['certtype'] = constants.CERTIFICATE_TYPE_ADMIN_ENDPOINT
    resp = rest_api_request(token, "POST", api_cmd, json.dumps(api_cmd_payload))

    if 'result' in resp and resp['result'] == 'OK':
        LOG.info('Update admin endpoint request succeed')
    else:
        LOG.error('Request response %s' % resp)
        raise Exception('Update %s admin endpoint failed')


def dc_get_subcloud_sysinv_url(subcloud_name):
    user_auth = v3.Password(
        auth_url=CONF.endpoint_cache.auth_uri,
        username=CONF.endpoint_cache.username,
        user_domain_name=CONF.endpoint_cache.user_domain_name,
        password=CONF.endpoint_cache.password,
        project_name=CONF.endpoint_cache.project_name,
        project_domain_name=CONF.endpoint_cache.project_domain_name,
    )

    timeout = CONF.endpoint_cache.http_connect_timeout
    admin_session = session.Session(auth=user_auth, timeout=timeout)

    ks_client = keystone_client.Client(
        session=admin_session,
        region_name=constants.REGION_ONE_NAME,
        interface=constants.OS_INTERFACE_INTERNAL)
    services = ks_client.services.list(name='sysinv')
    if len(services) == 0:
        raise Exception('Cannot find sysinv service')

    s_id = services[0].id
    sc_sysinv_urls = ks_client.endpoints.list(
        service=s_id,
        interface=constants.OS_INTERFACE_ADMIN,
        region=subcloud_name)

    if len(sc_sysinv_urls) == 0:
        raise Exception('Cannot find sysinv endpoint for %s' %
                        subcloud_name)
    sc_sysinv_url = sc_sysinv_urls[0].url
    LOG.info('%s sysinv endpoint %s' % (subcloud_name, sc_sysinv_url))
    if not sc_sysinv_url:
        raise Exception('{} sysinv endpoint is None'.format(subcloud_name))
    return sc_sysinv_url


def dc_get_service_endpoint_url(region, service_name, endpoint_type):
    user_auth = v3.Password(
        auth_url=CONF.endpoint_cache.auth_uri,
        username=CONF.endpoint_cache.username,
        user_domain_name=CONF.endpoint_cache.user_domain_name,
        password=CONF.endpoint_cache.password,
        project_name=CONF.endpoint_cache.project_name,
        project_domain_name=CONF.endpoint_cache.project_domain_name,
    )

    timeout = CONF.endpoint_cache.http_connect_timeout
    admin_session = session.Session(auth=user_auth, timeout=timeout)

    ks_client = keystone_client.Client(
        session=admin_session,
        region_name=constants.REGION_ONE_NAME,
        interface=constants.OS_INTERFACE_INTERNAL)
    services = ks_client.services.list(name=service_name)
    if len(services) == 0:
        raise Exception('Cannot find %s service' % service_name)

    s_id = services[0].id
    endpoint_urls = ks_client.endpoints.list(
        service=s_id,
        interface=endpoint_type,
        region=region)

    if len(endpoint_urls) == 0:
        raise Exception('Cannot find %s endpoint for %s' %
                        (service_name, region))
    endpoint_url = endpoint_urls[0].url
    LOG.info('%s %s endpoint %s' % (region, service_name, endpoint_url))
    return endpoint_url


def update_subcloud_ca_cert(
        token, sc_name, sysinv_url, ca_crt, tls_crt, tls_key):

    api_cmd = sysinv_url + '/certificate/certificate_renew'
    api_cmd_payload = dict()
    api_cmd_payload['certtype'] = \
        constants.CERTIFICATE_TYPE_ADMIN_ENDPOINT_INTERMEDIATE_CA
    api_cmd_payload['root_ca_crt'] = base64.b64decode(ca_crt)
    api_cmd_payload['sc_ca_cert'] = base64.b64decode(tls_crt)
    api_cmd_payload['sc_ca_key'] = base64.b64decode(tls_key)
    resp = rest_api_request(token, "POST", api_cmd, json.dumps(api_cmd_payload))

    if 'result' in resp and resp['result'] == 'OK':
        LOG.info('Update %s intermediate CA cert request succeed' % sc_name)
    else:
        LOG.error('Request response %s' % resp)
        raise Exception('Update %s intermediate CA cert failed' % sc_name)


def get_subcloud(token, subcloud_name):
    service_name = 'dcmanager'
    api_url = dc_get_service_endpoint_url(constants.SYSTEM_CONTROLLER_REGION,
                                          service_name,
                                          constants.OS_INTERFACE_INTERNAL)
    api_cmd = api_url + '/subclouds/%s' % subcloud_name
    LOG.info('api_cmd %s' % api_cmd)
    resp = rest_api_request(token, "GET", api_cmd)

    return resp


def load_subclouds(resp):
    data = resp
    print(data)
    list = []
    for obj in data['subclouds']:
        sc = {}
        sc['name'] = obj['name']
        sc['management-state'] = obj['management-state']
        sc['availability-status'] = obj['availability-status']
        sc['sync_status'] = obj['sync_status']
        for ss in obj['endpoint_sync_status']:
            sc[ss['endpoint_type']] = ss['sync_status']
        list.append(sc)

    return list


def get_subclouds_from_dcmanager(token):
    service_name = 'dcmanager'
    api_url = dc_get_service_endpoint_url(constants.SYSTEM_CONTROLLER_REGION,
                                          service_name,
                                          constants.OS_INTERFACE_INTERNAL)
    api_cmd = api_url + '/subclouds'
    LOG.debug('api_cmd %s' % api_cmd)
    resp = rest_api_request(token, "GET", api_cmd)

    return load_subclouds(resp)


def update_subcloud_status(token, subcloud_name, status):
    service_name = 'dcmanager'
    api_url = dc_get_service_endpoint_url(constants.SYSTEM_CONTROLLER_REGION,
                                          service_name,
                                          constants.OS_INTERFACE_INTERNAL)
    api_cmd = api_url + '/subclouds/%s/update_status' % subcloud_name
    api_cmd_payload = dict()
    api_cmd_payload['endpoint'] = ENDPOINT_TYPE_DC_CERT
    api_cmd_payload['status'] = status
    resp = rest_api_request(token, "PATCH", api_cmd, json.dumps(api_cmd_payload))

    if 'result' in resp and resp['result'] == 'OK':
        LOG.info('Update admin endpoint request succeed')
    else:
        LOG.error('Request response %s' % resp)
        raise Exception('Update %s admin endpoint failed')


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
        CONF.keystone_authtoken.auth_url + '/v3/auth/tokens',
        CONF.keystone_authtoken.project_name,
        CONF.keystone_authtoken.username,
        CONF.keystone_authtoken.password,
        CONF.keystone_authtoken.user_domain_name,
        CONF.keystone_authtoken.project_domain_name,
        CONF.keystone_authtoken.region_name)

    return token


def get_dc_token(region_name):
    token = _get_token(
        CONF.endpoint_cache.auth_uri + '/auth/tokens',
        CONF.endpoint_cache.project_name,
        CONF.endpoint_cache.username,
        CONF.endpoint_cache.password,
        CONF.endpoint_cache.user_domain_name,
        CONF.endpoint_cache.project_domain_name,
        region_name)

    return token


def _get_token(auth_url, auth_project, username, password, user_domain,
               project_domain, region_name):
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
                   help='Authorization url')
    ]

    keystone_opt_group = cfg.OptGroup(name='keystone_authtoken',
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


def get_subclouds():
    """get all name of all subclouds from k8s secret

    Every subcloud comes with an intermediate CA entry in k8s secret
    :return: list of subcloud names
    """

    secret_pattern = re.compile('-adminep-ca-certificate$')
    kube_op = sys_kube.KubeOperator()
    secret_list = kube_op.kube_list_secret(ENDPOINT_TYPE_DC_CERT)

    subcloud_names = []
    for secret in secret_list:
        secret_name = secret.metadata.name
        m = secret_pattern.search(secret_name)
        if m:
            start = m.start()
            if start > 0:
                subcloud_names.append(secret_name[0:m.start()])

    return subcloud_names


def get_intermediate_ca_secret_name(sc):
    return '{}-adminep-ca-certificate'.format(sc)


def get_sc_intermediate_ca_secret(sc):
    secret_name = get_intermediate_ca_secret_name(sc)
    kube_op = sys_kube.KubeOperator()
    return kube_op.kube_get_secret(secret_name, CERT_NAMESPACE_SYS_CONTROLLER)


def get_endpoint_certificate(endpoint):
    import urlparse
    import ssl
    url = urlparse.urlparse(endpoint)
    server = url.netloc.split(':')
    if len(server) > 1:
        host = server[0]
        port = int(server[1])
    else:
        host = server[0]
        port = 443
    return ssl.get_server_certificate((host, port))


def get_dc_role():
    global dc_role
    if dc_role == DC_ROLE_UNDETECTED:
        token = get_token()
        service_type = 'platform'
        service_name = 'sysinv'
        sysinv_url = token.get_service_internal_url(service_type,
                                                    service_name)
        api_cmd = sysinv_url + '/isystems'
        res = rest_api_request(token, "GET", api_cmd)['isystems']
        if len(res) == 1:
            system = res[0]
            dc_role = system['distributed_cloud_role']
            LOG.info('Result %s' % system)
        else:
            raise Exception('Failed to access system data')

    return dc_role
