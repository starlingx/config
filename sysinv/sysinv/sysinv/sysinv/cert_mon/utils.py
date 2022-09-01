# Copyright (c) 2020-2022 Wind River Systems, Inc.
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
import re
import ssl
import socket
import tempfile

import requests
from eventlet.green import subprocess
from six.moves.urllib.parse import urlparse
from oslo_config import cfg
from oslo_log import log
from oslo_utils import encodeutils
from oslo_serialization import base64
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
        LOG.info('Update admin endpoint certificate request succeeded')
    else:
        LOG.error('Request response %s' % resp)
        raise Exception('Update admin endpoint certificate failed')


def verify_adminep_cert_chain():
    """
    Verify admin endpoint certificate chain & delete if invalid
    :param context: an admin context.
    :return: True/False if chain is valid

    * Retrieve ICA & AdminEP cert secrets from k8s
    * base64 decode ICA cert (tls.crt from SC_INTERMEDIATE_CA_SECRET_NAME)
    *   & adminep (tls.crt from SC_ADMIN_ENDPOINT_SECRET_NAME)
    *   & store the crts in tempfiles
    * Run openssl verify against RootCA to verify the chain
    """
    kube_op = sys_kube.KubeOperator()

    secret_ica = kube_op.kube_get_secret(constants.SC_INTERMEDIATE_CA_SECRET_NAME,
                                         CERT_NAMESPACE_SUBCLOUD_CONTROLLER)
    if 'tls.crt' not in secret_ica.data:
        raise Exception('%s tls.crt (ICA) data missing'
                        % (constants.SC_INTERMEDIATE_CA_SECRET_NAME))

    secret_adminep = kube_op.kube_get_secret(constants.SC_ADMIN_ENDPOINT_SECRET_NAME,
                                             CERT_NAMESPACE_SUBCLOUD_CONTROLLER)
    if 'tls.crt' not in secret_adminep.data:
        raise Exception('%s tls.crt data missing'
                        % (constants.SC_ADMIN_ENDPOINT_SECRET_NAME))

    txt_ca_crt = base64.decode_as_text(secret_ica.data['tls.crt'])
    txt_tls_crt = base64.decode_as_text(secret_adminep.data['tls.crt'])

    with tempfile.NamedTemporaryFile() as ca_tmpfile:
        ca_tmpfile.write(txt_ca_crt.encode('utf8'))
        ca_tmpfile.flush()
        with tempfile.NamedTemporaryFile() as adminep_tmpfile:
            adminep_tmpfile.write(txt_tls_crt.encode('utf8'))
            adminep_tmpfile.flush()

            cmd = ['openssl', 'verify', '-CAfile', constants.DC_ROOT_CA_CERT_PATH,
                   '-untrusted', ca_tmpfile.name, adminep_tmpfile.name]
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    universal_newlines=True)
            stdout, stderr = proc.communicate()
            proc.wait()
            if 0 == proc.returncode:
                LOG.info('verify_adminep_cert_chain passed. Valid chain')
                return True
            else:
                LOG.info('verify_adminep_cert_chain: Chain is invalid\n%s\n%s'
                         % (stdout, stderr))

                res = kube_op.kube_delete_secret(constants.SC_ADMIN_ENDPOINT_SECRET_NAME,
                                                 CERT_NAMESPACE_SUBCLOUD_CONTROLLER)
                LOG.info('Deleting AdminEP secret due to invalid chain. %s:%s, result %s, msg %s'
                         % (CERT_NAMESPACE_SUBCLOUD_CONTROLLER,
                         constants.SC_ADMIN_ENDPOINT_SECRET_NAME,
                         res.status, res.message))
                return False


def dc_get_subcloud_sysinv_url(subcloud_name, dc_token):
    """Pulls the sysinv platform URL from the given token"""
    url = dc_token.get_service_admin_url(constants.SERVICE_TYPE_PLATFORM,
                                         constants.SYSINV_USERNAME,
                                         subcloud_name)
    if url:
        LOG.debug('%s sysinv endpoint %s' % (subcloud_name, url))
        return url
    else:
        LOG.error('Cannot find sysinv endpoint for %s' % subcloud_name)
        raise Exception('Cannot find sysinv endpoint for %s' % subcloud_name)


def dc_get_service_endpoint_url(token,
                                service_name='dcmanager',
                                service_type='dcmanager',
                                region=constants.SYSTEM_CONTROLLER_REGION):
    """Pulls the dcmanager service internal URL from the given token"""
    url = token.get_service_internal_url(service_type, service_name, region)
    if url:
        LOG.debug('%s %s endpoint %s' % (region, service_name, url))
        return url
    else:
        LOG.error('Cannot find %s endpoint for %s' % (service_name, region))
        raise Exception('Cannot find %s endpoint for %s' % (service_name, region))


def update_subcloud_ca_cert(
        token, sc_name, sysinv_url, ca_crt, tls_crt, tls_key):

    api_cmd = sysinv_url + '/certificate/certificate_renew'
    api_cmd_payload = dict()
    api_cmd_payload['certtype'] = \
        constants.CERTIFICATE_TYPE_ADMIN_ENDPOINT_INTERMEDIATE_CA
    api_cmd_payload['root_ca_crt'] = ca_crt
    api_cmd_payload['sc_ca_cert'] = tls_crt
    api_cmd_payload['sc_ca_key'] = tls_key
    timeout = int(CONF.endpoint_cache.http_connect_timeout)

    resp = rest_api_request(token, "POST", api_cmd,
                            json.dumps(api_cmd_payload), timeout=timeout)

    if 'result' in resp and resp['result'] == 'OK':
        LOG.info('Update %s intermediate CA cert request succeed' % sc_name)
    else:
        LOG.error('Request response %s' % resp)
        raise Exception('Update %s intermediate CA cert failed' % sc_name)


def get_subcloud(token, subcloud_name):
    api_url = dc_get_service_endpoint_url(token)
    api_cmd = api_url + '/subclouds/%s' % subcloud_name
    LOG.info('api_cmd %s' % api_cmd)
    resp = rest_api_request(token, "GET", api_cmd)

    return resp


def load_subclouds(resp):
    sc_list = []
    for obj in resp['subclouds']:
        sc = {}
        sc['name'] = obj['name']
        sc['management-state'] = obj['management-state']
        sc['availability-status'] = obj['availability-status']
        sc['sync_status'] = obj['sync_status']
        for ss in obj['endpoint_sync_status']:
            sc[ss['endpoint_type']] = ss['sync_status']
        sc_list.append(sc)

    return sc_list


def get_subclouds_from_dcmanager(token):
    api_url = dc_get_service_endpoint_url(token)
    api_cmd = api_url + '/subclouds'
    LOG.debug('api_cmd %s' % api_cmd)
    resp = rest_api_request(token, "GET", api_cmd)

    return load_subclouds(resp)


def is_subcloud_online(subcloud_name, token=None):
    """Check if subcloud is online"""
    if not token:
        token = get_token()
    subcloud_info = get_subcloud(token, subcloud_name)
    if not subcloud_info:
        LOG.error('Cannot find subcloud %s' % subcloud_name)
        return False
    return subcloud_info['availability-status'] == AVAILABILITY_ONLINE


def update_subcloud_status(token, subcloud_name, status):
    api_url = dc_get_service_endpoint_url(token)
    api_cmd = api_url + '/subclouds/%s/update_status' % subcloud_name
    api_cmd_payload = dict()
    api_cmd_payload['endpoint'] = ENDPOINT_TYPE_DC_CERT
    api_cmd_payload['status'] = status
    resp = rest_api_request(token, "PATCH",
                            api_cmd, json.dumps(api_cmd_payload))

    if 'result' in resp and resp['result'] == 'OK':
        LOG.info('Updated subcloud %s status: %s' % (subcloud_name, status))
    else:
        LOG.error("Failed to update subcloud %s status to '%s', resp=%s"
                  % (subcloud_name, status, resp))
        raise Exception('Update subcloud status failed, subcloud=%s'
                        % subcloud_name)


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
    token = _get_token(
        CONF.keystone_authtoken.auth_url + '/v3/auth/tokens',
        CONF.keystone_authtoken.project_name,
        CONF.keystone_authtoken.username,
        CONF.keystone_authtoken.password,
        CONF.keystone_authtoken.user_domain_name,
        CONF.keystone_authtoken.project_domain_name,
        CONF.keystone_authtoken.region_name)
    return token


def get_dc_token(region_name=constants.SYSTEM_CONTROLLER_REGION):
    """Get token for the dcmanager user.

    Note: Although region_name can be specified, the token used here is a
    "project-scoped" token (i.e., not specific to the subcloud/region name).
    A token obtained using one region_name can be re-used across any
    subcloud. We take advantage of this in our DC token caching strategy.
    """
    token = _get_token(
        CONF.endpoint_cache.auth_uri + '/auth/tokens',
        CONF.endpoint_cache.project_name,
        CONF.endpoint_cache.username,
        CONF.endpoint_cache.password,
        CONF.endpoint_cache.user_domain_name,
        CONF.endpoint_cache.project_domain_name,
        region_name)
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


def get_subcloud_secrets():
    """get subcloud name and ICA secret name pairs from k8s secret
       Every subcloud comes with an ICA entry in k8s secret
       :return: dict of subcloud name and ICA secret name pairs
    """

    secret_pattern = re.compile('-adminep-ca-certificate$')
    kube_op = sys_kube.KubeOperator()
    secret_list = kube_op.kube_list_secret(ENDPOINT_TYPE_DC_CERT)

    dict = {}
    for secret in secret_list:
        secret_name = secret.metadata.name
        m = secret_pattern.search(secret_name)
        if m:
            start = m.start()
            if start > 0:
                dict.update({secret_name[0:m.start()]: secret_name})

    return dict


def get_subclouds():
    """get name of all subclouds from k8s secret

    Every subcloud comes with an ICA entry in k8s secret
    :return: list of subcloud names
    """

    subcloud_secrets = get_subcloud_secrets()
    return list(subcloud_secrets.keys())


def get_intermediate_ca_secret_name(sc):
    return '{}-adminep-ca-certificate'.format(sc)


def get_sc_intermediate_ca_secret(sc):
    secret_name = get_intermediate_ca_secret_name(sc)
    kube_op = sys_kube.KubeOperator()
    return kube_op.kube_get_secret(secret_name, CERT_NAMESPACE_SYS_CONTROLLER)


def get_endpoint_certificate(endpoint, timeout_secs=10):
    url = urlparse(endpoint)
    host = url.hostname
    port = url.port
    if timeout_secs is not None and timeout_secs > 0:
        # The call to ssl.get_server_certificate blocks for a long time if the
        # server is not available. A timeout is not available in python 2.7.
        # See https://bugs.python.org/issue31870
        # Until the timeout=<val> option is available in
        # get_server_certificate(), we first check if the port is open
        # by connecting using a timeout, then we do the certificate check:
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout_secs)
        except Exception:
            LOG.warn("get_endpoint_certificate: connection failed to %s:%s",
                     host, port)
            raise
        finally:
            if sock is not None:
                sock.close()
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
            LOG.debug('DC role: %s' % system)
        else:
            raise Exception('Failed to access system data')

    return dc_role


def get_isystems_uuid(token):
    uuid = ''
    sysinv_url = token.get_service_internal_url(constants.SERVICE_TYPE_PLATFORM, constants.SYSINV_USERNAME)
    api_cmd = sysinv_url + '/isystems'
    res = rest_api_request(token, "GET", api_cmd)['isystems']
    if len(res) == 1:
        system = res[0]
        uuid = system['uuid']
    else:
        raise Exception('Failed to access system data')

    return uuid


def enable_https(token, system_uuid):
    ret = True
    sysinv_url = token.get_service_internal_url(constants.SERVICE_TYPE_PLATFORM, constants.SYSINV_USERNAME)
    api_cmd = sysinv_url + '/isystems/' + system_uuid

    patch = []
    patch.append({'op': 'replace', 'path': '/https_enabled', 'value': 'true'})

    resp = rest_api_request(token, "PATCH", api_cmd, json.dumps(patch))

    if resp['capabilities']['https_enabled'] is True:
        LOG.info('Enable https patch request succeeded')
    else:
        ret = False
        LOG.exception('Enable https failed! resp=%s' % resp)

    return ret


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

    response = rest_api_upload(token, pem_file_path, api_cmd, data)
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
    token_getters = {'internal': get_token, 'dc': get_dc_token}

    def __init__(self, token_type):
        self._token = None
        self._token_type = token_type
        self._getter_func = self.token_getters[token_type]

    def get_token(self):
        """Get a new token if required; otherwise use the cached token"""
        if not self._token or self._token.is_expired():
            LOG.debug("TokenCache %s, Acquiring new token, previous token: %s",
                      self._token_type, self._token)
            self._token = self._getter_func()
        return self._token
