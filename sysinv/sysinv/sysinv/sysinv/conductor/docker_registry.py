#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import base64
import keyring
import requests

from sysinv.common import constants
from sysinv.common import exception

DOCKER_CERT_PATH = '/etc/ssl/private/registry-cert.crt'
SYSTEM_CERT_PATH = '/etc/ssl/certs/ca-bundle.crt'
KEYRING_SERVICE = 'CGCS'
REGISTRY_USERNAME = 'admin'
REGISTRY_BASEURL = 'https://%s/v2/' % constants.DOCKER_REGISTRY_SERVER
MAX_IMAGES_COUNT = 100000  # override default of 100 & allow downloading entire catalog


def get_registry_password():
    registry_password = keyring.get_password(
        KEYRING_SERVICE, REGISTRY_USERNAME)
    if not registry_password:
        raise exception.DockerRegistryCredentialNotFound(
            name=REGISTRY_USERNAME)
    return registry_password


def docker_registry_authenticate(www_authenticate):
    """
    returns a dictionary of headers to add as part of original request
    including access_token
    takes the Www-Authenticate header from the 401 response of a
    registry request
    like 'Bearer realm="https://192.168.204.2:9002/token/",
          service="192.168.204.2:9001",scope="registry:catalog:*"'

    :param www_authenticate: a Www-Authenticate header as described above
    """

    # additional headers from the result of authentication
    # for example, access_token
    # send these along with the request to the docker registry
    auth_headers = {'connection': 'close'}

    # take off the "Bearer"
    auth_params = www_authenticate.split(' ')
    # unsupported www_authenticate header
    if len(auth_params) != 2 or auth_params[0] != 'Bearer':
        return {}

    auth_params = auth_params[1].split(',')
    # each auth_params should be an entry like
    # service="192.168.204.2:9001"
    for auth_param in auth_params:
        auth_param = auth_param.split('=')
        # we need to strip quotes from the auth challenge
        # if we send the "scope" field in quotes, we will get
        # "token intended for another audience" errors
        auth_headers[auth_param[0]] = auth_param[1].strip('\"')

    # 'realm' specifies a token server to authenticate to
    if 'realm' not in auth_headers:
        return {}

    # make a request to the token server
    # the credentials are passed as a header while the rest
    # are passed as params
    auth_string = base64.b64encode("%s:%s" % (REGISTRY_USERNAME, get_registry_password()))
    token_server_request_headers = {"authorization": "Basic %s" % auth_string}
    # we need try twice.
    # SYSTEM_CERT_PATH if the docker registry cert is signed by a trusted CA
    # DOCKER_CERT_PATH if the registry certificate is self-signed
    try:
        token_server_response = requests.get(auth_headers['realm'],
                                             verify=SYSTEM_CERT_PATH,
                                             params=auth_headers,
                                             headers=token_server_request_headers)
    except requests.exceptions.SSLError:
        token_server_response = requests.get(auth_headers['realm'],
                                             verify=DOCKER_CERT_PATH,
                                             params=auth_headers,
                                             headers=token_server_request_headers)
    if token_server_response.status_code == 200:
        auth_headers['Authorization'] = "Bearer %s" % token_server_response.json().get("access_token")

    return auth_headers


def docker_registry_get(path, registry_url=REGISTRY_BASEURL):
    # we need to have this header to get the correct digest when giving the tag
    headers = {"Accept": "application/vnd.docker.distribution.manifest.v2+json"}

    try:
        resp = requests.get("%s%s?n=%s" % (registry_url, path, MAX_IMAGES_COUNT),
                            verify=SYSTEM_CERT_PATH, headers=headers)
    except requests.exceptions.SSLError:
        resp = requests.get("%s%s?n=%s" % (registry_url, path, MAX_IMAGES_COUNT),
                            verify=DOCKER_CERT_PATH, headers=headers)

    # authenticated registry, need to do auth with token server
    if resp.status_code == 401:
        auth_headers = docker_registry_authenticate(resp.headers["Www-Authenticate"])
        headers.update(auth_headers)
        try:
            resp = requests.get("%s%s?n=%s" % (registry_url, path, MAX_IMAGES_COUNT),
                                verify=SYSTEM_CERT_PATH, headers=headers)
        except requests.exceptions.SSLError:
            resp = requests.get("%s%s?n=%s" % (registry_url, path, MAX_IMAGES_COUNT),
                                verify=DOCKER_CERT_PATH, headers=headers)

    return resp


def docker_registry_delete(path, registry_url=REGISTRY_BASEURL):
    headers = {}

    try:
        resp = requests.delete("%s%s" % (registry_url, path),
                               verify=SYSTEM_CERT_PATH, headers=headers)
    except requests.exceptions.SSLError:
        resp = requests.delete("%s%s" % (registry_url, path),
                               verify=DOCKER_CERT_PATH, headers=headers)

    # authenticated registry, need to do auth with token server
    if resp.status_code == 401:
        auth_headers = docker_registry_authenticate(resp.headers["Www-Authenticate"])
        headers.update(auth_headers)

        try:
            resp = requests.delete("%s%s" % (registry_url, path),
                                   verify=SYSTEM_CERT_PATH, headers=headers)
        except requests.exceptions.SSLError:
            resp = requests.delete("%s%s" % (registry_url, path),
                                   verify=DOCKER_CERT_PATH, headers=headers)

    return resp
