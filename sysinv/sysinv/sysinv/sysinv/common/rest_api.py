#
# Copyright (c) 2015-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import json
import os
import signal

import six
from six.moves.urllib.request import urlopen
from six.moves.urllib.request import Request
from six.moves.urllib.error import HTTPError
from six.moves.urllib.error import URLError
import socket
import ssl

from oslo_log import log
from oslo_utils import encodeutils
from sysinv.common import configp
from sysinv.common import exception as si_exception
from sysinv.openstack.common.keystone_objects import Token

from sysinv.common.exception import OpenStackException
from sysinv.common.exception import OpenStackRestAPIException

LOG = log.getLogger(__name__)


def _get_token(auth_url, auth_project, username, password, user_domain,
               project_domain, region_name, timeout=30):
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

        request_info.data = encodeutils.safe_encode(payload)

        request = urlopen(request_info, timeout=timeout)
        # Identity API v3 returns token id in X-Subject-Token
        # response header.
        token_id = request.headers.get('X-Subject-Token')
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


def get_token(region_name):
    token = None

    if not configp.CONFP:
        configp.load("/etc/sysinv/api-paste.ini")

    if configp.CONFP.get('filter:authtoken') or "":
        token = _get_token(
            configp.CONFP['filter:authtoken']['auth_uri'],
            configp.CONFP['filter:authtoken']['project_name'],  # tenant
            configp.CONFP['filter:authtoken']['username'],        # username
            configp.CONFP['filter:authtoken']['password'],    # password
            configp.CONFP['filter:authtoken']['user_domain_name'],
            configp.CONFP['filter:authtoken']['project_domain_name'],
            region_name)

    return token


def _timeout_handler(signum, frame):
    if signum == 14:
        LOG.error("raise signal _timeout_handler")
        raise si_exception.SysInvSignalTimeout
    else:
        LOG.error("signal timeout_handler %s" % signum)


def rest_api_request(token, method, api_cmd, api_cmd_headers=None,
                     api_cmd_payload=None, timeout=10):
    """
    Make a rest-api request
    Returns: response as a dictionary
    """

    # signal.signal(signal.SIGALRM, _timeout_handler)
    # if hasattr(signal, 'SIGALRM'):
    #     signal.alarm(timeout)

    LOG.info("%s cmd:%s hdr:%s payload:%s" % (method,
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

        ca_file = get_system_ca_file()
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
                                                 cafile=ca_file)
        request = urlopen(request_info, timeout=timeout, context=ssl_context)

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
            response = json.loads('"%s"' % e.msg)
        else:
            response = json.loads("{}")

        LOG.info("HTTPError response=%s" % (response))
        raise OpenStackRestAPIException(six.text_type(e), e.code, "%s" % e)

    except URLError as e:
        LOG.warn("URLError Error e=%s" % (e))
        raise OpenStackException(six.text_type(e), "%s" % e)

    except si_exception.SysInvSignalTimeout as e:
        LOG.warn("Timeout Error e=%s" % (e))
        raise OpenStackException(six.text_type(e), "%s" % e)

    finally:
        signal.alarm(0)
        return response


def rest_api_request_raise(token, method, api_cmd, api_cmd_headers=None,
                           api_cmd_payload=None, timeout=10):
    """
    Make a rest-api request, raise exceptions for errors
    Returns: response as a dictionary from json response
    raise HTTPError and URLError

    This function is slightly different from rest_api_request:
    1. it actually raise/uncatch exceptions mentioned, rest_api_request
       eats the exceptions by return response in finally block
    2. it does NOT wrap the exceptions, so the caller knows the failure of
       rest-api call, so to perform its own reattempt strategy.
       The exception is 401, it force token expired and reraise.
    3. only a dictionary of decoded from json response is return,
       rest_api_request returns string of error message in the case of error.
    """

    LOG.info("%s cmd:%s hdr:%s payload:%s" % (method,
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

        ca_file = get_system_ca_file()
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
                                                 cafile=ca_file)
        request = urlopen(request_info, timeout=timeout, context=ssl_context)

        response = request.read()

        if response == "":
            response = json.loads("{}")
        else:
            response = json.loads(response)
        request.close()

    except HTTPError as e:
        if 401 == e.code:
            if token:
                LOG.info("force token expired")
                token.set_expired()
        LOG.warn("HTTP Error e.code=%s e=%s, response %s" % (e.code, e, response))
        raise

    except socket.timeout:
        raise si_exception.SysInvSignalTimeout("Timeout sending rest request")

    return response


def get_system_ca_file():
    """Return path to system default CA file."""
    # Duplicate of sysinv.common.utils.get_system_ca_file() to
    # avoid circular import
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
