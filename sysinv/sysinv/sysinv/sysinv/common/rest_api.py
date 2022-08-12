#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import json
import signal

import six
from six.moves.urllib.request import urlopen
from six.moves.urllib.request import Request
from six.moves.urllib.error import HTTPError
from six.moves.urllib.error import URLError

from oslo_log import log
from oslo_utils import encodeutils
from sysinv.common import configp
from sysinv.common import exception as si_exception
from sysinv.openstack.common.keystone_objects import Token

from sysinv.common.exception import OpenStackException
from sysinv.common.exception import OpenStackRestAPIException

LOG = log.getLogger(__name__)


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

        request_info.data = encodeutils.safe_encode(payload)

        request = urlopen(request_info)
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
