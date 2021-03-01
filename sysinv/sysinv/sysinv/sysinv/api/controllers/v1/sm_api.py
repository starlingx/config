#
# Copyright (c) 2016-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import json
import pecan
import socket

from oslo_log import log
from sysinv.common.rest_api import get_token
from sysinv.common.rest_api import rest_api_request

LOG = log.getLogger(__name__)

SM_API_HOST = socket.gethostname()
SM_API_PORT = 7777
SM_API_PATH = "http://{host}:{port}".\
    format(host=SM_API_HOST, port=SM_API_PORT)


def _get_token():
    system = pecan.request.dbapi.isystem_get_one()
    return get_token(system.region_name)


def swact_pre_check(hostname, timeout):
    """
    Sends a Swact Pre-Check command to SM.
    """
    token = _get_token()
    api_cmd = SM_API_PATH
    api_cmd += "/v1/servicenode/%s" % hostname

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = dict()
    api_cmd_payload['origin'] = "sysinv"
    api_cmd_payload['action'] = "swact-pre-check"
    api_cmd_payload['admin'] = "unknown"
    api_cmd_payload['oper'] = "unknown"
    api_cmd_payload['avail'] = ""

    response = rest_api_request(token, "PATCH", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)

    return response


def lock_pre_check(hostname, timeout):
    """
        Sends a Lock Pre-Check command to SM.
        """
    token = _get_token()
    api_cmd = SM_API_PATH
    api_cmd += "/v1/servicenode/%s" % hostname

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = dict()
    api_cmd_payload['origin'] = "sysinv"
    api_cmd_payload['action'] = "lock-pre-check"
    api_cmd_payload['admin'] = "unknown"
    api_cmd_payload['oper'] = "unknown"
    api_cmd_payload['avail'] = ""

    response = rest_api_request(token, "PATCH", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)

    return response


def service_list():
    """
    Sends a service list command to SM.
    """
    token = _get_token()
    api_cmd = SM_API_PATH
    api_cmd += "/v1/services"

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['Accept'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    response = rest_api_request(token, "GET", api_cmd, api_cmd_headers, None)

    return response


def service_show(hostname):
    """
    Sends a service show command to SM.
    """
    token = _get_token()
    api_cmd = SM_API_PATH
    api_cmd += "/v1/services/%s" % hostname

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['Accept'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    response = rest_api_request(token, "GET", api_cmd, api_cmd_headers, None)
    return response


def servicenode_list():
    """
    Sends a service list command to SM.
    """
    token = _get_token()
    api_cmd = SM_API_PATH
    api_cmd += "/v1/nodes"

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['Accept'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    response = rest_api_request(token, "GET", api_cmd, api_cmd_headers, None)

    return response


def servicenode_show(hostname):
    """
    Sends a service show command to SM.
    """
    token = _get_token()
    api_cmd = SM_API_PATH
    api_cmd += "/v1/nodes/%s" % hostname

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['Accept'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    response = rest_api_request(token, "GET", api_cmd, api_cmd_headers, None)

    return response


def sm_servicegroup_list():
    """
    Sends a service list command to SM.
    """
    token = _get_token()
    api_cmd = SM_API_PATH
    api_cmd += "/v1/sm_sda"

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['Accept'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    response = rest_api_request(token, "GET", api_cmd, api_cmd_headers, None)

    # rename the obsolete sm_sda to sm_servicegroups
    if isinstance(response, dict):
        if 'sm_sda' in response:
            response['sm_servicegroup'] = response.pop('sm_sda')

    return response


def sm_servicegroup_show(hostname):
    """
    Sends a service show command to SM.
    """
    token = _get_token()
    api_cmd = SM_API_PATH
    api_cmd += "/v1/sm_sda/%s" % hostname

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['Accept'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    response = rest_api_request(token, "GET", api_cmd, api_cmd_headers, None)

    return response
