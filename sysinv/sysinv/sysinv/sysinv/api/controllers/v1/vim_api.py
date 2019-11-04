#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import json

from oslo_log import log
from sysinv.api.controllers.v1.rest_api import rest_api_request
from sysinv.common import constants

LOG = log.getLogger(__name__)


def vim_get_host_services_state(token, hostname, timeout):
    """
    Asks VIM for host services state for a host.
    """
    api_cmd = None
    if token:
        api_cmd = token.get_service_url("nfvi", "nfv")

    if not api_cmd:
        api_cmd = "http://localhost:30001"

    api_cmd += "nfvi-plugins/v1/hosts/" + hostname + "/servicestate"

    response = rest_api_request(token, "GET", api_cmd, timeout)
    return response


def vim_host_add(token, uuid, hostname, subfunctions,
                 admininistrative, operational, availability,
                 subfunction_oper, subfunction_avail,
                 timeout):
    """
    Requests VIM to add a host.
    """
    LOG.warn("vim_host_add hostname=%s, subfunctions=%s "
             "%s-%s-%s  subfunction_oper=%s subfunction_avail=%s" %
             (hostname, subfunctions, admininistrative, operational,
              availability, subfunction_oper, subfunction_avail))
    api_cmd = None
    if token:
        api_cmd = token.get_service_url("nfvi", "nfv")

    if not api_cmd:
        api_cmd = "http://localhost:30001"

    api_cmd += "/nfvi-plugins/v1/hosts/"

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = dict()
    api_cmd_payload['uuid'] = uuid
    api_cmd_payload['hostname'] = hostname
    api_cmd_payload['subfunctions'] = subfunctions
    api_cmd_payload['administrative'] = admininistrative
    api_cmd_payload['operational'] = operational
    api_cmd_payload['availability'] = availability
    api_cmd_payload['subfunction_oper'] = subfunction_oper
    api_cmd_payload['subfunction_avail'] = subfunction_avail

    LOG.warn("vim_host_add api_cmd=%s headers=%s payload=%s" %
             (api_cmd, api_cmd_headers, api_cmd_payload))

    response = rest_api_request(token, "POST", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)
    return response


def vim_host_action(token, uuid, hostname, action, timeout):
    """
    Request VIM to perform host action.
    """

    response = None
    _valid_actions = [constants.UNLOCK_ACTION,
                      constants.LOCK_ACTION,
                      constants.FORCE_LOCK_ACTION]

    if action not in _valid_actions:
        LOG.error("Unrecognized vim_host_action=%s" % action)
        return response

    LOG.warn("vim_host_action hostname=%s, action=%s" % (hostname, action))

    api_cmd = None
    if token:
        api_cmd = token.get_service_url("nfvi", "nfv")

    if not api_cmd:
        api_cmd = "http://localhost:30001"

    api_cmd += "/nfvi-plugins/v1/hosts/%s" % uuid

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = dict()
    api_cmd_payload['uuid'] = uuid
    api_cmd_payload['hostname'] = hostname
    api_cmd_payload['action'] = action

    LOG.warn("vim_host_action hostname=%s, action=%s  api_cmd=%s "
             "headers=%s payload=%s" %
             (hostname, action, api_cmd, api_cmd_headers, api_cmd_payload))

    response = rest_api_request(token, "PATCH", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)
    return response
    # 200 if complete; 203 In progress ok.
    # 400/500 if rejected


def vim_host_delete(token, uuid, hostname, timeout):
    """
    Asks VIM to delete a host
    """

    api_cmd = None
    if token:
        api_cmd = token.get_service_url("nfvi", "nfv")

    if not api_cmd:
        api_cmd = "http://localhost:30001"

    api_cmd += "/nfvi-plugins/v1/hosts/%s" % uuid

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = dict()
    api_cmd_payload['uuid'] = uuid
    api_cmd_payload['hostname'] = hostname
    api_cmd_payload['action'] = 'delete'

    response = rest_api_request(token, "DELETE", api_cmd,
                                api_cmd_headers,
                                json.dumps(api_cmd_payload),
                                timeout=timeout)
    return response


def vim_host_upgrade_state(token, uuid, hostname, upgrade_inprogress, timeout):
    """
    Inform VIM if we are in an upgrade
    """

    response = None

    api_cmd = None
    if token:
        api_cmd = token.get_service_url("nfvi", "nfv")

    if not api_cmd:
        api_cmd = "http://localhost:30001"

    api_cmd += "/nfvi-plugins/v1/hosts"

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    upgrade = dict()

    upgrade_inprogress = bool(upgrade_inprogress)
    upgrade['inprogress'] = upgrade_inprogress
    upgrade['recover-instances'] = not upgrade_inprogress

    api_cmd_payload = dict()
    api_cmd_payload['uuid'] = uuid
    api_cmd_payload['hostname'] = hostname
    api_cmd_payload['upgrade'] = upgrade

    response = rest_api_request(token, "PATCH", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)
    return response


def set_vim_upgrade_state(host, upgrade_state):
    """Sets the VIM upgrade state for the host"""
    return vim_host_upgrade_state(
        token=None,
        uuid=host['uuid'],
        hostname=host['hostname'],
        upgrade_inprogress=upgrade_state,
        timeout=constants.VIM_DEFAULT_TIMEOUT_IN_SECS)


def vim_host_get_instances(token, uuid, hostname, timeout):
    """
    Returns instance counts for a given host
    """

    response = None

    api_cmd = None
    if token:
        api_cmd = token.get_service_url("nfvi", "nfv")

    if not api_cmd:
        api_cmd = "http://localhost:30001"

    api_cmd += "/nfvi-plugins/v1/hosts"
    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = dict()
    api_cmd_payload['uuid'] = uuid
    api_cmd_payload['hostname'] = hostname

    response = rest_api_request(token, "GET", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)
    return response


def vim_host_update(token, uuid, hostname, timeout):
    """
    Inform VIM of host change
    """

    api_cmd = None
    if token:
        api_cmd = token.get_service_url("nfvi", "nfv")

    if not api_cmd:
        api_cmd = "http://localhost:30001"

    api_cmd += "/nfvi-plugins/v1/hosts"

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = dict()
    api_cmd_payload['uuid'] = uuid
    api_cmd_payload['hostname'] = hostname

    response = rest_api_request(token, "PATCH", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)

    LOG.debug("vim_host_update api_cmd=%s headers=%s payload=%s" %
              (api_cmd, api_cmd_headers, api_cmd_payload))

    return response
