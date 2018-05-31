#
# Copyright (c) 2015-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time
import json
from rest_api import rest_api_request
from sysinv.common import exception as si_exception
from sysinv.openstack.common import log
LOG = log.getLogger(__name__)


def host_add(token, address, port, ihost_mtce, timeout):
    """
    Sends a Host Add command to maintenance.
    """

    # api_cmd = "http://localhost:2112"
    api_cmd = "http://%s:%s" % (address, port)
    api_cmd += "/v1/hosts/"

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = dict()
    api_cmd_payload = ihost_mtce

    LOG.info("host_add for %s cmd=%s hdr=%s payload=%s" %
             (ihost_mtce['hostname'],
              api_cmd, api_cmd_headers, api_cmd_payload))

    response = rest_api_request(token, "POST", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)

    return response


def host_modify(token, address, port, ihost_mtce, timeout, max_retries=1):
    """
    Sends a Host Modify command to maintenance.
    """

    # api_cmd = "http://localhost:2112"
    api_cmd = "http://%s:%s" % (address, port)
    api_cmd += "/v1/hosts/%s" % ihost_mtce['uuid']

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = dict()
    api_cmd_payload = ihost_mtce

    LOG.debug("host_modify for %s cmd=%s hdr=%s payload=%s" %
              (ihost_mtce['hostname'],
              api_cmd, api_cmd_headers, api_cmd_payload))

    num_of_try = 0
    response = None
    while num_of_try < max_retries and response is None:
        try:
            num_of_try = num_of_try + 1
            LOG.info("number of calls to rest_api_request=%d (max_retry=%d)" %
                      (num_of_try, max_retries))
            response = rest_api_request(token, "PATCH", api_cmd, api_cmd_headers,
                                        json.dumps(api_cmd_payload), timeout)
            if response is None:
                time.sleep(3)               # delays for 3 seconds
        except si_exception.SysInvSignalTimeout as e:
            # Note: Even there is a timeout but neither of these "except" got it.
            LOG.warn("WARNING rest_api_request Timeout Error e=%s" % (e))
            raise si_exception.SysInvSignalTimeout
        except:
            LOG.warn("WARNING rest_api_request Unexpected Error")

    return response


def host_delete(token, address, port, ihost_mtce, timeout):
    """
    Sends a Host Delete command to maintenance.
    """

    api_cmd = "http://%s:%s" % (address, port)
    api_cmd += "/v1/hosts/%s" % ihost_mtce['uuid']

    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "sysinv/1.0"

    api_cmd_payload = None

    LOG.info("host_delete for %s cmd=%s hdr=%s payload=%s" %
             (ihost_mtce['uuid'], api_cmd, api_cmd_headers, api_cmd_payload))

    response = rest_api_request(token, "DELETE", api_cmd, api_cmd_headers,
                                json.dumps(api_cmd_payload), timeout)

    return response
