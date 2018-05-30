#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from rest_api import rest_api_request, get_token

from sysinv.openstack.common import log
LOG = log.getLogger(__name__)


def patch_query(token, timeout, region_name):
    """
    Request the list of patches known to the patch service
    """
    api_cmd = None

    if not token:
        token = get_token(region_name)

    if token:
        api_cmd = token.get_service_url("patching", "patching")

    api_cmd += "/v1/query/"

    response = rest_api_request(token, "GET", api_cmd, timeout=timeout)
    return response


def patch_query_hosts(token, timeout, region_name):
    """
    Request the patch state for all hosts known to the patch service
    """
    api_cmd = None

    if not token:
        token = get_token(region_name)

    if token:
        api_cmd = token.get_service_url("patching", "patching")

    api_cmd += "/v1/query_hosts/"

    response = rest_api_request(token, "GET", api_cmd, timeout=timeout)
    return response


def patch_drop_host(token, timeout, hostname, region_name):
    """
    Notify the patch service to drop the specified host
    """
    api_cmd = None

    if not token:
        token = get_token(region_name)

    if token:
        api_cmd = token.get_service_url("patching", "patching")

    api_cmd += "/v1/drop_host/%s" % hostname

    response = rest_api_request(token, "POST", api_cmd, timeout=timeout)
    return response
