#
# Copyright (c) 2016-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from oslo_log import log
from sysinv.common.rest_api import get_token
from sysinv.common.rest_api import rest_api_request

LOG = log.getLogger(__name__)
token = None


def _get_token(region_name):
    global token
    if not token or token.is_expired():
        LOG.debug("Requesting a new token.")
        token = get_token(region_name)
    else:
        LOG.debug("Token is still valid. Reusing.")
    return token


def patch_query(token, timeout, region_name):
    """
    Request the list of patches known to the patch service
    """
    api_cmd = None
    token = _get_token(region_name)

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
    token = _get_token(region_name)

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
    token = _get_token(region_name)

    if token:
        api_cmd = token.get_service_url("patching", "patching")

    api_cmd += "/v1/drop_host/%s" % hostname

    response = rest_api_request(token, "POST", api_cmd, timeout=timeout)
    return response


def patch_is_applied(token, timeout, region_name, patches):
    """
    Query the applied state for a list of patches
    """
    api_cmd = None
    token = _get_token(region_name)

    if token:
        api_cmd = token.get_service_url("patching", "patching")

    patch_dependencies = ""
    for patch in patches:
        patch_dependencies += "/%s" % patch

    api_cmd += "/v1/is_applied%s" % patch_dependencies

    response = rest_api_request(token, "GET", api_cmd, timeout=timeout)
    return response


def patch_is_available(token, timeout, region_name, patches):
    """
    Query the available state for a list of patches
    """
    api_cmd = None
    token = _get_token(region_name)

    if token:
        api_cmd = token.get_service_url("patching", "patching")

    patch_dependencies = ""
    for patch in patches:
        patch_dependencies += "/%s" % patch

    api_cmd += "/v1/is_available%s" % patch_dependencies

    response = rest_api_request(token, "GET", api_cmd, timeout=timeout)
    return response


def patch_report_app_dependencies(token, timeout, region_name, patches, app_name):
    """
    Report the application patch dependencies
    """
    api_cmd = None
    token = _get_token(region_name)

    if token:
        api_cmd = token.get_service_url("patching", "patching")

    patch_dependencies = ""
    for patch in patches:
        patch_dependencies += "/%s" % patch

    api_cmd += "/v1/report_app_dependencies%s?app=%s" % (patch_dependencies, app_name)

    response = rest_api_request(token, "POST", api_cmd, timeout=timeout)
    return response
