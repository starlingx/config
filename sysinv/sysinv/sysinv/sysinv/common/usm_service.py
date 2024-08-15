#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


# USM Unified Software Management Handling

import os
from oslo_log import log
import tsconfig.tsconfig as tsc

from sysinv.common import exception
from sysinv.common import constants
from sysinv.common.rest_api import get_token
from sysinv.common.rest_api import rest_api_request


LOG = log.getLogger(__name__)
token = None


# NOTE (bqian) for compatibility, create a software upgrade
# entity.
# This is temporary to bridge between legacy upgrade and USM
# major release deploy and should be removed once the transition
# completes.
class UsmUpgrade(object):
    def __init__(self, state, from_load, to_load):
        self.state = state
        self.from_load = from_load
        self.to_load = to_load

    def __eq__(self, other):
        return self.state == other.state and \
               self.from_load == other.from_load and \
               self.to_load == other.to_load

    def __ne__(self, other):
        return not (self == other)


def get_region_name(dbapi):
    system = dbapi.isystem_get_one()
    region_name = system.region_name
    return region_name


def get_usm_endpoint(token):
    return token.get_service_internal_url("usm", "usm")


def _get_token(region_name):
    global token
    if not token or token.is_expired():
        LOG.debug("Requesting a new token")
        token = get_token(region_name)
    else:
        LOG.debug("Token is still valid. Reusing.")
    return token


def get_software_upgrade(region_name, timeout=30):
    token = _get_token(region_name)
    endpoint = get_usm_endpoint(token)

    if not endpoint:
        return None

    endpoint += "/v1/deploy/software_upgrade"

    response = rest_api_request(token, "GET", endpoint, timeout=timeout)
    return response


def get_host_deploy(dbapi, hostname):

    region_name = get_region_name(dbapi)
    token = _get_token(region_name)
    endpoint = get_usm_endpoint(token)

    if not endpoint:
        return None

    endpoint += "/v1/deploy_host"

    hostlist = rest_api_request(token, "GET", endpoint, timeout=10)
    if hostlist is None:
        return None

    if hostname is None:
        return hostlist

    for host in hostlist:
        if host['hostname'] == hostname:
            return host
    return None


def is_usm_authapi_ready():
    return os.path.exists(tsc.VOLATILE_CONTROLLER_CONFIG_COMPLETE)


def get_platform_upgrade(dbapi, usm_only=False):
    """
    Get upgrade object from either sysinv db or USM service.
    Upgrade object is from USM service if the service is present,
    if not, the object is from sysinv db.
    """

    # Authorized USM APIs are available only after bootstrap & unlock
    if not is_usm_authapi_ready():
        raise exception.NotFound()

    upgrade = None
    region_name = get_region_name(dbapi)

    try:
        response = get_software_upgrade(region_name)
        if response:
            upgrade = UsmUpgrade(state=response["state"],
                                 from_load=response["from_release"],
                                 to_load=response["to_release"])
    except Exception:
        # it is ok, legacy upgrade does not have usm service available
        pass

    # USM upgrade completed is considered as no upgrade in progress
    if upgrade and upgrade.state == constants.DEPLOY_STATE_COMPLETED:
        raise exception.NotFound()

    # query legacy upgrade API
    if upgrade is None and not usm_only:
        upgrade = dbapi.software_upgrade_get_one()

    # no upgrade in progress (USM and legacy)
    if upgrade is None:
        raise exception.NotFound()

    return upgrade
