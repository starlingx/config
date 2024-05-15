#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


# USM Unified Software Management Handling

from oslo_log import log

from sysinv.common.rest_api import get_token
from sysinv.common.rest_api import rest_api_request


LOG = log.getLogger(__name__)


# NOTE (bqian) for compatibility, create a software upgrade
# entity.
# This is temporary to bridge between legacy upgrade and USM
# major release deploy and should be removed once the transition
# completes.
class UsmUpgrade(object):
    def __init__(self, state, from_load, to_load):
        self.state = None
        self.from_load = None
        self.to_load = None

    def __eq__(self, other):
        return self.state == other.state and \
               self.from_load == other.from_load and \
               self.to_load == other.to_load

    def __ne__(self, other):
        return not (self == other)


def get_software_upgrade(token, region_name, timeout=30):

    if not token:
        token = get_token(region_name)

    endpoint = token.get_service_url("usm", "usm")

    if not endpoint:
        return None

    endpoint += "/v1/deploy/software_upgrade"

    response = rest_api_request(token, "GET", endpoint, timeout=timeout)
    return response


def get_platform_upgrade(dbapi):
    """
    Get upgrade object from either sysinv db or USM service.
    Upgrade object is from USM service if the service is present,
    if not, the object is from sysinv db.
    """

    upgrade = None
    system = dbapi.isystem_get_one()
    region_name = system.region_name

    try:
        response = get_software_upgrade(None, region_name)
        if response:
            upgrade = UsmUpgrade(state=response["state"],
                                 from_load=response["from_release"],
                                 to_load=response["to_release"])
    except Exception:
        # it is ok, legacy upgrade does not have usm service available
        pass

    if upgrade is None:
        upgrade = dbapi.software_upgrade_get_one()

    return upgrade
