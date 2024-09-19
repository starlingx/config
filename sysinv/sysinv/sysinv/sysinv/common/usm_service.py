#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# USM Unified Software Management Handling

from datetime import datetime
import os
from oslo_log import log
from six.moves.urllib.error import HTTPError
from six.moves.urllib.error import URLError

from sysinv.common import exception
from sysinv.common import constants
from sysinv.common.rest_api import get_token
from sysinv.common.rest_api import rest_api_request
from sysinv.common.rest_api import rest_api_request_raise
import tsconfig.tsconfig as tsc


LOG = log.getLogger(__name__)
token = None
usm_upgrade = {"upgrade": None, "retrieved_at": None}


# NOTE (bqian) for compatibility, create a software upgrade
# entity.
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

    @property
    def from_release(self):
        return self.from_load

    @property
    def to_release(self):
        return self.to_load


class UsmHostUpgrade(object):
    def __init__(self, hostname, from_sw_version, to_sw_version, state):
        self.hostname = hostname
        self.from_sw_version = get_software_version(from_sw_version)
        self.to_sw_version = get_software_version(to_sw_version)
        self.state = state

    # backward compatibility
    @property
    def software_load(self):
        return self.from_sw_version

    # backward compatibility
    @property
    def target_load(self):
        return self.to_sw_version

    @staticmethod
    def get_by_hostname(dbapi, hostname):
        host_deploy = get_host_deploy(dbapi, hostname)
        if host_deploy:
            return UsmHostUpgrade(host_deploy.get("hostname"),
                                  host_deploy.get("software_release"),
                                  host_deploy.get("target_release"),
                                  host_deploy.get("host_state"))
        return None

    @staticmethod
    def update_host_sw_version(hostname, sw_version):
        # TODO(heitormatsui): implement in the future, so that sysinv can
        #  send software_controller the sw_version reported by the host
        pass


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


def get_software_upgrade(region_name, timeout=10):
    token = _get_token(region_name)
    endpoint = get_usm_endpoint(token)

    if not endpoint:
        return None

    endpoint += "/v1/deploy/software_upgrade"

    response = rest_api_request_raise(token, "GET", endpoint, timeout=timeout)
    return response


def is_host_next_to_be_deployed(dbapi, hostname):
    region_name = get_region_name(dbapi)
    token = _get_token(region_name)
    endpoint = get_usm_endpoint(token)

    if not endpoint:
        return None

    endpoint += "/v1/deploy_host/next?hostname=%s" % hostname

    return rest_api_request(token, "GET", endpoint, timeout=10)


def get_host_deploy(dbapi, hostname):

    region_name = get_region_name(dbapi)
    token = _get_token(region_name)
    endpoint = get_usm_endpoint(token)

    if not endpoint:
        return None

    endpoint += "/v1/deploy_host"

    hostlist = rest_api_request(token, "GET", endpoint)
    if hostlist is None:
        return None

    if hostname is None:
        return hostlist

    if type(hostlist) is not list:
        hostlist = [hostlist]

    for host in hostlist:
        if type(host) is not dict:
            break
        if host.get('hostname') == hostname:
            return host
    return None


def is_usm_authapi_ready():
    return os.path.exists(tsc.VOLATILE_CONTROLLER_CONFIG_COMPLETE)


def get_platform_upgrade(dbapi, timeout=10):
    """
    Get upgrade object from USM service.
    """
    global usm_upgrade

    def _get_usm_upgrade(region_name, timeout):
        upgrade = None
        response = get_software_upgrade(region_name, timeout)
        if response:
            upgrade = UsmUpgrade(state=response["state"],
                                 from_load=response["from_release"],
                                 to_load=response["to_release"])
        return upgrade

    if timeout < 2:
        timeout = 2
    start_time = datetime.now()
    # Authorized USM APIs are available only after bootstrap & unlock
    if not is_usm_authapi_ready():
        raise exception.NotFound()

    region_name = get_region_name(dbapi)
    upgrade = None

    remain_time = timeout
    while True:
        try:
            if remain_time < 1:
                # minimum 1 second timeout calling RESTApi
                remain_time = 1
            upgrade = _get_usm_upgrade(region_name, remain_time)
            usm_upgrade["upgrade"] = upgrade
            usm_upgrade["retrieved_at"] = datetime.utcnow()

            if remain_time < timeout:
                # only log when there is reattempt
                LOG.info("Reattempt to query USM platform upgrade state has completed successfully")

            if upgrade is None:
                # no upgrade in progress
                raise exception.NotFound()

            break

        except (HTTPError, URLError, exception.SysInvSignalTimeout) as ex:
            if isinstance(ex, HTTPError):
                msg = f"Query USM platform upgrade state failed. HTTP Error: {ex.code}"
            else:
                msg = str(ex)
            LOG.warn(msg)

            delta = datetime.now() - start_time
            secs = delta.total_seconds()
            remain_time = timeout - secs
            if remain_time <= 0:
                LOG.warn(f"Failed to retrieve USM platform upgrade state after {timeout} secs")
                break
            else:
                LOG.warn("Failed to query USM platform upgrade state. Reattempt...")

    if upgrade is None:
        # return the cache if it is recently updated, raise CannotQueryPlatformUpgrade
        # if no valid cache to use.
        if not usm_upgrade["retrieved_at"]:
            raise exception.CannotQueryPlatformUpgrade()

        secs_from_latest_retrieved = (datetime.utcnow() - usm_upgrade["retrieved_at"]).total_seconds()
        if secs_from_latest_retrieved > 120:
            # data too old
            raise exception.CannotQueryPlatformUpgrade()

        LOG.warn(f"Use cached USM platform upgrade state of {secs_from_latest_retrieved} seconds old")
        upgrade = usm_upgrade["upgrade"]

    # USM upgrade completed is considered as no upgrade in progress
    if upgrade and upgrade.state == constants.DEPLOY_STATE_COMPLETED:
        raise exception.NotFound()

    return upgrade


def get_software_version(version):
    """
    Returns software version from given string if a valid format, None otherwise
    :param version: MM.mm.pp or MM.mm
    :returns: MM.mm
    """
    version_separator = "."
    if version_separator in version:
        return ".".join(version.split(version_separator)[:2])
    return None
