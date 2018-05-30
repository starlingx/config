# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
from pecan import rest

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _


LOG = log.getLogger(__name__)


class HealthController(rest.RestController):
    """REST controller for System Health."""

    def __init__(self):
        self._api_token = None

    @wsme_pecan.wsexpose(wtypes.text)
    def get_all(self):
        """Provides information about the health of the system"""
        try:
            success, output = pecan.request.rpcapi.get_system_health(
                pecan.request.context)
        except Exception as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_(
                "Unable to perform health query."))
        return output

    @wsme_pecan.wsexpose(wtypes.text, wtypes.text)
    def get_one(self, upgrade):
        """Validates the health of the system for an upgrade"""
        try:
            success, output = pecan.request.rpcapi.get_system_health(
                pecan.request.context, upgrade=True)
        except Exception as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_(
                "Unable to perform health upgrade query."))
        return output
