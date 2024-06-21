# Copyright (c) 2016-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _

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

    @wsme_pecan.wsexpose(wtypes.text, wtypes.text, wtypes.text, wtypes.text, wtypes.text)
    def get_one(self, upgrade, relaxed=None, rootca=None, alarm_ignore_list=None):
        """Validates the health of the system for an upgrade"""
        force = False
        if relaxed:
            force = True
        if upgrade == 'upgrade':
            try:
                success, output = pecan.request.rpcapi.get_system_health(
                    pecan.request.context, upgrade=True, force=force)
            except Exception as e:
                LOG.exception(e)
                raise wsme.exc.ClientSideError(_(
                    "Unable to perform health upgrade query."))
            return output
        elif upgrade == 'kube-upgrade':
            try:
                success, output = pecan.request.rpcapi.get_system_health(
                    pecan.request.context, kube_upgrade=True, force=force,
                    kube_rootca_update=rootca, alarm_ignore_list=alarm_ignore_list)
            except Exception as e:
                LOG.exception(e)
                raise wsme.exc.ClientSideError(_(
                    "Unable to perform kubernetes health upgrade query."))
            return output
        else:
            raise wsme.exc.ClientSideError(_(
                "Unsupported upgrade type %s." % upgrade))
