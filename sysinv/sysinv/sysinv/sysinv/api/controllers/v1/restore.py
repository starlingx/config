# Copyright (c) 2020 Wind River Systems, Inc.
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
from sysinv.api.controllers.v1 import base
from sysinv.common import utils as cutils

LOG = log.getLogger(__name__)
LOCK_NAME = 'RestoreController'


class Restore(base.APIBase):
    """API representation of a restore.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a restore.
    """

    action = wtypes.text
    "Action to take"

    def __repr__(self):
        return "<restore action:%s>" % self.action


class RestoreController(rest.RestController):
    """REST controller for Restore."""

    @wsme_pecan.wsexpose(wtypes.text)
    def get_all(self):
        """Query the restore state"""

        try:
            output = pecan.request.rpcapi.get_restore_state(
                pecan.request.context)
        except Exception as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_(
                "Unable to perform restore query."))
        return output

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(wtypes.text, body=Restore)
    def patch(self, body):
        """Modify the restore state"""

        try:
            if body.action == "start":
                output = pecan.request.rpcapi.start_restore(
                    pecan.request.context)
            elif body.action == "complete":
                output = pecan.request.rpcapi.complete_restore(
                    pecan.request.context)
            else:
                raise wsme.exc.ClientSideError(_(
                    "Unknown restore action {}".format(body.action)))

        except Exception as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_(
                "Unable to perform restore modify state."))

        return output
