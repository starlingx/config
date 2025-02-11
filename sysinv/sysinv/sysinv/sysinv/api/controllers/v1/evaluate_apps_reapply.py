#!/usr/bin/env python
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log
import pecan
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import types

LOG = log.getLogger(__name__)


class EvaluateAppsReapplyController(rest.RestController):
    """REST controller for evaluating apps reapply"""

    @wsme_pecan.wsexpose(wtypes.text, body=types.apidict)
    def post(self, body):
        """
        Evaluate apps reapply.

        This method handles the POST request to evaluate the reapplication of apps.
        It expects a JSON body with a 'type' field indicating the type of trigger.

        Inside the metadata.yaml of each app there is a key
        behavior.evaluate_reapply.triggers. The app configures there whether it needs
        to be reapplied if the system calls some of the triggers defined there. This
        happens because some apps need to adapt to the system that has undergone some
        specific change.

        Args:
            body (dict): The request body containing the 'type' field.

        Returns:
            str: A success message indicating that the evaluation was triggered
                 successfully.

        Example:
            body = {'type': 'usm-deploy-complete'}
        """

        try:
            if not body or "type" not in body:
                raise wsme.exc.ClientSideError(
                    "Invalid request body: missing 'type' field")

            pecan.request.rpcapi.evaluate_apps_reapply(
                pecan.request.context,
                trigger=body)

            return "Evaluation triggered successfully"
        except Exception as e:
            LOG.error(f"Failed to evaluate apps reapply: {str(e)}")
            raise wsme.exc.ClientSideError(
                f"Failed to evaluate apps reapply: {str(e)}")
