#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
from pecan import rest
import wsmeext.pecan as wsme_pecan


class FluxController(rest.RestController):
    """REST controller for Flux-related operations."""

    _custom_actions = {
        'rollback': ['POST'],
    }

    @wsme_pecan.wsexpose(bool)
    def update(self):

        return pecan.request.rpcapi.upgrade_flux_controllers(
            pecan.request.context)

    @wsme_pecan.wsexpose(bool)
    def rollback(self):

        return pecan.request.rpcapi.rollback_flux_controllers(
            pecan.request.context)
