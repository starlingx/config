#!/usr/bin/env python
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.common import app_metadata

LOG = log.getLogger(__name__)


class ReorderAppsController(rest.RestController):

    @wsme_pecan.wsexpose([wtypes.text])
    def get_all(self):
        """Reorders apps based on the metadata.yaml presenting the application tarball

        The purpose of this function is to print the updated apps
        order based on the metadata.yaml of the tarballs.
        """

        try:
            order_apps = app_metadata.get_reorder_apps()
            return order_apps
        except Exception as e:
            raise wsme.exc.ClientSideError(
                f"Unable to get order of apps. Reason: {e}")
