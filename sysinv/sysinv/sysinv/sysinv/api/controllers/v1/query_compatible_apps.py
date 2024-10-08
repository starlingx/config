#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from distutils.util import strtobool
from oslo_log import log
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.common import app_metadata

LOG = log.getLogger(__name__)


class QueryCompatibleAppsController(rest.RestController):
    """REST controller for get compatible tarballs with platform."""

    @wsme_pecan.wsexpose([wtypes.text], wtypes.text, wtypes.text)
    def get_all(self, k8s_ver, include_path="false"):

        try:
            compatible_apps = app_metadata.make_application_query(k8s_ver,
                                                           strtobool(include_path))
            return compatible_apps
        except Exception as e:
            raise wsme.exc.ClientSideError(
                f"Unable to obtain compatible app list. Reason: {e}")
