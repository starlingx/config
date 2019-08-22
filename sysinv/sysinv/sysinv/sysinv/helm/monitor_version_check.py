#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from sysinv.helm import base

MONITOR_SUPPORTED_VERSIONS = [
    '1.0-1',
]


class StxMonitorVersionCheckHelm(base.BaseHelm):
    """Class to provide application version check"""

    def _get_supported_versions(self):
        return MONITOR_SUPPORTED_VERSIONS

    def version_check(self, app_version):
        return app_version in self._get_supported_versions()
