#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.helm import base

SUPPORTED_VERSIONS = {
    '1.0-17-centos-stable-versioned',
    '1.0-17-centos-stable-latest',
    '1.0-17',
}


class StxOpenstackVersionCheckHelm(base.BaseHelm):
    """Class to provide application version check"""

    def _get_supported_versions(self):
        return SUPPORTED_VERSIONS

    def version_check(self, app_version):
        return app_version in self._get_supported_versions()
