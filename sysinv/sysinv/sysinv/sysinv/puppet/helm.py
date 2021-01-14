#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from sysinv.puppet import base


class HelmPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for helm configuration"""

    SERVICE_NAME = 'helmv2'

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)
        return {
            'platform::helm::v2::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)

        return {
            'platform::helm::v2::db::postgresql::password': dbpass,
        }
