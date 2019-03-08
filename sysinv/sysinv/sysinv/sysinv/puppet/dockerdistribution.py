#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.puppet import base


class DockerDistributionPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for docker distribution"""

    def get_system_config(self):
        config = {
            'platform::dockerdistribution::params::registry_ks_endpoint':
                self._operator.keystone.get_auth_uri() + '/v3',
        }

        return config
