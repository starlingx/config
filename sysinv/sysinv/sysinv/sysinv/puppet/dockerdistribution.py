#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import utils
from sysinv.puppet import base


class DockerDistributionPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for docker distribution"""

    def get_system_config(self):
        config = {
            'platform::dockerdistribution::params::registry_ks_endpoint':
                self._operator.keystone.get_auth_uri() + '/v3',
        }

        return config

    def get_secure_system_config(self):
        registry_credentials = utils.get_local_docker_registry_auth()
        config = {
            'platform::dockerdistribution::params::registry_username': registry_credentials['username'],
            'platform::dockerdistribution::params::registry_password': registry_credentials['password']
        }

        return config
