#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.openstack.common import log as logging

from . import base

LOG = logging.getLogger(__name__)


class KubernetesPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for kubernetes configuration"""

    def get_system_config(self):
        config = {}
        if self._kubernetes_enabled():
            config.update(
                {'platform::kubernetes::params::enabled': True,
                 'platform::kubernetes::params::pod_network_cidr':
                     '192.168.0.0/16',
                 'platform::kubernetes::params::apiserver_advertise_address':
                     self._get_management_address(),
                 })

        return config
