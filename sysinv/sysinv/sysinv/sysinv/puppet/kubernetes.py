#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import subprocess

from sysinv.common import constants
from sysinv.common import exception
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

    def get_host_config(self, host):
        config = {}
        if self._kubernetes_enabled():
            if constants.COMPUTE in host.subfunctions:
                create_node = False
                try:
                    # Check if this host has already been configured as a
                    # kubernetes node.
                    cmd = ['kubectl',
                           '--kubeconfig=/etc/kubernetes/admin.conf',
                           'get', 'node', host.hostname]
                    subprocess.check_call(cmd)
                except subprocess.CalledProcessError:
                    # The node does not exist
                    create_node = True

                if create_node:
                    try:
                        # Generate the token and join command for this host.
                        cmd = ['kubeadm', 'token', 'create',
                               '--print-join-command', '--description',
                               'Bootstrap token for %s' % host.hostname]
                        join_cmd = subprocess.check_output(cmd)
                        config.update(
                            {'platform::kubernetes::worker::params::join_cmd':
                                join_cmd,
                             })
                    except subprocess.CalledProcessError:
                        raise exception.SysinvException(
                            'Failed to generate bootstrap token')

        return config
