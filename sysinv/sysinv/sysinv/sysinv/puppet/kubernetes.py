#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import subprocess

from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common import log as logging

from . import base

LOG = logging.getLogger(__name__)


class KubernetesPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for kubernetes configuration"""
    ETCD_SERVICE_PORT = '2379'

    def get_system_config(self):
        config = {}
        if self._kubernetes_enabled():
            config.update(
                {'platform::kubernetes::params::enabled': True,
                 'platform::kubernetes::params::pod_network_cidr':
                     '192.168.0.0/16',
                 'platform::kubernetes::params::apiserver_advertise_address':
                     self._get_management_address(),
                 'platform::kubernetes::params::etcd_endpoint':
                     self._get_etcd_endpoint(),
                 })

        return config

    def get_secure_system_config(self):
        config = {}
        if self._kubernetes_enabled():
            # This is retrieving the certificates that 'kubeadm init'
            # generated. We will want to change this to generate the
            # certificates ourselves, store in hiera and then feed those
            # back into 'kubeadm init'.
            if os.path.exists('/etc/kubernetes/pki/ca.crt'):
                # Store required certificates in configuration.
                with open('/etc/kubernetes/pki/ca.crt', 'r') as f:
                    ca_crt = f.read()
                with open('/etc/kubernetes/pki/ca.key', 'r') as f:
                    ca_key = f.read()
                with open('/etc/kubernetes/pki/sa.key', 'r') as f:
                    sa_key = f.read()
                with open('/etc/kubernetes/pki/sa.pub', 'r') as f:
                    sa_pub = f.read()
                config.update(
                    {'platform::kubernetes::params::ca_crt': ca_crt,
                     'platform::kubernetes::params::ca_key': ca_key,
                     'platform::kubernetes::params::sa_key': sa_key,
                     'platform::kubernetes::params::sa_pub': sa_pub,
                     })
        return config

    def get_host_config(self, host):
        config = {}
        if self._kubernetes_enabled():
            if host.personality == constants.COMPUTE:
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

    def _get_etcd_endpoint(self):
        addr = self._format_url_address(self._get_management_address())
        protocol = "http"
        url = "%s://%s:%s" % (protocol, str(addr), str(self.ETCD_SERVICE_PORT))
        return url
