#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import
import os
import subprocess

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils
from sysinv.openstack.common import log as logging

from sysinv.puppet import base

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
                     self._get_pod_network_cidr(),
                 'platform::kubernetes::params::service_network_cidr':
                     self._get_cluster_service_subnet(),
                 'platform::kubernetes::params::apiserver_advertise_address':
                     self._get_cluster_host_address(),
                 'platform::kubernetes::params::etcd_endpoint':
                     self._get_etcd_endpoint(),
                 'platform::kubernetes::params::service_domain':
                     self._get_dns_service_domain(),
                 'platform::kubernetes::params::dns_service_ip':
                     self._get_dns_service_ip(),
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

        # Retrieve labels for this host
        config.update(self._get_host_label_config(host))

        # Update cgroup resource controller parameters for this host
        config.update(self._get_host_k8s_cgroup_config(host))

        if host.personality != constants.WORKER:
            return config

        if self._kubernetes_enabled():
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
        addr = self._format_url_address(self._get_cluster_host_address())
        protocol = "http"
        url = "%s://%s:%s" % (protocol, str(addr), str(self.ETCD_SERVICE_PORT))
        return url

    def _get_pod_network_cidr(self):
        return self._get_network_config(constants.NETWORK_TYPE_CLUSTER_POD)

    def _get_cluster_service_subnet(self):
        return self._get_network_config(constants.NETWORK_TYPE_CLUSTER_SERVICE)

    def _get_network_config(self, networktype):
        try:
            network = self.dbapi.network_get_by_type(networktype)
        except exception.NetworkTypeNotFound:
            # network not configured
            return {}
        address_pool = self.dbapi.address_pool_get(network.pool_uuid)
        subnet = str(address_pool.network) + '/' + str(address_pool.prefix)
        return subnet

    def _get_dns_service_domain(self):
        # Setting this to a constant for now. Will be configurable later
        return constants.DEFAULT_DNS_SERVICE_DOMAIN

    def _get_dns_service_ip(self):
        # Setting this to a constant for now. Will be configurable later
        return constants.DEFAULT_DNS_SERVICE_IP

    def _get_host_label_config(self, host):
        config = {}
        labels = self.dbapi.label_get_by_host(host.uuid)
        host_label_keys = []
        for label in labels:
            host_label_keys.append(label.label_key)
        config.update(
            {'platform::kubernetes::params::host_labels': host_label_keys})
        return config

    def _get_host_k8s_cgroup_config(self, host):
        config = {}

        # determine set of all logical cpus and nodes
        host_cpus = self._get_host_cpu_list(host, threads=True)
        host_cpuset = set([c.cpu for c in host_cpus])
        host_nodeset = set([c.numa_node for c in host_cpus])

        # determine set of platform logical cpus and nodes
        platform_cpus = self._get_host_cpu_list(
            host, function=constants.PLATFORM_FUNCTION, threads=True)
        platform_cpuset = set([c.cpu for c in platform_cpus])
        platform_nodeset = set([c.numa_node for c in platform_cpus])

        # determine set of nonplatform logical cpus and nodes
        nonplatform_cpuset = host_cpuset - platform_cpuset
        nonplatform_nodeset = set()
        for c in host_cpus:
            if c.cpu not in platform_cpuset:
                nonplatform_nodeset.update([c.numa_node])

        if constants.WORKER in utils.get_personalities(host):
            if self.is_openstack_compute(host):
                k8s_cpuset = utils.format_range_set(platform_cpuset)
                k8s_nodeset = utils.format_range_set(platform_nodeset)
            else:
                k8s_cpuset = utils.format_range_set(nonplatform_cpuset)
                k8s_nodeset = utils.format_range_set(nonplatform_nodeset)
        else:
            k8s_cpuset = utils.format_range_set(host_cpuset)
            k8s_nodeset = utils.format_range_set(host_nodeset)

        LOG.debug('host:%s, k8s_cpuset:%s, k8s_nodeset:%s',
                  host.hostname, k8s_cpuset, k8s_nodeset)

        config.update(
            {'platform::kubernetes::params::k8s_cpuset':
             "\"%s\"" % k8s_cpuset,
             'platform::kubernetes::params::k8s_nodeset':
             "\"%s\"" % k8s_nodeset,
             })

        return config
