#
# Copyright (c) 2018-2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import
from eventlet.green import subprocess
import json
import keyring
import netaddr
import os
import random
import re
import tempfile

from oslo_log import log as logging
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import utils
from sysinv import objects
from sysinv.puppet import base
from sysinv.puppet import interface

LOG = logging.getLogger(__name__)

# Offset aligns with kubeadm DNS IP allocation scheme:
# kubenetes/cmd/kubeadm/app/constants/constants.go:GetDNSIP
CLUSTER_SERVICE_DNS_IP_OFFSET = 10

# certificate keyring params
CERTIFICATE_KEY_SERVICE = "kubernetes"
CERTIFICATE_KEY_USER = "certificate-key"


class KubernetesPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for kubernetes configuration"""
    ETCD_SERVICE_PORT = '2379'

    def __init__(self, *args, **kwargs):
        super(KubernetesPuppet, self).__init__(*args, **kwargs)
        self._kube_operator = kubernetes.KubeOperator()

    def get_system_config(self):
        config = {}
        config.update(
            {'platform::kubernetes::params::enabled': True,
             'platform::kubernetes::params::service_domain':
                 self._get_dns_service_domain(),
             'platform::kubernetes::params::dns_service_ip':
                 self._get_dns_service_ip(),
             'platform::kubernetes::params::upgrade_to_version':
                 self._get_kubernetes_upgrade_to_version(),
             })

        return config

    def get_host_config(self, host):
        config = {}

        # Update node configuration for host
        config.update(self._get_host_node_config(host))

        # Retrieve labels for this host
        config.update(self._get_host_label_config(host))

        # Update cgroup resource controller parameters for this host
        config.update(self._get_host_k8s_cgroup_config(host))

        # Update PCI device plugin parameters for this host
        config.update(self._get_host_pcidp_config(host))

        # Generate the token and join command for this host.
        config.update(self._get_host_join_command(host))

        # Get the kubernetes version for this host
        config.update(self._get_kubernetes_version(host))

        return config

    def get_host_config_upgrade(self, host):
        """Updates the config for upgrade with updated kubernetes params

        :param host: host object
        """
        config = {}

        # Generate the join command for this host
        config.update(self._get_host_join_command(host))

        # Get the kubernetes version
        config.update(self._get_active_kubernetes_version())

        LOG.info("get_host_config_upgrade kubernetes config=%s" % config)

        return config

    def get_secure_static_config(self):
        """Update the hiera configuration to add certificate-key"""

        key = keyring.get_password(CERTIFICATE_KEY_SERVICE,
                CERTIFICATE_KEY_USER)
        if not key:
            key = '{:064x}'.format(random.getrandbits(8 * 32))
            keyring.set_password(CERTIFICATE_KEY_SERVICE,
                    CERTIFICATE_KEY_USER, key)
            LOG.info('storing kubernetes_kubeadm_certificate_key')

        config = {}

        config.update({
                'kubernetes::kubeadm::certificate-key': key,
        })

        return config

    @staticmethod
    def _get_active_kubernetes_version():
        """Get the active kubernetes version
        """
        # During a platform upgrade, the version is still None
        # when N+1 controller-1 is creating hieradata.
        # The version is updated from the running kubernetes version.
        config = {}

        kube_operator = kubernetes.KubeOperator()
        kube_version = kube_operator.kube_get_kubernetes_version()

        config.update({
            'platform::kubernetes::params::version': kube_version,
        })

        return config

    def _get_host_join_command(self, host):
        config = {}
        if not utils.is_initial_config_complete():
            return config

        join_cmd = self._get_kubernetes_join_cmd(host)
        config.update({'platform::kubernetes::params::join_cmd': join_cmd})

        return config

    @staticmethod
    def _get_kubernetes_join_cmd(host):
        # The token expires after 24 hours and is needed for a reinstall.
        # The puppet manifest handles the case where the node already exists.
        try:
            join_cmd_additions = ''
            if host.personality == constants.CONTROLLER:
                # Upload the certificates used during kubeadm join
                # The cert key will be printed in the last line of the output

                # We will create a temp file with the kubeadm config
                # We need this because the kubeadm config could have changed
                # since bootstrap. Reading the kubeadm config each time
                # it is needed ensures we are not using stale data

                fd, temp_kubeadm_config_view = tempfile.mkstemp(
                    dir='/tmp', suffix='.yaml')
                with os.fdopen(fd, 'w') as f:
                    cmd = ['kubeadm', 'config', 'view']
                    subprocess.check_call(cmd, stdout=f)

                # We will use a custom key to encrypt kubeadm certificates
                # to make sure all hosts decrypt using the same key

                key = str(keyring.get_password(CERTIFICATE_KEY_SERVICE,
                        CERTIFICATE_KEY_USER))
                with open(temp_kubeadm_config_view, "a") as f:
                    f.write("---\r\napiVersion: kubeadm.k8s.io/v1beta2\r\n"
                            "kind: InitConfiguration\r\ncertificateKey: "
                            "{}".format(key))

                cmd = ['kubeadm', 'init', 'phase', 'upload-certs',
                       '--upload-certs', '--config',
                       temp_kubeadm_config_view]

                subprocess.check_call(cmd)
                join_cmd_additions = \
                    " --control-plane --certificate-key %s" % key
                os.unlink(temp_kubeadm_config_view)

            cmd = ['kubeadm', 'token', 'create', '--print-join-command',
                   '--description', 'Bootstrap token for %s' % host.hostname]
            join_cmd = subprocess.check_output(cmd)
            join_cmd_additions += \
                " --cri-socket /var/run/containerd/containerd.sock"
            join_cmd = join_cmd.strip() + join_cmd_additions
            LOG.info('get_kubernetes_join_cmd join_cmd=%s' % join_cmd)
        except Exception:
            LOG.exception("Exception generating bootstrap token")
            raise exception.SysinvException(
                'Failed to generate bootstrap token')

        return join_cmd

    def _get_etcd_endpoint(self):
        addr = self._format_url_address(self._get_cluster_host_address())
        protocol = "http"
        url = "%s://%s:%s" % (protocol, str(addr), str(self.ETCD_SERVICE_PORT))
        return url

    def _get_pod_network_cidr(self):
        return self._get_network_config(constants.NETWORK_TYPE_CLUSTER_POD)

    def _get_pod_network_ipversion(self):
        subnet = netaddr.IPNetwork(self._get_pod_network_cidr())
        return subnet.version

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
        subnet = netaddr.IPNetwork(self._get_cluster_service_subnet())
        return str(subnet[CLUSTER_SERVICE_DNS_IP_OFFSET])

    def _get_kubernetes_upgrade_to_version(self):
        try:
            # Get the kubernetes upgrade record
            kube_upgrade_obj = self.dbapi.kube_upgrade_get_one()
        except exception.NotFound:
            # No upgrade is in progress
            return None
        else:
            return kube_upgrade_obj.to_version

    def _get_kubernetes_version(self, host):
        config = {}

        # Get the kubernetes upgrade record for this host
        kube_host_upgrade_obj = objects.kube_host_upgrade.get_by_host_id(
            self.context, host.id)
        version = kube_host_upgrade_obj.target_version
        if version is None:
            # The target version is not set if an upgrade hasn't been started,
            # so get the running kubernetes version.
            try:
                version = self._kube_operator.kube_get_kubernetes_version()
            except Exception:
                # During initial installation of the first controller,
                # kubernetes may not be running yet. In that case, none of the
                # puppet manifests being applied will need the kubernetes
                # version.
                LOG.warning("Unable to retrieve kubernetes version")

        config.update({'platform::kubernetes::params::version': version})
        return config

    def _get_host_node_config(self, host):
        node_ip = self._get_address_by_name(
            host.hostname, constants.NETWORK_TYPE_MGMT).address
        return {
            'platform::kubernetes::params::node_ip': node_ip
        }

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

        vswitch_cpus = self._get_host_cpu_list(
            host, function=constants.VSWITCH_FUNCTION, threads=True)
        vswitch_cpuset = set([c.cpu for c in vswitch_cpus])

        # determine set of isolcpus logical cpus and nodes
        isol_cpus = self._get_host_cpu_list(
            host, function=constants.ISOLATED_FUNCTION, threads=True)
        isol_cpuset = set([c.cpu for c in isol_cpus])

        # determine reserved sets of logical cpus in a string range set format
        # to pass as options to kubelet
        k8s_platform_cpuset = utils.format_range_set(platform_cpuset)
        k8s_all_reserved_cpuset = utils.format_range_set(platform_cpuset |
                                                         vswitch_cpuset |
                                                         isol_cpuset)

        # determine platform reserved memory
        k8s_reserved_mem = 0
        host_memory = self.dbapi.imemory_get_by_ihost(host.id)
        numa_memory = utils.get_numa_index_list(host_memory)
        for node, memory in numa_memory.items():
            reserved_mib = memory[0].platform_reserved_mib
            if reserved_mib is not None:
                k8s_reserved_mem += reserved_mib

        # determine set of nonplatform logical cpus
        # TODO(jgauld): Commented out for now, using host_cpuset instead.
        # nonplatform_cpuset = host_cpuset - platform_cpuset

        if constants.WORKER in utils.get_personalities(host):
            if self.is_openstack_compute(host):
                k8s_cpuset = utils.format_range_set(platform_cpuset)
                k8s_nodeset = utils.format_range_set(platform_nodeset)
            else:
                # kubelet cpumanager is configured with static policy.
                # The resulting DefaultCPUSet excludes reserved cpus
                # based on topology, and that also happens to correspond
                # to the platform_cpuset. kubepods are allowed to
                # span all host numa nodes.
                # TODO(jgauld): Temporary workaround until we have a version
                # of kubelet that excludes reserved cpus from DefaultCPUSet.
                # The intent is to base k8s_cpuset on nonplatform_cpuset.
                # Commented out for now, using host_cpuset instead.
                # k8s_cpuset = utils.format_range_set(nonplatform_cpuset)
                k8s_cpuset = utils.format_range_set(host_cpuset)
                k8s_nodeset = utils.format_range_set(host_nodeset)
        else:
            k8s_cpuset = utils.format_range_set(host_cpuset)
            k8s_nodeset = utils.format_range_set(host_nodeset)

        LOG.debug('host:%s, k8s_cpuset:%s, k8s_nodeset:%s',
                  host.hostname, k8s_cpuset, k8s_nodeset)

        # determine cpu/topology mgr policies
        labels = self.dbapi.label_get_by_host(host.uuid)
        for label in labels:
            if label.label_key == constants.KUBE_TOPOLOGY_MANAGER_LABEL:
                config.update({'platform::kubernetes::params::k8s_topology_mgr_policy': label.label_value})
            elif label.label_key == constants.KUBE_CPU_MANAGER_LABEL:
                config.update({'platform::kubernetes::params::k8s_cpu_mgr_policy': label.label_value})

        config.update(
            {'platform::kubernetes::params::k8s_cpuset':
             "\"%s\"" % k8s_cpuset,
             'platform::kubernetes::params::k8s_nodeset':
             "\"%s\"" % k8s_nodeset,
             'platform::kubernetes::params::k8s_platform_cpuset':
             k8s_platform_cpuset,
             'platform::kubernetes::params::k8s_all_reserved_cpuset':
             k8s_all_reserved_cpuset,
             'platform::kubernetes::params::k8s_reserved_mem':
             k8s_reserved_mem,
             })

        return config

    def _get_host_pcidp_config(self, host):
        config = {}
        if constants.WORKER not in utils.get_personalities(host):
            return config

        labels = self.dbapi.label_get_by_host(host.uuid)
        sriovdp_worker = False
        for l in labels:
            if (constants.SRIOVDP_LABEL ==
                    str(l.label_key) + '=' + str(l.label_value)):
                sriovdp_worker = True
                break

        if (sriovdp_worker is True):
            config.update({
                'platform::kubernetes::worker::pci::pcidp_network_resources':
                    self._get_pcidp_network_resources(),
            })
        return config

    def _get_network_interfaces_by_class(self, ifclass):
        # Construct a list of all configured interfaces of a particular class
        interfaces = []
        for iface in self.context['interfaces'].values():
            if iface['ifclass'] == ifclass:
                interfaces.append(iface)
        return interfaces

    def _get_pcidp_vendor_id(self, port):
        vendor = None
        # The vendor id can be found by inspecting the '[xxxx]' at the
        # end of the port's pvendor field
        vendor = re.search(r'\[([0-9a-fA-F]{1,4})\]$', port['pvendor'])
        if vendor:
            vendor = vendor.group(1)
        return vendor

    def _get_pcidp_device_id(self, port, ifclass):
        device = None
        if ifclass == constants.INTERFACE_CLASS_PCI_SRIOV:
            device = port['sriov_vf_pdevice_id']
        else:
            # The device id can be found by inspecting the '[xxxx]' at the
            # end of the port's pdevice field
            device = re.search(r'\[([0-9a-fA-F]{1,4})\]$', port['pdevice'])
            if device:
                device = device.group(1)
        return device

    def _get_pcidp_driver(self, port, iface, ifclass):
        if ifclass == constants.INTERFACE_CLASS_PCI_SRIOV:
            sriov_vf_driver = iface.get('sriov_vf_driver', None)
            if (sriov_vf_driver and
                    constants.SRIOV_DRIVER_TYPE_VFIO in sriov_vf_driver):
                driver = constants.SRIOV_DRIVER_VFIO_PCI
            else:
                driver = port['sriov_vf_driver']
        else:
            driver = port['driver']
        return driver

    def _get_pcidp_network_resources_by_ifclass(self, ifclass):
        resources = {}

        interfaces = self._get_network_interfaces_by_class(ifclass)
        for iface in interfaces:

            if ifclass == constants.INTERFACE_CLASS_PCI_SRIOV:
                port = interface.get_sriov_interface_port(self.context, iface)
            else:
                port = interface.get_interface_port(self.context, iface)
            if not port:
                continue

            datanets = interface.get_interface_datanets(self.context, iface)
            for datanet in datanets:
                dn_name = datanet['name'].strip()
                resource = resources.get(dn_name, None)
                if not resource:
                    resource = {
                        "resourceName": "{}_net_{}".format(
                            ifclass, dn_name).replace("-", "_"),
                        "selectors": {
                            "vendors": [],
                            "devices": [],
                            "drivers": [],
                            "pfNames": []
                        }
                    }

                vendor = self._get_pcidp_vendor_id(port)
                if not vendor:
                    LOG.error("Failed to get vendor id for pci device %s", port['pciaddr'])
                    continue

                device = self._get_pcidp_device_id(port, ifclass)
                if not device:
                    LOG.error("Failed to get device id for pci device %s", port['pciaddr'])
                    continue

                driver = self._get_pcidp_driver(port, iface, ifclass)
                if not device:
                    LOG.error("Failed to get driver for pci device %s", port['pciaddr'])
                    continue

                vendor_list = resource['selectors']['vendors']
                if vendor not in vendor_list:
                    vendor_list.append(vendor)

                device_list = resource['selectors']['devices']
                if device not in device_list:
                    device_list.append(device)

                driver_list = resource['selectors']['drivers']
                if driver not in driver_list:
                    driver_list.append(driver)

                pf_name_list = resource['selectors']['pfNames']
                if port['name'] not in pf_name_list:
                    pf_name_list.append(port['name'])

                if interface.is_a_mellanox_device(self.context, iface):
                    resource['isRdma'] = True

                resources[dn_name] = resource

        return list(resources.values())

    def _get_pcidp_network_resources(self):
        # Construct a list of all PCI passthrough and SRIOV resources
        # for use with the SRIOV device plugin
        sriov_resources = self._get_pcidp_network_resources_by_ifclass(
            constants.INTERFACE_CLASS_PCI_SRIOV)
        pcipt_resources = self._get_pcidp_network_resources_by_ifclass(
            constants.INTERFACE_CLASS_PCI_PASSTHROUGH)
        return json.dumps({'resourceList': sriov_resources + pcipt_resources})
