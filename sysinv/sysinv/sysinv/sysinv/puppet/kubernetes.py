#
# Copyright (c) 2018-2022 Wind River Systems, Inc.
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
from sysinv.common import device as dconstants
from sysinv.common.retrying import retry
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

# kubeadm configuration option
KUBECONFIG = "--kubeconfig=%s" % kubernetes.KUBERNETES_ADMIN_CONF

# kubernetes root CA certificate params
KUBE_ROOTCA_CERT_NS = 'deployment'
KUBE_ROOTCA_CERT_SECRET = 'system-kube-rootca-certificate'

# retry for urllib3 max retry error
API_RETRY_ATTEMPT_NUMBER = 20
API_RETRY_INTERVAL = 10 * 1000


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

        # Get kubernetes certificates config for this host
        config.update(self._get_host_k8s_certificates_config(host))

        # Get the kubernetes version for this host
        config.update(self._get_kubeadm_kubelet_version(host))

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

    def get_secure_system_config(self):
        """Update the hiera configuration secure data"""

        config = {}

        cert, key = self._get_kubernetes_rootca_cert_key()
        config.update({
            'platform::kubernetes::params::rootca_cert': cert,
            'platform::kubernetes::params::rootca_key': key,
        })

        secret_list = [constants.KUBE_ADMIN_CERT]
        cert_data = self._get_kubernetes_components_cert_and_key(secret_list)
        config.update({
            'platform::kubernetes::params::admin_cert': cert_data[constants.KUBE_ADMIN_CERT][0],
            'platform::kubernetes::params::admin_key': cert_data[constants.KUBE_ADMIN_CERT][1],
        })

        return config

    @staticmethod
    def _get_kubernetes_rootca_cert_key():
        """"Get kubernetes root CA certficate secret from cert-manager"""

        try:
            kube_operator = kubernetes.KubeOperator()
            secret = kube_operator.kube_get_secret(KUBE_ROOTCA_CERT_SECRET,
                                                    KUBE_ROOTCA_CERT_NS)

            # The root CA cert/key are not stored in kubernetes yet
            if not secret:
                return 'undef', 'undef'
            if hasattr(secret, 'data') and secret.data:
                cert = secret.data.get('tls.crt', None)
                key = secret.data.get('tls.key', None)
                if cert and key:
                    return cert, key
            raise Exception('Failed to get secret %s\\%s' % (
                            KUBE_ROOTCA_CERT_NS, KUBE_ROOTCA_CERT_SECRET))
        except exception.KubeNotConfigured:
            # During ansible bootstrap, kubernetes is not configured.
            # Set the cert and key to 'undef'
            return 'undef', 'undef'

    @staticmethod
    def _get_kubernetes_components_cert_and_key(secret_names):
        """"Get kubernetes components certficates from secrets issued by
            cert-manager Certificate resource.
        """
        certificate_dict = {}
        kube_operator = kubernetes.KubeOperator()
        for secret_name in secret_names:
            try:
                secret = kube_operator.kube_get_secret(secret_name,
                                                KUBE_ROOTCA_CERT_NS)
                # The respective cert/key are not stored in kubernetes yet
                if not secret:
                    certificate_dict[secret_name] = 'undef', 'undef'
                if hasattr(secret, 'data') and secret.data:
                    cert = secret.data.get('tls.crt', None)
                    key = secret.data.get('tls.key', None)
                    if cert and key:
                        certificate_dict[secret_name] = cert, key
            except exception.KubeNotConfigured:
                # During ansible bootstrap, kubernetes is not configured.
                # Set the cert and key to 'undef'
                certificate_dict[secret_name] = 'undef', 'undef'
        return certificate_dict

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

    def _retry_on_token(ex):  # pylint: disable=no-self-argument
        LOG.warn('Retrying in _get_kubernetes_join_cmd')
        return True

    @retry(stop_max_attempt_number=API_RETRY_ATTEMPT_NUMBER,
           wait_fixed=API_RETRY_INTERVAL,
           retry_on_exception=_retry_on_token)
    def _get_kubernetes_join_cmd(self, host):
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
                    cmd = ['kubectl', 'get', 'cm', '-n', 'kube-system',
                           'kubeadm-config', '-o=jsonpath={.data.ClusterConfiguration}',
                           KUBECONFIG]
                    subprocess.check_call(cmd, stdout=f)  # pylint: disable=not-callable

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

                subprocess.check_call(cmd)  # pylint: disable=not-callable
                join_cmd_additions = \
                    " --control-plane --certificate-key %s" % key
                os.unlink(temp_kubeadm_config_view)

                # Configure the IP address of the API Server for the controller host.
                # If not set the default network interface will be used, which does not
                # ensure it will be the Cluster IP address of this host.
                host_cluster_ip = self._get_host_cluster_address(host)
                join_cmd_additions += \
                    " --apiserver-advertise-address %s" % host_cluster_ip

            cmd = ['kubeadm', KUBECONFIG, 'token', 'create', '--print-join-command',
                   '--description', 'Bootstrap token for %s' % host.hostname]
            join_cmd = subprocess.check_output(cmd, universal_newlines=True)  # pylint: disable=not-callable
            join_cmd_additions += \
                " --cri-socket /var/run/containerd/containerd.sock"
            join_cmd = join_cmd.strip() + join_cmd_additions
            LOG.info('get_kubernetes_join_cmd join_cmd=%s' % join_cmd)
        except Exception:
            LOG.warning("Exception generating bootstrap token")
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

    def _get_kubeadm_kubelet_version(self, host):
        config = {}
        kubeadm_version = None
        kubelet_version = None
        kube_upgrade_state = None

        # Grab the upgrade state if any.
        try:
            kube_upgrade_obj = objects.kube_upgrade.get_one(
                self.context)
            kube_upgrade_state = kube_upgrade_obj.state
        except exception.NotFound:
            pass

        try:
            kube_version = self.dbapi.kube_cmd_version_get()

            # kubeadm version is system-wide
            kubeadm_version = kube_version.kubeadm_version
            # default kubelet version is system-wide
            kubelet_version = kube_version.kubelet_version

            # If there's a k8s upgrade in progress the kubelet version
            # is determined by the upgrade state of the host.
            if kube_upgrade_state:
                kube_host_upgrade = objects.kube_host_upgrade.get_by_host_id(
                    self.context, host.id)
                if kube_host_upgrade.status in [
                        kubernetes.KUBE_HOST_UPGRADING_KUBELET,
                        kubernetes.KUBE_HOST_UPGRADED_KUBELET]:
                    kubelet_version = kube_host_upgrade.target_version.lstrip('v')

            config.update({'platform::kubernetes::params::kubeadm_version': kubeadm_version})
            config.update({'platform::kubernetes::params::kubelet_version': kubelet_version})
        except Exception:
            LOG.exception("Exception getting kubeadm kubelet version")
            raise exception.KubeVersionUnavailable()

        return config

    def _get_host_cluster_address(self, host):
        """Retrieve the named host address for the cluster host network"""
        address = self._get_address_by_name(
            host.hostname, constants.NETWORK_TYPE_CLUSTER_HOST)
        return address.address

    def _get_host_node_config(self, host):
        node_ip = self._get_address_by_name(
            host.hostname, constants.NETWORK_TYPE_CLUSTER_HOST).address
        return {
            'platform::kubernetes::params::node_ip': node_ip
        }

    def _get_host_label_config(self, host):
        config = {}
        labels = self.dbapi.label_get_by_host(host.uuid)
        host_label_keys = []
        for label in labels:
            host_label_keys.append(label.label_key + "=" + label.label_value)
        config.update(
            {'platform::kubernetes::params::host_labels': host_label_keys})
        return config

    def _get_host_k8s_certificates_config(self, host):
        config = {}
        # kubernetes components certificate secrets

        kube_apiserver_cert_secret = constants.KUBE_APISERVER_CERT.format(host.hostname)
        kube_apiserver_kubelet_client_cert_secret = constants.KUBE_APISERVER_KUBELET_CERT.format(host.hostname)
        kube_scheduler_cert_secret = constants.KUBE_SCHEDULER_CERT.format(host.hostname)
        kube_controller_manager_cert_secret = constants.KUBE_CONTROLLER_MANAGER_CERT.format(host.hostname)
        kube_kubelet_cert_secret = constants.KUBE_KUBELET_CERT.format(host.hostname)

        secret_list = [kube_apiserver_cert_secret, kube_apiserver_kubelet_client_cert_secret,
                        kube_scheduler_cert_secret, kube_controller_manager_cert_secret,
                        kube_kubelet_cert_secret]

        cert_data = self._get_kubernetes_components_cert_and_key(secret_list)
        config.update({
            'platform::kubernetes::params::apiserver_cert': cert_data[kube_apiserver_cert_secret][0],
            'platform::kubernetes::params::apiserver_key': cert_data[kube_apiserver_cert_secret][1],
            'platform::kubernetes::params::apiserver_kubelet_cert':
                cert_data[kube_apiserver_kubelet_client_cert_secret][0],
            'platform::kubernetes::params::apiserver_kubelet_key':
                cert_data[kube_apiserver_kubelet_client_cert_secret][1],
            'platform::kubernetes::params::scheduler_cert': cert_data[kube_scheduler_cert_secret][0],
            'platform::kubernetes::params::scheduler_key': cert_data[kube_scheduler_cert_secret][1],
            'platform::kubernetes::params::controller_manager_cert': cert_data[kube_controller_manager_cert_secret][0],
            'platform::kubernetes::params::controller_manager_key': cert_data[kube_controller_manager_cert_secret][1],
            'platform::kubernetes::params::kubelet_cert': cert_data[kube_kubelet_cert_secret][0],
            'platform::kubernetes::params::kubelet_key': cert_data[kube_kubelet_cert_secret][1],
        })

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

        # determine whether to reserve isolated CPUs
        reserve_isolcpus = True
        labels = self.dbapi.label_get_by_host(host.uuid)
        for l in labels:
            if (constants.KUBE_IGNORE_ISOL_CPU_LABEL ==
                    str(l.label_key) + '=' + str(l.label_value)):
                reserve_isolcpus = False
                break
        if reserve_isolcpus:
            k8s_all_reserved_cpuset = utils.format_range_set(platform_cpuset |
                                                             vswitch_cpuset |
                                                             isol_cpuset)
        else:
            k8s_all_reserved_cpuset = utils.format_range_set(platform_cpuset |
                                                             vswitch_cpuset)

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
             "\"%s\"" % k8s_platform_cpuset,
             'platform::kubernetes::params::k8s_all_reserved_cpuset':
             "\"%s\"" % k8s_all_reserved_cpuset,
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
                'platform::kubernetes::worker::pci::pcidp_resources':
                    self._get_pcidp_resources(host),
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

    def _get_pcidp_fec_driver(self, device):
        sriov_vf_driver = device.get('sriov_vf_driver', None)
        if (sriov_vf_driver and
                constants.SRIOV_DRIVER_TYPE_VFIO in sriov_vf_driver):
            driver = constants.SRIOV_DRIVER_VFIO_PCI
        else:
            driver = device['sriov_vf_driver']
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
                if not driver:
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
                if ifclass == constants.INTERFACE_CLASS_PCI_SRIOV:
                    # In sriov case, we need specify each VF for resource pool
                    # Get VF addresses assigned to this logical VF interface
                    vf_addr_list = []
                    all_vf_addr_list = []
                    vf_addrs = port.get('sriov_vfs_pci_address', None)
                    if vf_addrs:
                        all_vf_addr_list = vf_addrs.split(',')
                        vf_addr_list = interface.get_sriov_interface_vf_addrs(
                            self.context, iface, all_vf_addr_list)

                    vfnolst = [utils.get_sriov_vf_index(addr, all_vf_addr_list)
                                   for addr in vf_addr_list]
                    vfnolst = [str(vfno) for vfno in vfnolst]
                    vfnolist_str = ",".join(vfnolst)
                    if vfnolist_str:
                        # concat into the form of 'ens785f0#0,2,7,9'
                        pfname_with_vfs = "%s#%s" % (port['name'], vfnolist_str)
                        pf_name_list.append(pfname_with_vfs)
                    else:
                        # error case, cannot find the vf numbers in sriov case
                        LOG.error("Failed to get vf numbers for pci device %s", port['name'])
                        continue
                else:
                    if port['name'] not in pf_name_list:
                        pf_name_list.append(port['name'])

                if interface.is_a_mellanox_device(self.context, iface):
                    resource['selectors']['isRdma'] = True

                resources[dn_name] = resource

        return list(resources.values())

    def _get_pcidp_fec_resources(self, host):
        resources = {}

        for ddevid in dconstants.ACCLR_FEC_RESOURCES:

            fec_name = dconstants.ACCLR_FEC_RESOURCES[ddevid]['fec_name']

            for d in self.dbapi.pci_device_get_by_host(host.id):
                if d['pdevice_id'] != ddevid:
                    continue

                resource = resources.get(fec_name, None)
                if not resource:
                    resource = {
                        "resourceName": fec_name,
                        "deviceType": "accelerator",
                        "selectors": {
                            "vendors": [],
                            "devices": [],
                            "drivers": []
                        }
                    }

                vendor = d.get('pvendor_id', None)
                if not vendor:
                    LOG.error("Failed to get vendor id for pci device %s",
                              d['pciaddr'])
                    continue

                device = d.get('sriov_vf_pdevice_id', None)
                if not device:
                    LOG.error("Failed to get device id for pci device %s",
                              d['pciaddr'])
                    continue

                driver = self._get_pcidp_fec_driver(d)
                if not driver:
                    LOG.error("Failed to get driver for pci device %s",
                              d['pciaddr'])
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

                resources[fec_name] = resource

        return list(resources.values())

    def _get_pcidp_resources(self, host):
        # Construct a list of all PCI passthrough and SRIOV resources
        # for use with the SRIOV device plugin
        sriov_resources = self._get_pcidp_network_resources_by_ifclass(
            constants.INTERFACE_CLASS_PCI_SRIOV)
        pcipt_resources = self._get_pcidp_network_resources_by_ifclass(
            constants.INTERFACE_CLASS_PCI_PASSTHROUGH)
        fec_resources = self._get_pcidp_fec_resources(host)
        return json.dumps({'resourceList': sriov_resources + pcipt_resources + fec_resources})
