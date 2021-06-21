# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import keyring
import os

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils

from tsconfig import tsconfig

from sysinv.puppet import base

HOSTNAME_CLUSTER_HOST_SUFFIX = '-cluster-host'


class PlatformPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for platform configuration"""

    def get_static_config(self):
        config = {}
        config.update(self._get_static_software_config())
        return config

    def get_secure_static_config(self):
        config = {}
        config.update(self._get_secure_amqp_config())
        return config

    def get_system_config(self):
        config = {}
        config.update(self._get_system_config())
        config.update(self._get_amqp_config())
        config.update(self._get_resolv_config())
        config.update(self._get_haproxy_config())
        config.update(self._get_sdn_config())
        config.update(self._get_region_config())
        config.update(self._get_distributed_cloud_role())
        config.update(self._get_sm_config())
        config.update(self._get_drbd_sync_config())
        config.update(self._get_remotelogging_config())
        config.update(self._get_certificate_config())
        config.update(self._get_systemcontroller_config())
        return config

    def get_secure_system_config(self):
        config = {}
        config.update(self._get_user_config())
        config.update(self._get_dc_root_ca_config())
        return config

    def get_host_config(self, host):
        config = {}
        config.update(self._get_hosts_config(host))
        config.update(self._get_nfs_config(host))
        config.update(self._get_host_platform_config(host, self.config_uuid))
        config.update(self._get_host_ntp_config(host))
        config.update(self._get_host_ptp_config(host))
        config.update(self._get_host_sysctl_config(host))
        config.update(self._get_host_drbd_config(host))
        config.update(self._get_host_tpm_config(host))
        config.update(self._get_host_cpu_config(host))
        config.update(self._get_host_memory_config(host))
        config.update(self._get_kvm_timer_advance_config(host))
        config.update(self._get_host_lldp_config(host))
        return config

    def get_host_config_upgrade(self, host):
        config = {}
        config.update(self._get_host_platform_config_upgrade(host, self.config_uuid))
        return config

    def _get_static_software_config(self):
        return {
            'platform::params::software_version': self.quoted_str(tsconfig.SW_VERSION),
        }

    def _get_secure_amqp_config(self):
        password = self._generate_random_password()
        keyring.set_password('amqp', 'rabbit', password)
        return {
            'platform::amqp::params::auth_password': password,
        }

    def _get_system_config(self):
        system = self._get_system()
        application_applied = utils.is_openstack_applied(self.dbapi)

        return {
            'platform::params::controller_upgrade': False,
            'platform::params::config_path': tsconfig.CONFIG_PATH,
            'platform::params::security_profile': system.security_profile,
            'platform::params::security_feature': system.security_feature,
            'platform::config::params::timezone': system.timezone,
            'platform::params::vswitch_type': self._vswitch_type(),
            'platform::params::stx_openstack_applied': application_applied,
        }

    def _get_hosts_config(self, host):
        # list of host tuples (host name, address name, newtork type) that need
        # to be populated in the /etc/hosts file
        hostnames = [
            # management network hosts
            (constants.CONTROLLER_HOSTNAME,
             constants.CONTROLLER_HOSTNAME,
             constants.NETWORK_TYPE_MGMT),

            (constants.CONTROLLER_0_HOSTNAME,
             constants.CONTROLLER_0_HOSTNAME,
             constants.NETWORK_TYPE_MGMT),

            (constants.CONTROLLER_1_HOSTNAME,
             constants.CONTROLLER_1_HOSTNAME,
             constants.NETWORK_TYPE_MGMT),

            (constants.CONTROLLER_PLATFORM_NFS,
             constants.CONTROLLER_PLATFORM_NFS,
             constants.NETWORK_TYPE_MGMT),

            # pxeboot network hosts
            (constants.PXECONTROLLER_HOSTNAME,
             constants.CONTROLLER_HOSTNAME,
             constants.NETWORK_TYPE_PXEBOOT),

            # oam network hosts
            (constants.OAMCONTROLLER_HOSTNAME,
             constants.CONTROLLER_HOSTNAME,
             constants.NETWORK_TYPE_OAM),

            # cinder storage hosts
            (constants.CONTROLLER_CINDER,
             constants.CONTROLLER_CINDER,
             constants.NETWORK_TYPE_MGMT),

            # ceph storage hosts
            (constants.STORAGE_0_HOSTNAME,
             constants.STORAGE_0_HOSTNAME,
             constants.NETWORK_TYPE_MGMT),

            (constants.STORAGE_1_HOSTNAME,
             constants.STORAGE_1_HOSTNAME,
             constants.NETWORK_TYPE_MGMT),

            # cluster network hosts
            (constants.CONTROLLER_0_HOSTNAME + HOSTNAME_CLUSTER_HOST_SUFFIX,
             constants.CONTROLLER_0_HOSTNAME,
             constants.NETWORK_TYPE_CLUSTER_HOST),

            (constants.CONTROLLER_1_HOSTNAME + HOSTNAME_CLUSTER_HOST_SUFFIX,
             constants.CONTROLLER_1_HOSTNAME,
             constants.NETWORK_TYPE_CLUSTER_HOST),

            (constants.STORAGE_0_HOSTNAME + HOSTNAME_CLUSTER_HOST_SUFFIX,
             constants.STORAGE_0_HOSTNAME,
             constants.NETWORK_TYPE_CLUSTER_HOST),

            (constants.STORAGE_1_HOSTNAME + HOSTNAME_CLUSTER_HOST_SUFFIX,
             constants.STORAGE_1_HOSTNAME,
             constants.NETWORK_TYPE_CLUSTER_HOST),

            (host.hostname + HOSTNAME_CLUSTER_HOST_SUFFIX,
             host.hostname,
             constants.NETWORK_TYPE_CLUSTER_HOST),
        ]

        hosts = {}
        for hostname, name, networktype in hostnames:
            try:
                address = self._get_address_by_name(name, networktype)
                hosts.update({hostname: {'ip': address.address}})
            except exception.AddressNotFoundByName:
                pass
        return {
            'platform::config::params::hosts': hosts
        }

    def _get_amqp_config(self):
        return {
            'platform::amqp::params::host':
                self._get_management_address(),
            'platform::amqp::params::host_url':
                self._format_url_address(self._get_management_address()),
        }

    def _get_resolv_config(self):
        servers = [self._get_management_address()]

        dns = self.dbapi.idns_get_one()
        if dns.nameservers:
            servers += dns.nameservers.split(',')

        return {
            'platform::dns::resolv::servers': servers
        }

    def _get_user_config(self):
        user = self.dbapi.iuser_get_one()
        return {
            'platform::users::params::sysadmin_password':
                user.passwd_hash,
            'platform::users::params::sysadmin_password_max_age':
                user.passwd_expiry_days,
        }

    def _get_haproxy_config(self):
        public_address = self._get_address_by_name(
            constants.CONTROLLER, constants.NETWORK_TYPE_OAM)
        private_address = self._get_address_by_name(
            constants.CONTROLLER, constants.NETWORK_TYPE_MGMT)
        public_address_url = self._format_url_address(public_address.address)
        https_enabled = self._https_enabled()

        config = {
            'platform::haproxy::params::public_ip_address':
                public_address.address,
            'platform::haproxy::params::public_address_url':
                public_address_url,
            'platform::haproxy::params::private_ip_address':
                private_address.address,
            'platform::haproxy::params::enable_https':
                https_enabled,
        }

        try:
            tpmconfig = self.dbapi.tpmconfig_get_one()
            if tpmconfig.tpm_path:
                config.update({
                    'platform::haproxy::params::tpm_object': tpmconfig.tpm_path
                })
        except exception.NotFound:
            pass

        return config

    def _get_sdn_config(self):
        return {
            'platform::params::sdn_enabled': self._sdn_enabled()
        }

    def _get_region_config(self):
        if not self._region_config():
            return {}

        region_1_name = self._operator.keystone.get_region_name()
        region_2_name = self._region_name()
        return {
            'platform::params::region_config': self._region_config(),
            'platform::params::region_1_name': region_1_name,
            'platform::params::region_2_name': region_2_name,
        }

    def _get_distributed_cloud_role(self):
        if self._distributed_cloud_role() is None:
            return {}

        return {
            'platform::params::distributed_cloud_role': self._distributed_cloud_role(),
        }

    def _get_sm_config(self):
        multicast_address = self._get_address_by_name(
            constants.SM_MULTICAST_MGMT_IP_NAME,
            constants.NETWORK_TYPE_MULTICAST)
        return {
            'platform::sm::params::mgmt_ip_multicast':
                multicast_address.address,
            'platform::sm::params::cluster_host_ip_multicast':
                multicast_address.address,
        }

    def _get_host_platform_config(self, host, config_uuid):
        if not config_uuid:
            config_uuid = host.config_target

        # required parameters
        config = {
            'platform::params::hostname': host.hostname,
            'platform::params::software_version': self.quoted_str(host.software_load),
        }

        # optional parameters
        if config_uuid:
            config.update({
                'platform::config::params::config_uuid': config_uuid
            })

        if host.personality == constants.CONTROLLER:

            controller0_address = self._get_address_by_name(
                constants.CONTROLLER_0_HOSTNAME, constants.NETWORK_TYPE_MGMT)

            controller1_address = self._get_address_by_name(
                constants.CONTROLLER_1_HOSTNAME, constants.NETWORK_TYPE_MGMT)

            if host.hostname == constants.CONTROLLER_0_HOSTNAME:
                mate_hostname = constants.CONTROLLER_1_HOSTNAME
                mate_address = controller1_address
            else:
                mate_hostname = constants.CONTROLLER_0_HOSTNAME
                mate_address = controller0_address

            config.update({
                'platform::params::controller_0_ipaddress':
                    controller0_address.address,
                'platform::params::controller_1_ipaddress':
                    controller1_address.address,
                'platform::params::controller_0_hostname':
                    constants.CONTROLLER_0_HOSTNAME,
                'platform::params::controller_1_hostname':
                    constants.CONTROLLER_1_HOSTNAME,
                'platform::params::mate_hostname': mate_hostname,
                'platform::params::mate_ipaddress': mate_address.address,
            })

        system = self._get_system()
        config.update({
            'platform::params::system_name':
                system.name,
            'platform::params::system_mode':
                system.system_mode,
            'platform::params::system_type':
                system.system_type,
        })

        virtual_system = utils.is_virtual_system_config(self.dbapi)
        config.update({
            'platform::params::virtual_system':
                virtual_system
        })

        cpu_count = self._get_platform_cpu_count(host)
        config.update({
            'platform::params::platform_cpu_count':
                cpu_count,
        })

        return config

    def _get_host_platform_config_upgrade(self, host, config_uuid):
        config = {}
        if not config_uuid:
            config_uuid = host.config_target

        if config_uuid:
            config.update({
                'platform::config::params::config_uuid': config_uuid
            })
        return config

    def _get_host_ntp_config(self, host):
        ntp = self.dbapi.intp_get_one()
        if host.personality == constants.CONTROLLER:
            servers = ntp.ntpservers.split(',') if ntp.ntpservers else []
        else:
            controller0_address = self._get_address_by_name(
                constants.CONTROLLER_0_HOSTNAME, constants.NETWORK_TYPE_MGMT)

            controller1_address = self._get_address_by_name(
                constants.CONTROLLER_1_HOSTNAME, constants.NETWORK_TYPE_MGMT)

            # All other hosts use the controller management IP addresses
            servers = [controller0_address.address,
                       controller1_address.address]

        # Logic behind setting the ntpdate_timeout:
        # If no servers are datafilled, the only one in
        # the list is the other controller.  When the first
        # controller is brought up, the other one doesn't
        # exist to respond, so we will always wait and timeout.
        # When the second controller is brought up, it will
        # always go to the active controller which should be
        # there and respond quickly.  So the compromise between
        # these two controller situations is a 30 second timeout.
        #
        # The 180 second timeout is used to cover for a 3 server +
        # peer controller situation where 2 DNS servers are
        # provided and neither DNS server responds to queries. The
        # longer timeout here will allow access to all 3 servers to
        # timeout and yet still have enough time to talk to and get
        # a useable response out of the peer controller.
        #
        # Also keep in mind that ntpdate's role is to bring
        # errant system clocks that are more than 1000 seconds from
        # reality back into line.  If the system clock is under 1000
        # seconds out, the ntpd will bring it back in line anyway,
        # and 11 minute mode will keep it accurate.  It also helps
        # minimize system clock stepping by ntpd, the likes of which
        # may occur 15-20 minutes after reboot when ntpd finally
        # decides what to do after analyzing all servers available
        # to it.  This clock stepping can be disruptive to the
        # system and thus we have ntpdate in place to minimize that.
        if servers:
            ntpdate_timeout = "180"
        else:
            ntpdate_timeout = "30"

        if host.clock_synchronization == constants.NTP:
            ntp_enabled = True
        else:
            ntp_enabled = False

        return {
            'platform::ntp::enabled': ntp_enabled,
            'platform::ntp::servers': servers,
            'platform::ntp::ntpdate_timeout': ntpdate_timeout,
        }

    def _get_host_ptp_config(self, host):
        ptp = self.dbapi.ptp_get_one()

        if host.clock_synchronization == constants.PTP:
            ptp_enabled = True
        else:
            ptp_enabled = False
            return {'platform::ptp::enabled': ptp_enabled}

        ptp_config = {
            'tx_timestamp_timeout': '20',
            'summary_interval': '6',
            'clock_servo': 'linreg',
            'delay_mechanism': ptp.mechanism.upper(),
            'time_stamping': ptp.mode.lower()
        }

        if ptp.mode.lower() == 'hardware':
            ptp_config.update({'boundary_clock_jbod': '1'})

        ptp_service_params = self.dbapi.service_parameter_get_all(
            service=constants.SERVICE_TYPE_PTP, section=constants.SERVICE_PARAM_SECTION_PTP_GLOBAL)

        # Merge options specified in service parameters with ptp database values and defaults
        for param in ptp_service_params:
            ptp_config.update({param.name: param.value})

        transport = constants.PTP_TRANSPORT_L2

        specified_transport = ptp_config.get('network_transport')
        if specified_transport:
            # Currently we can only set the network transport globally. Setting the transport flag
            # to udp will force puppet to apply the correct UDP family to each interface
            if specified_transport != constants.PTP_NETWORK_TRANSPORT_IEEE_802_3:
                transport = constants.PTP_TRANSPORT_UDP
        else:
            ptp_config.update({'network_transport': constants.PTP_NETWORK_TRANSPORT_IEEE_802_3})
            transport = ptp.transport

        # Generate ptp4l global options
        ptp4l_options = []
        for key, value in ptp_config.items():
            ptp4l_options.append({'name': key, 'value': value})

        # Get the options for the phc2sys system
        phc2sys_config = constants.PTP_PHC2SYS_DEFAULTS
        phc2sys_service_params = self.dbapi.service_parameter_get_all(
            service=constants.SERVICE_TYPE_PTP,
            section=constants.SERVICE_PARAM_SECTION_PTP_PHC2SYS)

        for param in phc2sys_service_params:
            phc2sys_config.update({param.name: param.value})

        phc2sys_options = ''
        for key, value in phc2sys_config.items():
            phc2sys_options += '-' + constants.PTP_PHC2SYS_OPTIONS_MAP[key] + ' ' + str(value) + ' '

        return {
            'platform::ptp::enabled': ptp_enabled,
            'platform::ptp::transport': transport,
            'platform::ptp::ptp4l_options': ptp4l_options,
            'platform::ptp::phc2sys_options': phc2sys_options
        }

    def _get_host_sysctl_config(self, host):
        config = {}

        if constants.LOWLATENCY in host.subfunctions:
            config.update({
                'platform::sysctl::params::low_latency': True
            })

        return config

    def _get_drbd_sync_config(self):
        drbdconfig = self.dbapi.drbdconfig_get_one()
        return {
            'platform::drbd::params::link_util': str(drbdconfig.link_util),
            'platform::drbd::params::num_parallel': str(drbdconfig.num_parallel),
            'platform::drbd::params::rtt_ms': str(drbdconfig.rtt_ms),
        }

    def _get_host_drbd_config(self, host):
        config = {}
        system = self._get_system()
        if system.system_type == constants.TIS_AIO_BUILD:
            # restrict DRBD syncing to platform cores/threads
            platform_cpus = self._get_host_cpu_list(
                host, function=constants.PLATFORM_FUNCTION, threads=True)

            # build a hex bitmap of the platform cores
            platform_cpumask = 0
            for cpu in platform_cpus:
                platform_cpumask |= 1 << cpu.cpu

            drbd_cpumask = '%x' % platform_cpumask

            config.update({
                'platform::drbd::params::cpumask': drbd_cpumask
            })
        return config

    def _get_host_tpm_config(self, host):
        config = {}
        if host.personality == constants.CONTROLLER:
            try:
                tpmdevice = self.dbapi.tpmdevice_get_by_host(host.id)
                if tpmdevice and len(tpmdevice) == 1:
                    tpm_data = tpmdevice[0].tpm_data
                    # some of the TPM certs may be base64 encoded
                    # for transmission over RPC and storage in DB,
                    # convert these back to their native encoding
                    encoded_files = tpm_data.pop("base64_encoded_files", [])
                    for binary in encoded_files:
                        tpm_data[binary] = tpm_data[binary].decode('base64')
                    config.update({
                        'platform::tpm::tpm_data': tpm_data
                    })
            except exception.NotFound:
                # No TPM device found
                pass
        return config

    def _get_host_cpu_config(self, host):
        config = {}
        if constants.WORKER in utils.get_personalities(host):
            host_cpus = self._get_host_cpu_list(host, threads=True)
            if not host_cpus:
                return config

            platform_cpus_no_threads = self._get_platform_cpu_list(host)
            vswitch_cpus_no_threads = self._get_vswitch_cpu_list(host)

            platform_numa_cpus = utils.get_numa_index_list(platform_cpus_no_threads)
            vswitch_numa_cpus = utils.get_numa_index_list(vswitch_cpus_no_threads)

            # build a list of platform reserved cpus per numa node
            platform_cores = []
            for node, cpus in platform_numa_cpus.items():
                cpu_list = ','.join([str(c.cpu) for c in cpus])
                platform_node = "\"node%d:%s\"" % (node, cpu_list)
                platform_cores.append(platform_node)

            # build a list of vswitch reserved cpu counts per numa node
            vswitch_cores = []
            for node, cpus in vswitch_numa_cpus.items():
                cpu_count = len(cpus)
                vswitch_node = "\"node%d:%d\"" % (node, cpu_count)
                vswitch_cores.append(vswitch_node)

            reserved_platform_cores = "(%s)" % ' '.join(platform_cores)
            reserved_vswitch_cores = "(%s)" % ' '.join(vswitch_cores)

            # all logical cpus
            host_cpus = self._get_host_cpu_list(host, threads=True)
            host_cpuset = set([c.cpu for c in host_cpus])
            host_ranges = utils.format_range_set(host_cpuset)
            n_cpus = len(host_cpuset)

            # platform logical cpus
            platform_cpus = self._get_host_cpu_list(
                host, function=constants.PLATFORM_FUNCTION, threads=True)
            platform_cpuset = set([c.cpu for c in platform_cpus])
            platform_ranges = utils.format_range_set(platform_cpuset)

            # vswitch logical cpus
            vswitch_cpus = self._get_host_cpu_list(
                host, constants.VSWITCH_FUNCTION, threads=True)
            vswitch_cpuset = set([c.cpu for c in vswitch_cpus])

            # non-platform logical cpus
            rcu_nocbs_cpuset = host_cpuset - platform_cpuset
            rcu_nocbs_ranges = utils.format_range_set(rcu_nocbs_cpuset)

            # isolated logical cpus
            app_isolated_cpus = self._get_host_cpu_list(
                host, constants.ISOLATED_FUNCTION, threads=True)
            app_isolated_cpuset = set([c.cpu for c in app_isolated_cpus])

            cpu_options = ""
            cpu_ranges = {}
            if constants.LOWLATENCY in host.subfunctions:
                # set PM QoS latency that achieves C1 state for all cpus
                config.update({
                    'platform::compute::pmqos::low_wakeup_cpus':
                        "\"%s\"" % host_ranges,
                    'platform::compute::pmqos::hight_wakeup_cpus':
                        "\"%s\"" % "",
                })
                cpu_ranges.update({"nohz_full": rcu_nocbs_ranges})

            isolcpus_ranges = utils.format_range_set(vswitch_cpuset.union(app_isolated_cpuset))

            cpu_ranges.update({
                "isolcpus": isolcpus_ranges,
                "rcu_nocbs": rcu_nocbs_ranges,
                "kthread_cpus": platform_ranges,
                "irqaffinity": platform_ranges
            })

            for key, value in cpu_ranges.items():
                if str(value).strip() != "":
                    cpu_options += "%s=%s " % (key, value)

            config.update({
                'platform::compute::params::worker_cpu_list':
                    "\"%s\"" % host_ranges,
                'platform::compute::params::platform_cpu_list':
                    "\"%s\"" % platform_ranges,
                'platform::compute::params::reserved_vswitch_cores':
                    reserved_vswitch_cores,
                'platform::compute::params::reserved_platform_cores':
                    reserved_platform_cores,
                'platform::compute::grub::params::n_cpus': n_cpus,
                'platform::compute::grub::params::cpu_options': cpu_options,
            })
        return config

    def _get_host_memory_config(self, host):
        config = {}
        if constants.WORKER in utils.get_personalities(host):
            host_memory = self.dbapi.imemory_get_by_ihost(host.id)
            memory_numa_list = utils.get_numa_index_list(host_memory)

            platform_cpus_no_threads = self._get_platform_cpu_list(host)
            platform_core_count = len(platform_cpus_no_threads)

            platform_nodes = []
            vswitch_nodes = []

            hugepages_2Ms = []
            hugepages_1Gs = []
            vswitch_2M_pages = []
            vswitch_1G_pages = []
            vm_4K_pages = []
            vm_2M_pages = []
            vm_1G_pages = []

            for node, memory_list in memory_numa_list.items():

                memory = memory_list[0]
                vswitch_2M_page = 0
                vswitch_1G_page = 0

                vm_pending_as_percentage = memory.vm_pending_as_percentage

                platform_size = memory.platform_reserved_mib
                platform_node = "\"node%d:%dMB:%d\"" % (
                    node, platform_size, platform_core_count)
                platform_nodes.append(platform_node)

                vswitch_size = memory.vswitch_hugepages_size_mib
                vswitch_pages = memory.vswitch_hugepages_reqd \
                    if memory.vswitch_hugepages_reqd is not None \
                    else memory.vswitch_hugepages_nr

                if vswitch_pages == 0:
                    vswitch_pages = memory.vswitch_hugepages_nr

                vswitch_node = "\"node%d:%dkB:%d\"" % (
                        node, vswitch_size * 1024, vswitch_pages)
                vswitch_nodes.append(vswitch_node)

                vm_hugepages_nr_2M = memory.vm_hugepages_nr_2M_pending \
                    if memory.vm_hugepages_nr_2M_pending is not None \
                    else memory.vm_hugepages_nr_2M
                vm_hugepages_nr_1G = memory.vm_hugepages_nr_1G_pending \
                    if memory.vm_hugepages_nr_1G_pending is not None \
                    else memory.vm_hugepages_nr_1G
                vm_hugepages_nr_4K = memory.vm_hugepages_nr_4K \
                    if memory.vm_hugepages_nr_4K is not None else 0

                total_hugepages_2M = vm_hugepages_nr_2M
                total_hugepages_1G = vm_hugepages_nr_1G

                if(vm_pending_as_percentage == "True"):
                    vm_hugepages_nr_2M = memory.vm_hugepages_nr_2M_pending if \
                        memory.vm_hugepages_nr_2M_pending is not None else \
                        memory.vm_hugepages_2M_percentage if memory.vm_hugepages_2M_percentage \
                        is not None else 0
                    vm_hugepages_nr_1G = memory.vm_hugepages_nr_1G_pending if \
                        memory.vm_hugepages_nr_1G_pending is not None else \
                        memory.vm_hugepages_1G_percentage if memory.vm_hugepages_1G_percentage \
                        is not None else 0

                    total_hugepages_2M = int(int(memory.node_memtotal_mib - platform_size
                        - vswitch_pages * memory.vswitch_hugepages_size_mib)
                        * vm_hugepages_nr_2M // 100 // constants.MIB_2M)
                    total_hugepages_1G = int(int(memory.node_memtotal_mib - platform_size
                        - vswitch_pages * memory.vswitch_hugepages_size_mib)
                        * vm_hugepages_nr_1G // 100 // constants.MIB_1G)

                if memory.vswitch_hugepages_size_mib == constants.MIB_2M:
                    total_hugepages_2M += vswitch_pages
                    vswitch_2M_page += vswitch_pages
                elif memory.vswitch_hugepages_size_mib == constants.MIB_1G:
                    total_hugepages_1G += vswitch_pages
                    vswitch_1G_page += vswitch_pages

                vswitch_2M_pages.append(vswitch_2M_page)
                vswitch_1G_pages.append(vswitch_1G_page)

                hugepages_2M = "\"node%d:%dkB:%d\"" % (
                    node, constants.MIB_2M * 1024, total_hugepages_2M)
                hugepages_1G = "\"node%d:%dkB:%d\"" % (
                    node, constants.MIB_1G * 1024, total_hugepages_1G)
                hugepages_2Ms.append(hugepages_2M)
                hugepages_1Gs.append(hugepages_1G)

                vm_4K_pages.append(vm_hugepages_nr_4K)
                vm_2M_pages.append(vm_hugepages_nr_2M)
                vm_1G_pages.append(vm_hugepages_nr_1G)

            platform_reserved_memory = "(%s)" % ' '.join(platform_nodes)
            vswitch_reserved_memory = "(%s)" % ' '.join(vswitch_nodes)

            nr_hugepages_2Ms = "(%s)" % ' '.join(hugepages_2Ms)
            nr_hugepages_1Gs = "(%s)" % ' '.join(hugepages_1Gs)

            vswitch_2M = "\"%s\"" % ','.join([str(i) for i in vswitch_2M_pages])
            vswitch_1G = "\"%s\"" % ','.join([str(i) for i in vswitch_1G_pages])
            vm_4K = "\"%s\"" % ','.join([str(i) for i in vm_4K_pages])
            vm_2M = "\"%s\"" % ','.join([str(i) for i in vm_2M_pages])
            vm_1G = "\"%s\"" % ','.join([str(i) for i in vm_1G_pages])

            config.update({
                'platform::compute::params::worker_base_reserved':
                    platform_reserved_memory,
                'platform::compute::params::compute_vswitch_reserved':
                    vswitch_reserved_memory,
                'platform::compute::hugepage::params::nr_hugepages_2M':
                    nr_hugepages_2Ms,
                'platform::compute::hugepage::params::nr_hugepages_1G':
                    nr_hugepages_1Gs,
                'platform::compute::hugepage::params::vswitch_2M_pages':
                    vswitch_2M,
                'platform::compute::hugepage::params::vswitch_1G_pages':
                    vswitch_1G,
                'platform::compute::hugepage::params::vm_4K_pages':
                    vm_4K,
                'platform::compute::hugepage::params::vm_2M_pages':
                    vm_2M,
                'platform::compute::hugepage::params::vm_1G_pages':
                    vm_1G,
            })

            default_pgsz = 'default_hugepagesz=2M'
            if sum(vswitch_1G_pages) != 0 or sum(vm_1G_pages) != 0:
                default_pgsz = 'default_hugepagesz=1G'
                grub_hugepages_1G = "hugepagesz=1G hugepages=%d" % (
                    sum(vswitch_1G_pages) + sum(vm_1G_pages))
                config.update({
                    'platform::compute::grub::params::g_hugepages':
                        grub_hugepages_1G,
                })

            config.update({
                'platform::compute::grub::params::default_pgsz':
                    default_pgsz,
            })

            if sum(vswitch_2M_pages) > 0:
                config.update({
                    'platform::vswitch::params::hugepage_dir':
                        '/mnt/huge-2048kB'
                })

        return config

    def _get_vcpu_pin_set(self, host):
        vm_cpus = self._get_host_cpu_list(
            host, function=constants.APPLICATION_FUNCTION, threads=True)
        cpu_list = [c.cpu for c in vm_cpus]
        return "\"%s\"" % utils.format_range_set(cpu_list)

    # kvm-timer-advance only enabled on computes with openstack compute label
    # vcpu_pin_set is only used when kvm-timer-advance is enabled
    def _get_kvm_timer_advance_config(self, host):
        kvm_timer_advance_enabled = False
        vcpu_pin_set = None

        if constants.WORKER in utils.get_personalities(host):
            host_labels = self.dbapi.label_get_by_host(host.id)
            if utils.has_openstack_compute(host_labels):
                kvm_timer_advance_enabled = True
                vcpu_pin_set = self._get_vcpu_pin_set(host)

        return {
            'platform::compute::kvm_timer_advance::enabled':
                kvm_timer_advance_enabled,
            'platform::compute::kvm_timer_advance::vcpu_pin_set':
                vcpu_pin_set,
        }

    def _get_nfs_config(self, host):

        # Calculate the optimal NFS r/w size based on the network mtu based
        # on the configured network(s)
        mtu = constants.DEFAULT_MTU
        interfaces = self.dbapi.iinterface_get_by_ihost(host.uuid)
        for interface in interfaces:
            if interface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM:
                if constants.NETWORK_TYPE_MGMT in interface['networktypelist']:
                    mtu = interface.imtu
                    break

        if self._get_address_by_name(
                constants.CONTROLLER_PLATFORM_NFS,
                constants.NETWORK_TYPE_MGMT).family == constants.IPV6_FAMILY:
            nfs_proto = 'udp6'
        else:
            nfs_proto = 'udp'

        # round to the nearest 1k of the MTU
        nfs_rw_size = (mtu // 1024) * 1024

        return {
            'platform::params::nfs_rw_size': nfs_rw_size,
            'platform::params::nfs_proto': nfs_proto,
        }

    def _get_remotelogging_config(self):
        remotelogging = self.dbapi.remotelogging_get_one()

        return {
            'platform::remotelogging::params::enabled':
                remotelogging.enabled,
            'platform::remotelogging::params::ip_address':
                remotelogging.ip_address,
            'platform::remotelogging::params::port':
                remotelogging.port,
            'platform::remotelogging::params::transport':
                remotelogging.transport,
        }

    def _get_certificate_config(self):
        config = {}

        if os.path.exists(constants.SSL_CERT_CA_FILE_SHARED):
            config.update({
                'platform::config::certs::params::ssl_ca_cert':
                    utils.get_file_content(constants.SSL_CERT_CA_FILE_SHARED),
            })

        return config

    def _get_dc_root_ca_config(self):
        config = {}
        system = self._get_system()
        if os.path.isfile(constants.ANSIBLE_BOOTSTRAP_COMPLETED_FLAG):
            cert_data = utils.get_admin_ep_cert(
                system.distributed_cloud_role)

            if cert_data is None:
                return config

            dc_root_ca_crt = cert_data['dc_root_ca_crt']
            admin_ep_crt = cert_data['admin_ep_crt']

            config.update({
                'platform::config::dccert::params::dc_root_ca_crt':
                    dc_root_ca_crt,
                'platform::config::dccert::params::dc_adminep_crt':
                    admin_ep_crt,
            })

        return config

    def _get_platform_cpu_count(self, host):
        cpus = self._get_host_cpu_list(host, constants.PLATFORM_FUNCTION, True)
        return len(cpus)

    def _get_host_lldp_config(self, host):
        driver_list = []

        # Default is lldpd
        driver_list.append('lldpd')

        self.context['_lldp_drivers'] = driver_list

        return {
            'sysinv::agent::lldp_drivers': driver_list
        }

    def _get_systemcontroller_config(self):
        config = {}
        if self._distributed_cloud_role() == \
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            # For regular DC, central-cloud's local registry is exposed on the OAM
            # interface (to provide the ability to push images externally to central
            # registry), so "registry.central" domain in dnsmasq.conf is set to system
            # controller's OAM IP on subcloud to allow subcloud to pull images from
            # central registry via the OAM interface.
            sc_network = self.dbapi.network_get_by_type(
                constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM)
            sc_network_addr_pool = self.dbapi.address_pool_get(
                sc_network.pool_uuid)
            sc_addr = sc_network_addr_pool.floating_address
            config.update({'platform::params::system_controller_addr':
                          sc_addr})

            # For virtual subcloud (StarlingX running in Openstack Nova VM - QEMU/KVM),
            # there is no physical OAM interface (no external network access) to connect
            # to central-cloud's local registry, so central registry is exposed on the
            # MGMT interface and "registry.central" domain needs to be set to system
            # controller's MGMT IP to allow subcloud to pull images from central registry
            # via the MGMT interface.
            if utils.is_virtual_system_config(self.dbapi):
                sc_mgmt_network = self.dbapi.network_get_by_type(
                    constants.NETWORK_TYPE_SYSTEM_CONTROLLER)
                sc_mgmt_network_addr_pool = self.dbapi.address_pool_get(
                    sc_mgmt_network.pool_uuid)
                sc_mgmt_addr = sc_mgmt_network_addr_pool.floating_address
                config.update({'platform::params::system_controller_mgmt_addr':
                              sc_mgmt_addr})
        return config
