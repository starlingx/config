#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
import itertools
import os
import operator

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils

from tsconfig import tsconfig

from sysinv.puppet import base

HOSTNAME_INFRA_SUFFIX = '-infra'

NOVA_UPGRADE_LEVEL_PIKE = 'pike'
NOVA_UPGRADE_LEVELS = {'18.03': NOVA_UPGRADE_LEVEL_PIKE}


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
        config.update(self._get_hosts_config())
        config.update(self._get_amqp_config())
        config.update(self._get_resolv_config())
        config.update(self._get_haproxy_config())
        config.update(self._get_sdn_config())
        config.update(self._get_region_config())
        config.update(self._get_distributed_cloud_role())
        config.update(self._get_sm_config())
        config.update(self._get_firewall_config())
        config.update(self._get_drbd_sync_config())
        config.update(self._get_nfs_config())
        config.update(self._get_remotelogging_config())
        config.update(self._get_snmp_config())
        return config

    def get_secure_system_config(self):
        config = {}
        config.update(self._get_user_config())
        return config

    def get_host_config(self, host):
        config = {}
        config.update(self._get_host_platform_config(host, self.config_uuid))
        config.update(self._get_host_ntp_config(host))
        config.update(self._get_host_ptp_config(host))
        config.update(self._get_host_sysctl_config(host))
        config.update(self._get_host_drbd_config(host))
        config.update(self._get_host_upgrade_config(host))
        config.update(self._get_host_tpm_config(host))
        config.update(self._get_host_cpu_config(host))
        config.update(self._get_host_memory_config(host))
        config.update(self._get_host_lldp_config(host))
        return config

    def _get_static_software_config(self):
        return {
            'platform::params::software_version': self.quoted_str(tsconfig.SW_VERSION),
        }

    def _get_secure_amqp_config(self):
        return {
            'platform::amqp::params::auth_password':
                self._generate_random_password(),
        }

    def _get_system_config(self):
        system = self._get_system()

        return {
            'platform::params::controller_upgrade': False,
            'platform::params::config_path': tsconfig.CONFIG_PATH,
            'platform::params::security_profile': system.security_profile,
            'platform::params::security_feature': system.security_feature,
            'platform::config::params::timezone': system.timezone,
            'platform::params::vswitch_type': self._vswitch_type(),
        }

    def _get_hosts_config(self):
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

            (constants.CONTROLLER_CGCS_NFS,
             constants.CONTROLLER_CGCS_NFS,
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

            (constants.CONTROLLER_CINDER,
             constants.CONTROLLER_CINDER,
             constants.NETWORK_TYPE_INFRA),

            # ceph storage hosts
            (constants.STORAGE_0_HOSTNAME,
             constants.STORAGE_0_HOSTNAME,
             constants.NETWORK_TYPE_MGMT),

            (constants.STORAGE_1_HOSTNAME,
             constants.STORAGE_1_HOSTNAME,
             constants.NETWORK_TYPE_MGMT),

            # infrastructure network hosts
            (constants.CONTROLLER_0_HOSTNAME + HOSTNAME_INFRA_SUFFIX,
             constants.CONTROLLER_0_HOSTNAME,
             constants.NETWORK_TYPE_INFRA),

            (constants.CONTROLLER_1_HOSTNAME + HOSTNAME_INFRA_SUFFIX,
             constants.CONTROLLER_1_HOSTNAME,
             constants.NETWORK_TYPE_INFRA),

            (constants.STORAGE_0_HOSTNAME + HOSTNAME_INFRA_SUFFIX,
             constants.STORAGE_0_HOSTNAME,
             constants.NETWORK_TYPE_INFRA),

            (constants.STORAGE_1_HOSTNAME + HOSTNAME_INFRA_SUFFIX,
             constants.STORAGE_1_HOSTNAME,
             constants.NETWORK_TYPE_INFRA),

            (constants.CONTROLLER_CGCS_NFS,
             constants.CONTROLLER_CGCS_NFS,
             constants.NETWORK_TYPE_INFRA),
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

    def _get_host_upgrade_config(self, host):
        config = {}
        try:
            upgrade = self.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            return config

        upgrade_states = [constants.UPGRADE_ACTIVATING,
                          constants.UPGRADE_ACTIVATION_FAILED,
                          constants.UPGRADE_ACTIVATION_COMPLETE,
                          constants.UPGRADE_COMPLETED]
        # we don't need compatibility mode after we activate
        if upgrade.state in upgrade_states:
            return config

        upgrade_load_id = upgrade.to_load

        host_upgrade = self.dbapi.host_upgrade_get_by_host(host['id'])
        if host_upgrade.target_load == upgrade_load_id:
            from_load = self.dbapi.load_get(upgrade.from_load)
            sw_version = from_load.software_version
            nova_level = NOVA_UPGRADE_LEVELS.get(sw_version)

            if not nova_level:
                raise exception.SysinvException(
                    ("No matching upgrade level found for version %s")
                    % sw_version)

            config.update({
                  'nova::upgrade_level_compute': nova_level
            })

        return config

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
            'platform::users::params::wrsroot_password':
                user.passwd_hash,
            'platform::users::params::wrsroot_password_max_age':
                user.passwd_expiry_days,
        }

    def _get_haproxy_config(self):
        public_address = self._get_address_by_name(
            constants.CONTROLLER, constants.NETWORK_TYPE_OAM)
        private_address = self._get_address_by_name(
            constants.CONTROLLER, constants.NETWORK_TYPE_MGMT)

        https_enabled = self._https_enabled()

        config = {
            'platform::haproxy::params::public_ip_address':
                public_address.address,
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
            'platform::sm::params::infra_ip_multicast':
                multicast_address.address,
        }

    def _get_firewall_config(self):
        config = {}
        rules_filepath = os.path.join(tsconfig.PLATFORM_CONF_PATH,
                                      'iptables.rules')
        if os.path.isfile(rules_filepath):
            config.update({
                'platform::firewall::oam::rules_file': rules_filepath
            })
        return config

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

        cpu_count = self._get_platform_cpu_count(host)
        config.update({
            'platform::params::platform_cpu_count':
                cpu_count,
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

        return {
            'platform::ntp::enabled': ntp.enabled,
            'platform::ntp::servers': servers,
            'platform::ntp::ntpdate_timeout': ntpdate_timeout,
        }

    def _get_host_ptp_config(self, host):
        ptp = self.dbapi.ptp_get_one()

        return {
            'platform::ptp::enabled':
                ptp.enabled,
            'platform::ptp::mode':
                ptp.mode,
            'platform::ptp::transport':
                ptp.transport,
            'platform::ptp::mechanism':
                ptp.mechanism,
        }

    def _get_host_sysctl_config(self, host):
        config = {}

        if host.personality == constants.CONTROLLER:
            remotelogging = self.dbapi.remotelogging_get_one()

            ip_forwarding = (self._region_config() or
                             self._sdn_enabled() or
                             remotelogging.enabled)

            # The forwarding IP version is based on the OAM network version
            address = self._get_address_by_name(
                constants.CONTROLLER_HOSTNAME, constants.NETWORK_TYPE_OAM)

            ip_version = address.family

            config.update({
                'platform::sysctl::params::ip_forwarding': ip_forwarding,
                'platform::sysctl::params::ip_version': ip_version,
            })

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

            # Define the full range of CPUs for the compute host
            max_cpu = max(host_cpus, key=operator.attrgetter('cpu'))
            worker_cpu_list = "\"0-%d\"" % max_cpu.cpu

            platform_cpus_no_threads = self._get_platform_cpu_list(host)
            vswitch_cpus_no_threads = self._get_vswitch_cpu_list(host)

            platform_cpu_list_with_quotes = \
                "\"%s\"" % ','.join([str(c.cpu) for c in platform_cpus_no_threads])

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

            host_cpus = sorted(host_cpus, key=lambda c: c.cpu)
            n_cpus = len(host_cpus)
            host_cpu_list = [c.cpu for c in host_cpus]

            platform_cpus = self._get_host_cpu_list(
                host, function=constants.PLATFORM_FUNCTION, threads=True)
            platform_cpus = sorted(platform_cpus, key=lambda c: c.cpu)
            platform_cpu_list = \
                "%s" % ','.join([str(c.cpu) for c in platform_cpus])

            vswitch_cpus = self._get_host_cpu_list(
                host, constants.VSWITCH_FUNCTION, threads=True)
            vswitch_cpus = sorted(vswitch_cpus, key=lambda c: c.cpu)
            vswitch_cpu_list = \
                "%s" % ','.join([str(c.cpu) for c in vswitch_cpus])

            # rcu_nocbs = all cores - platform cores
            rcu_nocbs = copy.deepcopy(host_cpu_list)
            for i in [int(s) for s in platform_cpu_list.split(',')]:
                rcu_nocbs.remove(i)

            # change the CPU list to ranges
            rcu_nocbs_ranges = ""
            for key, group in itertools.groupby(enumerate(rcu_nocbs),
                                                lambda (x, y): y - x):
                group = list(group)
                rcu_nocbs_ranges += "%s-%s," % (group[0][1], group[-1][1])
            rcu_nocbs_ranges = rcu_nocbs_ranges.rstrip(',')

            # non-vswitch CPUs = all cores - vswitch cores
            non_vswitch_cpus = host_cpu_list
            for i in [c.cpu for c in vswitch_cpus]:
                non_vswitch_cpus.remove(i)

            # change the CPU list to ranges
            non_vswitch_cpus_ranges = ""
            for key, group in itertools.groupby(enumerate(non_vswitch_cpus),
                                                lambda (x, y): y - x):
                group = list(group)
                non_vswitch_cpus_ranges += "\"%s-%s\"," % (group[0][1], group[-1][1])

            cpu_options = ""
            if constants.LOWLATENCY in host.subfunctions:
                vswitch_cpu_list_with_quotes = \
                    "\"%s\"" % ','.join([str(c.cpu) for c in vswitch_cpus])
                config.update({
                    'platform::compute::pmqos::low_wakeup_cpus':
                        vswitch_cpu_list_with_quotes,
                    'platform::compute::pmqos::hight_wakeup_cpus':
                        non_vswitch_cpus_ranges.rstrip(',')})
                vswitch_cpu_list = rcu_nocbs_ranges
                cpu_options += "nohz_full=%s " % vswitch_cpu_list

            cpu_options += "isolcpus=%s rcu_nocbs=%s kthread_cpus=%s " \
                "irqaffinity=%s" % (vswitch_cpu_list,
                                    rcu_nocbs_ranges,
                                    platform_cpu_list,
                                    platform_cpu_list)
            config.update({
                'platform::compute::params::worker_cpu_list':
                    worker_cpu_list,
                'platform::compute::params::platform_cpu_list':
                    platform_cpu_list_with_quotes,
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

            platform_cpus = self._get_platform_cpu_list(host)
            platform_cpu_count = len(platform_cpus)

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

                platform_size = memory.platform_reserved_mib
                platform_node = "\"node%d:%dMB:%d\"" % (
                    node, platform_size, platform_cpu_count)
                platform_nodes.append(platform_node)

                vswitch_size = memory.vswitch_hugepages_size_mib
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

                if memory.vswitch_hugepages_size_mib == constants.MIB_2M:
                    total_hugepages_2M += memory.vswitch_hugepages_nr
                    vswitch_2M_page += memory.vswitch_hugepages_nr
                elif memory.vswitch_hugepages_size_mib == constants.MIB_1G:
                    total_hugepages_1G += memory.vswitch_hugepages_nr
                    vswitch_1G_page += memory.vswitch_hugepages_nr

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

        return config

    def _get_nfs_config(self):

        # Calculate the optimal NFS r/w size based on the network mtu based
        # on the configured network(s)
        mtu = constants.DEFAULT_MTU
        try:
            interfaces = self.dbapi.iinterface_get_by_network(
                constants.NETWORK_TYPE_INFRA)
            for interface in interfaces:
                mtu = interface.imtu
        except exception.InvalidParameterValue:
            try:
                interfaces = self.dbapi.iinterface_get_by_network(
                    constants.NETWORK_TYPE_MGMT)
                for interface in interfaces:
                    mtu = interface.imtu
            except exception.InvalidParameterValue:
                pass

        if self._get_address_by_name(
                constants.CONTROLLER_PLATFORM_NFS,
                constants.NETWORK_TYPE_MGMT).family == constants.IPV6_FAMILY:
            nfs_proto = 'udp6'
        else:
            nfs_proto = 'udp'

        # round to the nearest 1k of the MTU
        nfs_rw_size = (mtu / 1024) * 1024

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

    def _get_snmp_config(self):
        system = self.dbapi.isystem_get_one()
        comm_strs = self.dbapi.icommunity_get_list()
        trapdests = self.dbapi.itrapdest_get_list()

        config = {
            'platform::snmp::params::system_name':
                system.name,
            'platform::snmp::params::system_location':
                system.location,
            'platform::snmp::params::system_contact':
                system.contact,
        }

        if comm_strs is not None:
            comm_list = []
            for i in comm_strs:
                comm_list.append(i.community)
            config.update({'platform::snmp::params::community_strings':
                           comm_list})

        if trapdests is not None:
            trap_list = []
            for e in trapdests:
                trap_list.append(e.ip_address + ' ' + e.community)
            config.update({'platform::snmp::params::trap_destinations':
                           trap_list})

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
