# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8

# Copyright 2013 Hewlett-Packard Development Company, L.P.
# Copyright 2013 International Business Machines Corporation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2024 Wind River Systems, Inc.
#


""" Perform activity related local inventory.

A single instance of :py:class:`sysinv.agent.manager.AgentManager` is
created within the *sysinv-agent* process, and is responsible for
performing all actions for this host managed by system inventory.

On start, collect and post inventory to conductor.

Commands (from conductors) are received via RPC calls.

"""

from __future__ import print_function
from eventlet.green import subprocess
import fileinput
import os
import retrying
import six
import shutil
import sys
import tempfile
import time
import socket
import yaml

from six.moves import configparser
from six import StringIO

from oslo_config import cfg
from oslo_context import context as mycontext
from oslo_log import log
from oslo_service import periodic_task
from oslo_utils import timeutils
from sysinv.agent import disk
from sysinv.agent import partition
from sysinv.agent import pv
from sysinv.agent import lvg
from sysinv.agent import lv
from sysinv.agent import pci
from sysinv.agent import node
from sysinv.agent import fpga
from sysinv.agent.lldp import plugin as lldp_plugin
from sysinv.common import fpga_constants
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import service
from sysinv.common import utils
from sysinv.objects import base as objects_base
from sysinv.puppet import common as puppet
from sysinv.conductor import rpcapiproxy as conductor_rpcapi
from sysinv.openstack.common.rpc.common import Timeout
from sysinv.openstack.common.rpc.common import serialize_remote_exception
from sysinv.openstack.common.rpc import service as rpc_service
from sysinv.openstack.common.rpc.common import RemoteError
from sysinv.zmq_rpc.zmq_rpc import ZmqRpcServer
from sysinv.zmq_rpc.zmq_rpc import is_rpc_hybrid_mode_active

import tsconfig.tsconfig as tsc

MANAGER_TOPIC = 'sysinv.agent_manager'

LOG = log.getLogger(__name__)

agent_opts = [
       cfg.StrOpt('api_url',
                  default=None,
                  help=('Url of SysInv API service. If not set SysInv can '
                        'get current value from Keystone service catalog.')),
              ]

audit_intervals_opts = [
       cfg.IntOpt('default', default=60),
       cfg.IntOpt('inventory_audit', default=60),
       cfg.IntOpt('lldp_audit', default=300),
       cfg.IntOpt('security_audit', default=900),
                  ]

dpdk_opts = [
             cfg.StrOpt('dpdk_elf',
                        default='/usr/sbin/ovs-vswitchd',
                        help='DPDK ELF file used for compatibility checks'),
            ]

CONF = cfg.CONF
CONF.register_opts(agent_opts, 'agent')
CONF.register_opts(audit_intervals_opts, 'agent_periodic_task_intervals')
CONF.register_opts(dpdk_opts, 'dpdk')

MAXSLEEP = 600  # 10 minutes

SYSINV_READY_FLAG = os.path.join(tsc.VOLATILE_PATH, ".sysinv_ready")

CONFIG_APPLIED_FILE = os.path.join(tsc.PLATFORM_CONF_PATH, ".config_applied")
CONFIG_APPLIED_DEFAULT = "install"

FIRST_BOOT_FLAG = constants.FIRST_BOOT_FLAG

PUPPET_HIERADATA_PATH = os.path.join(tsc.PUPPET_PATH, 'hieradata')
PUPPET_HIERADATA_CACHE_PATH = '/etc/puppet/cache/hieradata'

LOCK_AGENT_ACTION = 'agent-exclusive-action'


class FakeGlobalSectionHead(object):
    def __init__(self, fp):
        self.fp = fp
        self.sechead = '[global]\n'

    def readline(self):
        if self.sechead:
            try:
                return self.sechead
            finally:
                self.sechead = None
        else:
            return self.fp.readline()


class AgentManager(service.PeriodicService):
    """Sysinv Agent service main class."""

    RPC_API_VERSION = '1.0'

    NUMA = 'numa'
    CPU = 'cpu'
    PORT = 'port'
    PCI_DEVICE = 'pci_device'
    MEMORY = 'memory'
    DISK = 'disk'
    PV = 'pv'
    LVG = 'lvg'
    HOST_FILESYSTEMS = 'host_filesystems'
    KERNEL = 'kernel'

    # Note that this set must be extended when there are
    # additional inventory required for the initial
    # inventory complete (to be notified to conductor).
    INVENTORY_REPORTS_REQUIRED = {
        NUMA,
        PORT,
        PCI_DEVICE,
        CPU,
        MEMORY,
        DISK,
        PV,
        LVG,
        HOST_FILESYSTEMS,
        KERNEL}

    def __init__(self, host, topic):
        self.host = host
        self.topic = topic
        serializer = objects_base.SysinvObjectSerializer()
        super(AgentManager, self).__init__()
        self._rpc_service = None
        self._zmq_rpc_service = None

        # TODO(RPCHybridMode): Usage of RabbitMQ RPC is only required for
        #  21.12 -> 22.12 upgrades.
        #  Remove this in new releases, when it's no longer necessary do the
        #  migration work through RabbitMQ and ZeroMQ
        # NOTE: If more switches are necessary before RabbitMQ removal,
        # refactor this into an RPC layer
        if not CONF.rpc_backend_zeromq or is_rpc_hybrid_mode_active():
            self._rpc_service = rpc_service.Service(self.host, self.topic,
                                                    manager=self,
                                                    serializer=serializer)
        if CONF.rpc_backend_zeromq:
            self._zmq_rpc_service = ZmqRpcServer(
                self,
                CONF.rpc_zeromq_bind_ip,
                CONF.rpc_zeromq_agent_bind_port)

        self._report_to_conductor_iplatform_avail_flag = False
        self._report_to_conductor_fpga_info = True
        self._report_to_conductor_cstate_info = True
        self._ipci_operator = pci.PCIOperator()
        self._inode_operator = node.NodeOperator()
        self._idisk_operator = disk.DiskOperator()
        self._ifpga_operator = fpga.FpgaOperator()
        self._ipv_operator = pv.PVOperator()
        self._ipartition_operator = partition.PartitionOperator()
        self._host_fs_operator = lv.LVOperator()
        self._ilvg_operator = lvg.LVGOperator()
        self._lldp_operator = lldp_plugin.SysinvLldpPlugin()
        self._iconfig_read_config_reported = None
        self._ihost_min_cpu_mhz_allowed = 0
        self._ihost_max_cpu_mhz_allowed = 0
        self._ihost_cstates_available = None
        self._ihost_personality = None
        self._ihost_uuid = ""
        self._ihost_rootfs_device = ""
        self._agent_throttle = 0
        self._mgmt_ip = None
        self._hostname = None
        self._prev_disk = None
        self._prev_partition = None
        self._prev_lvg = None
        self._prev_pv = None
        self._prev_fs = None
        self._subfunctions = None
        self._subfunctions_configured = False
        self._first_grub_update = False
        self._inventoried_initial = False
        self._inventory_reported = set()
        self._first_boot_flag = os.path.exists(FIRST_BOOT_FLAG) or \
            os.path.exists(constants.VOLATILE_FIRST_BOOT_FLAG)

    def start(self):
        super(AgentManager, self).start()
        if self._rpc_service:
            self._rpc_service.start()
        if self._zmq_rpc_service:
            self._zmq_rpc_service.run()
        # Do not collect inventory and report to conductor at startup in
        # order to eliminate two inventory reports
        # (one from here and one from audit) being sent to the conductor
        if os.path.isfile('/etc/sysinv/sysinv.conf'):
            LOG.debug('sysinv-agent started, inventory to be reported by audit')
        else:
            LOG.debug('No config file for sysinv-agent found.')

        if tsc.system_mode == constants.SYSTEM_MODE_SIMPLEX:
            utils.touch(SYSINV_READY_FLAG)

    def stop(self):
        if self._rpc_service:
            self._rpc_service.stop()
        if self._zmq_rpc_service:
            self._zmq_rpc_service.stop()
        super(AgentManager, self).stop()

    def _report_to_conductor(self):
        """ Initial inventory report to conductor required

            returns: True if initial inventory report_to_conductor is required
        """

        initial_reports_required = \
                self.INVENTORY_REPORTS_REQUIRED - self._inventory_reported

        if self._inventory_reported:
            utils.touch(constants.SYSINV_REPORTED)

        if initial_reports_required:
            LOG.info("_report_to_conductor initial_reports_required=%s" %
                 initial_reports_required)
            return True
        else:
            return False

    def _report_to_conductor_iplatform_avail(self):
        # First report sent to conductor since boot
        utils.touch(constants.SYSINV_FIRST_REPORT_FLAG)
        # Sysinv-agent ready; used also by the init script.
        utils.touch(SYSINV_READY_FLAG)
        time.sleep(1)  # give time for conductor to process
        self._report_to_conductor_iplatform_avail_flag = True

    @staticmethod
    def _update_interface_irq_affinity(self, interface_list):
        cpus = {}
        platform_cpulist = '0'
        with open('/etc/platform/worker_reserved.conf', 'r') as infile:
            for line in infile:
                if "WORKER_PLATFORM_CORES" in line:
                    val = line.split("=")
                    cores = val[1].strip('\n')[1:-1]
                    for n in cores.split():
                        nodes = n.split(":")
                        cpus[nodes[0][-1]] = nodes[1].strip('"')
                if "PLATFORM_CPU_LIST" in line:
                    val = line.split("=")
                    platform_cpulist = val[1].strip('\n')[1:-1].strip('"')

        for info in interface_list:
            # vbox case, just use 0
            if info['numa_node'] == -1:
                info['numa_node'] = 0

            key = str(info['numa_node'])
            if key in cpus:
                cpulist = cpus[key]
            else:
                cpulist = platform_cpulist

                # Just log that we detect cross-numa performance degradation,
                # do not bother with alarms since that adds too much noise.
                LOG.info("Cross-numa performance degradation over port %s "
                         "on processor %d on host %s.  Better performance "
                         "if you configure platform interface on port "
                         "residing on processor 0, or configure a platform "
                         "core on processor %d." %
                         (info['name'], info['numa_node'], self.host,
                          info['numa_node']))

            LOG.info("Affine platform interface %s with cpulist %s" %
                    (info['name'], cpulist))
            cmd = '/usr/bin/affine-interrupts.sh %s %s' % \
                    (info['name'], cpulist)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            proc.communicate()
            LOG.info("%s return %d" % (cmd, proc.returncode))
            if proc.returncode == 1:
                LOG.error("Failed to affine platform interface %s interrupts with %s" %
                          (info['name'], cpulist))

    def _is_max_cpu_mhz_configurable(self):
        fail_result = "System does not support"

        output = utils.execute('/usr/bin/cpupower', 'info', run_as_root=True)

        if isinstance(output, tuple):
            cpu_info = output[0] or ''
            if not cpu_info.startswith(fail_result):
                return constants.CONFIGURABLE
        return constants.NOT_CONFIGURABLE

    def _get_min_cpu_mhz_allowed(self):
        """Get minimum CPU frequency from lscpu

        Returns:
            int: minimum CPU frequency in MHz
        """
        output = utils.execute(
            "lscpu | grep 'CPU min MHz' | awk '{ print $4 }' | cut -d ',' -f 1",
            shell=True)

        if isinstance(output, tuple):
            default_min = output[0]
            if default_min:
                LOG.info("Default CPU min frequency: {}".format(default_min))
                return int(default_min.split('.')[0])

    def _get_max_cpu_mhz_allowed(self):
        output = utils.execute(
            "lscpu | grep 'CPU max MHz' | awk '{ print $4 }' | cut -d ',' -f 1",
            shell=True)

        if isinstance(output, tuple):
            default_max = output[0]
            if default_max:
                LOG.info("Default CPU max frequency: {}".format(default_max))
                return int(default_max.split('.')[0])

    def _get_cstates_names(self):
        """Get the names of available c-state on the system.

        Returns:
            list(string,..): A list of c-state names
        """
        states = os.listdir(constants.CSTATE_PATH)
        cstates = []

        for state in states:
            with open(os.path.join(constants.CSTATE_PATH, state + "/name"),
                      'r') as file:
                c_name = file.readline()
                cstates.append(c_name.split('\n')[0])

        cstates.sort()
        return cstates

    def _force_grub_update(self):
        """ Force update the grub on the first AIO controller after the initial
            config is completed
        """
        if (not self._first_grub_update and
                # config_controller case
                os.path.isfile(tsc.INITIAL_CONFIG_COMPLETE_FLAG)):
            self._first_grub_update = True
            return True
        return False

    def periodic_tasks(self, context, raise_on_error=False):
        """ Periodic tasks are run at pre-specified intervals. """

        return self.run_periodic_tasks(context, raise_on_error=raise_on_error)

    def iconfig_read_config_applied(self):
        """ Read and return contents from the CONFIG_APPLIED_FILE
        """

        if not os.path.isfile(CONFIG_APPLIED_FILE):
            return None

        ini_str = '[DEFAULT]\n' + open(CONFIG_APPLIED_FILE, 'r').read()
        ini_fp = StringIO(ini_str)

        config_applied = configparser.RawConfigParser()
        config_applied.optionxform = str
        config_applied.readfp(ini_fp)

        if config_applied.has_option('DEFAULT', 'CONFIG_UUID'):
            config_uuid = config_applied.get('DEFAULT', 'CONFIG_UUID')
        else:
            # assume install
            config_uuid = CONFIG_APPLIED_DEFAULT

        return config_uuid

    def host_lldp_get_and_report(self, context, rpcapi, host_uuid):
        neighbour_dict_array = []
        agent_dict_array = []
        neighbours = []
        agents = []

        try:
            neighbours = self._lldp_operator.lldp_neighbours_list()
        except Exception as e:
            LOG.error("Failed to get LLDP neighbours: %s", str(e))

        for neighbour in neighbours:
            neighbour_dict = {
                'name_or_uuid': neighbour.key.portname,
                'msap': neighbour.msap,
                'state': neighbour.state,
                constants.LLDP_TLV_TYPE_CHASSIS_ID: neighbour.key.chassisid,
                constants.LLDP_TLV_TYPE_PORT_ID: neighbour.key.portid,
                constants.LLDP_TLV_TYPE_TTL: neighbour.ttl,
                constants.LLDP_TLV_TYPE_SYSTEM_NAME: neighbour.system_name,
                constants.LLDP_TLV_TYPE_SYSTEM_DESC: neighbour.system_desc,
                constants.LLDP_TLV_TYPE_SYSTEM_CAP: neighbour.capabilities,
                constants.LLDP_TLV_TYPE_MGMT_ADDR: neighbour.mgmt_addr,
                constants.LLDP_TLV_TYPE_PORT_DESC: neighbour.port_desc,
                constants.LLDP_TLV_TYPE_DOT1_LAG: neighbour.dot1_lag,
                constants.LLDP_TLV_TYPE_DOT1_PORT_VID: neighbour.dot1_port_vid,
                constants.LLDP_TLV_TYPE_DOT1_VID_DIGEST: neighbour.dot1_vid_digest,
                constants.LLDP_TLV_TYPE_DOT1_MGMT_VID: neighbour.dot1_mgmt_vid,
                constants.LLDP_TLV_TYPE_DOT1_PROTO_VIDS: neighbour.dot1_proto_vids,
                constants.LLDP_TLV_TYPE_DOT1_PROTO_IDS: neighbour.dot1_proto_ids,
                constants.LLDP_TLV_TYPE_DOT1_VLAN_NAMES: neighbour.dot1_vlan_names,
                constants.LLDP_TLV_TYPE_DOT1_VID_DIGEST: neighbour.dot1_vid_digest,
                constants.LLDP_TLV_TYPE_DOT3_MAC_STATUS: neighbour.dot3_mac_status,
                constants.LLDP_TLV_TYPE_DOT3_MAX_FRAME: neighbour.dot3_max_frame,
                constants.LLDP_TLV_TYPE_DOT3_POWER_MDI: neighbour.dot3_power_mdi,
            }
            neighbour_dict_array.append(neighbour_dict)

        if neighbour_dict_array:
            try:
                rpcapi.lldp_neighbour_update_by_host(context,
                                                     host_uuid,
                                                     neighbour_dict_array)
            except exception.SysinvException:
                LOG.exception("Sysinv Agent exception updating lldp neighbours.")
                self._lldp_operator.lldp_neighbours_clear()
                pass

        try:
            agents = self._lldp_operator.lldp_agents_list()
        except Exception as e:
            LOG.error("Failed to get LLDP agents: %s", str(e))

        for agent in agents:
            agent_dict = {
                'name_or_uuid': agent.key.portname,
                'state': agent.state,
                'status': agent.status,
                constants.LLDP_TLV_TYPE_CHASSIS_ID: agent.key.chassisid,
                constants.LLDP_TLV_TYPE_PORT_ID: agent.key.portid,
                constants.LLDP_TLV_TYPE_TTL: agent.ttl,
                constants.LLDP_TLV_TYPE_SYSTEM_NAME: agent.system_name,
                constants.LLDP_TLV_TYPE_SYSTEM_DESC: agent.system_desc,
                constants.LLDP_TLV_TYPE_SYSTEM_CAP: agent.capabilities,
                constants.LLDP_TLV_TYPE_MGMT_ADDR: agent.mgmt_addr,
                constants.LLDP_TLV_TYPE_PORT_DESC: agent.port_desc,
                constants.LLDP_TLV_TYPE_DOT1_LAG: agent.dot1_lag,
                constants.LLDP_TLV_TYPE_DOT1_VLAN_NAMES: agent.dot1_vlan_names,
                constants.LLDP_TLV_TYPE_DOT3_MAX_FRAME: agent.dot3_max_frame,
            }
            agent_dict_array.append(agent_dict)

        if agent_dict_array:
            try:
                rpcapi.lldp_agent_update_by_host(context,
                                                 host_uuid,
                                                 agent_dict_array)
            except exception.SysinvException:
                LOG.exception("Sysinv Agent exception updating lldp agents.")
                self._lldp_operator.lldp_agents_clear()
                pass

    def synchronized_network_config(func):  # pylint: disable=no-self-argument
        """ Synchronization decorator to acquire and release
            network_config_lock.
        """
        def wrap(self, *args, **kwargs):
            try:
                # Get lock to avoid conflict with apply_network_config.sh
                lockfd = self._acquire_network_config_lock()
                return func(self, *args, **kwargs)  # pylint: disable=not-callable
            finally:
                self._release_network_config_lock(lockfd)
        return wrap

    @synchronized_network_config
    def _lldp_enable_and_report(self, context, rpcapi, host_uuid):
        """ Temporarily enable interfaces and get lldp neighbor information.
            This method should only be called before
             INITIAL_CONFIG_COMPLETE_FLAG is set.
        """
        links_down = []
        try:
            # Turn on interfaces, so that lldpd can show all neighbors
            for interface in self._ipci_operator.pci_get_net_names():
                flag = self._ipci_operator.pci_get_net_flags(interface)
                # If administrative state is down, bring it up momentarily
                if not (flag & pci.IFF_UP):
                    subprocess.call(['ip', 'link', 'set', interface, 'up'])  # pylint: disable=not-callable
                    links_down.append(interface)
                    LOG.info('interface %s enabled to receive LLDP PDUs' % interface)
            self._lldp_operator.lldp_update()

            # delay maximum 30 seconds for lldpd to receive LLDP PDU
            timeout = 0
            link_wait_for_lldp = True
            while timeout < 30 and link_wait_for_lldp and links_down:
                time.sleep(5)
                timeout = timeout + 5
                link_wait_for_lldp = False

                for link in links_down:
                    if not self._lldp_operator.lldp_has_neighbour(link):
                        link_wait_for_lldp = True
                        break
            self.host_lldp_get_and_report(context, rpcapi, host_uuid)
        except Exception as e:
            LOG.exception(e)
            pass
        finally:
            # restore interface administrative state
            for interface in links_down:
                subprocess.call(['ip', 'link', 'set', interface, 'down'])  # pylint: disable=not-callable
                LOG.info('interface %s disabled after querying LLDP neighbors' % interface)

    def platform_update_by_host(self, rpcapi, context, host_uuid, msg_dict):
        """ Update host platform information.
            If this is the first boot (kickstart), then also update the Host
            Action State to reinstalled, and remove the flag.
        """
        if os.path.exists(FIRST_BOOT_FLAG):
            max_cpu_freq_dict = {
                constants.IHOST_IS_MAX_CPU_MHZ_CONFIGURABLE:
                self._is_max_cpu_mhz_configurable(),
                constants.IHOST_MAX_CPU_MHZ_ALLOWED:
                self._get_max_cpu_mhz_allowed()}
            msg_dict.update({constants.HOST_ACTION_STATE:
                             constants.HAS_REINSTALLED,
                             'max_cpu_dict': max_cpu_freq_dict})

        # Is this the first time since boot we are reporting to conductor?
        msg_dict.update({constants.SYSINV_AGENT_FIRST_REPORT:
                         not os.path.exists(constants.SYSINV_FIRST_REPORT_FLAG)})

        try:
            rpcapi.iplatform_update_by_ihost(context,
                                             host_uuid,
                                             msg_dict)
            if os.path.exists(FIRST_BOOT_FLAG):
                # Create volatile first_boot file, that will be checked by agent manager
                # when it get crashed and restarted, so that it will know this boot is still
                # first boot.
                try:
                    os.mknod(constants.VOLATILE_FIRST_BOOT_FLAG)
                except OSError:
                    LOG.error("%s could not be created." % constants.VOLATILE_FIRST_BOOT_FLAG)

                os.remove(FIRST_BOOT_FLAG)
                LOG.info("Removed %s" % FIRST_BOOT_FLAG)
        except exception.SysinvException:
            # For compatibility with 15.12
            LOG.warn("platform_update_by_host exception host_uuid=%s msg_dict=%s." %
                     (host_uuid, msg_dict))
            pass

        LOG.info("Sysinv Agent platform update by host: %s" % msg_dict)

    def _acquire_network_config_lock(self):
        """ Synchronization with apply_network_config.sh

        This method is to acquire the lock to avoid
        conflict with execution of apply_network_config.sh
        during puppet manifest application.

        :returns: fd of the lock, if successful. 0 on error.
        """
        lock_file_fd = os.open(
            constants.NETWORK_CONFIG_LOCK_FILE, os.O_CREAT | os.O_RDONLY)
        return utils.acquire_exclusive_nb_flock(lock_file_fd)

    def _release_network_config_lock(self, lockfd):
        """ Release the lock guarding apply_network_config.sh """
        if lockfd:
            utils.release_flock(lockfd)
            os.close(lockfd)

    def _get_ports_inventory(self):
        """Collect ports inventory for this host"""

        # During bootstrap (fresh install and also restore), and network first-boot
        #    send report unconditionally
        # During host configuration (subsequent reboots):
        #    worker in subfunction : do not send report until worker manifest applied
        #    otherwise: send report unconditionally

        port_list = []
        pci_device_list = []
        host_macs = []

        ansible_bootstrap_flag = \
            os.path.exists(constants.ANSIBLE_BOOTSTRAP_FLAG)
        worker_config_completed = \
            os.path.exists(tsc.VOLATILE_WORKER_CONFIG_COMPLETE)

        # do not send report if it is neither first boot nor
        # ansible-bootstrap, and worker config has not finished,
        # i.e. during subsequent reboot before the worker manifest
        # enables and binds any SR-IOV devices
        if (not self._first_boot_flag
                and not ansible_bootstrap_flag
                and constants.WORKER in self.subfunctions_list_get()
                and not worker_config_completed):
            return port_list, pci_device_list, host_macs

        # find list of network related inics for this host
        inics = self._ipci_operator.inics_get()

        # create an array of ports for each net entry of the NIC device
        iports = []
        for inic in inics:
            lockfd = 0
            try:
                # Get lock to avoid conflict with apply_network_config.sh
                lockfd = self._acquire_network_config_lock()
                pci_net_array = self._ipci_operator.pci_get_net_attrs(inic.pciaddr)
            finally:
                self._release_network_config_lock(lockfd)
            for net in pci_net_array:
                iports.append(pci.Port(inic, **net))

        # find list of pci devices for this host
        pci_devices = self._ipci_operator.pci_devices_get()

        # create an array of pci_devs for each net entry of the device
        pci_devs = []
        for pci_dev in pci_devices:
            pci_dev_array = self._ipci_operator.pci_get_device_attrs(
                pci_dev.pciaddr)
            for dev in pci_dev_array:
                pci_devs.append(pci.PCIDevice(pci_dev, **dev))

        # create a list of MAC addresses that will be used to identify the
        # inventoried host (one of the MACs should be the management MAC)
        host_macs = [port.mac for port in iports if port.mac]

        for port in iports:
            inic_dict = {'pciaddr': port.ipci.pciaddr,
                         'pclass': port.ipci.pclass,
                         'pvendor': port.ipci.pvendor,
                         'pdevice': port.ipci.pdevice,
                         'prevision': port.ipci.prevision,
                         'psvendor': port.ipci.psvendor,
                         'psdevice': port.ipci.psdevice,
                         'pname': port.name,
                         'numa_node': port.numa_node,
                         'sriov_totalvfs': port.sriov_totalvfs,
                         'sriov_numvfs': port.sriov_numvfs,
                         'sriov_vfs_pci_address': port.sriov_vfs_pci_address,
                         'sriov_vf_driver': port.sriov_vf_driver,
                         'sriov_vf_pdevice_id': port.sriov_vf_pdevice_id,
                         'driver': port.driver,
                         'mac': port.mac,
                         'mtu': port.mtu,
                         'speed': port.speed,
                         'link_mode': port.link_mode,
                         'dev_id': port.dev_id,
                         'dpdksupport': port.dpdksupport}

            LOG.debug('Sysinv Agent inic {}'.format(inic_dict))

            port_list.append(inic_dict)

        is_fpga_n3000_reset = \
            os.path.exists(fpga_constants.N3000_RESET_FLAG)

        for dev in pci_devs:
            pci_dev_dict = {'name': dev.name,
                            'pciaddr': dev.pci.pciaddr,
                            'pclass_id': dev.pclass_id,
                            'pvendor_id': dev.pvendor_id,
                            'pdevice_id': dev.pdevice_id,
                            'pclass': dev.pci.pclass,
                            'pvendor': dev.pci.pvendor,
                            'pdevice': dev.pci.pdevice,
                            'prevision': dev.pci.prevision,
                            'psvendor': dev.pci.psvendor,
                            'psdevice': dev.pci.psdevice,
                            'numa_node': dev.numa_node,
                            'sriov_totalvfs': dev.sriov_totalvfs,
                            'sriov_numvfs': dev.sriov_numvfs,
                            'sriov_vfs_pci_address': dev.sriov_vfs_pci_address,
                            'sriov_vf_driver': dev.sriov_vf_driver,
                            'sriov_vf_pdevice_id': dev.sriov_vf_pdevice_id,
                            'driver': dev.driver,
                            'enabled': dev.enabled,
                            'extra_info': dev.extra_info,
                            'fpga_n3000_reset': is_fpga_n3000_reset}
            LOG.debug('Sysinv Agent dev {}'.format(pci_dev_dict))

            pci_device_list.append(pci_dev_dict)

        return port_list, pci_device_list, host_macs

    def _retry_on_missing_host_uuid(ex):  # pylint: disable=no-self-argument
        LOG.info('Caught exception missing host. '
                 'Retrying...Exception: {}'.format(ex))
        return isinstance(ex, exception.LocalHostUUIDNotFound)

    @retrying.retry(wait_fixed=15 * 1000, stop_max_delay=300 * 1000,
                    retry_on_exception=_retry_on_missing_host_uuid)
    def _report_port_inventory(self, context, rpcapi=None,
                               port_list=None, pci_device_list=None):

        host_uuid = self._ihost_uuid
        if not host_uuid:
            raise exception.LocalHostUUIDNotFound()

        if rpcapi is None:
            rpcapi = conductor_rpcapi.ConductorAPI(
                topic=conductor_rpcapi.MANAGER_TOPIC)

        if pci_device_list is None or port_list is None:
            port_list, pci_device_list, host_macs = self._get_ports_inventory()

        if port_list:
            try:
                rpcapi.iport_update_by_ihost(context,
                                             host_uuid,
                                             port_list)
                self._inventory_reported.add(self.PORT)
            except RemoteError as e:
                LOG.error("iport_update_by_ihost RemoteError exc_type=%s" %
                        e.exc_type)

        if pci_device_list:
            try:
                # Don't ask conductor to cleanup stale entries while worker
                # manifest is not complete. For N3000 device, it could get rid
                # of a valid entry with a different PCI address but restored
                # from previous database backup
                cleanup_stale = \
                    os.path.exists(tsc.VOLATILE_WORKER_CONFIG_COMPLETE)
                rpcapi.pci_device_update_by_host(context,
                                                host_uuid,
                                                pci_device_list,
                                                cleanup_stale)
                self._inventory_reported.add(self.PCI_DEVICE)
            except exception.SysinvException:
                LOG.exception("Sysinv Agent exception updating pci_device.")
                pass

    def _get_kernel_running(self):
        """Get the running kernel
           Examples:
           lowlatency - 5.10.0-6-rt-amd64
           standard   - 5.10.0-6-amd64
        Returns:
            str: running kernel either standard or lowlatency
        """
        kernel_release = os.uname().release
        if '-rt-' in kernel_release:
            kernel_running = constants.KERNEL_LOWLATENCY
        else:
            kernel_running = constants.KERNEL_STANDARD
        return kernel_running

    def _report_cstates_and_frequency_update(self, context, rpcapi=None):
        """Report to conductor the minimum frequency, maximum frequency and
        cstates.
        """
        if not self._ihost_uuid:
            return

        freq_dict = {}
        try:
            min_freq = self._get_min_cpu_mhz_allowed()
            self._ihost_min_cpu_mhz_allowed = min_freq

            max_freq = self._get_max_cpu_mhz_allowed()
            self._ihost_max_cpu_mhz_allowed = max_freq

            freq_dict.update({
                constants.IHOST_MIN_CPU_MHZ_ALLOWED: min_freq,
                constants.IHOST_MAX_CPU_MHZ_ALLOWED: max_freq
            })

            if os.path.isfile(os.path.join(constants.CSTATE_PATH, "state0/name")):
                cstates_names = self._get_cstates_names()
                self._ihost_cstates_available = ','.join(cstates_names)
                freq_dict.update({
                    constants.IHOST_CSTATES_AVAILABLE: ','.join(cstates_names)
                })

        except OSError as ex:
            LOG.warning("Something wrong occurs during the cpu frequency"
                        f" search. {ex}")
            return

        if len(freq_dict) == 0:
            return

        if rpcapi is None:
            rpcapi = conductor_rpcapi.ConductorAPI(
                topic=conductor_rpcapi.MANAGER_TOPIC)

        LOG.info(f"Reporting CStates or Frequency changes {self._ihost_uuid}"
                 f" -> {freq_dict}")
        rpcapi.cstates_and_frequency_update_by_ihost(context,
                                                     self._ihost_uuid,
                                                     freq_dict)

    def ihost_inv_get_and_report(self, icontext):
        """Collect data for an ihost.

        This method allows an ihost data to be collected.

        :param:   icontext: an admin context
        :returns: updated ihost object, including all fields.
        """

        ihost = None
        mgmt_addr = None
        rpcapi = conductor_rpcapi.ConductorAPI(
            topic=conductor_rpcapi.MANAGER_TOPIC)

        port_list, pci_device_list, host_macs = self._get_ports_inventory()

        # get my ihost record which should be avail since booted
        LOG.debug('Sysinv Agent host_macs={} '.format(
            host_macs))

        rpc_timeout = False
        rpc_success = False
        wait_time = timeutils.utcnow()
        while (timeutils.utcnow() - wait_time).total_seconds() < MAXSLEEP:
            # wait for controller to come up first may be a DOR
            try:
                ihost = rpcapi.get_ihost_by_macs(icontext, host_macs)

            except Timeout:
                if not rpc_timeout:
                    rpc_timeout = True
                    LOG.info("get_ihost_by_macs rpc Timeout.")
                time.sleep(5)  # avoid calling timedout RPC in sequence
                continue
            except Exception:
                LOG.warn("Conductor RPC get_ihost_by_macs exception "
                         "response")

            if not ihost:
                hostname = socket.gethostname()
                if hostname != constants.LOCALHOST_HOSTNAME:
                    try:
                        ihost = rpcapi.get_ihost_by_hostname(icontext,
                                                             hostname)
                    except Timeout:
                        if not rpc_timeout:
                            rpc_timeout = True
                            LOG.info("get_ihost_by_hostname rpc Timeout.")
                        time.sleep(5)  # avoid calling timedout RPC in sequence
                        continue
                    except Exception as ex:
                        LOG.warn("Conductor RPC get_ihost_by_hostname "
                                 "exception response %s" % ex)

            if ihost:
                ipersonality = ihost.get('personality') or ""
                if not mgmt_addr:
                    try:
                        mgmt_addr = rpcapi.get_address_by_host_networktype(
                            icontext, ihost.get('hostname'), constants.NETWORK_TYPE_MGMT)
                    except Timeout:
                        if not rpc_timeout:
                            rpc_timeout = True
                            LOG.info("get_address_by_host_networktype rpc Timeout.")
                        time.sleep(5)  # avoid calling timedout RPC in sequence
                        continue
                    except RemoteError:
                        try:
                            # active controller is running an old release
                            # without get_address_by_host_networktype RPC
                            mgmt_addr = ihost['mgmt_ip']
                            LOG.info("get_address_by_host_networktype rpc RemoteError."
                                     "using mgmt_ip from ihost: {}".format(mgmt_addr))
                        except Exception:
                            LOG.warn("ihost_inv_get_and_report: ihost does not have "
                                     "mgmt_ip")

                    except Exception as ex:
                        LOG.warn("Conductor RPC get_address_by_host_networktype "
                                 "exception response %s" % ex)

            if ihost and ipersonality:
                self._ihost_uuid = ihost['uuid']
                self._ihost_personality = ihost['personality']
                self._mgmt_ip = mgmt_addr
                self._hostname = ihost['hostname']
                self._ihost_rootfs_device = ihost['rootfs_device']
                # new fields in ihost: cstates_available and min_cpu_mhz_allowed
                # TODO: These checks are only required for upgrade from version stx8.0.
                #       They can be removed in future releases.
                self._ihost_cstates_available = \
                    ihost.get('cstates_available') if 'cstates_available' in ihost else None
                self._ihost_min_cpu_mhz_allowed = \
                    ihost.get('min_cpu_mhz_allowed') if 'min_cpu_mhz_allowed' in ihost else 0
                self._ihost_max_cpu_mhz_allowed = ihost.get('max_cpu_mhz_allowed') or 0

                if os.path.isfile(tsc.PLATFORM_CONF_FILE):
                    # read the platform config file and check for UUID
                    found = False
                    with open(tsc.PLATFORM_CONF_FILE, "r") as fd:
                        for line in fd:
                            if line.find("UUID=") == 0:
                                found = True
                    if not found:
                        # the UUID is not found, append it
                        with open(tsc.PLATFORM_CONF_FILE, "a") as fd:
                            fd.write("UUID=" + self._ihost_uuid + "\n")

                # Report host install status
                msg_dict = {}
                self.platform_update_by_host(rpcapi,
                                             icontext,
                                             self._ihost_uuid,
                                             msg_dict)
                rpc_success = True
                LOG.info("Agent found matching ihost: %s" % ihost['uuid'])
                break

            time.sleep(30)

        if rpc_timeout:
            if rpc_success:
                LOG.info("get_ihost recovered from RPC timeout.")
            else:
                LOG.info("get_ihost failed due RPC timeout.")

        if not self._report_to_conductor() or ihost is None:
            # let the audit take care of it instead
            LOG.info("Sysinv no matching ihost found... await Audit")
            return

        # update the load first. This ensures the conductor knows the version
        # of the agent for the rest of inventory calls
        try:
            rpcapi.load_update_by_host(icontext, ihost['uuid'], tsc.SW_VERSION)
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception updating load conductor.")
            pass

        subfunctions = self.subfunctions_get()
        try:
            rpcapi.subfunctions_update_by_ihost(icontext,
                                                ihost['uuid'],
                                                subfunctions)
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception updating subfunctions "
                          "conductor.")
            pass

        self._report_port_inventory(icontext, rpcapi,
                                    port_list, pci_device_list)

        # Find list of numa_nodes and cpus for this ihost
        inumas, icpus = self._inode_operator.inodes_get_inumas_icpus()

        try:
            # may get duplicate key if already sent on earlier init
            rpcapi.inumas_update_by_ihost(icontext,
                                          ihost['uuid'],
                                          inumas)
            self._inventory_reported.add(self.NUMA)
        except RemoteError as e:
            LOG.error("inumas_update_by_ihost RemoteError exc_type=%s" %
                      e.exc_type)

        force_grub_update = self._force_grub_update()
        try:
            # may get duplicate key if already sent on earlier init
            rpcapi.icpus_update_by_ihost(icontext,
                                         ihost['uuid'],
                                         icpus,
                                         force_grub_update)
            self._inventory_reported.add(self.CPU)
        except RemoteError as e:
            LOG.error("icpus_update_by_ihost RemoteError exc_type=%s" %
                      e.exc_type)

        imemory = self._inode_operator.inodes_get_imemory()
        if imemory:
            try:
                # may get duplicate key if already sent on earlier init
                rpcapi.imemory_update_by_ihost(icontext,
                                               ihost['uuid'],
                                               imemory)
                self._inventory_reported.add(self.MEMORY)
            except RemoteError as e:
                LOG.error("imemory_update_by_ihost RemoteError exc_type=%s" %
                          e.exc_type)
                # Allow the audit to update
                pass
            except exception.SysinvException:
                LOG.exception("Sysinv Agent exception updating imemory "
                              "conductor.")
                pass

        idisk = self._idisk_operator.idisk_get()
        try:
            rpcapi.idisk_update_by_ihost(icontext,
                                         ihost['uuid'],
                                         idisk)
            self._inventory_reported.add(self.DISK)
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception updating idisk conductor.")
            pass

        self._update_disk_partitions(rpcapi, icontext,
                                     ihost['uuid'], force_update=True, first_report=True)

        ipv = self._ipv_operator.ipv_get()
        try:
            rpcapi.ipv_update_by_ihost(icontext,
                                       ihost['uuid'],
                                       ipv)
            self._inventory_reported.add(self.PV)
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception updating ipv conductor.")
            pass

        host_fs = self._host_fs_operator.ilv_get_supported_hostfs()
        try:
            rpcapi.hostfs_update_by_ihost(icontext,
                                          ihost['uuid'],
                                          host_fs)
            self._inventory_reported.add(self.HOST_FILESYSTEMS)
        except RemoteError as e:
            # ignore because active controller is not yet upgraded,
            # so it's current load may not implement this RPC call
            if "NameError" in str(e):
                LOG.warn("Skip report host filesystems. "
                            "Upgrade in progress.")
                self._inventory_reported.add(self.HOST_FILESYSTEMS)
            else:
                LOG.exception(f"Failed to report host filesystems update: {e}")
            pass
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception updating host_fs conductor.")
            pass

        ilvg = self._ilvg_operator.ilvg_get()
        try:
            rpcapi.ilvg_update_by_ihost(icontext,
                                        ihost['uuid'],
                                        ilvg)
            self._inventory_reported.add(self.LVG)
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception updating ilvg conductor.")
            pass

        kernel_running = self._get_kernel_running()
        try:
            rpcapi.report_kernel_running(icontext,
                                         ihost['uuid'],
                                         kernel_running)
            self._inventory_reported.add(self.KERNEL)
        except RemoteError as e:
            LOG.error("report_kernel_running "
                      f"RemoteError exc_type={e.exc_type}")
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception updating kernel conductor.")
            pass

        if constants.WORKER in self.subfunctions_list_get():
            platform_interfaces = []
            # retrieve the mgmt interfaces and associated numa nodes
            try:
                platform_interfaces = rpcapi.get_platform_interfaces(icontext,
                                                                     ihost['id'])
            except exception.SysinvException:
                LOG.exception("Sysinv Agent exception getting platform interfaces.")
                pass
            self._update_interface_irq_affinity(self, platform_interfaces)

        # Ensure subsequent unlocks are faster
        nova_lvgs = rpcapi.ilvg_get_nova_ilvg_by_ihost(icontext, self._ihost_uuid)
        if self._ihost_uuid and \
           os.path.isfile(tsc.INITIAL_CONFIG_COMPLETE_FLAG):
            if not self._report_to_conductor_iplatform_avail_flag and \
               not self._wait_for_nova_lvg(icontext, rpcapi, self._ihost_uuid, nova_lvgs):
                imsg_dict = {'availability': constants.AVAILABILITY_AVAILABLE}

                config_uuid = self.iconfig_read_config_applied()
                imsg_dict.update({'config_applied': config_uuid})

                self.platform_update_by_host(rpcapi,
                                             icontext,
                                             self._ihost_uuid,
                                             imsg_dict)

                self._report_to_conductor_iplatform_avail()
                self._iconfig_read_config_reported = config_uuid

    def subfunctions_get(self):
        """ returns subfunctions on this host.
        """

        self._subfunctions = ','.join(tsc.subfunctions)

        return self._subfunctions

    @staticmethod
    def subfunctions_list_get():
        """ returns list of subfunctions on this host.
        """
        subfunctions = ','.join(tsc.subfunctions)
        subfunctions_list = subfunctions.split(',')

        return subfunctions_list

    def subfunctions_configured(self, subfunctions_list):
        """ Determines whether subfunctions configuration is completed.
            return: Bool whether subfunctions configuration is completed.
        """
        if (constants.CONTROLLER in subfunctions_list and
                constants.WORKER in subfunctions_list):
            if not os.path.exists(tsc.INITIAL_WORKER_CONFIG_COMPLETE):
                self._subfunctions_configured = False
                return False

        self._subfunctions_configured = True
        return True

    def notify_initial_inventory_completed(self, context):
        """Report the inventory completion event for this host to the
        conductor when the conditions for inventory complete have
        been met.

        :param context: an admin context
        """
        def _conditions_for_inventory_complete_met():
            # NOTE: condition(s) for inventory complete must be
            # reviewed for update when additional inventory is posted.
            reports_required = \
                self.INVENTORY_REPORTS_REQUIRED - self._inventory_reported
            if not reports_required:
                return True
            else:
                LOG.info("_conditions_for_inventory_complete_met requires %s" %
                         reports_required)
                return False

        if self._inventory_reported:
            utils.touch(constants.SYSINV_REPORTED)

        if (_conditions_for_inventory_complete_met() and not
                self._inventoried_initial):
            LOG.info("Initial inventory completed host %s" %
                     self._ihost_uuid)
            rpcapi = conductor_rpcapi.ConductorAPI(
                topic=conductor_rpcapi.MANAGER_TOPIC)

            rpcapi.initial_inventory_completed(context,
                                               self._ihost_uuid)
            self._inventoried_initial = True

    def _report_config_applied(self, context, config_dict=None, status=None, error=None):
        """Report the latest configuration applied for this host to the
        conductor.
        :param context: an admin context
        :param config_dict: configuration applied
        :param status: config status
        :param error: config error
        """
        rpcapi = conductor_rpcapi.ConductorAPI(
            topic=conductor_rpcapi.MANAGER_TOPIC)

        config_uuid = self.iconfig_read_config_applied()
        if config_uuid != self._iconfig_read_config_reported:
            LOG.info("Agent config applied  %s" % config_uuid)

            imsg_dict = {'config_applied': config_uuid}
            if config_dict:
                imsg_dict.update({'config_dict': config_dict,
                                  'status': status,
                                  'error': error})
            rpcapi.iconfig_update_by_ihost(context,
                                           self._ihost_uuid,
                                           imsg_dict)

            self._iconfig_read_config_reported = config_uuid

    @staticmethod
    def _update_config_applied(config_uuid):
        """
        Write the latest applied configuration.
        :param config_uuid: The configuration UUID
        """
        config_applied = "CONFIG_UUID=" + str(config_uuid)
        with open(CONFIG_APPLIED_FILE, 'w') as fc:
            fc.write(config_applied)

    @staticmethod
    def _wait_for_nova_lvg(icontext, rpcapi, ihost_uuid, nova_lvgs=None):
        """See if we wait for a provisioned nova-local volume group

        This method queries the conductor to see if we are provisioning
        a nova-local volume group on this boot cycle. This check is used
        to delay sending the platform availability to the conductor.

        :param:   icontext: an admin context
        :param:   rpcapi: conductor rpc api
        :param:   ihost_uuid: an admin context
        :returns: True if we are provisioning false otherwise
        """
        rc = False
        if not nova_lvgs:
            nova_lvgs = rpcapi.ilvg_get_nova_ilvg_by_ihost(icontext, ihost_uuid)

        for volume in nova_lvgs:
            if (volume.lvm_vg_name == constants.LVG_NOVA_LOCAL and
                    volume.vg_state == constants.LVG_ADD):

                LOG.info("_wait_for_nova_lvg: Must wait before reporting node "
                            "availability. Conductor sees unprovisioned "
                            "nova-local state. Would result in an invalid host "
                            "aggregate assignment.")
                rc = True

        return rc

    def _is_config_complete(self):
        """Check if this node has completed config

        This method queries node's config flag file to see if it has
        complete config.
        :return: True if the complete flag file exists false otherwise
        """
        if not os.path.isfile(tsc.INITIAL_CONFIG_COMPLETE_FLAG):
            return False
        subfunctions = self.subfunctions_list_get()
        if constants.CONTROLLER in subfunctions:
            if not os.path.isfile(tsc.INITIAL_CONTROLLER_CONFIG_COMPLETE):
                return False
        if constants.WORKER in subfunctions:
            if not os.path.isfile(tsc.INITIAL_WORKER_CONFIG_COMPLETE):
                return False
        if constants.STORAGE in subfunctions:
            if not os.path.isfile(tsc.INITIAL_STORAGE_CONFIG_COMPLETE):
                return False
        return True

    def _create_host_filesystems(self, rpcapi, icontext):
        # Create the hosts filesystems for kubelet, docker, backup, scratch

        filesystems = []

        if self._prev_fs is not None:
            # Skip if host filesystems already exists
            return

        try:
            # Get the supported filesystems for this host with default
            # sizes
            kubelet_lv_size = constants.KUBELET_STOR_SIZE
            docker_lv_size = constants.KUBERNETES_DOCKER_STOR_SIZE

            disk_size = utils.get_disk_capacity_mib(self._ihost_rootfs_device)
            disk_size = int(disk_size // 1024)

            # Get the distributed cloud role to determine filesystems size
            # Will first try to get it with tsconfig (local platform.conf file)
            # and if not available will try getting it with a RPC call
            system_dc_role = tsc.distributed_cloud_role
            system_type = tsc.system_type
            if not system_dc_role:
                try:
                    system = rpcapi.get_isystem(icontext)
                    system_dc_role = system.get("distributed_cloud_role", None)
                    system_type = system.get("system_type", None)
                except AttributeError:
                    # safe to ignore during upgrades
                    LOG.warn("Skip getting system DC role and system type. "
                             "Upgrade in progress?")

            if self._ihost_personality == constants.CONTROLLER:
                if disk_size > constants.DEFAULT_SMALL_DISK_SIZE:
                    LOG.info("Disk size for %s: %s ... large disk defaults" %
                             (self._ihost_rootfs_device, disk_size))

                    platform_lv_size = constants.DEFAULT_PLATFORM_STOR_SIZE
                    if (system_dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER and
                            system_type == constants.TIS_STD_BUILD):
                        platform_lv_size = constants.DEFAULT_PLATFORM_SYSTEMCONTROLLER_STOR_SIZE

                    backup_lv_size = \
                        constants.DEFAULT_DATABASE_STOR_SIZE + \
                        platform_lv_size + \
                        constants.BACKUP_OVERHEAD

                elif disk_size >= constants.MINIMUM_SMALL_DISK_SIZE:
                    LOG.info("Disk size for %s : %s ... small disk defaults" %
                             (self._ihost_rootfs_device, disk_size))

                    # Due to the small size of the disk we can't provide the
                    # proper amount of backup space which is (database +
                    # platform_lv + BACKUP_OVERHEAD) so we are using a smaller
                    # default.
                    backup_lv_size = constants.DEFAULT_SMALL_BACKUP_STOR_SIZE

                elif (disk_size >= constants.MINIMUM_TINY_DISK_SIZE and
                    rpcapi.is_virtual_system_config(icontext) and
                        tsc.system_type == constants.TIS_AIO_BUILD):
                    # Supports StarlingX running in QEMU/KVM VM with a tiny
                    # disk (AIO only)
                    LOG.info("Disk size for %s : %s ... tiny disk defaults "
                             "for virtual system configuration" %
                             (self._ihost_rootfs_device, disk_size))
                    kubelet_lv_size = constants.TINY_KUBELET_STOR_SIZE
                    docker_lv_size = constants.TINY_KUBERNETES_DOCKER_STOR_SIZE
                    backup_lv_size = constants.DEFAULT_TINY_BACKUP_STOR_SIZE

                else:
                    LOG.info("Disk size for %s : %s ... disk too small" %
                             (self._ihost_rootfs_device, disk_size))
                    raise exception.SysinvException(
                        "Disk size requirements not met.")

            # check if the scratch fs is supported for current host
            if utils.is_filesystem_supported(constants.FILESYSTEM_NAME_SCRATCH,
                                             self._ihost_personality):
                scratch_lv_size = utils.get_current_fs_size("scratch")
                data = {
                    'name': constants.FILESYSTEM_NAME_SCRATCH,
                    'size': scratch_lv_size,
                    'logical_volume': constants.FILESYSTEM_LV_DICT[
                        constants.FILESYSTEM_NAME_SCRATCH]
                }
                filesystems.append(data)

            # check if the backup fs is supported for current host
            if utils.is_filesystem_supported(constants.FILESYSTEM_NAME_BACKUP,
                                             self._ihost_personality):
                data = {
                    'name': constants.FILESYSTEM_NAME_BACKUP,
                    'size': backup_lv_size,
                    'logical_volume': constants.FILESYSTEM_LV_DICT[
                        constants.FILESYSTEM_NAME_BACKUP]
                }
                filesystems.append(data)

            # check if the docker fs is supported for current host
            if utils.is_filesystem_supported(constants.FILESYSTEM_NAME_DOCKER,
                                             self._ihost_personality):
                data = {
                    'name': constants.FILESYSTEM_NAME_DOCKER,
                    'size': docker_lv_size,
                    'logical_volume': constants.FILESYSTEM_LV_DICT[
                        constants.FILESYSTEM_NAME_DOCKER]
                }
                filesystems.append(data)

            # check if the kubelet fs is supported for current host
            if utils.is_filesystem_supported(constants.FILESYSTEM_NAME_KUBELET,
                                             self._ihost_personality):
                data = {
                    'name': constants.FILESYSTEM_NAME_KUBELET,
                    'size': kubelet_lv_size,
                    'logical_volume': constants.FILESYSTEM_LV_DICT[
                        constants.FILESYSTEM_NAME_KUBELET]
                }
                filesystems.append(data)

            if utils.is_filesystem_supported(constants.FILESYSTEM_NAME_LOG,
                                            self._ihost_personality):
                log_lv_size = utils.get_current_fs_size("log")
                data = {
                    'name': constants.FILESYSTEM_NAME_LOG,
                    'size': log_lv_size,
                    'logical_volume': constants.FILESYSTEM_LV_DICT[
                        constants.FILESYSTEM_NAME_LOG]
                }
                filesystems.append(data)

            if utils.is_filesystem_supported(constants.FILESYSTEM_NAME_VAR,
                                            self._ihost_personality):
                var_lv_size = \
                        utils.get_current_fs_size(constants.FILESYSTEM_NAME_VAR)
                data = {
                    'name': constants.FILESYSTEM_NAME_VAR,
                    'size': var_lv_size,
                    'logical_volume': constants.FILESYSTEM_LV_DICT[
                        constants.FILESYSTEM_NAME_VAR]
                }
                filesystems.append(data)

            if utils.is_filesystem_supported(constants.FILESYSTEM_NAME_ROOT,
                                             self._ihost_personality):
                root_lv_size = utils.get_current_fs_size("root")
                data = {
                    'name': constants.FILESYSTEM_NAME_ROOT,
                    'size': root_lv_size,
                    'logical_volume': constants.FILESYSTEM_LV_DICT[
                        constants.FILESYSTEM_NAME_ROOT]
                }
                filesystems.append(data)

            if filesystems:
                # Create the filesystems if they do not already exist.
                # This audit does not check if the fs size has changed.
                # Doing so would interfere with the resizes done via
                # the HostFs API
                rpcapi.create_host_filesystems(
                    icontext, self._ihost_uuid, filesystems)
                self._prev_fs = filesystems

        except Exception as e:
            LOG.exception(
                "Sysinv Agent exception creating the host filesystems."
                " %s" % e)
            self._prev_fs = None

    @utils.synchronized(constants.PARTITION_MANAGE_LOCK)
    def _update_disk_partitions(self, rpcapi, icontext,
                                host_uuid, force_update=False, first_report=False):
        ipartition = self._ipartition_operator.ipartition_get()
        if not force_update:
            if self._prev_partition == ipartition:
                return
            self._prev_partition = ipartition
        try:
            rpcapi.ipartition_update_by_ihost(
                icontext, host_uuid, ipartition, first_report)
        except AttributeError:
            # safe to ignore during upgrades
            LOG.warn("Skip updating ipartition conductor. "
                     "Upgrade in progress?")
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception updating "
                          "ipartition conductor.")
            if not force_update:
                self._prev_partition = None

    @periodic_task.periodic_task(spacing=CONF.agent_periodic_task_intervals.inventory_audit,
                                 run_immediately=True)
    def _inventory_audit(self, context):
        # periodically, perform inventory audit
        self.agent_audit(context, host_uuid=self._ihost_uuid,
                         force_updates=None)

    @periodic_task.periodic_task(spacing=CONF.agent_periodic_task_intervals.lldp_audit)
    def _lldp_audit(self, context):

        if not self._ihost_uuid:
            return

        LOG.debug("SysInv Agent LLDP Audit running.")

        icontext = mycontext.get_admin_context()
        rpcapi = conductor_rpcapi.ConductorAPI(topic=conductor_rpcapi.MANAGER_TOPIC)

        if self._is_config_complete():
            self.host_lldp_get_and_report(icontext, rpcapi, self._ihost_uuid)
        else:
            self._lldp_enable_and_report(icontext, rpcapi, self._ihost_uuid)

    @periodic_task.periodic_task(spacing=CONF.agent_periodic_task_intervals.security_audit)
    def _security_audit(self, context):
        if not self._ihost_uuid:
            return

        # only allow audit if host is inventoried and ready
        # to receive puppet runtime configuration requests
        if not self._inventoried_initial:
            return

        LOG.debug("Sysinv Agent Security Audit running.")

        # get sysadmin password locally
        with open("/etc/shadow", "r") as f:
            user_attrs = []
            lines = f.readlines()
            for line in lines:
                if "sysadmin" in line:
                    user_attrs = line.split(":")
                    break
            if not user_attrs:
                LOG.warn("No shadow entry found for 'sysadmin' user.")
                return

        icontext = mycontext.get_admin_context()
        rpcapi = conductor_rpcapi.ConductorAPI(topic=conductor_rpcapi.MANAGER_TOPIC)

        # get user information from the database
        try:
            iuser = rpcapi.get_iuser(icontext)
        except RemoteError as e:
            # ignore because active controller is not yet upgraded,
            # so it's current load may not implement this RPC call
            if "AttributeError" in str(e):
                LOG.warn("Skip security audit. Upgrade in progress.")
            else:
                LOG.error("Failed to get user configuration via RPC.")
            return
        if not iuser.passwd_hash:
            LOG.warn("No password configured for 'sysadmin' in the database.")
            return

        # compare sysadmin password hash with the value retrieved from the
        # database and trigger user config manifest reapply if values differ
        if iuser.passwd_hash != user_attrs[1]:
            LOG.info("Configuration mismatch for 'sysadmin' user, attempting to reconfigure...")
            rpcapi.update_user_config(icontext, [self._ihost_uuid])
        else:
            LOG.debug("No divergence found within 'sysadmin' user configuration.")

    @utils.synchronized(LOCK_AGENT_ACTION, external=False)
    def agent_audit(self, context, host_uuid, force_updates, cinder_device=None):
        # perform inventory audit
        if self._ihost_uuid != host_uuid:
            # The function call is not for this host agent
            return

        icontext = mycontext.get_admin_context()
        rpcapi = conductor_rpcapi.ConductorAPI(topic=conductor_rpcapi.MANAGER_TOPIC)

        if self._ihost_uuid:
            if os.path.isfile(tsc.INITIAL_CONFIG_COMPLETE_FLAG):
                self._report_config_applied(icontext)

        if self._report_to_conductor():
            LOG.info("Sysinv Agent audit running inv_get_and_report.")
            self.ihost_inv_get_and_report(icontext)

        if self._ihost_uuid:
            try:
                nova_lvgs = rpcapi.ilvg_get_nova_ilvg_by_ihost(icontext, self._ihost_uuid)
            except Timeout:
                LOG.info("ilvg_get_nova_ilvg_by_ihost() Timeout.")
                nova_lvgs = None

        if self._ihost_uuid and \
           os.path.isfile(tsc.INITIAL_CONFIG_COMPLETE_FLAG):
            imsg_dict = {}
            if not self._report_to_conductor_iplatform_avail_flag and \
               not self._wait_for_nova_lvg(icontext, rpcapi, self._ihost_uuid, nova_lvgs):
                imsg_dict = {'availability': constants.AVAILABILITY_AVAILABLE}

                config_uuid = self.iconfig_read_config_applied()
                imsg_dict.update({'config_applied': config_uuid})

                if self._ihost_personality == constants.CONTROLLER:
                    idisk = self._idisk_operator.idisk_get()
                    try:
                        rpcapi.idisk_update_by_ihost(icontext,
                                                     self._ihost_uuid,
                                                     idisk)
                        self._inventory_reported.add(self.DISK)
                    except exception.SysinvException:
                        LOG.exception("Sysinv Agent exception updating idisk "
                                      "conductor.")
                        pass

                self._report_to_conductor_iplatform_avail()
                self._iconfig_read_config_reported = config_uuid

            iscsi_initiator_name = self.get_host_iscsi_initiator_name()
            nvme_host_id = self.get_host_nvme_host_id()
            nvme_host_nqn = self.get_host_nvme_host_nqn()

            if iscsi_initiator_name is not None:
                imsg_dict.update({'iscsi_initiator_name': iscsi_initiator_name})
            if nvme_host_id is not None:
                imsg_dict.update({'nvme_host_id': nvme_host_id})
            if nvme_host_nqn is not None:
                imsg_dict.update({'nvme_host_nqn': nvme_host_nqn})

            self.platform_update_by_host(rpcapi,
                                         icontext,
                                         self._ihost_uuid,
                                         imsg_dict)

        if self._ihost_uuid:
            LOG.debug("SysInv Agent Inventory Audit running.")

            if force_updates:
                LOG.info("SysInv Agent Inventory Audit force updates: (%s)" %
                         (', '.join(force_updates)))

            imemory = self._inode_operator.inodes_get_imemory()
            rpcapi.imemory_update_by_ihost(icontext,
                                           self._ihost_uuid,
                                           imemory)
            self._inventory_reported.add(self.MEMORY)

            # if this audit is requested by conductor, clear
            # previous states for disk, lvg, pv and fs to force an update
            if force_updates:
                if constants.DISK_AUDIT_REQUEST in force_updates:
                    self._prev_disk = None
                if constants.LVG_AUDIT_REQUEST in force_updates:
                    self._prev_lvg = None
                if constants.PV_AUDIT_REQUEST in force_updates:
                    self._prev_pv = None
                if constants.PARTITION_AUDIT_REQUEST in force_updates:
                    self._prev_partition = None
                if constants.FILESYSTEM_AUDIT_REQUEST in force_updates:
                    self._prev_fs = None

            # Update disks
            idisk = self._idisk_operator.idisk_get()
            if ((self._prev_disk is None) or
                    (self._prev_disk != idisk)):
                self._prev_disk = idisk
                try:
                    rpcapi.idisk_update_by_ihost(icontext,
                                                 self._ihost_uuid,
                                                 idisk)
                    self._inventory_reported.add(self.DISK)
                except exception.SysinvException:
                    LOG.exception("Sysinv Agent exception updating idisk"
                                  "conductor.")
                    self._prev_disk = None

            # Update disk partitions
            if self._ihost_personality != constants.STORAGE:
                self._update_disk_partitions(rpcapi, icontext, self._ihost_uuid)

            # Update local volume groups
            ilvg = self._ilvg_operator.ilvg_get(cinder_device=cinder_device)
            if ((self._prev_lvg is None) or
                    (self._prev_lvg != ilvg)):
                self._prev_lvg = ilvg
                try:
                    rpcapi.ilvg_update_by_ihost(icontext,
                                                self._ihost_uuid,
                                                ilvg)
                    self._inventory_reported.add(self.LVG)
                except exception.SysinvException:
                    LOG.exception("Sysinv Agent exception updating ilvg"
                                  "conductor.")
                    self._prev_lvg = None
                    pass

            # Update physical volumes
            ipv = self._ipv_operator.ipv_get(cinder_device=cinder_device)
            if ((self._prev_pv is None) or
                    (self._prev_pv != ipv)):
                self._prev_pv = ipv
                try:
                    rpcapi.ipv_update_by_ihost(icontext,
                                               self._ihost_uuid,
                                               ipv)
                    self._inventory_reported.add(self.PV)
                except exception.SysinvException:
                    LOG.exception("Sysinv Agent exception updating ipv"
                                  "conductor.")
                    self._prev_pv = None
                    pass

            self._create_host_filesystems(rpcapi, icontext)

            # Update host filesystems
            host_fs = self._host_fs_operator.ilv_get_supported_hostfs()
            if ((self._prev_fs is None) or
                    (self._prev_fs != host_fs)):
                self._prev_fs = host_fs
            try:
                rpcapi.hostfs_update_by_ihost(icontext,
                                              self._ihost_uuid,
                                              host_fs)
                self._inventory_reported.add(self.HOST_FILESYSTEMS)
            except RemoteError as e:
                # ignore because active controller is not yet upgraded,
                # so it's current load may not implement this RPC call
                if "NameError" in str(e):
                    LOG.warn("Skip report host filesystems. "
                                "Upgrade in progress.")
                    self._inventory_reported.add(self.HOST_FILESYSTEMS)
                else:
                    LOG.exception(f"Failed to report host filesystems update: {e}")
                pass
            except exception.SysinvException:
                LOG.exception("Sysinv Agent exception updating host_fs"
                                " conductor.")
                self._prev_fs = None
                pass

            # Collect FPGA PCI data for this host.
            # We know that the PCI address of the N3000 can change the first time
            # We reset it after boot, so we need to gather the new PCI device
            # information and send it to sysinv-conductor.
            # This needs to exactly mirror what sysinv-agent does as far as PCI
            # updates.  We could potentially modify sysinv-agent to do the PCI
            # updates when triggered by an RPC cast, but we don't need to rescan
            # all PCI devices, just the N3000 devices.
            if os.path.exists(fpga_constants.N3000_RESET_FLAG) and \
                    self._report_to_conductor_fpga_info:
                LOG.info("Found n3000 reset flag, continuing.")
                LOG.info("Updating N3000 PCI info.")
                pci_device_list = self._ifpga_operator.get_n3000_pci_info()
                try:
                    if pci_device_list:
                        LOG.info("reporting N3000 PCI devices for host %s: %s" %
                                (self._ihost_uuid, pci_device_list))

                        # Don't ask conductor to cleanup stale entries while worker
                        # manifest is not complete. For N3000 device, it could get rid
                        # of a valid entry with a different PCI address but restored
                        # from previous database backup
                        cleanup_stale = \
                            os.path.exists(tsc.VOLATILE_WORKER_CONFIG_COMPLETE)
                        rpcapi.pci_device_update_by_host(icontext,
                                                        self._ihost_uuid,
                                                        pci_device_list,
                                                        cleanup_stale)
                except Exception:
                    LOG.exception("Exception updating n3000 PCI devices, "
                                "this will likely cause problems.")
                    pass

                # Collect FPGA data for this host.
                fpgainfo_list = self._ifpga_operator.get_fpga_info()
                LOG.info("reporting FPGA inventory for host %s: %s" %
                        (self._ihost_uuid, fpgainfo_list))
                try:
                    rpcapi.fpga_device_update_by_host(icontext, self._ihost_uuid, fpgainfo_list)
                    self._report_to_conductor_fpga_info = False
                except exception.SysinvException:
                    LOG.exception("Exception updating fpga devices.")
                    pass

            if self._report_to_conductor_cstate_info:
                try:
                    self._report_cstates_and_frequency_update(icontext, rpcapi)
                    self._report_to_conductor_cstate_info = False
                except RemoteError as e:
                    # ignore because active controller is not yet upgraded,
                    # so it's current load may not implement this RPC call
                    if "AttributeError" in str(e):
                        LOG.warn("Skip report cstates and frequency update. "
                                 "Upgrade in progress.")
                    else:
                        LOG.exception(f"Failed to report cstates and frequency update: {e}")
                except exception.SysinvException as ex:
                    LOG.exception("Sysinv Agent exception "
                                  f"reporting cstates and frequency update: "
                                  f"{ex}")

            # if the platform firewall failed to be applied (by not having kube-api available
            # during AIO manifest execution or lack of config in the host yaml file) ask for
            # conductor to reapply
            if os.path.isfile(constants.PLATFORM_FIREWALL_CONFIG_REQUIRED):
                try:
                    LOG.info("platform firewall config requested")
                    rpcapi.request_firewall_runtime_update(icontext, self._ihost_uuid)
                except Exception:
                    LOG.exception("Exception when requesting platform firewall config")
                    pass

            # Notify conductor of inventory completion after necessary
            # inventory reports have been sent to conductor.
            # This is as defined by _conditions_for_inventory_complete_met().
            self.notify_initial_inventory_completed(icontext)

            self._report_config_applied(icontext)

            if os.path.isfile(tsc.PLATFORM_CONF_FILE):
                # read the platform config file and check for UUID
                if 'UUID' not in open(tsc.PLATFORM_CONF_FILE).read():
                    # the UUID is not in found, append it
                    with open(tsc.PLATFORM_CONF_FILE, "a") as fd:
                        fd.write("UUID=" + self._ihost_uuid)

    def configure_lldp_systemname(self, context, systemname):
        """Configure the systemname into the lldp agent with the supplied data.

        :param context: an admin context.
        :param systemname: the systemname
        """

        rpcapi = conductor_rpcapi.ConductorAPI(
                               topic=conductor_rpcapi.MANAGER_TOPIC)
        # Update the lldp agent
        self._lldp_operator.lldp_update_systemname(systemname)
        # Trigger an audit to ensure the db is up to date
        self.host_lldp_get_and_report(context, rpcapi, self._ihost_uuid)

    def iconfig_update_install_uuid(self, context, host_uuids, install_uuid):
        """Update install_uuid in /etc/platform/platform.conf

        :param context: request context.
        :param host_uuids: The host uuid or list of host uuids to update
                           the install_uuid
        :param install_uuid: The updated install_uuid that will be
        :                    written into /etc/platform/platform.conf
        """

        if (self._ihost_uuid and self._ihost_uuid in host_uuids and
                tsc.install_uuid != install_uuid):
            LOG.info("Updating install_uuid to %s." % install_uuid)
            temp_platform_conf_file = os.path.join(tsc.PLATFORM_CONF_PATH,
                                                   'platform.conf.temp')
            shutil.copyfile(tsc.PLATFORM_CONF_FILE, temp_platform_conf_file)
            for line in fileinput.FileInput(temp_platform_conf_file, inplace=1):
                if line.startswith("INSTALL_UUID="):
                    print("INSTALL_UUID=%s" % install_uuid)
                else:
                    print(line, end='')
            fileinput.close()
            os.rename(temp_platform_conf_file, tsc.PLATFORM_CONF_FILE)

            # Set the install_uuid to the value we just configured.
            tsc.install_uuid = install_uuid

    def _retry_on_personality_is_none(ex):  # pylint: disable=no-self-argument
        LOG.info('Caught exception _retry_on_personality_is_none '
                 'Retrying ... Exception: {}'.format(ex))
        return isinstance(ex, exception.LocalManagementPersonalityNotFound)

    @retrying.retry(wait_fixed=10 * 1000, stop_max_delay=300 * 1000,
                    retry_on_exception=_retry_on_personality_is_none)
    @utils.synchronized(LOCK_AGENT_ACTION, external=False)
    def iconfig_update_file(self, context, iconfig_uuid, iconfig_dict):
        """Configure the iiconfig_uuid, by updating file based upon
           iconfig_dict.

        :param context: request context.
        :param iconfig_uuid: iconfig_uuid,
        :param iconfig_dict: iconfig_dict dictionary of attributes:
        :          {personalities: list of ihost personalities
        :           file_names: list of full path file names
        :           file_content: file contents
        :          }
        :returns: none
        """
        LOG.debug("AgentManager.iconfig_update_file: updating iconfig"
                  " %s %s %s" % (iconfig_uuid, iconfig_dict,
                                 self._ihost_personality))

        permissions = iconfig_dict.get('permissions')
        nobackup = iconfig_dict.get('nobackup')
        if not permissions:
            permissions = constants.CONFIG_FILE_PERMISSION_DEFAULT

        if not self._ihost_personality:
            raise exception.LocalManagementPersonalityNotFound(
                config_uuid=iconfig_uuid, config_dict=iconfig_dict,
                host_personality=self._ihost_personality)

        if self._ihost_personality in iconfig_dict['personalities']:
            file_content = iconfig_dict['file_content']

            if not file_content:
                LOG.info("AgentManager: no file_content %s %s %s" %
                         (iconfig_uuid, iconfig_dict,
                          self._ihost_personality))

            file_names = iconfig_dict['file_names']
            for file_name in file_names:
                file_name_sysinv = file_name + ".sysinv"

                LOG.debug("AgentManager.iconfig_update_file: updating file %s "
                          "with content: %s"
                          % (file_name,
                             iconfig_dict['file_content']))

                if os.path.isfile(file_name):
                    if not nobackup:
                        if not os.path.isfile(file_name_sysinv):
                            shutil.copy2(file_name, file_name_sysinv)

                if isinstance(file_content, dict):
                    f_content = file_content.get(file_name)
                else:
                    f_content = file_content

                if f_content is not None:
                    # create a temporary file to hold the runtime configuration values
                    dirname = os.path.dirname(file_name)
                    basename = os.path.basename(file_name)
                    fd, tmppath = tempfile.mkstemp(dir=dirname, prefix=basename)
                    with os.fdopen(fd, 'wb') as f:
                        f_content = six.ensure_binary(f_content)
                        f.write(f_content)
                    if os.path.islink(file_name):
                        os.unlink(file_name)
                    os.rename(tmppath, file_name)
                    os.chmod(file_name, permissions)

            self._update_config_applied(iconfig_uuid)
            self._report_config_applied(context)

    def _report_inventory(self, context, config_dict):
        inventory_update = config_dict.get(puppet.REPORT_INVENTORY_UPDATE, None)
        LOG.info("report_inventory request=%s" % inventory_update)
        if inventory_update == puppet.REPORT_PCI_SRIOV_CONFIG:
            self._report_port_inventory(context)
        else:
            LOG.error("report_inventory unknown request=%s" % inventory_update)

    def _retry_on_config_exception(ex):  # pylint: disable=no-self-argument
        LOG.info('Caught exception _retry_on_config_exception. '
                 'Retrying... Exception: {}'.format(ex))
        if isinstance(ex, exception.AgentInventoryInfoNotFound):
            return True
        elif isinstance(ex, exception.FilesystemNotFound):
            return True
        return False

    @staticmethod
    def _update_local_puppet_cache(hieradata_path):
        cache_dir = PUPPET_HIERADATA_CACHE_PATH
        cache_dir_temp = cache_dir + '.temp'
        try:
            if os.path.isdir(cache_dir_temp):
                shutil.rmtree(cache_dir_temp)
            shutil.copytree(hieradata_path, cache_dir_temp)
            subprocess.check_call(['sync'])  # pylint: disable=not-callable

            if os.path.isdir(cache_dir):
                shutil.rmtree(cache_dir)
            os.rename(cache_dir_temp, cache_dir)
        except Exception:
            LOG.exception("Failed to update local puppet cache.")
            raise

    @retrying.retry(wait_fixed=15 * 1000, stop_max_delay=300 * 1000,
                    retry_on_exception=_retry_on_config_exception)
    @utils.synchronized(LOCK_AGENT_ACTION, external=False)
    def config_apply_runtime_manifest(self, context, config_uuid, config_dict):
        """Asynchronously, have the agent apply the runtime manifest with the
        list of supplied tasks.

        :param context: request context
        :param config_uuid: configuration uuid
        :param config_dict: dictionary of attributes, such as:
        :          {personalities: personalities to apply
        :           classes:       the list of classes to include in the manifest
        :           host_uuids:    (opt) host or hosts to apply manifests to
                                   string or dict of uuid strings
        :           puppet.REPORT_STATUS_CFG: (opt) name of cfg operation to
                                              report back to sysinv conductor
        :          }
        if puppet.REPORT_STATUS_CFG is set then Sysinv Agent will return the
        config operation status by calling back report_config_status(...).
        :returns: none ... uses asynchronous cast().
        """

        # runtime manifests can not be applied without the initial
        # configuration applied
        force = config_dict.get('force', False)
        if (not force and
                not os.path.isfile(tsc.INITIAL_CONFIG_COMPLETE_FLAG)):
            return

        # The conductor may send requests to this function, before the
        # agent finished its first inventory.
        # We raise the exception in case any of the needed information is
        # missing and the retry decorator will run this function again.
        # NOTE: usually all these parameters are set at the same time
        # during the first inventory, but just to be safe we are
        # checking that all of them are set.
        if (not self._mgmt_ip or
                not self._ihost_uuid or
                not self._ihost_personality):
            raise exception.AgentInventoryInfoNotFound(
                config_uuid=config_uuid, config_dict=config_dict,
                host_personality=self._ihost_personality,
                host_uuid=self._ihost_uuid, mgmt_ip=self._mgmt_ip)

        personalities = config_dict.get('personalities')
        host_uuids = config_dict.get('host_uuids')

        if host_uuids:
            # ignore requests that are not intended for this host
            if self._ihost_uuid not in host_uuids:
                return
        else:
            # ignore requests that are not intended for host personality
            for subfunction in self.subfunctions_list_get():
                if subfunction in personalities:
                    break
            else:
                return

        LOG.info("config_apply_runtime_manifest: %s %s %s" % (
            config_uuid, config_dict, self._ihost_personality))
        try:

            if not os.path.exists(tsc.PUPPET_PATH):
                # we must be controller-standby or storage, mount /var/run/platform
                LOG.info("controller-standby or storage, mount /var/run/platform")
                remote_dir = "controller-platform-nfs:" + tsc.PLATFORM_PATH
                local_dir = os.path.join(tsc.VOLATILE_PATH, 'platform')
                # JK - could also consider mkstemp for atomicity
                if not os.path.exists(local_dir):
                    LOG.info("create local dir '%s'" % local_dir)
                    os.makedirs(local_dir)
                hieradata_path = os.path.join(
                    tsc.PUPPET_PATH.replace(
                        tsc.PLATFORM_PATH, local_dir),
                    'hieradata')
                with utils.mounted(remote_dir, local_dir):
                    self._apply_runtime_manifest(config_dict, hieradata_path=hieradata_path)
            else:
                LOG.info("controller-active")
                self._apply_runtime_manifest(config_dict)
        except OSError:
            # race condition on the mount
            if not os.path.exists(local_dir):
                LOG.warn("OSError encountered, re-create local dir '%s'" % local_dir)
                os.makedirs(local_dir)
                raise exception.FilesystemNotFound(fs_id=local_dir)
        except Exception:
            # We got an error, serialize and return the exception to conductor
            if config_dict.get(puppet.REPORT_STATUS_CFG):
                config_dict['host_uuid'] = self._ihost_uuid
                LOG.info("Manifests application failed. "
                         "Reporting failure to conductor. "
                         "Details: %s." % config_dict)
                error = serialize_remote_exception(sys.exc_info())
                rpcapi = conductor_rpcapi.ConductorAPI(
                    topic=conductor_rpcapi.MANAGER_TOPIC)
                rpcapi.report_config_status(context, config_dict,
                                            status=puppet.REPORT_FAILURE,
                                            error=error)
            raise

        if config_dict.get(puppet.REPORT_INVENTORY_UPDATE):
            self._report_inventory(context, config_dict)

        report_status_config = config_dict.get(puppet.REPORT_STATUS_CFG)
        if report_status_config:
            config_dict['host_uuid'] = self._ihost_uuid
            LOG.info("config runtime manifests application succeeded. "
                     "Reporting %s apply success to conductor." %
                     report_status_config)
            LOG.debug("config runtime details: %s." % config_dict)

            self._report_config_applied(
                context, config_dict, status=puppet.REPORT_SUCCESS, error=None)
        else:
            self._report_config_applied(context)

    def _apply_runtime_manifest(self, config_dict, hieradata_path=PUPPET_HIERADATA_PATH):

        LOG.info("_apply_runtime_manifest with hieradata_path = '%s' " % hieradata_path)

        # create a temporary file to hold the runtime configuration values
        fd, tmpfile = tempfile.mkstemp(suffix='.yaml')

        try:
            config = {
                'classes': config_dict.get('classes', [])
            }
            personalities = config_dict.get('personalities', [])

            personality = None

            for subfunction in self.subfunctions_list_get():
                # We need to find the subfunction that matches the personality
                # being requested. e.g. in AIO systems if we request a worker
                # personality we should apply the manifest with that
                # personality
                if subfunction in personalities:
                    personality = subfunction

            if not personality:
                LOG.error("failed to find 'personality' in host subfunctions")
                return

            with open(tmpfile, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)

            puppet.puppet_apply_manifest(self._hostname,
                                         personality,
                                         'runtime', tmpfile,
                                         hieradata_path=hieradata_path)
            applied_classes = config.get('classes')
            LOG.info('Runtime manifest apply completed for classes %s.' %
                     applied_classes)

            # Following Ansible bootstrap in AIO, grub update manifests must
            # be applied to account for any cpu reconfigurations that might
            # have occurred during initial host bootstrap or configurations.
            #
            # NOTE: Don't create and add new puppet manifests to this list.
            # If there are configurations that must be applied
            #    a) during bootstrap, implement in Ansible playbook
            #    b) during initial host configurations, implement in sysinv
            if (os.path.isfile(constants.ANSIBLE_BOOTSTRAP_FLAG) and
                    applied_classes == ['platform::compute::grub::runtime',
                                        'platform::compute::config::runtime']):
                # Set ready flag for maintenance to proceed with the unlock of
                # the initial controller.
                utils.touch(constants.UNLOCK_READY_FLAG)
            elif (os.path.isfile(tsc.MGMT_NETWORK_RECONFIGURATION_UNLOCK) and
                    applied_classes == ['openstack::keystone::endpoint::reconfig']):
                # Set ready flag for maintenance to proceed with the unlock
                # after mgmt ip reconfiguration
                utils.touch(constants.UNLOCK_READY_FLAG)
        except Exception:
            LOG.exception("failed to apply runtime manifest")
            raise
        finally:
            os.close(fd)
            os.remove(tmpfile)
            # Update local puppet cache anyway to be consistent.
            self._update_local_puppet_cache(hieradata_path)

    def delete_load(self, context, host_uuid, software_version):
        """Remove the specified load

        :param context: request context
        :param host_uuid: the host uuid
        :param software_version: the version of the load to remove
        """

        LOG.debug("AgentManager.delete_load: %s" % (software_version))
        if self._ihost_uuid and self._ihost_uuid == host_uuid:
            LOG.info("AgentManager removing load %s" % software_version)

            cleanup_script = constants.DELETE_LOAD_SCRIPT
            if os.path.isfile(cleanup_script):
                with open(os.devnull, "w") as fnull:
                    try:
                        subprocess.check_call(  # pylint: disable=not-callable
                            [cleanup_script, software_version],
                            stdout=fnull, stderr=fnull)
                    except subprocess.CalledProcessError:
                        LOG.error("Failure during cleanup script")
                    else:
                        rpcapi = conductor_rpcapi.ConductorAPI(
                            topic=conductor_rpcapi.MANAGER_TOPIC)
                        rpcapi.finalize_delete_load(context, software_version)
            else:
                LOG.error("Cleanup script %s does not exist." % cleanup_script)

        return

    def create_simplex_backup(self, context, software_upgrade):
        """Creates the upgrade metadata and creates the system backup

        :param context: request context.
        :param software_upgrade: software_upgrade object
        :returns: none
        """
        try:
            from controllerconfig.upgrades import \
                management as upgrades_management
        except ImportError:
            LOG.error("Attempt to import during create_simplex_backup failed")
            return

        if tsc.system_mode != constants.SYSTEM_MODE_SIMPLEX:
            LOG.error("create_simplex_backup called for non-simplex system")
            return

        LOG.info("Starting simplex upgrade data collection")
        success = True
        try:
            upgrades_management.create_simplex_backup(software_upgrade)
        except Exception as ex:
            LOG.info("Exception during simplex upgrade data collection")
            LOG.exception(ex)
            success = False
        else:
            LOG.info("Simplex upgrade data collection complete")

        rpcapi = conductor_rpcapi.ConductorAPI(
            topic=conductor_rpcapi.MANAGER_TOPIC)
        rpcapi.complete_simplex_backup(context, success=success)

        return

    def device_update_image(self, context, host_uuid, pci_addr, filename, transaction_id,
                            retimer_included):
        """Write the device image to the device at the specified address.

        Transaction is the transaction ID as specified by sysinv-conductor.

        This must send back either success or failure to sysinv-conductor
        via an RPC cast.  The transaction ID is sent back to allow sysinv-conductor
        to locate the transaction in the DB.

        TODO: could get fancier with an image cache and delete based on LRU.
        """
        LOG.debug("AgentManager.device_update_image: %s" % pci_addr)
        if self._ihost_uuid and self._ihost_uuid == host_uuid:
            self._ifpga_operator.device_update_image(context,
                                                     host_uuid,
                                                     pci_addr,
                                                     filename,
                                                     transaction_id,
                                                     retimer_included)

    def execute_command(self, context, host_uuid, command):
        """Execute a command on behalf of sysinv-conductor

        :param context: request context
        :param host_uuid: the host uuid
        :param command: the command to execute
        """

        LOG.debug("AgentManager.execute_command: (%s)" % (command))
        if self._ihost_uuid and self._ihost_uuid == host_uuid:
            LOG.info("AgentManager execute_command: (%s)" % (command))
            with open(os.devnull, "w") as fnull:
                try:
                    subprocess.check_call(command, stdout=fnull, stderr=fnull)  # pylint: disable=not-callable
                except subprocess.CalledProcessError as e:
                    LOG.error("Failed to execute (%s) (%d)",
                              command, e.returncode)
                except OSError as e:
                    LOG.error("Failed to execute (%s), OS error:(%d)",
                              command, e.errno)

                LOG.info("(%s) executed.", command)

    def get_host_iscsi_initiator_name(self):
        iscsi_initiator_name = None
        try:
            stdout, __ = utils.execute('cat', '/etc/iscsi/initiatorname.iscsi',
                                       run_as_root=True)
            if stdout:
                stdout = stdout.strip()
                iscsi_initiator_name = stdout.split('=')[-1]
            LOG.info("iscsi initiator name = %s" % iscsi_initiator_name)
        except Exception:
            LOG.error("Failed retrieving iscsi initiator name")

        return iscsi_initiator_name

    def get_host_nvme_host_id(self):
        nvme_host_id = None
        try:
            stdout, __ = utils.execute('cat', '/etc/nvme/hostid',
                                       run_as_root=True)
            if stdout:
                nvme_host_id = stdout.strip()
            LOG.info("nvme host id = %s" % nvme_host_id)
        except Exception:
            LOG.error("Failed retrieving nvme host id")

        return nvme_host_id

    def get_host_nvme_host_nqn(self):
        nvme_host_nqn = None
        try:
            stdout, __ = utils.execute('cat', '/etc/nvme/hostnqn',
                                       run_as_root=True)
            if stdout:
                nvme_host_nqn = stdout.strip()
            LOG.info("nvme host nqn = %s" % nvme_host_nqn)
        except Exception:
            LOG.error("Failed retrieving nvme host nqn")

        return nvme_host_nqn

    def disk_prepare(self, context, host_uuid, idisk_dict,
                     skip_format, is_cinder_device):
        """prepare disk for system use.

        :param context: an admin context
        :param host_uuid: ihost uuid unique id
        :param idisk_dict: values for idisk volume object
        :param skip_format: bool value tells if the idisk should be GPT formatted
        :param is_cinder_device: bool value tells if the idisk is for cinder
        """
        LOG.debug("AgentManager.disk_prepare: %s" % idisk_dict)
        if self._ihost_uuid and self._ihost_uuid == host_uuid:
            self._idisk_operator.disk_prepare(host_uuid,
                                              idisk_dict,
                                              skip_format,
                                              is_cinder_device)

    def update_host_memory(self, context, host_uuid):
        """update the host memory

        :param context: an admin context
        :param host_uuid: ihost uuid unique id
        :return: None
        """
        if self._ihost_uuid and self._ihost_uuid == host_uuid:
            rpcapi = conductor_rpcapi.ConductorAPI(
                topic=conductor_rpcapi.MANAGER_TOPIC)
            memory = self._inode_operator.inodes_get_imemory()
            rpcapi.imemory_update_by_ihost(context,
                                           self._ihost_uuid,
                                           memory,
                                           force_update=True)
            self._inventory_reported.add(self.MEMORY)

    def refresh_helm_repo_information(self, context):
        """Refresh the helm chart repository information.

        :param context: an admin context
        :return: None
        """
        if self._ihost_personality == constants.CONTROLLER:
            LOG.debug("AgentManager.refresh_helm_repo_information")
            with open(os.devnull, "w") as fnull:
                try:
                    subprocess.check_call(['sudo', '-u', 'sysadmin',  # pylint: disable=not-callable
                                           'helm', 'repo', 'update'],
                                          stdout=fnull, stderr=fnull)
                except subprocess.CalledProcessError:
                    # Just log an error. Don't stop any callers from further execution.
                    LOG.warn("Failed to update helm repo data for user sysadmin.")

    def update_host_lvm(self, context, host_uuid):
        if self._ihost_uuid and self._ihost_uuid == host_uuid:
            rpcapi = conductor_rpcapi.ConductorAPI(
                topic=conductor_rpcapi.MANAGER_TOPIC)

            ipartition = self._ipartition_operator.ipartition_get(skip_gpt_check=True)
            try:
                rpcapi.ipartition_update_by_ihost(
                    context, self._ihost_uuid, ipartition)
            except AttributeError:
                # safe to ignore during upgrades
                LOG.warn("Skip updating ipartition rook conductor. "
                         "Upgrade in progress?")
            except exception.SysinvException:
                LOG.exception("Sysinv Agent exception updating rook"
                              "ipartition conductor.")

            # Update local volume groups
            ilvg = self._ilvg_operator.ilvg_get()
            try:
                rpcapi.ilvg_update_by_ihost(context,
                                            self._ihost_uuid,
                                            ilvg)
                self._inventory_reported.add(self.LVG)
            except exception.SysinvException:
                LOG.exception("Sysinv Agent exception updating ilvg"
                              "conductor.")

            # Update physical volumes
            ipv = self._ipv_operator.ipv_get()
            try:
                rpcapi.ipv_update_by_ihost(context,
                                           self._ihost_uuid,
                                           ipv)
                self._inventory_reported.add(self.PV)
            except exception.SysinvException:
                LOG.exception("Sysinv Agent exception updating ipv"
                              "conductor.")

    # TODO(RPCHybridMode): This is only useful for 21.12 -> 22.12 upgrades.
    #  Remove this method in new releases, when it's no longer necessary to
    #  perform upgrade through hybrid mode messaging system
    def delete_sysinv_hybrid_state(self, context, host_uuid):
        """Delete the Sysinv flag of Hybrid Mode.

        :param host_uuid: ihost uuid unique id
        :return: None
        """

        if self._ihost_uuid and self._ihost_uuid == host_uuid:
            if os.path.exists(tsc.SYSINV_HYBRID_RPC_FLAG):
                utils.delete_if_exists(tsc.SYSINV_HYBRID_RPC_FLAG)
                LOG.info("Sysinv Hybrid Mode deleted.")
                LOG.info("Sysinv services will be restarted")
                # pylint: disable=not-callable
                subprocess.call(['/usr/bin/sysinv-service-restart.sh'])
            else:
                LOG.info("Hybrid flag doesn't exist. Ignoring delete.")

    def report_initial_inventory(self, context, host_uuid):
        # conductor requests re-report initial inventory
        if self._ihost_uuid and self._ihost_uuid == host_uuid:
            os.remove(constants.SYSINV_REPORTED)
            self._prev_fs = None
            self._inventoried_initial = False
            self._inventory_reported = set()
