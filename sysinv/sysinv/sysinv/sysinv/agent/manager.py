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
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#


""" Perform activity related local inventory.

A single instance of :py:class:`sysinv.agent.manager.AgentManager` is
created within the *sysinv-agent* process, and is responsible for
performing all actions for this host managed by system inventory.

On start, collect and post inventory to conductor.

Commands (from conductors) are received via RPC calls.

"""

import errno
import fcntl
import os
import shutil
import subprocess
import sys
import tempfile
import time
from six.moves import configparser
import StringIO
import socket
import yaml

from sysinv.agent import disk
from sysinv.agent import partition
from sysinv.agent import pv
from sysinv.agent import lvg
from sysinv.agent import pci
from sysinv.agent import node
from sysinv.agent import lldp
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import service
from sysinv.common import utils
from sysinv.objects import base as objects_base
from sysinv.puppet import common as puppet
from sysinv.conductor import rpcapi as conductor_rpcapi
from sysinv.openstack.common import context as mycontext
from sysinv.openstack.common import log
from sysinv.openstack.common import periodic_task
from sysinv.openstack.common.rpc.common import Timeout
from sysinv.openstack.common.rpc.common import serialize_remote_exception
from oslo_config import cfg


from sysinv.openstack.common.rpc.common import RemoteError

import tsconfig.tsconfig as tsc


MANAGER_TOPIC = 'sysinv.agent_manager'

LOG = log.getLogger(__name__)

agent_opts = [
       cfg.StrOpt('api_url',
                  default=None,
                  help=('Url of SysInv API service. If not set SysInv can '
                        'get current value from Keystone service catalog.')),
       cfg.IntOpt('audit_interval',
                  default=60,
                  help='Maximum time since the last check-in of a agent'),
              ]

CONF = cfg.CONF
CONF.register_opts(agent_opts, 'agent')

MAXSLEEP = 300  # 5 minutes

SYSINV_READY_FLAG = os.path.join(tsc.VOLATILE_PATH, ".sysinv_ready")

CONFIG_APPLIED_FILE = os.path.join(tsc.PLATFORM_CONF_PATH, ".config_applied")
CONFIG_APPLIED_DEFAULT = "install"

FIRST_BOOT_FLAG = os.path.join(
    tsc.PLATFORM_CONF_PATH, ".first_boot")

PUPPET_HIERADATA_PATH = os.path.join(tsc.PUPPET_PATH, 'hieradata')

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

    def __init__(self, host, topic):
        serializer = objects_base.SysinvObjectSerializer()
        super(AgentManager, self).__init__(host, topic, serializer=serializer)

        self._report_to_conductor = False
        self._report_to_conductor_iplatform_avail_flag = False
        self._ipci_operator = pci.PCIOperator()
        self._inode_operator = node.NodeOperator()
        self._idisk_operator = disk.DiskOperator()
        self._ipv_operator = pv.PVOperator()
        self._ipartition_operator = partition.PartitionOperator()
        self._ilvg_operator = lvg.LVGOperator()
        self._lldp_operator = lldp.LLDPOperator()
        self._iconfig_read_config_reported = None
        self._ihost_personality = None
        self._ihost_uuid = ""
        self._agent_throttle = 0
        self._mgmt_ip = None
        self._prev_disk = None
        self._prev_partition = None
        self._prev_lvg = None
        self._prev_pv = None
        self._subfunctions = None
        self._subfunctions_configured = False
        self._notify_subfunctions_alarm_clear = False
        self._notify_subfunctions_alarm_raise = False
        self._tpmconfig_rpc_failure = False
        self._tpmconfig_host_first_apply = False
        self._first_grub_update = False

    def start(self):
        super(AgentManager, self).start()

        # Do not collect inventory and report to conductor at startup in
        # order to eliminate two inventory reports
        # (one from here and one from audit) being sent to the conductor
        if os.path.isfile('/etc/sysinv/sysinv.conf'):
            LOG.debug('sysinv-agent started, inventory to be reported by audit')
        else:
            LOG.debug('No config file for sysinv-agent found.')

        if tsc.system_mode == constants.SYSTEM_MODE_SIMPLEX:
            utils.touch(SYSINV_READY_FLAG)

    def _report_to_conductor_iplatform_avail(self):
        utils.touch(SYSINV_READY_FLAG)
        time.sleep(1)  # give time for conductor to process
        self._report_to_conductor_iplatform_avail_flag = True

    @staticmethod
    def _update_interface_irq_affinity(self, interface_list):
        cpus = {}
        platform_cpulist = '0'
        with open('/etc/nova/compute_reserved.conf', 'r') as infile:
            for line in infile:
                if "COMPUTE_PLATFORM_CORES" in line:
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
                         "if you configure %s interface on port "
                         "residing on processor 0, or configure a platform "
                         "core on processor %d." %
                         (info['name'], info['numa_node'], self.host,
                          info['networktype'], info['numa_node']))

            LOG.info("Affine %s interface %s with cpulist %s" %
                    (info['networktype'], info['name'], cpulist))
            cmd = '/usr/bin/affine-interrupts.sh %s %s' % \
                    (info['name'], cpulist)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            proc.communicate()
            LOG.info("%s return %d" % (cmd, proc.returncode))
            if proc.returncode == 1:
                LOG.error("Failed to affine %s %s interrupts with %s" %
                          (info['networktype'], info['name'], cpulist))

    def _update_ttys_dcd_status(self, context, host_id):
        # Retrieve the serial line carrier detect flag
        ttys_dcd = None
        rpcapi = conductor_rpcapi.ConductorAPI(
                           topic=conductor_rpcapi.MANAGER_TOPIC)
        try:
            ttys_dcd = rpcapi.get_host_ttys_dcd(context, host_id)
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception getting host ttys_dcd.")
            pass
        if ttys_dcd is not None:
            self._config_ttys_login(ttys_dcd)
        else:
            LOG.debug("ttys_dcd is not configured")

    @staticmethod
    def _get_active_device():
        # the list of currently configured console devices,
        # like 'tty1 ttyS0' or just 'ttyS0'
        # The last entry in the file is the active device connected
        # to /dev/console.
        active_device = 'ttyS0'
        try:
            cmd = 'cat /sys/class/tty/console/active | grep ttyS'
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            output = proc.stdout.read().strip()
            proc.communicate()[0]
            if proc.returncode != 0:
                LOG.info("Cannot find the current configured serial device, "
                         "return default %s" % active_device)
                return active_device
            # if more than one devices are found, take the last entry
            if ' ' in output:
                devs = output.split(' ')
                active_device = devs[len(devs) - 1]
            else:
                active_device = output
        except subprocess.CalledProcessError as e:
            LOG.error("Failed to execute (%s) (%d)", cmd, e.returncode)
        except OSError as e:
            LOG.error("Failed to execute (%s) OS error (%d)", cmd, e.errno)

        return active_device

    @staticmethod
    def _is_local_flag_disabled(device):
        """
        :param device:
        :return: boolean: True if the local flag is disabled 'i.e. -clocal is
                          set'. This means the serial data carrier detect
                          signal is significant
        """
        try:
            # uses -o for only-matching and -e for a pattern beginning with a
            # hyphen (-), the following command returns 0 if the local flag
            # is disabled
            cmd = 'stty -a -F /dev/%s | grep -o -e -clocal' % device
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            proc.communicate()[0]
            return proc.returncode == 0
        except subprocess.CalledProcessError as e:
            LOG.error("Failed to execute (%s) (%d)", cmd, e.returncode)
            return False
        except OSError as e:
            LOG.error("Failed to execute (%s) OS error (%d)", cmd, e.errno)
            return False

    def _config_ttys_login(self, ttys_dcd):
        # agetty is now enabled by systemd
        # we only need to disable the local flag to enable carrier detection
        # and enable the local flag when the feature is turned off
        toggle_flag = None
        active_device = self._get_active_device()
        local_flag_disabled = self._is_local_flag_disabled(active_device)
        if str(ttys_dcd) in ['True', 'true']:
            LOG.info("ttys_dcd is enabled")
            # check if the local flag is disabled
            if not local_flag_disabled:
                LOG.info("Disable (%s) local line" % active_device)
                toggle_flag = 'stty -clocal -F /dev/%s' % active_device
        else:
            if local_flag_disabled:
                # enable local flag to ignore the carrier detection
                LOG.info("Enable local flag for device :%s" % active_device)
                toggle_flag = 'stty clocal -F /dev/%s' % active_device

        if toggle_flag:
            try:
                subprocess.Popen(toggle_flag, stdout=subprocess.PIPE,
                                 shell=True)
                # restart serial-getty
                restart_cmd = ('systemctl restart serial-getty@%s.service'
                               % active_device)
                subprocess.check_call(restart_cmd, shell=True)
            except subprocess.CalledProcessError as e:
                LOG.error("subprocess error: (%d)", e.returncode)

    def _force_grub_update(self):
        """ Force update the grub on the first AIO controller after the initial
            config is completed
        """
        if (not self._first_grub_update and
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
        ini_fp = StringIO.StringIO(ini_str)

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

        do_compute = constants.COMPUTE in self.subfunctions_list_get()

        try:
            neighbours = self._lldp_operator.lldp_neighbours_list(do_compute)
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
            agents = self._lldp_operator.lldp_agents_list(do_compute)
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

    def synchronized_network_config(func):
        """ Synchronization decorator to acquire and release
            network_config_lock.
        """
        def wrap(self, *args, **kwargs):
            try:
                # Get lock to avoid conflict with apply_network_config.sh
                lockfd = self._acquire_network_config_lock()
                return func(self, *args, **kwargs)
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
                    subprocess.call(['ip', 'link', 'set', interface, 'up'])
                    links_down.append(interface)
                    LOG.info('interface %s enabled to receive LLDP PDUs' % interface)
            subprocess.call(['lldpcli', 'update'])
            # delay maximum 30 seconds for lldpd to receive LLDP PDU
            timeout = 0
            link_wait_for_lldp = True
            while timeout < 30 and link_wait_for_lldp and links_down:
                time.sleep(5)
                timeout = timeout + 5
                link_wait_for_lldp = False
                for link in links_down:
                    if not self._lldp_operator.lldpd_has_neighbour(link):
                        link_wait_for_lldp = True
                        break
            self.host_lldp_get_and_report(context, rpcapi, host_uuid)
        except Exception as e:
            LOG.exception(e)
            pass
        finally:
            # restore interface administrative state
            for interface in links_down:
                subprocess.call(['ip', 'link', 'set', interface, 'down'])
                LOG.info('interface %s disabled after querying LLDP neighbors' % interface)

    def platform_update_by_host(self, rpcapi, context, host_uuid, msg_dict):
        """ Update host platform information.
            If this is the first boot (kickstart), then also update the Host
            Action State to reinstalled, and remove the flag.
        """
        if os.path.exists(FIRST_BOOT_FLAG):
            msg_dict.update({constants.HOST_ACTION_STATE:
                             constants.HAS_REINSTALLED})

        try:
            rpcapi.iplatform_update_by_ihost(context,
                                             host_uuid,
                                             msg_dict)
            if os.path.exists(FIRST_BOOT_FLAG):
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
        count = 1
        delay = 5
        max_count = 5
        while count <= max_count:
            try:
                fcntl.flock(lock_file_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return lock_file_fd
            except IOError as e:
                # raise on unrelated IOErrors
                if e.errno != errno.EAGAIN:
                    raise
                else:
                    LOG.info("Could not acquire lock({}): {} ({}/{}), "
                             "will retry".format(lock_file_fd, str(e),
                                                 count, max_count))
                    time.sleep(delay)
                    count += 1
        LOG.error("Failed to acquire lock (fd={})".format(lock_file_fd))
        return 0

    def _release_network_config_lock(self, lockfd):
        """ Release the lock guarding apply_network_config.sh """
        if lockfd:
            fcntl.flock(lockfd, fcntl.LOCK_UN)
            os.close(lockfd)

    def ihost_inv_get_and_report(self, icontext):
        """Collect data for an ihost.

        This method allows an ihost data to be collected.

        :param:   icontext: an admin context
        :returns: updated ihost object, including all fields.
        """

        rpcapi = conductor_rpcapi.ConductorAPI(
                           topic=conductor_rpcapi.MANAGER_TOPIC)

        ihost = None

        # find list of network related inics for this ihost
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
            pci_dev_array = self._ipci_operator.pci_get_device_attrs(pci_dev.pciaddr)
            for dev in pci_dev_array:
                pci_devs.append(pci.PCIDevice(pci_dev, **dev))

        # create a list of MAC addresses that will be used to identify the
        # inventoried host (one of the MACs should be the management MAC)
        ihost_macs = [port.mac for port in iports if port.mac]

        # get my ihost record which should be avail since booted

        LOG.debug('Sysinv Agent iports={}, ihost_macs={}'.format(
            iports, ihost_macs))

        slept = 0
        while slept < MAXSLEEP:
            # wait for controller to come up first may be a DOR
            try:
                ihost = rpcapi.get_ihost_by_macs(icontext, ihost_macs)
            except Timeout:
                LOG.info("get_ihost_by_macs rpc Timeout.")
                return  # wait for next audit cycle
            except Exception as ex:
                LOG.warn("Conductor RPC get_ihost_by_macs exception "
                         "response")

            if not ihost:
                hostname = socket.gethostname()
                if hostname != constants.LOCALHOST_HOSTNAME:
                    try:
                        ihost = rpcapi.get_ihost_by_hostname(icontext,
                                           hostname)
                    except Timeout:
                        LOG.info("get_ihost_by_hostname rpc Timeout.")
                        return  # wait for next audit cycle
                    except Exception as ex:
                        LOG.warn("Conductor RPC get_ihost_by_hostname "
                                 "exception response %s" % ex)

            if ihost:
                ipersonality = ihost.get('personality') or ""

            if ihost and ipersonality:
                self._report_to_conductor = True
                self._ihost_uuid = ihost['uuid']
                self._ihost_personality = ihost['personality']
                self._mgmt_ip = ihost['mgmt_ip']

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
                LOG.info("Agent found matching ihost: %s" % ihost['uuid'])
                break

            time.sleep(30)
            slept += 30

        if not self._report_to_conductor:
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

        # post to sysinv db by ihost['uuid']
        iport_dict_array = []
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
                         'driver': port.driver,
                         'mac': port.mac,
                         'mtu': port.mtu,
                         'speed': port.speed,
                         'link_mode': port.link_mode,
                         'dev_id': port.dev_id,
                         'dpdksupport': port.dpdksupport}

            LOG.debug('Sysinv Agent inic {}'.format(inic_dict))

            iport_dict_array.append(inic_dict)
        try:
            # may get duplicate key if already sent on earlier init
            rpcapi.iport_update_by_ihost(icontext,
                                         ihost['uuid'],
                                         iport_dict_array)
        except RemoteError as e:
            LOG.error("iport_update_by_ihost RemoteError exc_type=%s" %
                      e.exc_type)
            self._report_to_conductor = False
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception updating iport conductor.")
            pass

        try:
            rpcapi.subfunctions_update_by_ihost(icontext,
                                                ihost['uuid'],
                                                subfunctions)
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception updating subfunctions "
                          "conductor.")
            pass

        # post to sysinv db by ihost['uuid']
        pci_device_dict_array = []
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
                            'driver': dev.driver,
                            'enabled': dev.enabled,
                            'extra_info': dev.extra_info}
            LOG.debug('Sysinv Agent dev {}'.format(pci_dev_dict))

            pci_device_dict_array.append(pci_dev_dict)
        try:
            # may get duplicate key if already sent on earlier init
            rpcapi.pci_device_update_by_host(icontext,
                                             ihost['uuid'],
                                             pci_device_dict_array)
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception updating iport conductor.")
            pass

        # Find list of numa_nodes and cpus for this ihost
        inumas, icpus = self._inode_operator.inodes_get_inumas_icpus()

        try:
            # may get duplicate key if already sent on earlier init
            rpcapi.inumas_update_by_ihost(icontext,
                                          ihost['uuid'],
                                          inumas)
        except RemoteError as e:
            LOG.error("inumas_update_by_ihost RemoteError exc_type=%s" %
                      e.exc_type)
            if e.exc_type == 'TimeoutError':
                self._report_to_conductor = False
        except Exception as e:
            LOG.exception("Sysinv Agent exception updating inuma e=%s." % e)
            self._report_to_conductor = True
            pass
        except exception.SysinvException:
            LOG.exception("Sysinv Agent uncaught exception updating inuma.")
            pass

        force_grub_update = self._force_grub_update()
        try:
            # may get duplicate key if already sent on earlier init
            rpcapi.icpus_update_by_ihost(icontext,
                                         ihost['uuid'],
                                         icpus,
                                         force_grub_update)
        except RemoteError as e:
            LOG.error("icpus_update_by_ihost RemoteError exc_type=%s" %
                      e.exc_type)
            if e.exc_type == 'TimeoutError':
                self._report_to_conductor = False
        except Exception as e:
            LOG.exception("Sysinv Agent exception updating icpus e=%s." % e)
            self._report_to_conductor = True
            pass
        except exception.SysinvException:
            LOG.exception("Sysinv Agent uncaught exception updating icpus conductor.")
            pass

        imemory = self._inode_operator.inodes_get_imemory()
        if imemory:
            try:
                # may get duplicate key if already sent on earlier init
                rpcapi.imemory_update_by_ihost(icontext,
                                               ihost['uuid'],
                                               imemory)
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
        except RemoteError as e:
            # TODO (oponcea): Valid for R4->R5, remove in R6.
            # safe to ignore during upgrades
            if 'has no property' in str(e) and 'available_mib' in str(e):
                LOG.warn("Skip updating idisk conductor. "
                         "Upgrade in progress?")
            else:
                LOG.exception("Sysinv Agent exception updating idisk conductor.")
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception updating idisk conductor.")
            pass

        self._update_disk_partitions(rpcapi, icontext,
                                     ihost['uuid'], force_update=True)

        ipv = self._ipv_operator.ipv_get()
        try:
            rpcapi.ipv_update_by_ihost(icontext,
                                       ihost['uuid'],
                                       ipv)
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception updating ipv conductor.")
            pass

        ilvg = self._ilvg_operator.ilvg_get()
        try:
            rpcapi.ilvg_update_by_ihost(icontext,
                                        ihost['uuid'],
                                        ilvg)
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception updating ilvg conductor.")
            pass

        if constants.COMPUTE in self.subfunctions_list_get():
            platform_interfaces = []
            # retrieve the mgmt and infra interfaces and associated numa nodes
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

                iscsi_initiator_name = self.get_host_iscsi_initiator_name()
                if iscsi_initiator_name is not None:
                    imsg_dict.update({'iscsi_initiator_name': iscsi_initiator_name})

                # Before setting the host to AVAILABILITY_AVAILABLE make
                # sure that nova_local aggregates are correctly set otherwise starting
                # instances from images will fail as no host is found.
                for volume in nova_lvgs:
                    # Skip making the aggregate RPC call on hosts that don't
                    # have a nova-local volume group.
                    if (volume.lvm_vg_name == constants.LVG_NOVA_LOCAL):
                        try:
                            rpcapi.update_nova_local_aggregates(icontext, self._ihost_uuid)
                        except AttributeError:
                            # safe to ignore during upgrades
                            LOG.warn("Skip configuration of nova-local aggregates. "
                                     "Upgrade in progress?")
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
                constants.COMPUTE in subfunctions_list):
            if not os.path.exists(tsc.INITIAL_COMPUTE_CONFIG_COMPLETE):
                self._subfunctions_configured = False
                return False

        self._subfunctions_configured = True
        return True

    def _report_config_applied(self, context):
        """Report the latest configuration applied for this host to the
        conductor.
        :param context: an admin context
        """
        rpcapi = conductor_rpcapi.ConductorAPI(
            topic=conductor_rpcapi.MANAGER_TOPIC)

        config_uuid = self.iconfig_read_config_applied()
        if config_uuid != self._iconfig_read_config_reported:
            LOG.info("Agent config applied  %s" % config_uuid)

            imsg_dict = {'config_applied': config_uuid}
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
        if constants.COMPUTE in subfunctions:
            if not os.path.isfile(tsc.INITIAL_COMPUTE_CONFIG_COMPLETE):
                return False
        if constants.STORAGE in subfunctions:
            if not os.path.isfile(tsc.INITIAL_STORAGE_CONFIG_COMPLETE):
                return False
        return True

    @utils.synchronized(constants.PARTITION_MANAGE_LOCK)
    def _update_disk_partitions(self, rpcapi, icontext,
                                host_uuid, force_update=False):
        ipartition = self._ipartition_operator.ipartition_get()
        if not force_update:
            if self._prev_partition == ipartition:
                return
            self._prev_partition = ipartition
        try:
            rpcapi.ipartition_update_by_ihost(
                icontext, host_uuid, ipartition)
        except AttributeError:
            # safe to ignore during upgrades
            LOG.warn("Skip updating ipartition conductor. "
                     "Upgrade in progress?")
        except exception.SysinvException:
            LOG.exception("Sysinv Agent exception updating "
                          "ipartition conductor.")
            if not force_update:
                self._prev_partition = None

    @periodic_task.periodic_task(spacing=CONF.agent.audit_interval,
                                 run_immediately=True)
    def _agent_audit(self, context):
        # periodically, perform inventory audit
        self.agent_audit(context, host_uuid=self._ihost_uuid,
                         force_updates=None)

    @utils.synchronized(LOCK_AGENT_ACTION, external=False)
    def agent_audit(self, context, host_uuid, force_updates, cinder_device=None):
        # perform inventory audit
        if self._ihost_uuid != host_uuid:
            # The function call is not for this host agent
            return

        icontext = mycontext.get_admin_context()
        rpcapi = conductor_rpcapi.ConductorAPI(
                               topic=conductor_rpcapi.MANAGER_TOPIC)

        if self._ihost_uuid:
            if os.path.isfile(tsc.INITIAL_CONFIG_COMPLETE_FLAG):
                self._report_config_applied(icontext)

        if self._report_to_conductor is False:
            LOG.info("Sysinv Agent audit running inv_get_and_report.")
            self.ihost_inv_get_and_report(icontext)

        try:
            nova_lvgs = rpcapi.ilvg_get_nova_ilvg_by_ihost(icontext, self._ihost_uuid)
        except Timeout:
            LOG.info("ilvg_get_nova_ilvg_by_ihost() Timeout.")
            nova_lvgs = None

        if self._ihost_uuid and \
           os.path.isfile(tsc.INITIAL_CONFIG_COMPLETE_FLAG):
            if not self._report_to_conductor_iplatform_avail_flag and \
               not self._wait_for_nova_lvg(icontext, rpcapi, self._ihost_uuid, nova_lvgs):
                imsg_dict = {'availability': constants.AVAILABILITY_AVAILABLE}

                config_uuid = self.iconfig_read_config_applied()
                imsg_dict.update({'config_applied': config_uuid})

                iscsi_initiator_name = self.get_host_iscsi_initiator_name()
                if iscsi_initiator_name is not None:
                    imsg_dict.update({'iscsi_initiator_name': iscsi_initiator_name})

                if self._ihost_personality == constants.CONTROLLER:
                    idisk = self._idisk_operator.idisk_get()
                    try:
                        rpcapi.idisk_update_by_ihost(icontext,
                                                     self._ihost_uuid,
                                                     idisk)
                    except RemoteError as e:
                        # TODO (oponcea): Valid for R4->R5, remove in R6.
                        # safe to ignore during upgrades
                        if 'has no property' in str(e) and 'available_mib' in str(e):
                            LOG.warn("Skip updating idisk conductor. "
                                     "Upgrade in progress?")
                        else:
                            LOG.exception("Sysinv Agent exception updating idisk "
                                          "conductor.")
                    except exception.SysinvException:
                        LOG.exception("Sysinv Agent exception updating idisk "
                                      "conductor.")
                        pass

                # Before setting the host to AVAILABILITY_AVAILABLE make
                # sure that nova_local aggregates are correctly set otherwise starting
                # instances from images will fail as no host is found.
                for volume in nova_lvgs:
                    # Skip making the aggregate RPC call on hosts that don't
                    # have a nova-local volume group.
                    if (volume.lvm_vg_name == constants.LVG_NOVA_LOCAL):
                        try:
                            rpcapi.update_nova_local_aggregates(icontext, self._ihost_uuid)
                        except AttributeError:
                            # safe to ignore during upgrades
                            LOG.warn("Skip configuration of nova-local aggregates. "
                                     "Upgrade in progress?")
                self.platform_update_by_host(rpcapi,
                                             icontext,
                                             self._ihost_uuid,
                                             imsg_dict)

                self._report_to_conductor_iplatform_avail()
                self._iconfig_read_config_reported = config_uuid

            if (self._ihost_personality == constants.CONTROLLER and
                     not self._notify_subfunctions_alarm_clear):

                subfunctions_list = self.subfunctions_list_get()
                if ((constants.CONTROLLER in subfunctions_list) and
                        (constants.COMPUTE in subfunctions_list)):
                    if self.subfunctions_configured(subfunctions_list) and \
                            not self._wait_for_nova_lvg(icontext, rpcapi, self._ihost_uuid):

                        ihost_notify_dict = {'subfunctions_configured': True}
                        rpcapi.notify_subfunctions_config(icontext,
                                                        self._ihost_uuid,
                                                        ihost_notify_dict)
                        self._notify_subfunctions_alarm_clear = True
                    else:
                        if not self._notify_subfunctions_alarm_raise:
                            ihost_notify_dict = {'subfunctions_configured': False}
                            rpcapi.notify_subfunctions_config(icontext,
                                                                self._ihost_uuid,
                                                                ihost_notify_dict)
                            self._notify_subfunctions_alarm_raise = True
                else:
                    self._notify_subfunctions_alarm_clear = True

        if self._ihost_uuid:
            LOG.debug("SysInv Agent Audit running.")

            if force_updates:
                LOG.debug("SysInv Agent Audit force updates: (%s)" %
                          (', '.join(force_updates)))

            self._update_ttys_dcd_status(icontext, self._ihost_uuid)
            if self._agent_throttle > 5:
                # throttle updates
                self._agent_throttle = 0
                imemory = self._inode_operator.inodes_get_imemory()
                rpcapi.imemory_update_by_ihost(icontext,
                                               self._ihost_uuid,
                                               imemory)
                if self._is_config_complete():
                    self.host_lldp_get_and_report(icontext, rpcapi, self._ihost_uuid)
                else:
                    self._lldp_enable_and_report(icontext, rpcapi, self._ihost_uuid)
            self._agent_throttle += 1

            if self._ihost_personality == constants.CONTROLLER:
                # Audit TPM configuration only on Controller
                # node personalities
                self._audit_tpm_device(icontext, self._ihost_uuid)
                # Force disk update
                self._prev_disk = None

            # if this audit is requested by conductor, clear
            # previous states for disk, lvg and pv to force an update
            if force_updates:
                if constants.DISK_AUDIT_REQUEST in force_updates:
                    self._prev_disk = None
                if constants.LVG_AUDIT_REQUEST in force_updates:
                    self._prev_lvg = None
                if constants.PV_AUDIT_REQUEST in force_updates:
                    self._prev_pv = None
                if constants.PARTITION_AUDIT_REQUEST in force_updates:
                    self._prev_partition = None

            # Update disks
            idisk = self._idisk_operator.idisk_get()
            if ((self._prev_disk is None) or
                    (self._prev_disk != idisk)):
                self._prev_disk = idisk
                try:
                    rpcapi.idisk_update_by_ihost(icontext,
                                                 self._ihost_uuid,
                                                 idisk)
                except RemoteError as e:
                    # TODO (oponcea): Valid for R4->R5, remove in R6.
                    # safe to ignore during upgrades
                    if 'has no property' in str(e) and 'available_mib' in str(e):
                        LOG.warn("Skip updating idisk conductor. "
                                 "Upgrade in progress?")
                    else:
                        LOG.exception("Sysinv Agent exception updating idisk "
                                      "conductor.")
                except exception.SysinvException:
                    LOG.exception("Sysinv Agent exception updating idisk"
                                  "conductor.")
                    self._prev_disk = None

            # Update disk partitions
            if self._ihost_personality != constants.STORAGE:
                self._update_disk_partitions(rpcapi, icontext, self._ihost_uuid)

            # Update physical volumes
            ipv = self._ipv_operator.ipv_get(cinder_device=cinder_device)
            if ((self._prev_pv is None) or
                    (self._prev_pv != ipv)):
                self._prev_pv = ipv
                try:
                    rpcapi.ipv_update_by_ihost(icontext,
                                               self._ihost_uuid,
                                               ipv)
                except exception.SysinvException:
                    LOG.exception("Sysinv Agent exception updating ipv"
                                  "conductor.")
                    self._prev_pv = None
                    pass

            # Update local volume groups
            ilvg = self._ilvg_operator.ilvg_get(cinder_device=cinder_device)
            if ((self._prev_lvg is None) or
                    (self._prev_lvg != ilvg)):
                self._prev_lvg = ilvg
                try:
                    rpcapi.ilvg_update_by_ihost(icontext,
                                                self._ihost_uuid,
                                                ilvg)
                except exception.SysinvException:
                    LOG.exception("Sysinv Agent exception updating ilvg"
                                  "conductor.")
                    self._prev_lvg = None
                    pass

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

        do_compute = constants.COMPUTE in self.subfunctions_list_get()
        rpcapi = conductor_rpcapi.ConductorAPI(
                               topic=conductor_rpcapi.MANAGER_TOPIC)
        # Update the lldp agent
        self._lldp_operator.lldp_update_systemname(context, systemname,
                                                   do_compute)
        # Trigger an audit to ensure the db is up to date
        self.host_lldp_get_and_report(context, rpcapi, self._ihost_uuid)

    def configure_isystemname(self, context, systemname):
        """Configure the systemname into the /etc/sysinv/motd.system with the supplied data.

        :param context: an admin context.
        :param systemname: the systemname
        """

        # Update GUI and CLI with new System Name
        LOG.debug("AgentManager.configure_isystemname: updating systemname in /etc/sysinv/motd.system ")
        if systemname:
            # update /etc/sysinv/motd.system for the CLI
            with open('/etc/sysinv/motd.system', 'w') as fd:
                fd.write('\n')
                fd.write('====================================================================\n')
                fd.write('         SYSTEM: %s\n' % systemname)
                fd.write('====================================================================\n')
                fd.write('\n')

            # Update lldp agent with new system name
            self.configure_lldp_systemname(context, systemname)

        return

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

                    # Remove resolv.conf file. It may have been created as a
                    # symlink by the volatile configuration scripts.
                    subprocess.call(["rm", "-f", file_name])

                if isinstance(file_content, dict):
                    f_content = file_content.get(file_name)
                else:
                    f_content = file_content

                os.umask(0)
                if f_content is not None:
                    with os.fdopen(os.open(file_name, os.O_CREAT | os.O_WRONLY,
                               permissions), 'wb') as f:
                        f.write(f_content)

            self._update_config_applied(iconfig_uuid)
            self._report_config_applied(context)

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

        try:
            # runtime manifests can not be applied without the initial
            # configuration applied
            force = config_dict.get('force', False)
            if (not force and
                    not os.path.isfile(tsc.INITIAL_CONFIG_COMPLETE_FLAG)):
                return

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

            time_slept = 0
            while not self._mgmt_ip and time_slept < 300:
                time.sleep(15)
                time_slept += 15

            if not self._mgmt_ip:
                LOG.warn("config_apply_runtime_manifest: "
                          " timed out waiting for local management ip"
                          " %s %s %s" %
                         (config_uuid, config_dict, self._ihost_personality))
                return

            if not os.path.exists(tsc.PUPPET_PATH):
                # we must be controller-standby or storage, mount /var/run/platform
                LOG.info("controller-standby or storage, mount /var/run/platform")
                remote_dir = "controller-platform-nfs:" + tsc.PLATFORM_PATH
                local_dir = os.path.join(tsc.VOLATILE_PATH, 'platform')
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

        if config_dict.get(puppet.REPORT_STATUS_CFG):
            config_dict['host_uuid'] = self._ihost_uuid
            LOG.debug("Manifests application succeeded. "
                      "Reporting success to conductor. "
                      "Details: %s." % config_dict)
            rpcapi = conductor_rpcapi.ConductorAPI(
                topic=conductor_rpcapi.MANAGER_TOPIC)
            rpcapi.report_config_status(context, config_dict,
                                        status=puppet.REPORT_SUCCESS,
                                        error=None)

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
                # being requested. e.g. in AIO systems if we request a compute
                # personality we should apply the manifest with that
                # personality
                if subfunction in personalities:
                    personality = subfunction

            if not personality:
                LOG.error("failed to find 'personality' in host subfunctions")
                return

            with open(tmpfile, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)

            puppet.puppet_apply_manifest(self._mgmt_ip,
                                         personality,
                                         'runtime', tmpfile,
                                         hieradata_path=hieradata_path)
        except Exception:
            LOG.exception("failed to apply runtime manifest")
            raise
        finally:
            os.close(fd)
            os.remove(tmpfile)

    def configure_ttys_dcd(self, context, uuid, ttys_dcd):
        """Configure the getty on the serial device.

        :param context: an admin context.
        :param uuid: the host uuid
        :param ttys_dcd: the flag to enable/disable dcd
        """

        LOG.debug("AgentManager.configure_ttys_dcd: %s %s" % (uuid, ttys_dcd))
        if self._ihost_uuid and self._ihost_uuid == uuid:
            LOG.debug("AgentManager configure getty on serial console")
            self._config_ttys_login(ttys_dcd)
        return

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
                        subprocess.check_call(
                            [cleanup_script, software_version],
                            stdout=fnull, stderr=fnull)
                    except subprocess.CalledProcessError:
                        LOG.error("Failure during cleanup script")
                    else:
                        rpcapi = conductor_rpcapi.ConductorAPI(
                            topic=conductor_rpcapi.MANAGER_TOPIC)
                        rpcapi.finalize_delete_load(context)
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
            from controllerconfig import backup_restore
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

    def _audit_tpm_device(self, context, host_id):
        """ Audit the tpmdevice status on this host and update. """
        rpcapi = conductor_rpcapi.ConductorAPI(
                           topic=conductor_rpcapi.MANAGER_TOPIC)
        tpmconfig = None
        tpmdevice = None
        response_dict = {'is_configured': False}  # guilty until proven innocent
        try:
            tpmconfig = rpcapi.get_system_tpmconfig(context)
        except exception.SysinvException:
            pass
        finally:
            if not tpmconfig:
                LOG.debug("Sysinv Agent cannot get host system tpmconfig.")
                return

        try:
            tpmdevice = rpcapi.get_tpmdevice_by_host(context, host_id)
            if tpmdevice:
                # if we found a tpmdevice configuration then
                # that implies that a tpmconfig has as already
                # been applied on this host. Set it here since
                # that flag (originally set in apply_tpm_config())
                # would be cleared on Sysinv agent restarts/swacts
                self._tpmconfig_host_first_apply = True
        except exception.SysinvException:
            # it could be that a TPM configuration was attempted before
            # this controller was provisioned in which case we will
            # raise a failure. However it could also be that the agent
            # simply hasn't applied the tpmdevice configuration.
            # Check for both cases.
            if self._tpmconfig_host_first_apply:
                LOG.debug("Sysinv Agent still applying host "
                          "tpmdevice configuration.")
                return
        finally:
            if not self._tpmconfig_host_first_apply:
                rpcapi.tpm_config_update_by_host(context,
                                                 host_id,
                                                 response_dict)

        if (tpmconfig and tpmdevice and
                (self._tpmconfig_rpc_failure or
                 tpmdevice['state'] != constants.TPMCONFIG_APPLYING)):
            # If there is an rpc failure then always send an update
            # If there has been no rpc failure, and TPM is not in
            # applying state and if TPM is configured in the system,
            # then query the tpm path, and inform the conductor
            if os.path.isfile(tpmconfig['tpm_path']):
                response_dict['is_configured'] = True

            LOG.debug("Conductor: config_update_by_host for host (%s), "
                      "response(%s)" % (host_id, response_dict))
            rpcapi.tpm_config_update_by_host(context,
                                             host_id,
                                             response_dict)

    def apply_tpm_config(self, context, tpm_context):
        """Configure or Update TPM device on this node

        :param context: request context
        :param tpm_context: the tpm object context
        """

        if (self._ihost_uuid and self._ihost_personality and
                self._ihost_personality == constants.CONTROLLER):
            LOG.info("AgentManager apply_tpm_config: %s" % self._ihost_uuid)

            # this flag will be set to true the first time this
            # agent applies the tpmconfig
            self._tpmconfig_host_first_apply = True

            self._tpmconfig_rpc_failure = False
            response_dict = {}
            attribute_dict = {}
            rpcapi = conductor_rpcapi.ConductorAPI(
                            topic=conductor_rpcapi.MANAGER_TOPIC)

            # invoke tpmdevice-setup on this node.
            #
            # We also need to fetch and persist the content
            # of the TPM certificates in DB.
            try:
                utils.execute('tpmdevice-setup',
                              tpm_context['cert_path'],
                              tpm_context['tpm_path'],
                              tpm_context['public_path'],
                              run_as_root=True)

                attribute_dict['tpm_data'] = \
                        utils.read_filtered_directory_content(
                                os.path.dirname(tpm_context['tpm_path']),
                                "*.bin", "*.tpm")
            except exception.ProcessExecutionError as e:
                LOG.exception(e)
                response_dict['is_configured'] = False
            else:
                response_dict['is_configured'] = True
                attribute_dict['state'] = constants.TPMCONFIG_APPLYING

            # Only create a TPM device entry if the TPM certificates
            # were successfully created
            if response_dict['is_configured']:
                # Create a new TPM device for this host, or update it
                # with new TPM certs if such a device already exists.
                tpmdevice = rpcapi.tpm_device_update_by_host(context,
                                                             self._ihost_uuid,
                                                             attribute_dict)
                if not tpmdevice:
                    response_dict['is_configured'] = False

            # we will not tie this to agent audit, send back
            # response to conductor now.
            try:
                rpcapi.tpm_config_update_by_host(context,
                                                 self._ihost_uuid,
                                                 response_dict)
            except Timeout:
                # TPM configuration has applied, however incase
                # the agent cannot reach the conductor, tpmconfig
                # will be stuck in Applying state. Since the agent
                # audit by default does not send status updates during
                # "Applying" state, we will mark this as a failure case
                # and have the agent send an update (even in Applying state)
                LOG.info("tpm_config_update_by_host rpc Timeout.")
                self._tpmconfig_rpc_failure = True

        return

    def delete_pv(self, context, host_uuid, ipv_dict):
        """Delete LVM physical volume

         Also delete Logical volume Group if PV is last in group

        :param context: an admin context
        :param host_uuid: ihost uuid unique id
        :param ipv_dict: values for physical volume object
        :returns: pass or fail
        """
        LOG.debug("AgentManager.delete_pv: %s" % ipv_dict)
        if self._ihost_uuid and self._ihost_uuid == host_uuid:
            return self._ipv_operator.ipv_delete(ipv_dict)

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
                    subprocess.check_call(command, stdout=fnull, stderr=fnull)
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

    def disk_format_gpt(self, context, host_uuid, idisk_dict,
                        is_cinder_device):
        """GPT format a disk

        :param context: an admin context
        :param host_uuid: ihost uuid unique id
        :param idisk_dict: values for idisk volume object
        :param is_cinder_device: bool value tells if the idisk is for cinder
        :returns: pass or fail
        """
        LOG.debug("AgentManager.format_disk_gpt: %s" % idisk_dict)
        if self._ihost_uuid and self._ihost_uuid == host_uuid:
            return self._idisk_operator.disk_format_gpt(host_uuid,
                                                        idisk_dict,
                                                        is_cinder_device)
