#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

""" inventory idisk Utilities and helper functions."""

from eventlet.green import subprocess
import os
import pyudev
import re
import sys

from oslo_log import log as logging

from sysinv.common import disk_utils
from sysinv.common import constants
from sysinv.common import utils
from sysinv.conductor import rpcapi as conductor_rpcapi
from sysinv.openstack.common import context

LOG = logging.getLogger(__name__)


class DiskOperator(object):
    '''Class to encapsulate Disk operations for System Inventory'''

    def __init__(self):

        self.num_cpus = 0
        self.num_nodes = 0
        self.float_cpuset = 0
        self.default_hugepage_size_kB = 0
        self.total_memory_MiB = 0
        self.free_memory_MiB = 0
        self.total_memory_nodes_MiB = []
        self.free_memory_nodes_MiB = []
        self.topology = {}

        # self._get_cpu_topology()
        # self._get_default_hugepage_size_kB()
        # self._get_total_memory_MiB()
        # self._get_total_memory_nodes_MiB()
        # self._get_free_memory_MiB()
        # self._get_free_memory_nodes_MiB()

    def convert_range_string_to_list(self, s):
        olist = []
        s = s.strip()
        if s:
            for part in s.split(','):
                if '-' in part:
                    a, b = part.split('-')
                    a, b = int(a), int(b)
                    olist.extend(range(a, b + 1))
                else:
                    a = int(part)
                    olist.append(a)
        olist.sort()
        return olist

    def get_rootfs_node(self):
        cmdline_file = '/proc/cmdline'
        device = None

        with open(cmdline_file, 'r') as f:
            for line in f:
                for param in line.split():
                    params = param.split("=", 1)
                    if params[0] == "root":
                        if "UUID=" in params[1]:
                            key, uuid = params[1].split("=")
                            symlink = "/dev/disk/by-uuid/%s" % uuid
                            device = os.path.basename(os.readlink(symlink))
                        else:
                            device = os.path.basename(params[1])

        if device is not None:
            if constants.DEVICE_NAME_NVME in device:
                re_line = re.compile(r'^(nvme[0-9]*n[0-9]*)')
            else:
                re_line = re.compile(r'^(\D*)')
            match = re_line.search(device)
            if match:
                return os.path.join("/dev", match.group(1))

        return

    @utils.skip_udev_partition_probe
    def get_disk_available_mib(self, device_node):
        # Check that partition table format is GPT.
        # Return 0 if not.
        if not utils.disk_is_gpt(device_node=device_node):
            LOG.debug("Format of disk node %s is not GPT." % device_node)
            return 0

        pvs_command = '{} {}'.format('pvs | grep -w ', device_node)
        pvs_process = subprocess.Popen(pvs_command, stdout=subprocess.PIPE,
                                       shell=True, universal_newlines=True)
        pvs_output = pvs_process.stdout.read()

        if pvs_output:
            LOG.debug("Disk %s is completely used by a PV => 0 available mib."
                      % device_node)
            return 0

        # Get sector size command.
        sector_size_bytes_cmd = '{} {}'.format('blockdev --getss', device_node)

        # Get total free space in sectors command.
        avail_space_sectors_cmd = '{} {} {}'.format(
            'sgdisk -p', device_node, "| grep \"Total free space\"")

        # Get the sector size.
        sector_size_bytes_process = subprocess.Popen(
            sector_size_bytes_cmd, stdout=subprocess.PIPE, shell=True,
            universal_newlines=True)
        sector_size_bytes = sector_size_bytes_process.stdout.read().rstrip()

        # Get the free space.
        avail_space_sectors_process = subprocess.Popen(
            avail_space_sectors_cmd, stdout=subprocess.PIPE, shell=True,
            universal_newlines=True)
        avail_space_sectors_output = avail_space_sectors_process.stdout.read()
        avail_space_sectors = re.findall('\d+',
                                         avail_space_sectors_output)[0].rstrip()

        # Free space in MiB.
        avail_space_mib = (int(sector_size_bytes) * int(avail_space_sectors) //
                           (1024 ** 2))

        # Keep 2 MiB for partition table.
        if avail_space_mib >= 2:
            avail_space_mib = avail_space_mib - 2
        else:
            avail_space_mib = 0

        return avail_space_mib

    def disk_prepare(self, host_uuid, idisk_dict,
                     skip_format, is_cinder_device):
        disk_node = idisk_dict.get('device_path')

        disk_utils.disk_wipe(disk_node)
        if not skip_format:
            utils.execute('parted', disk_node, 'mklabel', 'gpt')

        if is_cinder_device:
            LOG.debug("Removing .node_cinder_lvm_config_complete_file")
            try:
                os.remove(constants.NODE_CINDER_LVM_CONFIG_COMPLETE_FILE)
            except OSError:
                LOG.error(".node_cinder_lvm_config_complete_file not present.")
                pass

        # On SX ensure wipe succeeds before DB is updated.
        # Flag file is used to mark wiping in progress.
        try:
            os.remove(constants.DISK_WIPE_IN_PROGRESS_FLAG)
        except OSError:
            # it's ok if file is not present.
            pass

        # We need to send the updated info about the host disks back to
        # the conductor.
        idisk_update = self.idisk_get()
        ctxt = context.get_admin_context()
        rpcapi = conductor_rpcapi.ConductorAPI(
            topic=conductor_rpcapi.MANAGER_TOPIC)
        rpcapi.idisk_update_by_ihost(ctxt,
                                     host_uuid,
                                     idisk_update)

    def handle_exception(self, e):
        traceback = sys.exc_info()[-1]
        LOG.error("%s @ %s:%s" % (e, traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

    def is_rotational(self, device_name):
        """Find out if a certain disk is rotational or not. Mostly used for
           determining if disk is HDD or SSD.
        """

        # Obtain the path to the rotational file for the current device.
        device = device_name['DEVNAME'].split('/')[-1]
        rotational_path = "/sys/block/{device}/queue/rotational"\
                          .format(device=device)

        rotational = None
        # Read file and remove trailing whitespaces.
        if os.path.isfile(rotational_path):
            with open(rotational_path, 'r') as rot_file:
                rotational = rot_file.read()
            rotational = rotational.rstrip()

        return rotational

    def get_device_id_wwn(self, device):
        """Determine the ID and WWN of a disk from the value of the DEVLINKS
           attribute.

           Note: This data is not currently being used for anything. We are
           gathering this information so the conductor can store for future use.
        """
        # The ID and WWN default to None.
        device_id = None
        device_wwn = None

        # If there is no DEVLINKS attribute, return None.
        if 'DEVLINKS' not in device:
            return device_id, device_wwn

        # Extract the ID and the WWN.
        LOG.debug("[DiskEnum] get_device_id_wwn: devlinks= %s" %
                  device['DEVLINKS'])
        devlinks = device['DEVLINKS'].split()
        for devlink in devlinks:
            if "by-id" in devlink:
                if "wwn" not in devlink:
                    device_id = devlink.split('/')[-1]
                    LOG.debug("[DiskEnum] by-id: %s id: %s" % (devlink,
                                                               device_id))
                else:
                    device_wwn = devlink.split('/')[-1]
                    LOG.debug("[DiskEnum] by-wwn: %s wwn: %s" % (devlink,
                                                                 device_wwn))

        return device_id, device_wwn

    def idisk_get(self):
        """Enumerate disk topology based on:

        :param self
        :returns list of disk and attributes
        """
        idisk = []
        context = pyudev.Context()

        for device in context.list_devices(DEVTYPE='disk'):
            if not utils.is_system_usable_block_device(device):
                continue

            if device['MAJOR'] in constants.VALID_MAJOR_LIST:
                if 'ID_PATH' in device:
                    device_path = "/dev/disk/by-path/" + device['ID_PATH']
                    LOG.debug("[DiskEnum] device_path: %s ", device_path)
                else:
                    # We should always have a udev supplied /dev/disk/by-path
                    # value as a matter of normal operation. We do not expect
                    # this to occur, thus the error.
                    #
                    # The kickstart files for the host install require the
                    # by-path value also to be present or the host install will
                    # fail. Since the installer and the runtime share the same
                    # kernel/udev we should not see this message on an installed
                    # system.
                    device_path = None
                    LOG.error("Device %s does not have an ID_PATH value provided "
                              "by udev" % device.device_node)

                size_mib = 0
                available_mib = 0
                model_num = ''
                serial_id = ''

                # Can merge all try/except in one block but this allows at
                # least attributes with no exception to be filled
                try:
                    size_mib = utils.get_disk_capacity_mib(device.device_node)
                except Exception as e:
                    self.handle_exception("Could not retrieve disk size - %s "
                                          % e)

                try:
                    available_mib = self.get_disk_available_mib(
                        device_node=device.device_node)
                except Exception as e:
                    self.handle_exception("Could not retrieve disk %s free space" % e)

                try:
                    # ID_MODEL received from udev is not correct for disks that
                    # are used entirely for LVM. LVM replaced the model ID with
                    # its own identifier that starts with "LVM PV".For this
                    # reason we will attempt to retrieve the correct model ID
                    # by using 2 different commands: hdparm and lsblk and
                    # hdparm. If one of them fails, the other one can attempt
                    # to retrieve the information. Else we use udev.

                    # try hdparm command first
                    hdparm_command = 'hdparm -I %s |grep Model' % (
                        device.get('DEVNAME'))
                    hdparm_process = subprocess.Popen(
                        hdparm_command,
                        stdout=subprocess.PIPE,
                        shell=True, universal_newlines=True)
                    hdparm_output = hdparm_process.communicate()[0]
                    if hdparm_process.returncode == 0:
                        second_half = hdparm_output.split(':')[1]
                        model_num = second_half.strip()
                    else:
                        # try lsblk command
                        lsblk_command = 'lsblk -dn --output MODEL %s' % (
                                             device.get('DEVNAME'))
                        lsblk_process = subprocess.Popen(
                                            lsblk_command,
                                            stdout=subprocess.PIPE,
                                            shell=True,
                                            universal_newlines=True)
                        lsblk_output = lsblk_process.communicate()[0]
                        if lsblk_process.returncode == 0:
                            model_num = lsblk_output.strip()
                        else:
                            # both hdparm and lsblk commands failed, try udev
                            model_num = device.get('ID_MODEL')
                    if not model_num:
                        model_num = constants.DEVICE_MODEL_UNKNOWN
                except Exception as e:
                    self.handle_exception("Could not retrieve disk model "
                                          "for disk %s. Exception: %s" %
                                          (device.get('DEVNAME'), e))
                try:
                    if 'ID_SCSI_SERIAL' in device:
                        serial_id = device['ID_SCSI_SERIAL']
                    else:
                        serial_id = device['ID_SERIAL_SHORT']
                except Exception as e:
                    self.handle_exception("Could not retrieve disk "
                                          "serial ID - %s " % e)

                capabilities = dict()
                if model_num:
                    capabilities.update({'model_num': model_num})

                if self.get_rootfs_node() == device.device_node:
                    capabilities.update({'stor_function': 'rootfs'})

                rotational = self.is_rotational(device)
                device_type = device.device_type

                rotation_rate = constants.DEVICE_TYPE_UNDETERMINED
                if rotational == '1':
                    device_type = constants.DEVICE_TYPE_HDD
                    if 'ID_ATA_ROTATION_RATE_RPM' in device:
                        rotation_rate = device['ID_ATA_ROTATION_RATE_RPM']
                elif rotational == '0':
                    if constants.DEVICE_NAME_NVME in device.device_node:
                        device_type = constants.DEVICE_TYPE_NVME
                    else:
                        device_type = constants.DEVICE_TYPE_SSD
                    rotation_rate = constants.DEVICE_TYPE_NA

                # TODO else: what is the other possible stor_function value?
                #      or do we just use pair { 'is_rootfs': True } instead?
                # Obtain device ID and WWN.
                device_id, device_wwn = self.get_device_id_wwn(device)

                attr = {
                        'device_node': device.device_node,
                        'device_num': device.device_number,
                        'device_type': device_type,
                        'device_path': device_path,
                        'device_id': device_id,
                        'device_wwn': device_wwn,
                        'size_mib': size_mib,
                        'available_mib': available_mib,
                        'serial_id': serial_id,
                        'capabilities': capabilities,
                        'rpm': rotation_rate,
                       }

                idisk.append(attr)

        LOG.debug("idisk= %s" % idisk)

        return idisk
