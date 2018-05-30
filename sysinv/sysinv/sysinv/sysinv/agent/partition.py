#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

""" Inventory disk partition utilities and helper functions."""

import json
import math
import parted
import pyudev
import subprocess
import sys
from sysinv.common import utils as utils
from sysinv.openstack.common import log as logging

LOG = logging.getLogger(__name__)

VENDOR_ID_LIO = 'LIO-ORG'


class PartitionOperator(object):
    """Class to encapsulate partition operations for System Inventory."""

    def __init__(self):
        pass

    def handle_exception(self, e):
        traceback = sys.exc_info()[-1]
        LOG.error("%s @ %s:%s" % (e, traceback.tb_frame.f_code.co_filename,
                                  traceback.tb_lineno))

    def get_sgdisk_info(self, device_path):
        """Obtain partition type GUID, type name and UUID.
        :param:   device_path: the disk's device path
        :returns: list of partition info
        """
        sgdisk_part_info = []
        fields = ['part_number', 'type_guid', 'type_name', 'uuid']
        sgdisk_command = '{} {}'.format('/usr/bin/partition_info.sh',
                                        device_path)

        try:
            sgdisk_process = subprocess.Popen(sgdisk_command,
                                              stdout=subprocess.PIPE,
                                              shell=True)
        except Exception as e:
            self.handle_exception("Could not retrieve partition information: "
                                  "%s" % e)
        sgdisk_output = sgdisk_process.stdout.read()

        rows = [row for row in sgdisk_output.split(';') if row.strip()]

        for row in rows:
            values = row.split()
            partition = dict(zip(fields, values))

            if 'part_number' in partition.keys():
                partition['part_number'] = int(partition['part_number'])

            sgdisk_part_info.append(partition)

        return sgdisk_part_info

    @utils.skip_udev_partition_probe
    def get_partition_info(self, device_path, device_node):
        """Obtain all information needed for the partitions on a disk.
        :param:   device_path: the disk's device path
        :param:   device_node: the disk's device node
        :returns: list of partitions"""
        # Check that partition table format is GPT. Return 0 if not.
        if not utils.disk_is_gpt(device_node=device_node):
            LOG.warn("Format of disk node %s is not GPT." % device_node)
            return None

        try:
            device = parted.getDevice(device_node)
            disk = parted.newDisk(device)
        except Exception as e:
            LOG.warn("No partition info for disk %s - %s" % (device_path, e))
            return None

        ipartitions = []

        sgdisk_partitions = self.get_sgdisk_info(device_path)
        LOG.debug("PARTED sgdisk_part_info: %s" % str(sgdisk_partitions))

        partitions = disk.partitions
        LOG.debug("PARTED %s partitions: %s" % (device_node, str(partitions)))

        for partition in partitions:
            part_device_node = partition.path
            part_device_path = '{}-part{}'.format(device_path,
                                                  partition.number)
            LOG.debug("PARTED part_device_path: %s" % part_device_path)
            size_mib = partition.getSize()
            LOG.debug("PARTED partition size: %s" % size_mib)
            start_mib = math.ceil(float(partition.geometry.start) / 2048)
            LOG.debug("PARTED partition start: %s" % start_mib)
            end_mib = math.ceil(float(partition.geometry.end) / 2048)
            LOG.debug("PARTED partition end %s" % end_mib)

            sgdisk_partition = next((
                part for part in sgdisk_partitions
                if part['part_number'] == partition.number),
                None)

            part_type_guid = None
            part_uuid = None
            part_type_name = None
            if sgdisk_partition:
                if 'type_guid' in sgdisk_partition:
                    part_type_guid = sgdisk_partition.get('type_guid').lower()
                if 'type_name' in sgdisk_partition:
                    part_type_name = sgdisk_partition.get(
                        'type_name').replace('.', ' ')
                if 'uuid' in sgdisk_partition:
                    part_uuid = sgdisk_partition.get('uuid').lower()
                LOG.debug("PARTED part_type_guid: %s" % part_type_guid)
                LOG.debug("PARTED part_uuid: %s" % part_uuid)

            part_attrs = {
                'device_node': part_device_node,
                'device_path': part_device_path,
                'start_mib': start_mib,
                'end_mib': end_mib,
                'size_mib': size_mib,
                'type_guid': part_type_guid,
                'type_name': part_type_name,
                'uuid': part_uuid,
            }

            ipartitions.append(part_attrs)

        return ipartitions

    def ipartition_get(self):
        """Enumerate partitions
        :param self
        :returns list of partitions and attributes
        """

        ipartitions = []

        # Get all disk devices.
        context = pyudev.Context()
        for device in context.list_devices(DEVTYPE='disk'):
            if device.get("ID_BUS") == "usb":
                # Skip USB devices
                continue
            if device.get("ID_VENDOR") == VENDOR_ID_LIO:
                # Skip iSCSI devices, they are links for volume storage
                continue
            if device.get("DM_VG_NAME") or device.get("DM_LV_NAME"):
                # Skip LVM devices
                continue
            major = device['MAJOR']

            if (major == '8' or major == '3' or major == '253' or
                    major == '259'):
                device_path = "/dev/disk/by-path/" + device['ID_PATH']
                device_node = device.device_node

                try:
                    new_partitions = self.get_partition_info(device_path=device_path,
                                                             device_node=device_node)
                except IOError as e:
                    LOG.error("Error getting new partitions for: %s. Reason: %s" %
                              (device_node, str(e)))

                if new_partitions:
                    ipartitions.extend(new_partitions)

        return ipartitions
