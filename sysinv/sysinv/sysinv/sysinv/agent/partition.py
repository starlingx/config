#
# Copyright (c) 2017-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

""" Inventory disk partition utilities and helper functions."""

import pyudev
import sys

from oslo_log import log as logging
from sysinv.common import constants
from sysinv.common import utils as utils

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

    def get_sfdisk_info(self, device_path):
        """Obtain partition type GUID, type name and UUID.
        :param:   device_path: the disk's device path
        :returns: list of partition info
        """
        sfdisk_part_info = []
        fields = ['part_number', 'device_node', 'type_guid', 'type_name',
                  'uuid', 'start_mib', 'end_mib', 'size_mib']
        sfdisk_command = '{} {}'.format('/usr/bin/partition_info.sh',
                                        device_path)

        sfdisk_stdout, sfdisk_stderr = utils.subprocess_open(command=sfdisk_command,
                                                             timeout=10)

        sfdisk_output = sfdisk_stdout.rstrip()

        rows = [row for row in sfdisk_output.split(';') if row.strip()]

        for row in rows:
            values = row.split()
            partition = dict(zip(fields, values))

            if 'part_number' in partition.keys():
                partition['part_number'] = int(partition['part_number'])

            sfdisk_part_info.append(partition)

        return sfdisk_part_info

    @utils.skip_udev_partition_probe
    def get_partition_info(self, device_path, device_node, skip_gpt_check=False):
        """Obtain all information needed for the partitions on a disk.
        :param:   device_path: the disk's device path
        :param:   device_node: the disk's device node
        :returns: list of partitions"""
        # Check that partition table format is GPT. Return 0 if not.
        if ((not utils.disk_is_gpt(device_node=device_node)) and (not skip_gpt_check)):
            LOG.debug("Format of disk node %s is not GPT." % device_node)
            return None

        ipartitions = []

        sfdisk_partitions = self.get_sfdisk_info(device_path)
        LOG.debug("PARTED sfdisk_part_info: %s" % str(sfdisk_partitions))

        for partition in sfdisk_partitions:
            partition_number = partition.get('part_number')
            size_mib = partition.get('size_mib')
            if constants.DEVICE_NAME_NVME in device_node:
                part_device_node = '{}p{}'.format(device_node,
                                                  partition_number)
            elif constants.DEVICE_NAME_MPATH in device_node:
                part_device_node = '{}-part{}'.format(device_node,
                                                  partition_number)
            else:
                part_device_node = '{}{}'.format(device_node, partition_number)

            part_device_path = utils.get_part_device_path(device_path,
                                                          partition_number)
            start_mib = partition.get('start_mib')
            end_mib = partition.get('end_mib')

            part_type_name = partition.get('type_name').replace('.', ' ')
            part_type_guid = partition.get('type_guid').lower()
            part_uuid = partition.get('uuid').lower()

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

    def ipartition_get(self, skip_gpt_check=False):
        """Enumerate partitions
        :param self
        :returns list of partitions and attributes
        """

        ipartitions = []

        # Get all disk devices.
        context = pyudev.Context()
        for device in context.list_devices(DEVTYPE='disk'):
            if not utils.is_system_usable_block_device(device):
                continue

            if device['MAJOR'] in constants.VALID_MAJOR_LIST:
                if 'ID_PATH' in device:
                    device_path = "/dev/disk/by-path/" + device['ID_PATH']
                    device_node = device.device_node
                elif (constants.DEVICE_NAME_MPATH in device.get("DM_NAME", "")
                      and 'DM_WWN' in device):
                    device_path = "/dev/disk/by-id/wwn-" + device['DM_WWN']
                    device_node = utils.get_mpath_from_dm(device.device_node)

                try:
                    new_partitions = self.get_partition_info(device_path=device_path,
                                                             device_node=device_node,
                                                             skip_gpt_check=skip_gpt_check)
                except IOError as e:
                    LOG.error("Error getting new partitions for: %s. Reason: %s" %
                              (device_node, str(e)))

                if new_partitions:
                    ipartitions.extend(new_partitions)

        return ipartitions
