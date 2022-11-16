# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" Disk Utilities and helper functions."""

from sysinv.agent import partition
from sysinv.common.utils import trycmd
from sysinv.common.utils import execute
from oslo_log import log

LOG = log.getLogger(__name__)


def device_wipe(device):
    """Wipe the begining and the end of a device, partition or disk"""

    # Wipe well known GPT table entries, if any.
    trycmd('wipefs', '-f', '-a', device)
    execute('udevadm', 'settle')

    # Wipe any other tables at the beginning of the device.
    out, err = trycmd(
        'dd', 'if=/dev/zero',
        'of=%s' % device,
        'bs=512', 'count=2048',
        'conv=fdatasync')
    LOG.info("Wiped beginning of device: %s - %s" % (out, err))

    # Get size of disk.
    size, __ = trycmd('blockdev', '--getsz',
                      device)
    size = size.rstrip()

    if size and size.isdigit():
        # Wipe at the end of device.
        out, err = trycmd(
            'dd', 'if=/dev/zero',
            'of=%s' % device,
            'bs=512', 'count=2048',
            'seek=%s' % (int(size) - 2048),
            'conv=fdatasync')
        LOG.info("Wiped end of device: %s - %s" % (out, err))


def disk_wipe(device):
    """Wipe GPT table entries.
    We ignore exit codes in case disk is toasted or not present.
    Note: Assumption is that entire disk is used
    :param device: disk device node or device path
    """
    LOG.info("Wiping device: %s " % device)
    partOp = partition.PartitionOperator()
    partitions = partOp.get_sfdisk_info(device)

    # Call the wiping method for each partition
    for part in partitions:
        device_wipe(part['device_node'])

    # Wipe the disk itself
    device_wipe(device)

    LOG.info("Device %s zapped" % device)
