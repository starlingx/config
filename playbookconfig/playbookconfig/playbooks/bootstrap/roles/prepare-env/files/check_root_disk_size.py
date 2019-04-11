#!/usr/bin/python
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import pyudev
import re
import subprocess
import sys

DEVICE_NAME_NVME = 'nvme'


def get_rootfs_node():
    """Cloned from sysinv"""
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
        if DEVICE_NAME_NVME in device:
            re_line = re.compile(r'^(nvme[0-9]*n[0-9]*)')
        else:
            re_line = re.compile(r'^(\D*)')
        match = re_line.search(device)
        if match:
            return os.path.join("/dev", match.group(1))

    return


def parse_fdisk(device_node):
    """Cloned/modified from sysinv"""
    # Run command
    fdisk_command = ('fdisk -l %s 2>/dev/null | grep "Disk %s:"' %
                     (device_node, device_node))
    fdisk_process = subprocess.Popen(fdisk_command, stdout=subprocess.PIPE,
                                     shell=True)
    fdisk_output = fdisk_process.stdout.read()

    # Parse output
    secnd_half = fdisk_output.split(',')[1]
    size_bytes = secnd_half.split()[0].strip()

    # Convert bytes to GiB (1 GiB = 1024*1024*1024 bytes)
    int_size = int(size_bytes)
    size_gib = int_size / 1073741824

    return int(size_gib)


def get_root_disk_size():
    """Get size of the root disk """
    context = pyudev.Context()
    rootfs_node = get_rootfs_node()
    print(rootfs_node)
    size_gib = 0

    for device in context.list_devices(DEVTYPE='disk'):
        # /dev/nvmeXn1 259 are for NVME devices
        major = device['MAJOR']
        if (major == '8' or major == '3' or major == '253' or
                major == '259'):
            devname = device['DEVNAME']
            if devname == rootfs_node:
                try:
                    size_gib = parse_fdisk(devname)
                except Exception:
                    break
                break
    return size_gib


if __name__ == '__main__':

    if len(sys.argv) < 2:
        raise Exception("Invalid input!")

    rds = get_root_disk_size()
    print(rds)
    if rds < int(sys.argv[1]):
        raise Exception("Failed validation!")
