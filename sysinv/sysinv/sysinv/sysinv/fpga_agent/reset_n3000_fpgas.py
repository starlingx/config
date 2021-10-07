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
# Copyright (c) 2021 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import os
import shlex
from eventlet.green import subprocess
from glob import glob
from oslo_log import log

from sysinv.common import utils
from sysinv.common import exception
from sysinv.fpga_agent.manager import get_n3000_devices
from sysinv.fpga_agent import constants

# Volatile flag file so we only reset the N3000s once after bootup.
LOG = log.getLogger(__name__)

SYSFS_DEVICE_PATH = "/sys/bus/pci/devices/"
FME_PATH = "/fpga/intel-fpga-dev.*/intel-fpga-fme.*/"
SPI_PATH = "spi-altera.*.auto/spi_master/spi*/spi*.*/"

# These are relative to SPI_PATH
EEPROM_LOAD_PATH = "pkvl/eeprom_load"
EEPROM_UPDATE_STATUS_PATH = "pkvl/eeprom_update_status"

# The value in eeprom_update_status must be 0x1111 to indicate successful
# update as documented in the Intel FPGA N3000 User Guide
EEPROM_UPDATE_SUCCESS = '0x1111'


def n3000_img_accessible():
    cmd = 'ctr -n=k8s.io image list name=="%s"' % constants.OPAE_IMG
    items = subprocess.check_output(shlex.split(cmd),  # pylint: disable=not-callable
                                    stderr=subprocess.STDOUT,
                                    universal_newlines=True)
    for line in items.splitlines():
        if constants.OPAE_IMG in line:
            LOG.info('%s image found' % constants.OPAE_IMG)
            return constants.OPAE_IMG
    LOG.info('%s image not found, check older image' %
                constants.OPAE_IMG)
    # During upgrade. check if previous version is available
    cmd = 'ctr -n=k8s.io image list name=="%s"' % constants.OPAE_IMG_PREV
    items = subprocess.check_output(shlex.split(cmd),  # pylint: disable=not-callable
                                    stderr=subprocess.STDOUT,
                                    universal_newlines=True)
    for line in items.splitlines():
        if constants.OPAE_IMG_PREV in line:
            LOG.info('%s image found' % constants.OPAE_IMG_PREV)
            return constants.OPAE_IMG_PREV
    LOG.info('%s image not found, try image pull from controller' %
             constants.OPAE_IMG_PREV)

    # n3000 image not found in containerd, get it from the controller
    try:
        subprocess.check_output(["crictl", "pull", constants.OPAE_IMG])  # pylint: disable=not-callable
        LOG.info("Image %s imported by containerd" % constants.OPAE_IMG)
        return constants.OPAE_IMG
    except subprocess.CalledProcessError as exc:
        msg = ("Failed to pull image %s, "
               "return code is %d, command output: %s." %
               (constants.OPAE_IMG, exc.returncode, exc.output))
        LOG.info(msg)
    # During upgrade the current version is not available,
    # try pulling the previous version
    try:
        subprocess.check_output(["crictl", "pull", constants.OPAE_IMG_PREV])  # pylint: disable=not-callable
        LOG.info("Image %s imported by containerd" % constants.OPAE_IMG_PREV)
        return constants.OPAE_IMG_PREV
    except subprocess.CalledProcessError as exc:
        msg = ("Failed to pull image %s, "
            "return code is %d, command output: %s." %
            (constants.OPAE_IMG_PREV, exc.returncode, exc.output))
        LOG.info(msg)
    return None


def reset_device_n3000(pci_addr, opae_img):
    # Reset the N3000 FPGA at the specified PCI address.
    try:
        # Build up the command to perform the reset.
        # Note the hack to work around OPAE tool locale issues
        cmd = ("ctr -n=k8s.io run --rm --privileged " + opae_img +
               " v1 rsu bmcimg " + pci_addr)
        # Issue the command to perform the firmware update.
        subprocess.check_output(shlex.split(cmd),  # pylint: disable=not-callable
                                stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        msg = ("Failed to reset device %s, "
               "return code is %d, command output: %s." %
               (pci_addr, exc.returncode,
                exc.output.decode('utf-8')))
        LOG.error(msg)
        LOG.error("Check for intel-max10 kernel logs.")
        raise exception.SysinvException(msg)


def get_n3000_sysfs_file(pattern):
    """Find a sysfs file related to the N3000.

    The result should be an empty string if the file doesn't exist,
    or a single line of text if it does.
    """

    # Convert the pattern to a list of matching filenames
    filenames = glob(pattern)

    # If there are no matching files, return an empty string.
    if len(filenames) == 0:
        return ""

    # If there's more than one filename, complain.
    if len(filenames) > 1:
        LOG.warn("Pattern %s gave %s matching filenames, using the first." %
                 (pattern, len(filenames)))

    filename = filenames[0]
    return filename


def update_device_n3000_retimer(pci_addr):
    # Write 1 to the eeprom_load sysfs node of the card
    eeprom_load_pattern = (SYSFS_DEVICE_PATH + pci_addr + FME_PATH +
                           SPI_PATH + EEPROM_LOAD_PATH)
    try:
        eeprom_load_file = get_n3000_sysfs_file(eeprom_load_pattern)
        with open(eeprom_load_file, "w") as writer:
            writer.write("1")
    except Exception as e:
        msg = "Failed to load retimer: %s" % str(e)
        LOG.error(msg)
        raise exception.SysinvException(msg)

    # Check the eeprom_update_status node for completion
    eeprom_update_status_pattern = (SYSFS_DEVICE_PATH + pci_addr + FME_PATH +
                                    SPI_PATH + EEPROM_UPDATE_STATUS_PATH)
    eeprom_update_status = get_n3000_sysfs_file(eeprom_update_status_pattern)
    with open(eeprom_update_status, 'r') as reader:
        status = reader.read()
        if EEPROM_UPDATE_SUCCESS not in status:
            LOG.error("Failed to update retimer, status=%s" % status)


def reset_n3000_fpgas():
    if not os.path.exists(constants.N3000_RESET_FLAG):
        # Reset all N3000 FPGAs on the system.
        # TODO: make this run in parallel if there are multiple devices.
        LOG.info("Resetting N3000 FPGAs.")
        got_exception = False
        fpga_addrs = get_n3000_devices()
        opae_img = n3000_img_accessible()
        if opae_img is None:
            LOG.info("n3000 opae image is not ready, exit...")
            return False

        for fpga_addr in fpga_addrs:
            try:
                reset_device_n3000(fpga_addr, opae_img)
            except Exception:
                got_exception = True

        if not got_exception and os.path.exists(constants.N3000_RETIMER_FLAG):
            # The retimer included flag is set, execute additional steps
            fpga_addrs = get_n3000_devices()
            for fpga_addr in fpga_addrs:
                try:
                    LOG.info("Updating retimer")
                    update_device_n3000_retimer(fpga_addr)
                    LOG.info("Resetting N3000 second time")
                    reset_device_n3000(fpga_addr, opae_img)
                except Exception:
                    got_exception = True

        LOG.info("Done resetting N3000 FPGAs.")
        if not got_exception:
            utils.touch(constants.N3000_RESET_FLAG)
            if os.path.exists(constants.N3000_RETIMER_FLAG):
                os.remove(constants.N3000_RETIMER_FLAG)
            return True
        else:
            return False
    else:
        return True
