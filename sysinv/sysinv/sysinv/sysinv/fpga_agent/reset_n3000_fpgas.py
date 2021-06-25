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
from oslo_log import log

from sysinv.common import utils
from sysinv.common import exception
from sysinv.fpga_agent.manager import get_n3000_devices
from sysinv.fpga_agent import constants
import tsconfig.tsconfig as tsc

# Volatile flag file so we only reset the N3000s once after bootup.
N3000_RESET_FLAG = os.path.join(tsc.VOLATILE_PATH, ".sysinv_n3000_reset")
LOG = log.getLogger(__name__)


def n3000_img_accessible():
    cmd = 'docker image list "%s"  --format "{{.Repository}}:{{.Tag}}"' % \
            constants.OPAE_IMG
    items = subprocess.check_output(shlex.split(cmd),  # pylint: disable=not-callable
                                   stderr=subprocess.STDOUT,
                                   universal_newlines=True)
    for line in items.splitlines():
        if line == constants.OPAE_IMG:
            LOG.info('%s image found' % constants.OPAE_IMG)
            return True

    LOG.info("%s image not found." % constants.OPAE_IMG)
    return False


def reset_device_n3000(pci_addr):
    # Reset the N3000 FPGA at the specified PCI address.
    try:
        # Build up the command to perform the reset.
        # Note the hack to work around OPAE tool locale issues
        cmd = ("docker run -t --privileged -e LC_ALL=en_US.UTF-8 "
               "-e LANG=en_US.UTF-8 " + constants.OPAE_IMG +
               " rsu bmcimg " + pci_addr)

        # Issue the command to perform the firmware update.
        subprocess.check_output(shlex.split(cmd),  # pylint: disable=not-callable
                                         stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        # "docker run" return code will be:
        #    125 if the error is with Docker daemon itself
        #    126 if the contained command cannot be invoked
        #    127 if the contained command cannot be found
        #    Exit code of contained command otherwise
        msg = ("Failed to reset device %s, "
               "return code is %d, command output: %s." %
               (pci_addr, exc.returncode,
                exc.output.decode('utf-8')))
        LOG.error(msg)
        LOG.error("Check for intel-max10 kernel logs.")
        raise exception.SysinvException(msg)


def reset_n3000_fpgas():
    if not os.path.exists(N3000_RESET_FLAG):
        # Reset all N3000 FPGAs on the system.
        # TODO: make this run in parallel if there are multiple devices.
        LOG.info("Resetting N3000 FPGAs.")
        got_exception = False
        fpga_addrs = get_n3000_devices()
        if not n3000_img_accessible() and \
                not os.path.exists(constants.DOCKER_LOGIN_FLAG):
            LOG.info("Either docker image or docker login is ready, exit...")
            return False

        for fpga_addr in fpga_addrs:
            try:
                reset_device_n3000(fpga_addr)
            except Exception:
                got_exception = True

        LOG.info("Done resetting N3000 FPGAs.")
        if not got_exception:
            utils.touch(N3000_RESET_FLAG)
            return True
        else:
            return False
    else:
        return True
