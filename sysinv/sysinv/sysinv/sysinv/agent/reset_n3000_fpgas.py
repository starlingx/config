# Copyright (c) 2021-2022, 2026 Wind River Systems, Inc.

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
# SPDX-License-Identifier: Apache-2.0

import os
from eventlet.green import subprocess
from oslo_log import log

from sysinv.common import fpga_constants
from sysinv.common import utils
from sysinv.common import exception
from sysinv.agent import fpga

# Volatile flag file so we only reset the N3000s once after bootup.
LOG = log.getLogger(__name__)

# OPAE 'rsu' tool, provided by the opae package installed on the host.
RSU_CMD = "/usr/bin/rsu"


def rsu_available():
    """True if the host-installed OPAE 'rsu' tool is executable."""
    return os.access(RSU_CMD, os.X_OK)


def run_rsu(image, pci_addr):
    """Reload the specified image on the device at the given PCI address."""
    cmd = [RSU_CMD, image, pci_addr]
    try:
        output = subprocess.check_output(cmd,  # pylint: disable=not-callable
                                         stderr=subprocess.STDOUT,
                                         universal_newlines=True)
        LOG.info(f"Reloaded {image} image on device {pci_addr}, "
                 f"output: {output}")
    except (subprocess.CalledProcessError, subprocess.SubprocessError) as exc:
        msg = (f"Failed to reload {image} image on device {pci_addr}, "
               f"return code: {exc.returncode}, output: {exc.output}. "
               f"Check intel-max10 kernel logs.")
        LOG.error(msg)
        raise exception.SysinvException(msg)


def reset_device_n3000(pci_addr):
    """Reset the N3000 FPGA at the specified PCI address."""
    run_rsu("bmcimg", pci_addr)


def update_device_n3000_retimer(pci_addr):
    """Reload the C827 retimer firmware of the N3000 at the given address."""
    run_rsu("retimer", pci_addr)


def reset_n3000_fpgas():
    if not os.path.exists(fpga_constants.N3000_RESET_FLAG):
        # Reset all N3000 FPGAs on the system.
        # TODO: make this run in parallel if there are multiple devices.
        LOG.info("Resetting N3000 FPGAs.")
        if not rsu_available():
            LOG.error("%s not found, the opae package is not installed. "
                      "Cannot reset the N3000 FPGAs." % RSU_CMD)
            return False
        got_exception = False
        try:
            fpga_addrs = fpga.FpgaOperator().get_n3000_devices()
        except Exception as e:
            LOG.error("Failed to get N3000 devices: %s" % e)
            return False

        for fpga_addr in fpga_addrs:
            try:
                reset_device_n3000(fpga_addr)
            except Exception:
                got_exception = True

        if not got_exception and os.path.exists(fpga_constants.N3000_RETIMER_FLAG):
            # The retimer included flag is set, execute additional steps
            LOG.info("Updating retimer")
            for fpga_addr in fpga.FpgaOperator().get_n3000_devices():
                try:
                    update_device_n3000_retimer(fpga_addr)
                except Exception:
                    got_exception = True

            # rsu re-enumerates the PCIe bus, so the addresses collected
            # above may no longer be valid. Query them again.
            LOG.info("Resetting N3000 second time")
            for fpga_addr in fpga.FpgaOperator().get_n3000_devices():
                try:
                    reset_device_n3000(fpga_addr)
                except Exception:
                    got_exception = True

        LOG.info("Done resetting N3000 FPGAs.")
        if not got_exception:
            utils.touch(fpga_constants.N3000_RESET_FLAG)
            if os.path.exists(fpga_constants.N3000_RETIMER_FLAG):
                os.remove(fpga_constants.N3000_RETIMER_FLAG)
            return True
        else:
            return False
    else:
        return True
