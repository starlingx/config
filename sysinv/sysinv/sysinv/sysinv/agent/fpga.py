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
# Copyright (c) 2020-2022 Wind River Systems, Inc.
#


""" Perform activity related to FPGA devices on a single host.

On start, collect and post FPGA inventory to conductor.

Commands (from conductors) are received via RPC calls.

"""

from __future__ import print_function
import errno
from eventlet.green import subprocess
from glob import glob
import six

import os
import shlex

from oslo_log import log
from six.moves.urllib.request import urlretrieve

from sysinv.agent import pci
from sysinv.common import fpga_constants
from sysinv.common import constants as cconstants
from sysinv.common import device as dconstants
from sysinv.common import exception
from sysinv.common import utils
from sysinv.conductor import rpcapi as conductor_rpcapi

import tsconfig.tsconfig as tsc

LOG = log.getLogger(__name__)

# This is the location where we cache the device image file while
# writing it to the hardware.
DEVICE_IMAGE_CACHE_DIR = "/usr/local/share/applications/sysinv"

SYSFS_DEVICE_PATH = "/sys/bus/pci/devices/"
FME_PATH = "/fpga/intel-fpga-dev.*/intel-fpga-fme.*/"
SPI_PATH = "spi-altera.*.auto/spi_master/spi*/spi*.*/"

# These are relative to FME_PATH
BITSTREAM_ID_PATH = "bitstream_id"

# These are relative to SPI_PATH
ROOT_HASH_PATH = "ifpga_sec_mgr/ifpga_sec*/security/sr_root_hash"
CANCELLED_CSKS_PATH = "ifpga_sec_mgr/ifpga_sec*/security/sr_canceled_csks"
IMAGE_LOAD_PATH = "fpga_flash_ctrl/fpga_image_load"
BMC_FW_VER_PATH = "bmcfw_flash_ctrl/bmcfw_version"
BMC_BUILD_VER_PATH = "max10_version"
RETIMER_A_VER_PATH = "pkvl/pkvl_a_version"
RETIMER_B_VER_PATH = "pkvl/pkvl_b_version"

# Length of the retimer version in database
RETIMER_VERSION_LENGTH = 32


class FpgaOperator(object):
    '''Class to encapsulate FPGA operations for System Inventory'''

    def __init__(self):
        pass

    def ensure_device_image_cache_exists(self):
        # Make sure the image cache directory exists, create it if needed.
        try:
            os.mkdir(DEVICE_IMAGE_CACHE_DIR, 0o755)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                msg = ("Unable to create device image cache directory %s!"
                    % DEVICE_IMAGE_CACHE_DIR)
                LOG.exception(msg)
                raise exception.SysinvException(msg)

    def get_http_port(self):
        # Get the http_port from /etc/platform/platform.conf.
        prefix = "http_port="
        http_port = cconstants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT
        if os.path.isfile(tsc.PLATFORM_CONF_FILE):
            with open(tsc.PLATFORM_CONF_FILE, 'r') as platform_file:
                for line in platform_file:
                    line = line.strip()
                    if line.startswith(prefix):
                        port = line[len(prefix):]
                        if utils.is_int_like(port):
                            LOG.info("Agent found %s%s" % (prefix, port))
                            http_port = port
                            break
                        else:
                            LOG.info("http_port entry: %s in platform.conf "
                                    "is not an integer" % port)
        return http_port

    def fetch_device_image(self, filename):
        # Pull the image from the controller.
        http_port = self.get_http_port()
        url = "http://controller:{}/device_images/{}".format(http_port, filename)
        local_path = DEVICE_IMAGE_CACHE_DIR + "/" + filename
        try:
            imagefile, headers = urlretrieve(url, local_path)
        except IOError:
            msg = ("Unable to retrieve device image from %s!" % url)
            LOG.exception(msg)
            raise exception.SysinvException(msg)
        return local_path

    def cleanup_container(self):
        # Delete container if exists
        cmd = 'ctr -n=k8s.io container list image=="%s"' % fpga_constants.OPAE_IMG
        items = subprocess.check_output(shlex.split(cmd),  # pylint: disable=not-callable
                                        stderr=subprocess.STDOUT,
                                        universal_newlines=True)
        for line in items.splitlines():
            if fpga_constants.OPAE_IMG in line:
                cmd = 'ctr -n=k8s.io container rm n3000-opae'
                subprocess.check_output(shlex.split(cmd),  # pylint: disable=not-callable
                                        stderr=subprocess.STDOUT,
                                        universal_newlines=True)
                LOG.info('Deleted stale container n3000-opae')
                break

    def set_cgroup_cpuset(self):
        # Set CPU affinity by updating the cpuset.cpus
        platform_cpulist = '0'
        cpuset_path = '/sys/fs/cgroup/cpuset/platform/'
        cpuset_file = os.path.join(cpuset_path, 'cpuset.cpus')
        if not os.path.exists(cpuset_path):
            os.makedirs(cpuset_path)
            with open('/etc/platform/worker_reserved.conf', 'r') as infile:
                for line in infile:
                    if "PLATFORM_CPU_LIST" in line:
                        val = line.split("=")
                        platform_cpulist = val[1].strip('\n')[1:-1].strip('"')
            with open(cpuset_file, 'w') as fd:
                LOG.info("Writing %s to file %s" % (platform_cpulist, cpuset_file))
                fd.write(platform_cpulist)

    def write_device_image_n3000(self, filename, pci_addr):
        # Write the firmware image to the FPGA at the specified PCI address.
        # We're assuming that the image update tools will catch the scenario
        # where the image is not compatible with the device.

        # If the container exists, the host probably rebooted during
        # a device update. Delete the container.
        self.cleanup_container()

        # Set cpu affinity for the container
        self.set_cgroup_cpuset()

        try:
            # Build up the command to perform the firmware update.
            # Note the hack to work around OPAE tool locale issues
            cmd = ("ctr -n=k8s.io run --rm --privileged " +
                "--env LC_ALL=en_US.UTF-8 --env LANG=en_US.UTF-8 " +
                "--cgroup platform " +
                "--mount type=bind,src=" + DEVICE_IMAGE_CACHE_DIR +
                ",dst=/mnt/images,options=rbind:ro " + fpga_constants.OPAE_IMG +
                " n3000-opae fpgasupdate -y --log-level debug /mnt/images/" +
                filename + " " + pci_addr)

            # Issue the command to perform the firmware update.
            subprocess.check_output(shlex.split(cmd),  # pylint: disable=not-callable
                                    stderr=subprocess.STDOUT)
            # TODO: switch to subprocess.Popen, parse the output and send
            #       progress updates.
        except subprocess.CalledProcessError as exc:
            # Check the return code, send completion info to sysinv-conductor.
            msg = ("Failed to update device image %s for device %s, "
                "return code is %d, command output: %s." %
                (filename, pci_addr, exc.returncode,
                    exc.output.decode('utf-8')))
            LOG.error(msg)
            LOG.error("Check for intel-max10 kernel logs.")
            raise exception.SysinvException(msg)

    def read_n3000_sysfs_file(self, pattern):
        # Read a sysfs file related to the N3000.
        # The result should be an empty string if the file doesn't exist,
        # or a single line of text if it does.

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
        infile = open(filename)
        try:
            line = infile.readline()
            return line.strip()
        except Exception:
            LOG.exception("Unable to read file %s" % filename)
        finally:
            infile.close()
        return ""

    def get_n3000_root_hash(self, pci_addr):
        # Query sysfs for the root key of the N3000 at the specified PCI address
        root_key_pattern = (SYSFS_DEVICE_PATH + pci_addr + FME_PATH +
                        SPI_PATH + ROOT_HASH_PATH)
        root_key = self.read_n3000_sysfs_file(root_key_pattern)
        # If the root key hasn't been programmed, return an empty string.
        if root_key == "hash not programmed":
            root_key = ""
        return root_key

    def get_n3000_revoked_keys(self, pci_addr):
        # Query sysfs for revoked keys of the N3000 at the specified PCI address
        revoked_key_pattern = (SYSFS_DEVICE_PATH + pci_addr + FME_PATH +
                            SPI_PATH + CANCELLED_CSKS_PATH)
        revoked_keys = self.read_n3000_sysfs_file(revoked_key_pattern)
        return revoked_keys

    def get_n3000_bitstream_id(self, pci_addr):
        # Query sysfs for bitstream ID of the N3000 at the specified PCI address
        bitstream_id_pattern = (SYSFS_DEVICE_PATH + pci_addr + FME_PATH +
                            BITSTREAM_ID_PATH)
        bitstream_id = self.read_n3000_sysfs_file(bitstream_id_pattern)
        return bitstream_id

    def get_n3000_boot_page(self, pci_addr):
        # Query sysfs for boot page of the N3000 at the specified PCI address
        image_load_pattern = (SYSFS_DEVICE_PATH + pci_addr + FME_PATH +
                            SPI_PATH + IMAGE_LOAD_PATH)
        image_load = self.read_n3000_sysfs_file(image_load_pattern)
        if image_load == "0":
            return "factory"
        elif image_load == "1":
            return "user"
        else:
            LOG.warn("Reading image load gave unexpected result: %s" % image_load)
            return ""

    def get_n3000_bmc_version(self, pci_addr, path):
        version_pattern = (SYSFS_DEVICE_PATH + pci_addr + FME_PATH +
                        SPI_PATH + path)
        version = self.read_n3000_sysfs_file(version_pattern)

        # If we couldn't read the file, return an empty string.
        if version == "":
            return ""

        # We're expecting a 32-bit value, possibly with "0x" in front.
        try:
            vint = int(version, 16)
        except ValueError:
            return ""

        if vint >= 1 << 32:
            LOG.warn("String (%s) read from file %s doesn't match the "
                    "expected pattern" % (version, version_pattern))
            return ""
        # There's probably a better way than this.
        # We want to match the version that Intel's "fpgainfo" tool reports.
        return ("%s.%s.%s.%s" % (chr(vint >> 24), str(vint >> 16 & 0xff),
                str(vint >> 8 & 0xff), str(vint & 0xff)))

    def get_n3000_bmc_fw_version(self, pci_addr):
        return self.get_n3000_bmc_version(pci_addr, BMC_FW_VER_PATH)

    def get_n3000_bmc_build_version(self, pci_addr):
        return self.get_n3000_bmc_version(pci_addr, BMC_BUILD_VER_PATH)

    def get_n3000_retimer_version(self, pci_addr, path):
        version_pattern = (SYSFS_DEVICE_PATH + pci_addr + FME_PATH +
                        SPI_PATH + path)
        version = self.read_n3000_sysfs_file(version_pattern)
        if len(version) > RETIMER_VERSION_LENGTH:
            LOG.warn("Retimer version string (%s) read from file %s is "
                    "unexpectedly long. It is truncating." %
                    (version, version_pattern))
            version = version[:RETIMER_VERSION_LENGTH]
        return version

    def get_n3000_retimer_a_version(self, pci_addr):
        return self.get_n3000_retimer_version(pci_addr, RETIMER_A_VER_PATH)

    def get_n3000_retimer_b_version(self, pci_addr):
        return self.get_n3000_retimer_version(pci_addr, RETIMER_B_VER_PATH)

    def get_n3000_devices(self):
        # First get the PCI addresses of each supported FPGA device
        cmd = ["lspci", "-Dm", "-d " + fpga_constants.N3000_VENDOR + ":" +
            fpga_constants.N3000_DEVICE]

        try:
            output = subprocess.check_output(  # pylint: disable=not-callable
                cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        except subprocess.CalledProcessError as exc:
            msg = ("Failed to get pci devices with vendor %s and device %s, "
                "return code is %d, command output: %s." %
                (fpga_constants.N3000_VENDOR, fpga_constants.N3000_DEVICE, exc.returncode,
                exc.output))
            LOG.warn(msg)
            raise exception.SysinvException(msg)

        # Parse the output of the lspci command and grab the PCI address
        fpga_addrs = []
        for line in output.splitlines():
            line = shlex.split(line.strip())
            fpga_addrs.append(line[0])
        return fpga_addrs

    def get_n3000_pci_info(self):
        """ Query PCI information about N3000 PCI devices.

        This needs to exactly mirror what sysinv-agent does as far as PCI
        updates.  We could potentially modify sysinv-agent to do the PCI
        updates when triggered by an RPC cast, but we don't need to rescan
        all PCI devices, just the N3000 devices.
        """
        pci_devs = []
        pci_device_list = []
        try:
            pci_operator = pci.PCIOperator()
            # We want to get updated info for the FPGA itself and any "virtual"
            # PCI devices implemented by the   This loop isn't very
            # efficient, but so far it's only a small number of devices.
            pci_devices = []
            for device in fpga_constants.N3000_DEVICES:
                pci_devices.extend(pci_operator.pci_devices_get(
                    vendor=fpga_constants.N3000_VENDOR, device=device))
            for pci_dev in pci_devices:
                pci_dev_array = pci_operator.pci_get_device_attrs(
                    pci_dev.pciaddr)
                for dev in pci_dev_array:
                    pci_devs.append(pci.PCIDevice(pci_dev, **dev))

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
                LOG.debug('Sysinv FPGA Agent dev {}'.format(pci_dev_dict))
                pci_device_list.append(pci_dev_dict)
        except Exception:
            LOG.exception("Unable to query FPGA pci information, "
                        "sysinv DB will be stale")

        return pci_device_list

    def watchdog_action(self, action):
        if action not in ["stop", "start"]:
            LOG.warn("watchdog_action called with invalid action: %s", action)
            return
        try:
            # Build up the command to perform the action.
            cmd = ["systemctl", action, "hostw"]

            # Issue the command to stop/start the watchdog
            subprocess.check_output(  # pylint: disable=not-callable
                cmd, stderr=subprocess.STDOUT,
                universal_newlines=True)
        except subprocess.CalledProcessError as exc:
            msg = ("Failed to %s hostw service, "
                    "return code is %d, command output: %s." %
                    (action, exc.returncode, exc.output))
            LOG.warn(msg)

    def stop_watchdog(self):
        self.watchdog_action("stop")

    def start_watchdog(self):
        self.watchdog_action("start")

    def get_fpga_info(self):
        # For now we only support the N3000, eventually we may need to support
        # other FPGA devices.

        # Get a list of N3000 FPGA device addresses.
        fpga_addrs = self.get_n3000_devices()

        # Next, get additional information information for devices in the list.
        fpgainfo_list = []
        for addr in fpga_addrs:
            # Store information for this FPGA
            fpgainfo = {'pciaddr': addr}
            fpgainfo['bmc_build_version'] = self.get_n3000_bmc_build_version(addr)
            fpgainfo['bmc_fw_version'] = self.get_n3000_bmc_fw_version(addr)
            fpgainfo['retimer_a_version'] = self.get_n3000_retimer_a_version(addr)
            fpgainfo['retimer_b_version'] = self.get_n3000_retimer_b_version(addr)
            fpgainfo['boot_page'] = self.get_n3000_boot_page(addr)
            fpgainfo['bitstream_id'] = self.get_n3000_bitstream_id(addr)
            fpgainfo['root_key'] = self.get_n3000_root_hash(addr)
            fpgainfo['revoked_key_ids'] = self.get_n3000_revoked_keys(addr)

            # TODO: Also retrieve the information about which NICs are on
            # the FPGA device.

            fpgainfo_list.append(fpgainfo)

        return fpgainfo_list

    def device_update_image(self, context, host_uuid, pci_addr, filename, transaction_id,
                            retimer_included):
        """Write the device image to the device at the specified address.

        Transaction is the transaction ID as specified by sysinv-conductor.

        This must send back either success or failure to sysinv-conductor
        via an RPC cast.  The transaction ID is sent back to allow sysinv-conductor
        to locate the transaction in the DB.

        TODO: could get fancier with an image cache and delete based on LRU.
        """

        rpcapi = conductor_rpcapi.ConductorAPI(
                        topic=conductor_rpcapi.MANAGER_TOPIC)

        try:
            LOG.info("ensure device image cache exists")
            self.ensure_device_image_cache_exists()

            # Pull the image from the controller via HTTP
            LOG.info("fetch device image %s" % filename)
            local_path = self.fetch_device_image(filename)

            # TODO: check CSK used to sign image, ensure it hasn't been cancelled
            # TODO: check root key used to sign image, ensure it matches root key of hardware
            #       Note: may want to check these in the sysinv API too.

            try:
                LOG.info("setting transaction id %s as in progress" % transaction_id)
                rpcapi.device_update_image_status(
                    context, host_uuid, transaction_id,
                    dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS)

                # Disable the watchdog service to prevent a reboot on things
                # like critical process death. We don't want to reboot while
                # flashing the FPGA.
                self.stop_watchdog()

                # Write the image to the specified PCI device.
                # TODO:  when we support more than just N3000, we'll need to
                # pick the appropriate low-level write function based on the
                # hardware type.
                LOG.info("writing device image %s to device %s" % (filename, pci_addr))
                self.write_device_image_n3000(filename, pci_addr)

                # If we get an exception trying to send the status update
                # there's not much we can do.
                try:
                    LOG.info("setting transaction id %s as complete" % transaction_id)
                    rpcapi.device_update_image_status(
                        context, host_uuid, transaction_id,
                        dconstants.DEVICE_IMAGE_UPDATE_COMPLETED)
                except Exception:
                    LOG.exception("Unable to send fpga update image status "
                                  "completion message for transaction %s."
                                  % transaction_id)
            finally:
                # Delete the image file.
                os.remove(local_path)
                # start the watchdog service again
                self.start_watchdog()
                # If device image contains c827 retimer firmware, set the retimer flag
                if retimer_included:
                    utils.touch(fpga_constants.N3000_RETIMER_FLAG)

        except exception.SysinvException as exc:
            LOG.info("setting transaction id %s as failed" % transaction_id)
            rpcapi.device_update_image_status(context, host_uuid,
                                            transaction_id,
                                            dconstants.DEVICE_IMAGE_UPDATE_FAILED,
                                            six.text_type(exc))
