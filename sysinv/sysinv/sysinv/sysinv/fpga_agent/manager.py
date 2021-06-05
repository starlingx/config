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
# Copyright (c) 2020 Wind River Systems, Inc.
#


""" Perform activity related to FPGA devices on a single host.

A single instance of :py:class:`sysinv.agent.manager.FpgaAgentManager` is
created within the *sysinv-fpga-agent* process, and is responsible for
performing all actions for this host related to FPGA devices.

On start, collect and post FPGA inventory to conductor.

Commands (from conductors) are received via RPC calls.

"""

from __future__ import print_function
import errno
from eventlet.green import subprocess
from glob import glob

import os
import shlex
import time
import urllib

from oslo_config import cfg
from oslo_log import log
from oslo_utils import uuidutils

from sysinv.agent import pci
from sysinv.common import constants as cconstants
from sysinv.common import device as dconstants
from sysinv.common import exception
from sysinv.common import service
from sysinv.common import utils
from sysinv.conductor import rpcapi as conductor_rpcapi
from sysinv.fpga_agent import constants
from sysinv.objects import base as objects_base
from sysinv.openstack.common import context as ctx

import tsconfig.tsconfig as tsc

MANAGER_TOPIC = 'sysinv.fpga_agent_manager'

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
CONF.register_opts(agent_opts, 'fpga_agent')

# TODO: Make this specified in the config file.
# This is the docker image containing the OPAE tools to access the FPGA device.
OPAE_IMG = "registry.local:9001/docker.io/starlingx/n3000-opae:stx.4.0-v1.0.0"

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


def wait_for_docker_login():
    # TODO: add a timeout
    LOG.info("Waiting for docker login flag.")
    while not os.path.exists(constants.DOCKER_LOGIN_FLAG):
        time.sleep(1)
    LOG.info("Found docker login flag, continuing.")


def ensure_device_image_cache_exists():
    # Make sure the image cache directory exists, create it if needed.
    try:
        os.mkdir(DEVICE_IMAGE_CACHE_DIR, 0o755)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            msg = ("Unable to create device image cache directory %s!"
                   % DEVICE_IMAGE_CACHE_DIR)
            LOG.exception(msg)
            raise exception.SysinvException(msg)


def get_http_port():
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


def fetch_device_image(filename):
    # Pull the image from the controller.
    http_port = get_http_port()
    url = "http://controller:{}/device_images/{}".format(http_port, filename)
    local_path = DEVICE_IMAGE_CACHE_DIR + "/" + filename
    try:
        imagefile, headers = urllib.urlretrieve(url, local_path)
    except IOError:
        msg = ("Unable to retrieve device image from %s!" % url)
        LOG.exception(msg)
        raise exception.SysinvException(msg)
    return local_path


def write_device_image_n3000(filename, pci_addr):
    # Write the firmware image to the FPGA at the specified PCI address.
    # We're assuming that the image update tools will catch the scenario
    # where the image is not compatible with the device.
    try:
        # Build up the command to perform the firmware update.
        # Note the hack to work around OPAE tool locale issues
        cmd = ("docker run -t --privileged -e LC_ALL=en_US.UTF-8 "
               "-e LANG=en_US.UTF-8 -v " + DEVICE_IMAGE_CACHE_DIR +
               ":" + "/mnt/images " + OPAE_IMG +
               " fpgasupdate -y --log-level debug /mnt/images/" +
               filename + " " + pci_addr)

        # Issue the command to perform the firmware update.
        subprocess.check_output(shlex.split(cmd),  # pylint: disable=not-callable
                                         stderr=subprocess.STDOUT)
        # TODO: switch to subprocess.Popen, parse the output and send
        #       progress updates.
    except subprocess.CalledProcessError as exc:
        # Check the return code, send completion info to sysinv-conductor.
        # "docker run" return code will be:
        #    125 if the error is with Docker daemon itself
        #    126 if the contained command cannot be invoked
        #    127 if the contained command cannot be found
        #    Exit code of contained command otherwise
        msg = ("Failed to update device image %s for device %s, "
               "return code is %d, command output: %s." %
               (filename, pci_addr, exc.returncode,
                exc.output.decode('utf-8')))
        LOG.error(msg)
        LOG.error("Check for intel-max10 kernel logs.")
        raise exception.SysinvException(msg)


def read_n3000_sysfs_file(pattern):
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


def get_n3000_root_hash(pci_addr):
    # Query sysfs for the root key of the N3000 at the specified PCI address
    root_key_pattern = (SYSFS_DEVICE_PATH + pci_addr + FME_PATH +
                     SPI_PATH + ROOT_HASH_PATH)
    root_key = read_n3000_sysfs_file(root_key_pattern)
    # If the root key hasn't been programmed, return an empty string.
    if root_key == "hash not programmed":
        root_key = ""
    return root_key


def get_n3000_revoked_keys(pci_addr):
    # Query sysfs for revoked keys of the N3000 at the specified PCI address
    revoked_key_pattern = (SYSFS_DEVICE_PATH + pci_addr + FME_PATH +
                           SPI_PATH + CANCELLED_CSKS_PATH)
    revoked_keys = read_n3000_sysfs_file(revoked_key_pattern)
    return revoked_keys


def get_n3000_bitstream_id(pci_addr):
    # Query sysfs for bitstream ID of the N3000 at the specified PCI address
    bitstream_id_pattern = (SYSFS_DEVICE_PATH + pci_addr + FME_PATH +
                           BITSTREAM_ID_PATH)
    bitstream_id = read_n3000_sysfs_file(bitstream_id_pattern)
    return bitstream_id


def get_n3000_boot_page(pci_addr):
    # Query sysfs for boot page of the N3000 at the specified PCI address
    image_load_pattern = (SYSFS_DEVICE_PATH + pci_addr + FME_PATH +
                          SPI_PATH + IMAGE_LOAD_PATH)
    image_load = read_n3000_sysfs_file(image_load_pattern)
    if image_load == "0":
        return "factory"
    elif image_load == "1":
        return "user"
    else:
        LOG.warn("Reading image load gave unexpected result: %s" % image_load)
        return ""


def get_n3000_bmc_version(pci_addr, path):
    version_pattern = (SYSFS_DEVICE_PATH + pci_addr + FME_PATH +
                       SPI_PATH + path)
    version = read_n3000_sysfs_file(version_pattern)

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


def get_n3000_bmc_fw_version(pci_addr):
    return get_n3000_bmc_version(pci_addr, BMC_FW_VER_PATH)


def get_n3000_bmc_build_version(pci_addr):
    return get_n3000_bmc_version(pci_addr, BMC_BUILD_VER_PATH)


def get_n3000_devices():
    # First get the PCI addresses of each supported FPGA device
    cmd = ["lspci", "-Dm", "-d " + constants.N3000_VENDOR + ":" +
           constants.N3000_DEVICE]

    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)  # pylint: disable=not-callable
    except subprocess.CalledProcessError as exc:
        msg = ("Failed to get pci devices with vendor %s and device %s, "
               "return code is %d, command output: %s." %
               (constants.N3000_VENDOR, constants.N3000_DEVICE, exc.returncode, exc.output))
        LOG.warn(msg)
        raise exception.SysinvException(msg)

    # Parse the output of the lspci command and grab the PCI address
    fpga_addrs = []
    for line in output.splitlines():
        line = shlex.split(line.strip())
        fpga_addrs.append(line[0])
    return fpga_addrs


def get_n3000_pci_info():
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
        # PCI devices implemented by the FPGA.  This loop isn't very
        # efficient, but so far it's only a small number of devices.
        pci_devices = []
        for device in constants.N3000_DEVICES:
            pci_devices.extend(pci_operator.pci_devices_get(
                vendor=constants.N3000_VENDOR, device=device))
        for pci_dev in pci_devices:
            pci_dev_array = pci_operator.pci_get_device_attrs(
                pci_dev.pciaddr)
            for dev in pci_dev_array:
                pci_devs.append(pci.PCIDevice(pci_dev, **dev))

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
                            'extra_info': dev.extra_info}
            LOG.debug('Sysinv FPGA Agent dev {}'.format(pci_dev_dict))
            pci_device_list.append(pci_dev_dict)
    except Exception:
        LOG.exception("Unable to query FPGA pci information, "
                      "sysinv DB will be stale")

    return pci_device_list


def watchdog_action(action):
    if action not in ["stop", "start"]:
        LOG.warn("watchdog_action called with invalid action: %s", action)
        return
    try:
        # Build up the command to perform the action.
        cmd = ["systemctl", action, "hostw"]

        # Issue the command to stop/start the watchdog
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)  # pylint: disable=not-callable
    except subprocess.CalledProcessError as exc:
        msg = ("Failed to %s hostw service, "
                 "return code is %d, command output: %s." %
                 (action, exc.returncode, exc.output))
        LOG.warn(msg)


def stop_watchdog():
    watchdog_action("stop")


def start_watchdog():
    watchdog_action("start")


class FpgaAgentManager(service.PeriodicService):
    """Sysinv FPGA Agent service main class."""

    RPC_API_VERSION = '1.0'

    def __init__(self, host, topic):
        serializer = objects_base.SysinvObjectSerializer()
        super(FpgaAgentManager, self).__init__(host, topic, serializer=serializer)

        self.host_uuid = None

    def start(self):
        super(FpgaAgentManager, self).start()

        if os.path.isfile('/etc/sysinv/sysinv.conf'):
            LOG.info('sysinv-fpga-agent started')
        else:
            LOG.info('No config file for sysinv-fpga-agent found.')
            raise exception.ConfigNotFound(message="Unable to find sysinv config file!")

        # Wait for puppet to log in to the local docker registry
        wait_for_docker_login()
        # Wait around until someone else updates the platform.conf file
        # with our host UUID.
        self.wait_for_host_uuid()

        context = ctx.get_admin_context()

        # Collect updated PCI device information for N3000 FPGAs
        # and send it to sysinv-conductor
        self.fpga_pci_update(context)

        # Collect FPGA inventory and report to conductor.
        self.report_fpga_inventory(context)

    def periodic_tasks(self, context, raise_on_error=False):
        """ Periodic tasks are run at pre-specified intervals. """
        return self.run_periodic_tasks(context, raise_on_error=raise_on_error)

    def wait_for_host_uuid(self):
        # Get our host UUID from /etc/platform/platform.conf.  Note that the
        # file can exist before the UUID is written to it.
        prefix = "UUID="
        while self.host_uuid is None:
            if os.path.isfile(tsc.PLATFORM_CONF_FILE):
                with open(tsc.PLATFORM_CONF_FILE, 'r') as platform_file:
                    for line in platform_file:
                        line = line.strip()
                        if not line.startswith(prefix):
                            continue
                        uuid = line[len(prefix):]
                        if uuidutils.is_uuid_like(uuid):
                            self.host_uuid = uuid
                            LOG.info("Agent found host UUID: %s" % uuid)
                            break
                        else:
                            LOG.info("UUID entry: %s in platform.conf "
                                     "isn't uuid-like" % uuid)

            time.sleep(5)

    def report_fpga_inventory(self, context):
        """Collect FPGA data for this host.

        This method allows host FPGA data to be collected.

        :param:   context: an admin context
        :returns: nothing
        """

        host_uuid = self.host_uuid

        rpcapi = conductor_rpcapi.ConductorAPI(
            topic=conductor_rpcapi.MANAGER_TOPIC)

        fpgainfo_list = self.get_fpga_info()

        LOG.info("reporting FPGA inventory for host %s: %s" %
                 (host_uuid, fpgainfo_list))
        try:
            rpcapi.fpga_device_update_by_host(context, host_uuid, fpgainfo_list)
        except exception.SysinvException:
            LOG.exception("Exception updating fpga devices.")
            pass

    def get_fpga_info(self):
        # For now we only support the N3000, eventually we may need to support
        # other FPGA devices.

        # Get a list of N3000 FPGA device addresses.
        fpga_addrs = get_n3000_devices()

        # Next, get additional information information for devices in the list.
        fpgainfo_list = []
        for addr in fpga_addrs:
            # Store information for this FPGA
            fpgainfo = {'pciaddr': addr}
            fpgainfo['bmc_build_version'] = get_n3000_bmc_build_version(addr)
            fpgainfo['bmc_fw_version'] = get_n3000_bmc_fw_version(addr)
            fpgainfo['boot_page'] = get_n3000_boot_page(addr)
            fpgainfo['bitstream_id'] = get_n3000_bitstream_id(addr)
            fpgainfo['root_key'] = get_n3000_root_hash(addr)
            fpgainfo['revoked_key_ids'] = get_n3000_revoked_keys(addr)

            # TODO: Also retrieve the information about which NICs are on
            # the FPGA device.

            fpgainfo_list.append(fpgainfo)

        return fpgainfo_list

    def fpga_pci_update(self, context):
        """Collect FPGA PCI data for this host.

        We know that the PCI address of the N3000 can change the first time
        We reset it after boot, so we need to gather the new PCI device
        information and send it to sysinv-conductor.

        This needs to exactly mirror what sysinv-agent does as far as PCI
        updates.  We could potentially modify sysinv-agent to do the PCI
        updates when triggered by an RPC cast, but we don't need to rescan
        all PCI devices, just the N3000 devices.

        :param:   context: an admin context
        :returns: nothing
        """

        LOG.info("Updating N3000 PCI info.")
        pci_device_list = get_n3000_pci_info()

        rpcapi = conductor_rpcapi.ConductorAPI(
            topic=conductor_rpcapi.MANAGER_TOPIC)

        host_uuid = self.host_uuid
        try:
            if pci_device_list:
                LOG.info("reporting N3000 PCI devices for host %s: %s" %
                         (host_uuid, pci_device_list))
                rpcapi.pci_device_update_by_host(context,
                                                 host_uuid,
                                                 pci_device_list,
                                                 cleanup_stale=True)
        except Exception:
            LOG.exception("Exception updating n3000 PCI devices, "
                          "this will likely cause problems.")
            pass

    def device_update_image(self, context, pci_addr, filename, transaction_id):
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
            ensure_device_image_cache_exists()

            # Pull the image from the controller via HTTP
            LOG.info("fetch device image %s" % filename)
            local_path = fetch_device_image(filename)

            # TODO: check CSK used to sign image, ensure it hasn't been cancelled
            # TODO: check root key used to sign image, ensure it matches root key of hardware
            #       Note: may want to check these in the sysinv API too.

            try:
                LOG.info("setting transaction id %s as in progress" % transaction_id)
                rpcapi.device_update_image_status(
                    context, self.host_uuid, transaction_id,
                    dconstants.DEVICE_IMAGE_UPDATE_IN_PROGRESS)

                # Disable the watchdog service to prevent a reboot on things
                # like critical process death. We don't want to reboot while
                # flashing the FPGA.
                stop_watchdog()

                # Write the image to the specified PCI device.
                # TODO:  when we support more than just N3000, we'll need to
                # pick the appropriate low-level write function based on the
                # hardware type.
                LOG.info("writing device image %s to device %s" % (filename, pci_addr))
                write_device_image_n3000(filename, pci_addr)

                # If we get an exception trying to send the status update
                # there's not much we can do.
                try:
                    LOG.info("setting transaction id %s as complete" % transaction_id)
                    rpcapi.device_update_image_status(
                        context, self.host_uuid, transaction_id,
                        dconstants.DEVICE_IMAGE_UPDATE_COMPLETED)
                except Exception:
                    LOG.exception("Unable to send fpga update image status "
                                  "completion message for transaction %s."
                                  % transaction_id)
            finally:
                # Delete the image file.
                os.remove(local_path)
                # start the watchdog service again
                start_watchdog()

        except exception.SysinvException as exc:
            LOG.info("setting transaction id %s as failed" % transaction_id)
            rpcapi.device_update_image_status(context, self.host_uuid,
                                            transaction_id,
                                            dconstants.DEVICE_IMAGE_UPDATE_FAILED,
                                            exc.message)
