#
# Copyright (c) 2013-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

""" inventory pci Utilities and helper functions."""

from eventlet.green import subprocess
import glob
import os
import shlex
import time

from oslo_log import log as logging
from oslo_config import cfg
from sysinv._i18n import _
from sysinv.common import constants
from sysinv.common import device as dconstants
from sysinv.common import utils

dpdk_opts = [
             cfg.StrOpt('dpdk_elf',
                        default='/usr/sbin/ovs-vswitchd',
                        help='DPDK ELF file used for compatibility checks'),
            ]

CONF = cfg.CONF
CONF.register_opts(dpdk_opts, 'dpdk')

LOG = logging.getLogger(__name__)

# Look for PCI class 0x0200 and 0x0280 so that we get generic ethernet
# controllers and those that may report as "other" network controllers.
ETHERNET_PCI_CLASSES = ['ethernet controller', 'network controller']

# Look for other devices we may want to inventory.
KNOWN_PCI_DEVICES = [{"vendor_id": constants.NOVA_PCI_ALIAS_QAT_PF_VENDOR,
                      "device_id": constants.NOVA_PCI_ALIAS_QAT_DH895XCC_PF_DEVICE,
                      "class_id": constants.NOVA_PCI_ALIAS_QAT_CLASS},
                      {"vendor_id": constants.NOVA_PCI_ALIAS_QAT_PF_VENDOR,
                      "device_id": constants.NOVA_PCI_ALIAS_QAT_C62X_PF_DEVICE,
                      "class_id": constants.NOVA_PCI_ALIAS_QAT_CLASS},
                     {"class_id": constants.NOVA_PCI_ALIAS_GPU_CLASS},
                     {"class_id": dconstants.PCI_DEVICE_CLASS_FPGA}]

# PCI-SIG 0x06 bridge devices to not inventory.
IGNORE_BRIDGE_PCI_CLASSES = ['bridge', 'isa bridge', 'host bridge']

# PCI-SIG 0x08 generic peripheral devices to not inventory.
IGNORE_PERIPHERAL_PCI_CLASSES = ['system peripheral', 'pic', 'dma controller',
                                 'iommu', 'rtc']

# PCI-SIG 0x11 signal processing devices to not inventory.
IGNORE_SIGNAL_PROCESSING_PCI_CLASSES = ['performance counters']

# Blacklist of devices we do not want to inventory, because they are dealt
# with separately (ie. Ethernet devices), or do not make sense to expose
# to a guest.
IGNORE_PCI_CLASSES = ETHERNET_PCI_CLASSES + IGNORE_BRIDGE_PCI_CLASSES + \
                     IGNORE_PERIPHERAL_PCI_CLASSES + \
                     IGNORE_SIGNAL_PROCESSING_PCI_CLASSES

pciaddr = 0
pclass = 1
pvendor = 2
pdevice = 3
prevision = 4
psvendor = 5
psdevice = 6

VALID_PORT_SPEED = ['10', '100', '1000', '10000', '25000', '40000', '100000']

# Network device flags (from include/uapi/linux/if.h)
IFF_UP = 1 << 0
IFF_BROADCAST = 1 << 1
IFF_DEBUG = 1 << 2
IFF_LOOPBACK = 1 << 3
IFF_POINTOPOINT = 1 << 4
IFF_NOTRAILERS = 1 << 5
IFF_RUNNING = 1 << 6
IFF_NOARP = 1 << 7
IFF_PROMISC = 1 << 8
IFF_ALLMULTI = 1 << 9
IFF_MASTER = 1 << 10
IFF_SLAVE = 1 << 11
IFF_MULTICAST = 1 << 12
IFF_PORTSEL = 1 << 13
IFF_AUTOMEDIA = 1 << 14
IFF_DYNAMIC = 1 << 15


class PCI(object):
    '''Class to encapsulate PCI data for System Inventory'''

    def __init__(self, pciaddr, pclass, pvendor, pdevice, prevision,
                 psvendor, psdevice):
        '''Construct a Ipci object with the given values.'''

        self.pciaddr = pciaddr
        self.pclass = pclass
        self.pvendor = pvendor
        self.pdevice = pdevice
        self.prevision = prevision
        self.psvendor = psvendor
        self.psdevice = psdevice

    def __eq__(self, rhs):
        return (self.pvendor == rhs.pvendor and
                self.pdevice == rhs.pdevice)

    def __hash__(self):
        return hash((self.pciaddr, self.pclass, self.pvendor, self.pdevice,
                    self.prevision, self.psvendor, self.psdevice))

    def __ne__(self, rhs):
        return (self.pvendor != rhs.pvendor or
                self.pdevice != rhs.pdevice)

    def __str__(self):
        return "%s [%s] [%s]" % (self.pciaddr, self.pvendor, self.pdevice)

    def __repr__(self):
        return "<PCI '%s'>" % str(self)


class Port(object):
    '''Class to encapsulate PCI data for System Inventory'''

    def __init__(self, ipci, **kwargs):
        '''Construct an Iport object with the given values.'''
        self.ipci = ipci
        self.name = kwargs.get('name')
        self.mac = kwargs.get('mac')
        self.mtu = kwargs.get('mtu')
        self.speed = kwargs.get('speed')
        self.link_mode = kwargs.get('link_mode')
        self.numa_node = kwargs.get('numa_node')
        self.dev_id = kwargs.get('dev_id')
        self.sriov_totalvfs = kwargs.get('sriov_totalvfs')
        self.sriov_numvfs = kwargs.get('sriov_numvfs')
        self.sriov_vfs_pci_address = kwargs.get('sriov_vfs_pci_address')
        self.sriov_vf_driver = kwargs.get('sriov_vf_driver')
        self.sriov_vf_pdevice_id = kwargs.get('sriov_vf_pdevice_id')
        self.driver = kwargs.get('driver')
        self.dpdksupport = kwargs.get('dpdksupport')

    def __str__(self):
        return "%s %s: [%s] [%s] [%s], [%s], [%s], [%s], [%s]" % (
            self.ipci, self.name, self.mac, self.mtu, self.speed,
            self.link_mode, self.numa_node, self.dev_id, self.dpdksupport)

    def __repr__(self):
        return "<Port '%s'>" % str(self)


class PCIDevice(object):
    '''Class to encapsulate extended PCI data for System Inventory'''

    def __init__(self, pci, **kwargs):
        '''Construct a PciDevice object with the given values.'''
        self.pci = pci
        self.name = kwargs.get('name')
        self.pclass_id = kwargs.get('pclass_id')
        self.pvendor_id = kwargs.get('pvendor_id')
        self.pdevice_id = kwargs.get('pdevice_id')
        self.numa_node = kwargs.get('numa_node')
        self.sriov_totalvfs = kwargs.get('sriov_totalvfs')
        self.sriov_numvfs = kwargs.get('sriov_numvfs')
        self.sriov_vfs_pci_address = kwargs.get('sriov_vfs_pci_address')
        self.sriov_vf_driver = kwargs.get('sriov_vf_driver')
        self.sriov_vf_pdevice_id = kwargs.get('sriov_vf_pdevice_id')
        self.driver = kwargs.get('driver')
        self.enabled = kwargs.get('enabled')
        self.extra_info = kwargs.get('extra_info')

    def __str__(self):
        return "%s %s: [%s]" % (
            self.pci, self.numa_node, self.driver)

    def __repr__(self):
        return "<PCIDevice '%s'>" % str(self)


class PCIOperator(object):
    '''Class to encapsulate PCI operations for System Inventory'''

    def format_lspci_output(self, device):
        # hack for now
        # NOTE: this does not properly handle the case where we have both
        # "-r" and "-p" optional info in the lspci output.
        if device[prevision].strip() == device[pvendor].strip():
            # no revision info reported, device[prevision] now stores the
            # psvendor, and device[psvendor] now stores the psdevice.  We
            # need to put things where they should be.
            device.append(device[psvendor])
            device[psvendor] = device[prevision]
            device[prevision] = "0"
        elif len(device) <= 6:  # one less entry, no revision
            LOG.debug("update psdevice length=%s" % len(device))
            device.append(device[psvendor])
        return device

    def get_pci_numa_node(self, pciaddr):
        fnuma_node = '/sys/bus/pci/devices/' + pciaddr + '/numa_node'
        try:
            with open(fnuma_node, 'r') as f:
                numa_node = f.readline().strip()
                LOG.debug("ATTR numa_node: %s " % numa_node)
        except Exception:
            LOG.debug("ATTR numa_node unknown for: %s " % pciaddr)
            numa_node = None
        return numa_node

    def get_pci_sriov_totalvfs(self, pciaddr):
        fsriov_totalvfs = '/sys/bus/pci/devices/' + pciaddr + '/sriov_totalvfs'
        try:
            with open(fsriov_totalvfs, 'r') as f:
                sriov_totalvfs = f.readline()
                LOG.debug("ATTR sriov_totalvfs: %s " % sriov_totalvfs)
                f.close()
        except Exception:
            LOG.debug("ATTR sriov_totalvfs unknown for: %s " % pciaddr)
            sriov_totalvfs = None
            pass
        return sriov_totalvfs

    def get_pci_sriov_numvfs(self, pciaddr):
        fsriov_numvfs = '/sys/bus/pci/devices/' + pciaddr + '/sriov_numvfs'
        try:
            with open(fsriov_numvfs, 'r') as f:
                sriov_numvfs = f.readline()
                LOG.debug("ATTR sriov_numvfs: %s " % sriov_numvfs)
                f.close()
        except Exception:
            LOG.debug("ATTR sriov_numvfs unknown for: %s " % pciaddr)
            sriov_numvfs = 0
            pass
        LOG.debug("sriov_numvfs: %s" % sriov_numvfs)
        return sriov_numvfs

    def get_pci_sriov_vfs_pci_address(self, pciaddr, sriov_numvfs):
        dirpcidev = '/sys/bus/pci/devices/' + pciaddr
        sriov_vfs_pci_address = []
        i = 0
        while i < int(sriov_numvfs):
            lvf = dirpcidev + '/virtfn' + str(i)
            try:
                sriov_vfs_pci_address.append(os.path.basename(os.readlink(lvf)))
            except Exception:
                LOG.warning("virtfn link %s non-existent (sriov_numvfs=%s)"
                            % (lvf, sriov_numvfs))
                pass
            i += 1
        LOG.debug("sriov_vfs_pci_address: %s" % sriov_vfs_pci_address)
        return sriov_vfs_pci_address

    def get_pci_sriov_vf_device_id(self, pciaddr, sriov_vfs_pci_address):
        vf_device_id = None
        for addr in sriov_vfs_pci_address:
            fdevice = '/sys/bus/pci/devices/' + addr + '/device'

            try:
                with open(fdevice, 'r') as f:
                    # Device id is a 16 bit hex value.  Strip off the hex
                    # identifier and trailing whitespace
                    vf_device_id = f.readline().rstrip()[2:]
                    if len(vf_device_id) < 4:
                        # Should never happen
                        raise ValueError(_(
                            "Device Id must be a 16 bit hex value"))
                    LOG.debug("ATTR sriov_vf_device_id: %s " % vf_device_id)
            except Exception:
                LOG.debug("ATTR sriov_vf_device_id unknown for: %s " % pciaddr)
                pass

            # All VFs have the same device id per device.
            if vf_device_id:
                break

        return vf_device_id

    def get_lspci_output_by_addr(self, pciaddr):
        with open(os.devnull, "w") as fnull:
            output = subprocess.check_output(  # pylint: disable=not-callable
                ['lspci', '-vmmks', pciaddr], stderr=fnull,
                universal_newlines=True)
        return output

    def get_pci_sriov_vf_driver_name(self, pciaddr, sriov_vfs_pci_address):
        vf_driver = None
        for addr in sriov_vfs_pci_address:
            try:
                output = self.get_lspci_output_by_addr(addr)
            except Exception as e:
                LOG.error("Error getting PCI data for SR-IOV "
                          "VF address %s: %s", addr, e)
                continue

            for line in output.split('\n'):
                pci_attr = shlex.split(line.strip())
                if (pci_attr and len(pci_attr) == 2 and 'Driver' in pci_attr[0]):
                    vf_driver = pci_attr[1]
                    break

            # All VFs have the same driver per device.
            if vf_driver:
                break

        return vf_driver

    def get_pci_sriov_vf_module_name(self, pciaddr, sriov_vfs_pci_address):
        vf_module = None
        for addr in sriov_vfs_pci_address:

            try:
                output = self.get_lspci_output_by_addr(addr)
            except Exception as e:
                LOG.error("Error getting PCI data for SR-IOV "
                          "VF address %s: %s", addr, e)
                continue

            for line in output.split('\n'):
                pci_attr = shlex.split(line.strip())
                if (pci_attr and len(pci_attr) == 2 and 'Module' in pci_attr[0]):
                    vf_module = pci_attr[1]
                    break

            # All VFs have the same module per device.
            if vf_module:
                break

        return vf_module

    def get_pci_driver_name(self, pciaddr):
        ddriver = '/sys/bus/pci/devices/' + pciaddr + '/driver/module/drivers'
        try:
            drivers = [
                os.path.basename(os.readlink(ddriver + '/' + d)) for d in os.listdir(ddriver)
                       ]
            driver = str(','.join(str(d) for d in drivers))

        except Exception:
            LOG.debug("ATTR driver unknown for: %s " % pciaddr)
            driver = None
            pass
        LOG.debug("driver: %s" % driver)
        return driver

    def pci_devices_get(self, vendor=None, device=None):
        cmd = ["lspci", "-Dm"]
        # See if the caller wants to limit us to a specific vendor/device.
        if vendor and device:
            option = "-d " + vendor + ":" + device
            cmd.append(option)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                universal_newlines=True)

        pci_devices = []
        for line in p.stdout:
            pci_device = shlex.split(line.strip())
            pci_device = self.format_lspci_output(pci_device)

            if any(x in pci_device[pclass].lower() for x in
                   IGNORE_PCI_CLASSES):
                continue

            dirpcidev = '/sys/bus/pci/devices/'
            physfn = dirpcidev + pci_device[pciaddr] + '/physfn'
            if not os.path.isdir(physfn):
                # Do not report VFs
                pci_devices.append(PCI(pci_device[pciaddr],
                                       pci_device[pclass],
                                       pci_device[pvendor],
                                       pci_device[pdevice],
                                       pci_device[prevision],
                                       pci_device[psvendor],
                                       pci_device[psdevice]))

        p.wait()

        return pci_devices

    def inics_get(self):

        p = subprocess.Popen(["lspci", "-Dmnn"], stdout=subprocess.PIPE,
                universal_newlines=True)

        pci_inics = []
        for line in p.stdout:
            inic = shlex.split(line.strip())
            if any(x in inic[pclass].lower() for x in ETHERNET_PCI_CLASSES):
                # hack for now
                if inic[prevision].strip() == inic[pvendor].strip():
                    # no revision info
                    inic.append(inic[psvendor])
                    inic[psvendor] = inic[prevision]
                    inic[prevision] = "0"
                elif len(inic) <= 6:  # one less entry, no revision
                    LOG.debug("update psdevice length=%s" % len(inic))
                    inic.append(inic[psvendor])

                dirpcidev = '/sys/bus/pci/devices/'
                physfn = dirpcidev + inic[pciaddr] + '/physfn'
                if os.path.isdir(physfn):
                    # Do not report VFs
                    continue
                pci_inics.append(PCI(inic[pciaddr], inic[pclass],
                                     inic[pvendor], inic[pdevice],
                                     inic[prevision], inic[psvendor],
                                     inic[psdevice]))

        p.wait()

        return pci_inics

    def pci_get_enabled_attr(self, class_id, vendor_id, product_id):
        for known_device in KNOWN_PCI_DEVICES:
            if (class_id == known_device.get("class_id", None) or
                (vendor_id == known_device.get("vendor_id", None) and
                    product_id == known_device.get("device_id", None))):
                return True
        return False

    def pci_get_device_attrs(self, pciaddr):
        ''' For this pciaddr, build a list of device attributes '''
        pci_attrs_array = []

        dirpcidev = '/sys/bus/pci/devices/'
        pciaddrs = os.listdir(dirpcidev)

        for a in pciaddrs:
            if ((a == pciaddr) or (a == ("0000:" + pciaddr))):
                LOG.debug("Found device pci bus: %s " % a)

                dirpcideva = dirpcidev + a

                numa_node = self.get_pci_numa_node(a)
                sriov_totalvfs = self.get_pci_sriov_totalvfs(a)
                sriov_numvfs = self.get_pci_sriov_numvfs(a)
                sriov_vfs_pci_address = self.get_pci_sriov_vfs_pci_address(a, sriov_numvfs)
                sriov_vf_driver = self.get_pci_sriov_vf_driver_name(a, sriov_vfs_pci_address)
                driver = self.get_pci_driver_name(a)

                fclass = dirpcideva + '/class'
                fvendor = dirpcideva + '/vendor'
                fdevice = dirpcideva + '/device'
                try:
                    with open(fvendor, 'r') as f:
                        pvendor_id = f.readline().strip('0x').strip()
                except Exception:
                    LOG.debug("ATTR vendor unknown for: %s " % a)
                    pvendor_id = None

                try:
                    with open(fdevice, 'r') as f:
                        pdevice_id = f.readline().replace('0x', '').strip()
                except Exception:
                    LOG.debug("ATTR device unknown for: %s " % a)
                    pdevice_id = None

                try:
                    with open(fclass, 'r') as f:
                        pclass_id = f.readline().replace('0x', '').strip()
                except Exception:
                    LOG.debug("ATTR class unknown for: %s " % a)
                    pclass_id = None

                name = "pci_" + a.replace(':', '_').replace('.', '_')
                sriov_vf_pdevice_id = self.get_pci_sriov_vf_device_id(
                    a, sriov_vfs_pci_address)

                attrs = {
                    "name": name,
                    "pci_address": a,
                    "pclass_id": pclass_id,
                    "pvendor_id": pvendor_id,
                    "pdevice_id": pdevice_id,
                    "numa_node": numa_node,
                    "sriov_totalvfs": sriov_totalvfs,
                    "sriov_numvfs": sriov_numvfs,
                    "sriov_vfs_pci_address":
                        ','.join(str(x) for x in sriov_vfs_pci_address),
                    "sriov_vf_driver": sriov_vf_driver,
                    "sriov_vf_pdevice_id": sriov_vf_pdevice_id,
                    "driver": driver,
                    "enabled": self.pci_get_enabled_attr(pclass_id,
                        pvendor_id, pdevice_id),
                         }

                pci_attrs_array.append(attrs)

        return pci_attrs_array

    def get_pci_net_directory(self, pciaddr):
        device_directory = '/sys/bus/pci/devices/' + pciaddr
        # Look for the standard device 'net' directory
        net_directory = device_directory + '/net/'
        if os.path.exists(net_directory):
            return net_directory
        # Otherwise check whether this is a virtio based device
        net_pattern = device_directory + '/virtio*/net/'
        results = glob.glob(net_pattern)
        if not results:
            return None
        if len(results) > 1:
            LOG.warning("PCI device {} has multiple virtio "
                        "sub-directories".format(pciaddr))
        return results[0]

    def _read_flags(self, fflags):
        try:
            with open(fflags, 'r') as f:
                hex_str = f.readline().rstrip()
                flags = int(hex_str, 16)
        except Exception:
            flags = None
        return flags

    def _get_netdev_operstate(self, dirpcinet, pci):
        foperstate = dirpcinet + pci + '/operstate'
        try:
            with open(foperstate, 'r') as f:
                operstate = f.readline().rstrip()
        except Exception:
            operstate = None
        return operstate

    def _get_netdev_speed(self, dirpcinet, pci):
        fspeed = dirpcinet + pci + '/speed'
        try:
            with open(fspeed, 'r') as f:
                speed = f.readline().rstrip()
        except Exception:
            speed = None
        return speed

    def _get_netdev_flags(self, dirpcinet, pci):
        fflags = dirpcinet + pci + '/flags'
        return self._read_flags(fflags)

    def pci_get_net_flags(self, name):
        fflags = '/sys/class/net/' + name + '/flags'
        return self._read_flags(fflags)

    def pci_get_net_names(self):
        '''build a list of network device names.'''
        names = []
        for name in os.listdir('/sys/class/net/'):
            if os.path.isdir('/sys/class/net/' + name):
                names.append(name)
        return names

    def _pci_wait_for_operational_state(self, iface, pci_addr, driver):
        """
        Waits for an interface to become operational, up to 1.5 seconds,
        but only for drivers that require this.

        Some network adapters may take up to 1 second to become operational,
        even though "flags" indicate that the interface is up.

        This function waits for the interface to become operational by polling
        the driver 16 times with 0.1 seconds in between each attempt.
        """

        if driver not in constants.DRIVERS_NOT_IMMEDIATELY_OPERATIONAL:
            return

        num_tries = 16
        sleep_dur = 0.1

        dirpcinet = self.get_pci_net_directory(pci_addr)

        for attempt in range(num_tries):
            operstate = self._get_netdev_operstate(dirpcinet, iface)
            if operstate == "up":
                return

            # Do not sleep at the end of the last iteration.
            if attempt < (num_tries - 1):
                time.sleep(sleep_dur)

        LOG.warning("%s did not become operational after %d attempts" %
                (iface, num_tries))

    def pci_get_net_attrs(self, pciaddr):
        ''' For this pciaddr, build a list of network attributes per port '''
        pci_attrs_array = []

        dirpcidev = '/sys/bus/pci/devices/'
        pciaddrs = os.listdir(dirpcidev)

        for a in pciaddrs:
            if ((a == pciaddr) or (a == ("0000:" + pciaddr))):
                # Look inside net expect to find address,speed,mtu etc. info
                # There may be more than 1 net device for this NIC.
                LOG.debug("Found NIC pci bus: %s " % a)

                dirpcideva = dirpcidev + a

                numa_node = self.get_pci_numa_node(a)
                sriov_totalvfs = self.get_pci_sriov_totalvfs(a)
                sriov_numvfs = self.get_pci_sriov_numvfs(a)
                sriov_vfs_pci_address = self.get_pci_sriov_vfs_pci_address(a, sriov_numvfs)

                # For network devices, return the supported kernel module
                # as the sriov_vf_driver. This is used to determine the driver
                # to use if an interface has an SR-IOV VF driver of 'netdevice'
                sriov_vf_driver = self.get_pci_sriov_vf_module_name(a, sriov_vfs_pci_address)

                sriov_vf_pdevice_id = self.get_pci_sriov_vf_device_id(a, sriov_vfs_pci_address)
                driver = self.get_pci_driver_name(a)

                # Determine DPDK support
                dpdksupport = False
                fvendor = dirpcideva + '/vendor'
                fdevice = dirpcideva + '/device'
                try:
                    with open(fvendor, 'r') as f:
                        vendor = f.readline().strip()
                except Exception:
                    LOG.debug("ATTR vendor unknown for: %s " % a)
                    vendor = None

                try:
                    with open(fdevice, 'r') as f:
                        device = f.readline().strip()
                except Exception:
                    LOG.debug("ATTR device unknown for: %s " % a)
                    device = None

                try:
                    with open(os.devnull, "w") as fnull:
                        query_pci_id_cmd = ["query_pci_id",
                                            "-v " + str(vendor),
                                            "-d " + str(device)]
                        if(CONF.dpdk.dpdk_elf is not None):
                            elf_arg = "--elfbinary " + str(CONF.dpdk.dpdk_elf)
                            query_pci_id_cmd.append(elf_arg)
                        subprocess.check_call(query_pci_id_cmd,  # pylint: disable=not-callable
                                              stdout=fnull, stderr=fnull)
                        dpdksupport = True
                        LOG.debug("DPDK does support NIC "
                                  "(vendor: %s device: %s)",
                                  vendor, device)
                except subprocess.CalledProcessError as e:
                    dpdksupport = False
                    if e.returncode == 1:
                        # NIC is not supprted
                        LOG.debug("DPDK does not support NIC "
                                  "(vendor: %s device: %s)",
                                  vendor, device)
                    else:
                        # command failed, default to DPDK support to False
                        LOG.info("Could not determine DPDK support for "
                                 "NIC (vendor %s device: %s), defaulting "
                                 "to False", vendor, device)

                # determine the net directory for this device
                dirpcinet = self.get_pci_net_directory(a)
                if dirpcinet is None:
                    LOG.warning("no /net for PCI device: %s " % a)
                    continue  # go to next PCI device

                # determine which netdevs are associated to this device
                netdevs = os.listdir(dirpcinet)
                for n in netdevs:
                    mac = None
                    fmac = dirpcinet + n + '/' + "address"
                    fmaster = dirpcinet + n + '/' + "master"
                    # if a port is a member of a bond the port MAC address
                    # must be retrieved from /proc/net/bonding/<bond_name>
                    if os.path.exists(fmaster):
                        dirmaster = os.path.realpath(fmaster)
                        master_name = os.path.basename(dirmaster)
                        procnetbonding = '/proc/net/bonding/' + master_name
                        found_interface = False

                        try:
                            with open(procnetbonding, 'r') as f:
                                for line in f:
                                    if 'Slave Interface: ' + n in line:
                                        found_interface = True
                                    if found_interface and 'Permanent HW addr:' in line:
                                        mac = line.split(': ')[1].rstrip()
                                        mac = utils.validate_and_normalize_mac(mac)
                                        break
                                if not mac:
                                    LOG.info("ATTR mac could not be determined "
                                             "for slave interface %s" % n)
                        except Exception:
                            LOG.info("ATTR mac could not be determined, "
                                     "could not open %s" % procnetbonding)
                    else:
                        try:
                            with open(fmac, 'r') as f:
                                mac = f.readline().rstrip()
                                mac = utils.validate_and_normalize_mac(mac)
                        except Exception:
                            LOG.info("ATTR mac unknown for: %s " % n)

                    fmtu = dirpcinet + n + '/' + "mtu"
                    try:
                        with open(fmtu, 'r') as f:
                            mtu = f.readline().rstrip()
                    except Exception:
                        LOG.debug("ATTR mtu unknown for: %s " % n)
                        mtu = None

                    # Check the administrative state before reading the speed
                    flags = self._get_netdev_flags(dirpcinet, n)

                    # If administrative state is down, bring it up momentarily
                    if not(flags & IFF_UP):
                        LOG.warning("Enabling device %s to query link speed" % n)
                        cmd = 'ip link set dev %s up' % n
                        _p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                              shell=True)
                        _p.wait()

                        self._pci_wait_for_operational_state(n, a, driver)

                    # Read the speed
                    speed = self._get_netdev_speed(dirpcinet, n)
                    if speed is None:
                        LOG.warning("ATTR speed unknown for: %s (flags: %s)" % (n, hex(flags)))
                    elif speed == '-1':
                        LOG.warning("Port speed detected as -1 for: %s (link operstate: %s)" %
                            (n, self._get_netdev_operstate(dirpcinet, n)))
                        speed = None
                    elif speed not in VALID_PORT_SPEED:
                        LOG.error("Invalid port speed = %s for %s " % (speed, n))
                        speed = None
                    # If the administrative state was down, take it back down
                    if not(flags & IFF_UP):
                        LOG.warning("Disabling device %s after querying link speed" % n)
                        cmd = 'ip link set dev %s down' % n
                        _p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                              shell=True)
                        _p.wait()

                    flink_mode = dirpcinet + n + '/' + "link_mode"
                    try:
                        with open(flink_mode, 'r') as f:
                            link_mode = f.readline().rstrip()
                    except Exception:
                        LOG.debug("ATTR link_mode unknown for: %s " % n)
                        link_mode = None

                    fdevport = dirpcinet + n + '/' + "dev_port"
                    try:
                        with open(fdevport, 'r') as f:
                            dev_port = int(f.readline().rstrip(), 0)
                    except Exception:
                        LOG.debug("ATTR dev_port unknown for: %s " % n)
                        # Kernel versions older than 3.15 used dev_id
                        # (incorrectly) to identify the network devices,
                        # therefore support the fallback if dev_port is not
                        # available
                        try:
                            fdevid = dirpcinet + n + '/' + "dev_id"
                            with open(fdevid, 'r') as f:
                                dev_port = int(f.readline().rstrip(), 0)
                        except Exception:
                            LOG.debug("ATTR dev_id unknown for: %s " % n)
                            dev_port = 0

                    attrs = {
                        "name": n,
                        "numa_node": numa_node,
                        "sriov_totalvfs": sriov_totalvfs,
                        "sriov_numvfs": sriov_numvfs,
                        "sriov_vfs_pci_address":
                            ','.join(str(x) for x in sriov_vfs_pci_address),
                        "sriov_vf_driver": sriov_vf_driver,
                        "sriov_vf_pdevice_id": sriov_vf_pdevice_id,
                        "driver": driver,
                        "pci_address": a,
                        "mac": mac,
                        "mtu": mtu,
                        "speed": speed,
                        "link_mode": link_mode,
                        "dev_id": dev_port,
                        "dpdksupport": dpdksupport
                    }

                    pci_attrs_array.append(attrs)

        return pci_attrs_array
