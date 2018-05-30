#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import subprocess
import shlex

pciaddr = 0
iclass = 1
vendor = 2
device = 3
revision = 4
svendor = 5
sdevice = 6


class Ipci:
    '''Class to encapsulate PCI data for System Inventory'''

    def __init__(self, pciaddr, iclass, vendor, device, revision,
                 svendor, sdevice, description=""):
        '''Construct a Ipci object with the given values.'''

        self.pciaddr = pciaddr
        self.iclass = iclass
        self.vendor = vendor
        self.device = device
        self.revision = revision
        self.svendor = svendor
        self.sdevice = sdevice

    def __eq__(self, rhs):
        return (self.vendorId == rhs.vendorId and
                self.deviceId == rhs.deviceId)

    def __ne__(self, rhs):
        return (self.vendorId != rhs.vendorId or
                self.deviceId != rhs.deviceId)

    def __str__(self):
        return "%s [%s] [%s]" % (
            self.description, self.vendorId, self.deviceId)

    def __repr__(self):
        return "<PciInfo '%s'>" % str(self)


class IpciOperator(object):
    '''Class to encapsulate PCI operations for System Inventory'''
    def pci_inics_get(self):

        p = subprocess.Popen(["lspci", "-Dm"], stdout=subprocess.PIPE)

        pci_inics = []
        for line in p.stdout:
            if 'Ethernet' in line:
                inic = shlex.split(line.strip())

                if inic[iclass].startswith('Ethernet controller'):
                    pci_inics.append(Ipci(inic[pciaddr], inic[iclass],
                        inic[vendor], inic[device], inic[revision],
                        inic[svendor], inic[sdevice]))

        p.wait()

        return pci_inics

    def pci_bus_scan_get_attributes(self, pciaddr):
        ''' For this pciaddr, build a list of dictattributes per port '''

        pciaddrs = os.listdir('/sys/bus/pci/devices/')
        for a in pciaddrs:
            if ((a == pciaddr) or ("0000:" + a == pciaddr)):
                # directory with match, so look inside net directory
                # expect to find address,speed,mtu etc. info
                p = subprocess.Popen(["cat", "a"], stdout=subprocess.PIPE)

                p.wait()


my_pci_inics = IpciOperator()

pci_inics = []
pci_inics = my_pci_inics.pci_inics_get()


# post these to database by host, pciaddr
for i in pci_inics:
        print ("JKUNG pciaddr=%s, iclass=%s, vendor=%s, device=%s, rev=%s, svendor=%s, sdevice=%s" % (i.pciaddr, i.iclass, i.vendor, i.device, i.revision, i.svendor, i.sdevice))

        # try:
        # rpc.db_post_by_host_and_mac()
        # except:
        #   try patch if that doesnt work, then continue
