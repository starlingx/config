#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants

# Account for those accelerators cards with a progIF set.
# PCI Device Class ID in hexadecimal string.


class pci_device_class_acclr(object):
    def __init__(self):
        self.pci_class_ids = ['120000', '120001']

    def __eq__(self, other):
        return (other in self.pci_class_ids)

    def __ne__(self, other):
        return (other not in self.pci_class_ids)

    def __str__(self):
        return ' '.join(self.pci_class_ids)


PCI_DEVICE_CLASS_FPGA = pci_device_class_acclr()

# Device Vendors
PCI_DEVICE_VENDOR_INTEL = "8086"

# Device Ids
PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF = "0d8f"
PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_VF = "0d90"

PCI_DEVICE_ID_ACC100_INTEL_5GNR_FEC_PF = "0d5c"
PCI_DEVICE_ID_ACC100_INTEL_5GNR_FEC_VF = "0d5d"

# SR-IOV enabled FEC devices
SRIOV_ENABLED_FEC_DEVICE_IDS = [PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
                                PCI_DEVICE_ID_ACC100_INTEL_5GNR_FEC_PF]

FPGA_INTEL_5GNR_FEC_DRIVER_IGB_UIO = "igb_uio"
FPGA_INTEL_5GNR_FEC_DRIVER_NONE = "none"

FPGA_INTEL_5GNR_FEC_VF_VALID_DRIVERS = [FPGA_INTEL_5GNR_FEC_DRIVER_IGB_UIO,
                                        constants.SRIOV_DRIVER_TYPE_VFIO,
                                        FPGA_INTEL_5GNR_FEC_DRIVER_NONE]
FPGA_INTEL_5GNR_FEC_PF_VALID_DRIVERS = [FPGA_INTEL_5GNR_FEC_DRIVER_IGB_UIO,
                                        FPGA_INTEL_5GNR_FEC_DRIVER_NONE]

# This dictionary is used when generating resourceName and device_config.
# Where:
# The key for both devices in the resultant device_config (puppet/device.py)
# is 'platform::devices::fpga::fec::params::device_config'.
# fec_name(Required): used in puppet/kubernetes.py to generate reourceName.
# dvconf(Optional): used in puppet/devices.py to generate device_config and
# represents optional puppet resources the device may require for
# configuration. The current implementation supports the invocation of only
# one ACCLR FEC class.
ACCLR_FEC_RESOURCES = {
    PCI_DEVICE_ID_ACC100_INTEL_5GNR_FEC_PF:
    {
        'fec_name': "intel_acc100_fec",
        'dvconf': {'platform::devices::acc100::fec::enabled': True}
    },
    PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF:
    {
        'fec_name': "intel_fpga_fec",
    }
}

# Device Image
DEVICE_IMAGE_TMP_PATH = '/tmp/device_images'
DEVICE_IMAGE_PATH = '/opt/platform/device_images'

BITSTREAM_TYPE_ROOT_KEY = 'root-key'
BITSTREAM_TYPE_FUNCTIONAL = 'functional'
BITSTREAM_TYPE_KEY_REVOCATION = 'key-revocation'

# Device Image Status
DEVICE_IMAGE_UPDATE_PENDING = 'pending'
DEVICE_IMAGE_UPDATE_IN_PROGRESS = 'in-progress'
DEVICE_IMAGE_UPDATE_IN_PROGRESS_ABORTED = 'in-progress-aborted'
DEVICE_IMAGE_UPDATE_COMPLETED = 'completed'
DEVICE_IMAGE_UPDATE_FAILED = 'failed'
DEVICE_IMAGE_UPDATE_NULL = ''

# Device Image Action
APPLY_ACTION = 'apply'
REMOVE_ACTION = 'remove'
