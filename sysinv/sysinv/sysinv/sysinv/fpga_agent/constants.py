#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# Currently we only support the following FPGA.  In the future we may need to
# expand this to a list of devices, each with their own special set of
# device-specific information.
N3000_VENDOR = "8086"
N3000_DEVICE = "0b30"

# These are "virtual" PCI devices implemented by the FPGA user image.
N3000_DEFAULT_DEVICE = "0b32"
N3000_FEC_PF_DEVICE = "0d8f"
N3000_FEC_VF_DEVICE = "0d90"

# We don't care about the VFs here, as they get created after we reset the
# FPGA and fix up the PCI device entries in the DB.
N3000_DEVICES = [
    N3000_DEVICE,
    N3000_FEC_PF_DEVICE,
    N3000_DEFAULT_DEVICE,
]
