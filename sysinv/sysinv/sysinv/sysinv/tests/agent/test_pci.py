#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the sysinv agent pci utilities.
"""

import mock

from sysinv.agent.pci import PCIOperator
from sysinv.tests import base


FAKE_LSPCI_OUTPUT = {
    '82:00.0':
    """Slot:   82:00.0
       Class:  Ethernet controller
       Vendor: Intel Corporation
       Device: 82599ES 10-Gigabit SFI/SFP+ Network Connection
       SVendor:        Intel Corporation
       SDevice:        Ethernet Server Adapter X520-2
       PhySlot:        803
       Rev:    01
       Driver: ixgbe
       Module: ixgbe
       NUMANode:""",
    '82:10.0':
    """Slot:   82:10.0
       Class:  Ethernet controller
       Vendor: Intel Corporation
       Device: 82599 Ethernet Controller Virtual Function
       SVendor:        Intel Corporation
       SDevice:        Device 000c
       Rev:    01
       Driver: vfio-pci
       Module: ixgbevf
       NUMANode:       1""",
    'b4:00.0':
    """Slot:   b4:00.0
       Class:  Processing accelerators
       Vendor: Intel Corporation
       Device: Device 0d8f
       SVendor:        Intel Corporation
       SDevice:        Device 0001
       Rev:    01
       Driver: igb_uio
       NUMANode:       1""",
    'b4:00.1':
    """Slot:   b4:00.1
       Class:  Processing accelerators
       Vendor: Intel Corporation
       Device: Device 0d90
       SVendor:        Intel Corporation
       SDevice:        Device e001
       Rev:    01
       Driver: igb_uio
       NUMANode:       1"""
}


def mock_get_lspci_output_by_addr(addr):
    return FAKE_LSPCI_OUTPUT[addr]


@mock.patch.object(PCIOperator, 'get_lspci_output_by_addr',
                   side_effect=mock_get_lspci_output_by_addr)
class TestPciOperator(base.TestCase):

    def setUp(self):
        super(TestPciOperator, self).setUp()
        self.pci_operator = PCIOperator()

    def tearDown(self):
        super(TestPciOperator, self).tearDown()

    def test_get_pci_sriov_vf_driver_name(self, get_lspci_output_by_addr):
        pfaddr = '82:00.0'
        vfaddrs = ['82:10.0']
        result = self.pci_operator.get_pci_sriov_vf_driver_name(pfaddr, vfaddrs)
        assert result == "vfio-pci"

    def test_get_pci_sriov_vf_module_name(self, get_lspci_output_by_addr):
        pfaddr = '82:00.0'
        vfaddrs = ['82:10.0']
        result = self.pci_operator.get_pci_sriov_vf_module_name(pfaddr, vfaddrs)
        assert result == "ixgbevf"

    def test_get_pci_sriov_vf_module_name_none(self, get_lspci_output_by_addr):
        pfaddr = 'b4:00.0'
        vfaddrs = ['b4:00.1']
        result = self.pci_operator.get_pci_sriov_vf_module_name(pfaddr, vfaddrs)
        assert result is None
