#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the sysinv agent pci utilities.
"""

import mock
try:
    from contextlib import nested  # Python 2
except ImportError:
    from contextlib import ExitStack
    from contextlib import contextmanager

    @contextmanager
    def nested(*contexts):
        """
        Reimplementation of nested in python 3.
        """
        with ExitStack() as stack:
            yield tuple(stack.enter_context(cm) for cm in contexts)

from sysinv.agent.pci import PCIOperator
from sysinv.agent.pci import PCI
from sysinv.agent.manager import AgentManager
from sysinv.tests import base

import tsconfig.tsconfig as tsc

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

FAKE_DEVICE_ATTRIBUTES = [{
    "name": "fake_device",
    "pci_address": "b4:00.0",
    "pclass_id": "120000",
    "pvendor_id": "8086",
    "pdevice_id": "0d8f",
    "numa_node": 0,
    "sriov_totalvfs": 8,
    "sriov_numvfs": 1,
    "sriov_vfs_pci_address": "b4:00.1",
    "sriov_vf_driver": "igb_uio",
    "sriov_vf_pdevice_id": "0d90",
    "driver": "igb_uio",
    "enabled": True,
}]

FAKE_PORT_ATTRIBUTES = [{
    "name": "fake_port",
    "numa_node": 0,
    "sriov_totalvfs": 8,
    "sriov_numvfs": 1,
    "sriov_vfs_pci_address": "82:10.0",
    "sriov_vf_driver": "ixgbevf",
    "sriov_vf_pdevice_id": "000c",
    "driver": "ixgbe",
    "pci_address": "82:00.0",
    "mac": "3c:fd:fe:b5:72:fd",
    "mtu": 1500,
    "speed": 1000,
    "link_mode": 0,
    "dev_id": 1,
    "dpdksupport": True
}]

FAKE_PORTS = [PCI(
    '82:10.0', 'Ethernet controller [0200]', 'Intel Corporation [8086]', 'Device [1518]',
    '-r04', 'Intel Corporation [8086]', 'Device [0000]')]

FAKE_DEVICES = [PCI(
    'b4:00.0', 'Processing accelerators', 'Intel Corporation [8086]', 'Device [0d8f]',
    '', 'Intel Corporation [8086]', 'Device [0000]')]


class TestPciOperator(base.TestCase):

    def setUp(self):
        super(TestPciOperator, self).setUp()
        self.pci_operator = PCIOperator()

    def tearDown(self):
        super(TestPciOperator, self).tearDown()

    def mock_get_lspci_output_by_addr(addr):  # pylint: disable=no-self-argument
        return FAKE_LSPCI_OUTPUT[addr]

    @mock.patch.object(PCIOperator, 'get_lspci_output_by_addr',
                       side_effect=mock_get_lspci_output_by_addr)
    def test_get_pci_sriov_vf_driver_name(self, get_lspci_output_by_addr):
        pfaddr = '82:00.0'
        vfaddrs = ['82:10.0']
        result = self.pci_operator.get_pci_sriov_vf_driver_name(pfaddr, vfaddrs)
        assert result == "vfio-pci"

    @mock.patch.object(PCIOperator, 'get_lspci_output_by_addr',
                       side_effect=mock_get_lspci_output_by_addr)
    def test_get_pci_sriov_vf_module_name(self, get_lspci_output_by_addr):
        pfaddr = '82:00.0'
        vfaddrs = ['82:10.0']
        result = self.pci_operator.get_pci_sriov_vf_module_name(pfaddr, vfaddrs)
        assert result == "ixgbevf"

    @mock.patch.object(PCIOperator, 'get_lspci_output_by_addr',
                       side_effect=mock_get_lspci_output_by_addr)
    def test_get_pci_sriov_vf_module_name_none(self, get_lspci_output_by_addr):
        pfaddr = 'b4:00.0'
        vfaddrs = ['b4:00.1']
        result = self.pci_operator.get_pci_sriov_vf_module_name(pfaddr, vfaddrs)
        assert result is None


class TestAgentOperator(base.TestCase):

    def setUp(self):
        super(TestAgentOperator, self).setUp()
        self.agent_manager = AgentManager('test-host', 'test-topic')

    def tearDown(self):
        super(TestAgentOperator, self).tearDown()

    def _get_ports_inventory(self):
        with nested(mock.patch.object(PCIOperator, 'pci_get_net_attrs'),
                    mock.patch.object(PCIOperator, 'pci_get_device_attrs'),
                    mock.patch.object(PCIOperator, 'inics_get'),
                    mock.patch.object(PCIOperator, 'pci_devices_get'),
                    mock.patch.object(AgentManager, '_acquire_network_config_lock'),
                    mock.patch.object(AgentManager, '_release_network_config_lock')) as (
                        mock_net_attrs, mock_device_attrs, mock_nics, mock_devices,
                        aquire_lock, release_lock):

            def fake_get_net_attrs(a):
                return FAKE_PORT_ATTRIBUTES

            def fake_get_device_attrs(a):
                return FAKE_DEVICE_ATTRIBUTES

            def fake_get_nics():
                return FAKE_PORTS

            def fake_get_devices():
                return FAKE_DEVICES

            mock_net_attrs.side_effect = fake_get_net_attrs
            mock_device_attrs.side_effect = fake_get_device_attrs
            mock_nics.side_effect = fake_get_nics
            mock_devices.side_effect = fake_get_devices

            ports, devices, macs = self.agent_manager._get_ports_inventory()
            return ports, devices, macs

    @mock.patch('os.path.exists')
    def test_get_pci_inventory_before_worker_initial_config_complete(self, mock_exists):
        def file_exists_side_effect(filename):
            # Neither the initial nor volatile worker config complete flags are set
            return False
        mock_exists.side_effect = file_exists_side_effect

        ports, devices, macs = self._get_ports_inventory()
        assert len(ports) == 1
        assert len(devices) == 1
        assert len(macs) == 1

    @mock.patch('os.path.exists')
    def test_get_pci_inventory_before_worker_config_complete(self, mock_exists):
        def file_exists_side_effect(filename):
            if filename == tsc.INITIAL_WORKER_CONFIG_COMPLETE:
                # Only the initial worker config complete flag is set
                return True
            else:
                return False
        mock_exists.side_effect = file_exists_side_effect

        ports, devices, macs = self._get_ports_inventory()
        assert len(ports) == 0
        assert len(devices) == 0
        assert len(macs) == 0

    @mock.patch('os.path.exists')
    def test_get_pci_inventory_after_worker_config_complete(self, mock_exists):
        def file_exists_side_effect(filename):
            if filename in [tsc.INITIAL_WORKER_CONFIG_COMPLETE,
                            tsc.VOLATILE_WORKER_CONFIG_COMPLETE]:
                # Both of the initial and volatile worker config complete flags are set
                return True
            else:
                return False
        mock_exists.side_effect = file_exists_side_effect

        ports, devices, macs = self._get_ports_inventory()
        assert len(ports) == 1
        assert len(devices) == 1
        assert len(macs) == 1
