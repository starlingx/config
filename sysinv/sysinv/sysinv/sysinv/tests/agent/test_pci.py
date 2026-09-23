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
from sysinv.common import constants
from sysinv.common import fpga_constants
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
    "dpdksupport": True,
    "numchannels": 32,
    "maxchannels": 64,
    "sriov_vf_numchannels": 2,
    "sriov_vf_maxchannels": 4
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

    @mock.patch('os.scandir')
    def test_get_pci_sriov_vf_netdev(self, mock_scandir):
        """Test _get_pci_sriov_vf_netdev returns netdev name when present."""
        mock_entry = mock.Mock()
        mock_entry.name = 'enp130s0f0'
        mock_entry.is_dir.return_value = True
        mock_scandir.return_value.__enter__ = mock.Mock(
            return_value=iter([mock_entry]))
        mock_scandir.return_value.__exit__ = mock.Mock(return_value=False)

        result = self.pci_operator._get_pci_sriov_vf_netdev('82:10.0')
        assert result == 'enp130s0f0'
        mock_scandir.assert_called_once_with(
            '/sys/bus/pci/devices/82:10.0/net/')

    @mock.patch('os.scandir')
    def test_get_pci_sriov_vf_netdev_empty_net_dir(self, mock_scandir):
        """Test _get_pci_sriov_vf_netdev returns None when net dir is empty."""
        mock_scandir.return_value.__enter__ = mock.Mock(
            return_value=iter([]))
        mock_scandir.return_value.__exit__ = mock.Mock(return_value=False)

        result = self.pci_operator._get_pci_sriov_vf_netdev('82:10.0')
        assert result is None

    @mock.patch('os.scandir')
    def test_get_pci_sriov_vf_netdev_vfio_pci_bound(self, mock_scandir):
        """Test _get_pci_sriov_vf_netdev returns None when VF is bound to
        vfio-pci (no kernel netdev, net dir does not exist)."""
        mock_scandir.side_effect = FileNotFoundError(
            "[Errno 2] No such file or directory: "
            "'/sys/bus/pci/devices/82:10.0/net/'")

        result = self.pci_operator._get_pci_sriov_vf_netdev('82:10.0')
        assert result is None

    @mock.patch('os.scandir')
    def test_get_pci_sriov_vf_netdev_permission_error(self, mock_scandir):
        """Test _get_pci_sriov_vf_netdev returns None on PermissionError."""
        mock_scandir.side_effect = PermissionError(
            "[Errno 13] Permission denied: "
            "'/sys/bus/pci/devices/82:10.0/net/'")

        result = self.pci_operator._get_pci_sriov_vf_netdev('82:10.0')
        assert result is None

    @mock.patch('os.scandir')
    def test_get_pci_sriov_vf_netdev_oserror(self, mock_scandir):
        """Test _get_pci_sriov_vf_netdev returns None on transient OSError
        (e.g. device hot-remove or reset during scan)."""
        mock_scandir.side_effect = OSError(
            "[Errno 6] No such device or address: "
            "'/sys/bus/pci/devices/82:10.0/net/'")

        result = self.pci_operator._get_pci_sriov_vf_netdev('82:10.0')
        assert result is None

    # Two distinct MACs, one per possible source, so a test can prove the
    # MAC was read from the correct place (netdev /sys vs bond file).
    SYSFS_MAC = 'a0:36:90:34:0c:06'    # netdev's own /sys/.../address
    BONDING_MAC = 'b0:11:22:33:44:55'  # /proc/net/bonding/<bond>

    # PCIOperator getters that pci_get_net_attrs calls but whose values are
    # irrelevant to the MAC-read logic under test.
    _IRRELEVANT_GETTERS = {
        'get_pci_numa_node': 1,
        'get_pci_sriov_totalvfs': '64\n',
        'get_pci_sriov_numvfs': '7\n',
        'get_pci_sriov_vfs_pci_address': ['0000:98:0a.0'],
        'get_pci_sriov_vf_module_name': 'iavf',
        'get_pci_sriov_vf_device_id': '154c',
        'get_pci_sriov_vf_maxchannels': (None, None),
        'get_pci_driver_name': 'i40e',
        '_get_interface_speed': '10000',
        '_get_interface_channels': (None, None),
    }

    def _run_pci_get_net_attrs_mac(self, master_name, is_bond):
        """Drive pci_get_net_attrs' MAC-read path for a netdev that has a
        'master' symlink, and return the reported mac.

        master_name: name the master symlink resolves to ('ovs-system',
                     'bond0', ...).
        is_bond:     whether /sys/class/net/<master>/bonding exists.
        """
        pciaddr = '0000:98:00.1'
        netdev = 'enp152s0f1'
        devices_dir = '/sys/bus/pci/devices/'
        netdir = devices_dir + pciaddr + '/net/'
        bonding_file = '/proc/net/bonding/' + master_name

        bonding_contents = (
            "Slave Interface: %s\n"
            "MII Status: up\n"
            "Permanent HW addr: %s\n" % (netdev, self.BONDING_MAC))

        def fake_listdir(path):
            # outer loop lists the pci devices dir; inner loop lists the
            # device's net dir. Return the matching entry for each.
            if path == devices_dir:
                return [pciaddr]
            if path == netdir:
                return [netdev]
            return []

        def fake_open(path, *args, **kwargs):
            # The two sources return DIFFERENT MACs so the assertion can
            # prove which one the code actually read.
            if path.endswith(netdev + '/address'):
                return mock.mock_open(read_data=self.SYSFS_MAC + '\n')()
            if path == bonding_file:
                return mock.mock_open(read_data=bonding_contents)()

            return mock.mock_open(read_data='0\n')()

        getters = [mock.patch.object(PCIOperator, name, return_value=val)
                   for name, val in self._IRRELEVANT_GETTERS.items()]

        with nested(
                mock.patch('os.listdir', side_effect=fake_listdir),
                # the 'master' symlink exists; the /sys bonding dir only
                # exists for a real bond -> drives the branch under test.
                mock.patch('os.path.exists', return_value=True),
                mock.patch('os.path.isdir', return_value=is_bond),
                mock.patch('os.path.realpath',
                           return_value='/sys/class/net/' + master_name),
                mock.patch('sysinv.agent.pci.query_pci_id.call_query_pci_id',
                           return_value=(True, '')),
                mock.patch('builtins.open', side_effect=fake_open),
                *getters):
            attrs = self.pci_operator.pci_get_net_attrs(pciaddr)
        return attrs

    def test_pci_get_net_attrs_mac_ovs_system_master(self):
        # A netdev enslaved to the OVS datapath 'ovs-system'
        # has a 'master' symlink but is NOT a Linux bond. The MAC must be
        # read from the netdev's own /sys .../address (SYSFS_MAC)
        attrs = self._run_pci_get_net_attrs_mac('ovs-system', is_bond=False)
        self.assertEqual(len(attrs), 1)
        self.assertEqual(attrs[0]['mac'], self.SYSFS_MAC)

    def test_pci_get_net_attrs_mac_real_bond_master(self):
        # A netdev that is a genuine Linux bond slave must resolve its
        # permanent HW address via /proc/net/bonding/<bond> (BONDING_MAC),
        attrs = self._run_pci_get_net_attrs_mac('bond0', is_bond=True)
        self.assertEqual(len(attrs), 1)
        self.assertEqual(attrs[0]['mac'], self.BONDING_MAC)


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
                    mock.patch.object(AgentManager, 'subfunctions_list_get'),
                    mock.patch.object(AgentManager, '_acquire_network_config_lock'),
                    mock.patch.object(AgentManager, '_release_network_config_lock')) as (
                        mock_net_attrs, mock_device_attrs, mock_nics, mock_devices,
                        mock_subfunctions, aquire_lock, release_lock):

            def fake_get_net_attrs(a):
                return FAKE_PORT_ATTRIBUTES

            def fake_get_device_attrs(a):
                return FAKE_DEVICE_ATTRIBUTES

            def fake_get_nics():
                return FAKE_PORTS

            def fake_get_devices():
                return FAKE_DEVICES

            def fake_subfunctions_list_get():
                return self.subfunctions_list

            mock_net_attrs.side_effect = fake_get_net_attrs
            mock_device_attrs.side_effect = fake_get_device_attrs
            mock_nics.side_effect = fake_get_nics
            mock_devices.side_effect = fake_get_devices
            mock_subfunctions.side_effect = fake_subfunctions_list_get

            ports, devices, macs = self.agent_manager._get_ports_inventory()
            return ports, devices, macs

    @mock.patch('os.path.exists')
    def test_get_pci_inventory_during_network_boot_install(self, mock_exists):
        def file_exists_side_effect(filename):
            if filename == constants.FIRST_BOOT_FLAG:
                # first boot flag is set.
                return True
            else:
                # ansible bootstrap flag is not set.
                # Neither the initial nor volatile worker config complete flags are set
                return False

        self.agent_manager._first_boot_flag = True
        mock_exists.side_effect = file_exists_side_effect
        self.subfunctions_list = [constants.WORKER]

        ports, devices, macs = self._get_ports_inventory()
        assert len(ports) == 1
        assert len(devices) == 1
        assert len(macs) == 1

    @mock.patch('os.path.exists')
    def test_get_pci_inventory_during_bootstrap_fresh_install(self, mock_exists):
        def file_exists_side_effect(filename):
            if filename == constants.ANSIBLE_BOOTSTRAP_FLAG:
                # ansible bootstrap flag is set.
                return True
            else:
                # Neither the initial nor volatile worker config complete flags are set
                return False

        mock_exists.side_effect = file_exists_side_effect
        self.subfunctions_list = [constants.WORKER]

        ports, devices, macs = self._get_ports_inventory()
        assert len(ports) == 1
        assert len(devices) == 1
        assert len(macs) == 1

    @mock.patch('os.path.exists')
    def test_get_pci_inventory_during_restore(self, mock_exists):
        def file_exists_side_effect(filename):
            if filename in [constants.ANSIBLE_BOOTSTRAP_FLAG,
                            tsc.RESTORE_IN_PROGRESS_FLAG]:
                # Both ansible bootstrap and restore flag are set.
                return True
            else:
                # Neither the initial nor volatile worker config complete flags are set
                return False

        mock_exists.side_effect = file_exists_side_effect
        self.subfunctions_list = [constants.WORKER]

        ports, devices, macs = self._get_ports_inventory()
        assert len(ports) == 1
        assert len(devices) == 1
        assert len(macs) == 1

    @mock.patch('os.path.exists')
    def test_get_pci_inventory_controller_before_config_complete(self, mock_exists):
        def file_exists_side_effect(filename):
            # Neither the initial nor volatile controller config complete flags are set
            # Neither first boot nor ansible bootstrap flag are not set.
            return False

        mock_exists.side_effect = file_exists_side_effect
        self.subfunctions_list = [constants.CONTROLLER]

        ports, devices, macs = self._get_ports_inventory()
        assert len(ports) == 1
        assert len(devices) == 1
        assert len(macs) == 1

    @mock.patch('os.path.exists')
    def test_get_pci_inventory_storage_before_config_complete(self, mock_exists):
        def file_exists_side_effect(filename):
            # Neither the initial nor volatile storage config complete flags are set
            # Neither first boot nor ansible bootstrap flag are not set.
            return False

        mock_exists.side_effect = file_exists_side_effect
        self.subfunctions_list = [constants.STORAGE]

        ports, devices, macs = self._get_ports_inventory()
        assert len(ports) == 1
        assert len(devices) == 1
        assert len(macs) == 1

    @mock.patch('os.path.exists')
    def test_get_pci_inventory_before_worker_initial_config_complete(self, mock_exists):
        def file_exists_side_effect(filename):
            # Neither the initial nor volatile worker config complete flags are set
            # Neither first boot nor ansible bootstrap flag are not set.
            return False
        mock_exists.side_effect = file_exists_side_effect
        self.subfunctions_list = [constants.WORKER]

        ports, devices, macs = self._get_ports_inventory()
        assert len(ports) == 0
        assert len(devices) == 0
        assert len(macs) == 0

    @mock.patch('os.path.exists')
    def test_get_pci_inventory_before_worker_config_complete(self, mock_exists):
        def file_exists_side_effect(filename):
            if filename == tsc.INITIAL_WORKER_CONFIG_COMPLETE:
                # Only the initial worker config complete flag is set
                return True
            else:
                # worker config complete is not set.
                # Neither first boot nor ansible bootstrap flag are set.
                return False
        mock_exists.side_effect = file_exists_side_effect
        self.subfunctions_list = [constants.WORKER]

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
                # Neither first boot nor ansible bootstrap flag are set.
                return False
        mock_exists.side_effect = file_exists_side_effect
        self.subfunctions_list = [constants.WORKER]

        ports, devices, macs = self._get_ports_inventory()
        for dev in devices:
            assert dev['fpga_n3000_reset'] is False
        assert len(ports) == 1
        assert len(devices) == 1
        assert len(macs) == 1

    @mock.patch('os.path.exists')
    def test_get_pci_inventory_n3000_reset_flag(self, mock_exists):
        def file_exists_side_effect(filename):
            if filename in [tsc.INITIAL_WORKER_CONFIG_COMPLETE,
                            tsc.VOLATILE_WORKER_CONFIG_COMPLETE,
                            fpga_constants.N3000_RESET_FLAG]:
                return True
            else:
                return False
        mock_exists.side_effect = file_exists_side_effect
        self.subfunctions_list = [constants.WORKER]

        ports, devices, macs = self._get_ports_inventory()
        for dev in devices:
            assert dev['fpga_n3000_reset'] is True
        assert len(ports) == 1
        assert len(devices) == 1
        assert len(macs) == 1
