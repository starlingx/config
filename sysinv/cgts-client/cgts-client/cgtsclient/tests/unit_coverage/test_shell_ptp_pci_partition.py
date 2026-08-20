#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Batch 7: ptp_interface, ptp_instance, ptp_ha, pci_device, partition.
"""
import unittest
from unittest import mock

from cgtsclient import exc
from cgtsclient.tests.unit_coverage._helpers import _make_resource
from cgtsclient.tests.unit_coverage._helpers import _patch_print
from cgtsclient.v1 import partition
from cgtsclient.v1 import pci_device
from cgtsclient.v1 import ptp_ha_phc2sys_control
from cgtsclient.v1 import ptp_instance
from cgtsclient.v1 import ptp_interface
from cgtsclient.v1 import ptp_interface_shell


# --- ptp_interface.py _find_ptp_interface ---
class TestPtpInterfaceFind(unittest.TestCase):
    def test_find_by_uuid(self):
        cc = mock.MagicMock()
        cc.ptp_interface.get.return_value = _make_resource(
            uuid='pi1',
            name='ptpif1'
        )
        r = ptp_interface._find_ptp_interface(
            cc,
            'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'
        )
        self.assertEqual(r.uuid, 'pi1')

    def test_find_by_name(self):
        cc = mock.MagicMock()
        cc.ptp_interface.list.return_value = (
            [_make_resource(uuid='pi1', name='ptpif1')]
        )
        r = ptp_interface._find_ptp_interface(cc, 'ptpif1')
        self.assertEqual(r.name, 'ptpif1')

    def test_find_not_found_by_uuid(self):
        cc = mock.MagicMock()
        cc.ptp_interface.get.side_effect = exc.HTTPNotFound()
        self.assertRaises(exc.CommandError, ptp_interface._find_ptp_interface, cc,
                          'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11')

    def test_find_not_found_by_name(self):
        cc = mock.MagicMock()
        cc.ptp_interface.list.return_value = []
        self.assertRaises(exc.CommandError,
                          ptp_interface._find_ptp_interface,
                          cc,
                          'missing')


# --- ptp_instance.py _find_ptp_instance ---
class TestPtpInstanceFind(unittest.TestCase):
    def test_find_by_uuid(self):
        cc = mock.MagicMock()
        cc.ptp_instance.get.return_value = _make_resource(
            uuid='pi1',
            name='ptp1'
        )
        r = ptp_instance._find_ptp_instance(
            cc,
            'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'
        )
        self.assertEqual(r.uuid, 'pi1')

    def test_find_by_name(self):
        cc = mock.MagicMock()
        cc.ptp_instance.list.return_value = (
            [_make_resource(uuid='pi1', name='ptp1')]
        )
        r = ptp_instance._find_ptp_instance(cc, 'ptp1')
        self.assertEqual(r.name, 'ptp1')

    def test_find_not_found_by_name(self):
        cc = mock.MagicMock()
        cc.ptp_instance.list.return_value = []
        self.assertRaises(exc.CommandError,
                          ptp_instance._find_ptp_instance,
                          cc,
                          'missing')


# --- pci_device.py ---
class TestPciDevice(unittest.TestCase):
    def test_display_name_with_name(self):
        p = _make_resource(name='mydev', uuid='abcdefgh-1234')
        self.assertEqual(pci_device.get_pci_device_display_name(p), 'mydev')

    def test_display_name_no_name(self):
        p = _make_resource(name='', uuid='abcdefgh-1234-5678')
        r = pci_device.get_pci_device_display_name(p)
        self.assertIn('(', r)

    def test_find_device_by_name(self):
        cc = mock.MagicMock()
        host = _make_resource(uuid='h1', hostname='c0')
        cc.pci_device.list.return_value = (
            [_make_resource(name='dev1', pciaddr='0000:00:01.0')]
        )
        r = pci_device.find_device(cc, host, 'dev1')
        self.assertEqual(r.name, 'dev1')

    def test_find_device_by_addr(self):
        cc = mock.MagicMock()
        host = _make_resource(uuid='h1', hostname='c0')
        cc.pci_device.list.return_value = (
            [_make_resource(name='dev1', pciaddr='0000:00:01.0')]
        )
        r = pci_device.find_device(cc, host, '0000:00:01.0')
        self.assertEqual(r.pciaddr, '0000:00:01.0')

    def test_find_device_not_found(self):
        cc = mock.MagicMock()
        host = _make_resource(uuid='h1', hostname='c0')
        cc.pci_device.list.return_value = []
        self.assertRaises(exc.CommandError,
                          pci_device.find_device,
                          cc,
                          host,
                          'missing')


# --- partition.py _find_partition ---
class TestPartitionFind(unittest.TestCase):
    def test_find_by_device_path(self):
        cc = mock.MagicMock()
        host = _make_resource(uuid='h1')
        cc.partition.list.return_value = (
            [_make_resource(uuid='p1', device_path='/dev/sda1')]
        )
        r = partition._find_partition(cc, host, '/dev/sda1')
        self.assertEqual(r.uuid, 'p1')

    def test_find_by_uuid(self):
        cc = mock.MagicMock()
        host = _make_resource(uuid='h1')
        cc.partition.list.return_value = (
            [_make_resource(uuid='p1', device_path='/dev/sda1')]
        )
        r = partition._find_partition(cc, host, 'p1')
        self.assertEqual(r.uuid, 'p1')

    def test_find_not_found(self):
        cc = mock.MagicMock()
        host = _make_resource(uuid='h1')
        cc.partition.list.return_value = []
        r = partition._find_partition(cc, host, 'missing')
        self.assertIsNone(r)

    def test_find_with_idisk(self):
        cc = mock.MagicMock()
        host = _make_resource(uuid='h1')
        disk = _make_resource(uuid='d1')
        cc.partition.list.return_value = (
            [_make_resource(uuid='p1', device_path='/dev/sda1')]
        )
        r = partition._find_partition(cc, host, '/dev/sda1', idisk=disk)
        self.assertEqual(r.uuid, 'p1')


# --- ptp_interface_shell.py ---
@_patch_print
class TestPtpInterfaceShellDeep(unittest.TestCase):

    @mock.patch('cgtsclient.v1.ptp_interface._find_ptp_interface')
    def test_parameter_op_empty(self, mock_find, *_):
        self.assertRaises(
            exc.CommandError,
            ptp_interface_shell._ptp_interface_parameter_op,
            None, 'add', 'ptpif1', [])


# --- ptp_instance_shell.py ---
@_patch_print
# --- pci_device_shell.py ---
@_patch_print
# --- ptp_ha_phc2sys_control.py ---
@_patch_print
class TestPtpHaPhc2sys(unittest.TestCase):

    def test_run_phc2sys_command_success(self, *_):
        with mock.patch('socket.socket') as mock_sock:
            inst = mock_sock.return_value
            inst.recv.return_value = b'OK'
            r = ptp_ha_phc2sys_control._run_phc2sys_command('/tmp/sock', 'status')
            self.assertEqual(r, 'OK')

    def test_run_phc2sys_command_none_response(self, *_):
        with mock.patch('socket.socket') as mock_sock:
            inst = mock_sock.return_value
            inst.recv.return_value = b'None'
            r = ptp_ha_phc2sys_control._run_phc2sys_command('/tmp/sock', 'status')
            self.assertIsNone(r)

    def test_run_phc2sys_connection_refused(self, *_):
        with mock.patch('socket.socket') as mock_sock:
            inst = mock_sock.return_value
            inst.connect.side_effect = ConnectionRefusedError('refused')
            self.assertRaises(exc.CommunicationError,
                              ptp_ha_phc2sys_control._run_phc2sys_command,
                              '/tmp/sock', 'cmd')

    def test_run_phc2sys_file_not_found(self, *_):
        with mock.patch('socket.socket') as mock_sock:
            inst = mock_sock.return_value
            inst.connect.side_effect = FileNotFoundError('no file')
            self.assertRaises(exc.CommandError,
                              ptp_ha_phc2sys_control._run_phc2sys_command,
                              '/tmp/sock', 'cmd')

    def test_run_phc2sys_permission_error(self, *_):
        with mock.patch('socket.socket') as mock_sock:
            inst = mock_sock.return_value
            inst.connect.side_effect = PermissionError('denied')
            self.assertRaises(exc.CommandError,
                              ptp_ha_phc2sys_control._run_phc2sys_command,
                              '/tmp/sock', 'cmd')


if __name__ == '__main__':
    unittest.main()
