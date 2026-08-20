#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Batch 10: ilvg, iinterface, iextoam, idns, idisk, icpu, iHost,
host_fs,
helm.
"""
import unittest
from unittest import mock

from cgtsclient import exc
from cgtsclient.tests.unit_coverage._helpers import _make_resource
from cgtsclient.tests.unit_coverage._helpers import _patch_print
from cgtsclient.v1 import helm_shell
from cgtsclient.v1 import host_fs
from cgtsclient.v1 import icpu
from cgtsclient.v1 import idisk
from cgtsclient.v1 import iinterface


# --- iinterface.py ---
class TestIinterfaceFind(unittest.TestCase):
    def test_find_by_name(self):
        cc = mock.MagicMock()
        cc.iinterface.list.return_value = (
            [_make_resource(uuid='if1', ifname='eth0')]
        )
        r = iinterface._find_interface(
            cc,
            _make_resource(uuid='h1', hostname='c0'),
            'eth0'
        )
        self.assertEqual(r.ifname, 'eth0')

    def test_find_not_found(self):
        cc = mock.MagicMock()
        cc.iinterface.list.return_value = []
        self.assertRaises(exc.CommandError, iinterface._find_interface, cc,
                          _make_resource(
                              uuid='h1',
                              hostname='c0'), 'missing'
                          )

    def test_get_ports_ethernet(self):
        cc = mock.MagicMock()
        ihost = _make_resource(uuid='h1', hostname='c0')
        iface = _make_resource(
            uuid='if1',
            ifname='eth0',
            iftype='ethernet',
            uses=[],
            dpdksupport=[]
        )
        port = mock.MagicMock()
        port.dpdksupport = True
        cc.iinterface.list_ports.return_value = [port]
        with mock.patch('cgtsclient.v1.port.get_port_display_name',
                        return_value='eth0'
                        ):
            iinterface._get_ports(cc, ihost, iface)
        self.assertEqual(iface.dpdksupport, [True])


# --- idisk.py ---
class TestIdiskFind(unittest.TestCase):
    def test_find_by_uuid(self):
        cc = mock.MagicMock()
        cc.idisk.get.return_value = (
            _make_resource(uuid='a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11')
        )
        r = idisk._find_disk(
            cc,
            _make_resource(uuid='h1'),
            'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'
        )
        self.assertIsNotNone(r)

    def test_find_by_uuid_not_found(self):
        cc = mock.MagicMock()
        cc.idisk.get.side_effect = exc.HTTPNotFound()
        r = idisk._find_disk(
            cc,
            _make_resource(uuid='h1'),
            'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'
        )
        self.assertIsNone(r)

    def test_find_by_device_node(self):
        cc = mock.MagicMock()
        cc.idisk.list.return_value = [
            _make_resource(
                uuid='d1',
                device_node='/dev/sda',
                device_path='/dev/disk/x',
            )]
        r = idisk._find_disk(cc, _make_resource(uuid='h1'), '/dev/sda')
        self.assertEqual(r.uuid, 'd1')

    def test_find_by_path_not_found(self):
        cc = mock.MagicMock()
        cc.idisk.list.return_value = []
        r = idisk._find_disk(cc, _make_resource(uuid='h1'), '/dev/missing')
        self.assertIsNone(r)

    def test_display_name(self):
        self.assertEqual(
            idisk.get_disk_display_name(
                _make_resource(device_node='/dev/sda', uuid='x')
            ),
            '/dev/sda'
        )
        r = idisk.get_disk_display_name(
            _make_resource(device_node='', uuid='abcdefgh')
        )
        self.assertIn('(', r)


# --- host_fs.py ---
class TestHostFsFind(unittest.TestCase):
    def test_find_by_id(self):
        cc = mock.MagicMock()
        cc.host_fs.get.return_value = _make_resource(
            uuid='fs1',
            name='scratch'
        )
        r = host_fs._find_fs(cc, _make_resource(uuid='h1'), '123')
        self.assertEqual(r.name, 'scratch')

    def test_find_by_name(self):
        cc = mock.MagicMock()
        cc.host_fs.list.return_value = (
            [_make_resource(uuid='fs1', name='scratch')]
        )
        r = host_fs._find_fs(cc, _make_resource(uuid='h1'), 'scratch')
        self.assertEqual(r.name, 'scratch')

    def test_find_by_uuid(self):
        cc = mock.MagicMock()
        cc.host_fs.list.return_value = (
            [_make_resource(uuid='fs-uuid-1', name='scratch')]
        )
        r = host_fs._find_fs(cc, _make_resource(uuid='h1'), 'fs-uuid-1')
        self.assertEqual(r.uuid, 'fs-uuid-1')

    def test_find_not_found(self):
        cc = mock.MagicMock()
        cc.host_fs.list.return_value = []
        self.assertRaises(exc.CommandError,
                          host_fs._find_fs,
                          cc,
                          _make_resource(uuid='h1'),
                          'missing')


# --- icpu.py ---
class TestIcpuCheck(unittest.TestCase):
    def test_check_core_functions_ok(self):
        cpus = [_make_resource(allocated_function=icpu.PLATFORM_CPU_TYPE),
                _make_resource(allocated_function=icpu.VSWITCH_CPU_TYPE),
                _make_resource(
                    allocated_function=icpu.APPLICATION_CPU_TYPE
        )]
        self.assertEqual(icpu.check_core_functions('worker', cpus), '')

    def test_check_no_app_worker(self):
        cpus = [_make_resource(allocated_function=icpu.PLATFORM_CPU_TYPE),
                _make_resource(allocated_function=icpu.VSWITCH_CPU_TYPE)]
        self.assertIn('application',
                      icpu.check_core_functions('worker', cpus).lower())


# --- helm_shell.py ---
@_patch_print
class TestHelmShellDeep2(unittest.TestCase):

    def test_find_overrides_found(self, *_):
        cc = mock.MagicMock()
        app = _make_resource(name='app1')
        cc.helm.list_charts.return_value = (
            [_make_resource(name='chart1', namespaces=['ns1'])]
        )
        r = helm_shell._find_overrides(cc, app, 'chart1', 'ns1')
        self.assertEqual(r.name, 'chart1')

    def test_find_overrides_not_found(self, *_):
        cc = mock.MagicMock()
        app = _make_resource(name='app1')
        cc.helm.list_charts.return_value = []
        self.assertRaises(exc.CommandError,
                          helm_shell._find_overrides,
                          cc,
                          app,
                          'missing',
                          'ns1')


# --- iextoam_shell.py ---
@_patch_print
class TestIextoamShellDeep(unittest.TestCase):
    pass


@_patch_print
class TestIlvgShellDeep(unittest.TestCase):
    pass


# --- idisk_shell.py ---


if __name__ == '__main__':
    unittest.main()
