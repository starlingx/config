#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Branch coverage: hit the untaken if/else branches."""
import unittest
from unittest import mock

from cgtsclient.common import base
from cgtsclient import exc
from cgtsclient.tests.unit_coverage._helpers import _make_resource
from cgtsclient.tests.unit_coverage._helpers import _patch_print
from cgtsclient.v1 import ethernetport_shell
from cgtsclient.v1 import icpu
from cgtsclient.v1 import port_shell


# --- exc.py 201->207: CgtsclientException with 'code' in kwargs ---


class TestExcBranches(unittest.TestCase):
    def test_cgtsclient_exception_with_code_in_kwargs(self):
        e = exc.CgtsclientException(code=404)
        self.assertIn('404', str(e.kwargs.get('code', '')))

    def test_cgtsclient_exception_bad_format(self):
        # kwargs doesn't match message format -> falls through to raw
        # message
        class MyExc(exc.CgtsclientException):
            message = "Error: %(missing_key)s"
        e = MyExc(wrong_key='val')
        self.assertIn('Error', str(e))


# --- base.py 73->76: _list with obj_class passed ---


class TestBaseBranches(unittest.TestCase):
    def test_list_with_obj_class(self):
        api = mock.MagicMock()
        api.json_request.return_value = (
            mock.MagicMock(),
            {'items': [{'id': '1'}]}
        )
        mgr = base.Manager(api)
        mgr.resource_class = base.Resource
        result = mgr._list('/v1/test', 'items', obj_class=base.Resource)
        self.assertEqual(len(result), 1)


# --- icpu.py branches: restructure with multiple cpus, None function,
# worker ---


class TestIcpuBranches(unittest.TestCase):
    def test_restructure_multiple_cpus_same_node(self):
        host = mock.MagicMock()
        cpu0 = mock.MagicMock(
            cpu_model='Xeon', numa_node=0,
            thread=0, cpu=0,
            allocated_function='platform')
        cpu1 = mock.MagicMock(
            cpu_model='Xeon', numa_node=0,
            thread=0, cpu=1,
            allocated_function='platform')
        cpu2 = mock.MagicMock(
            cpu_model='Xeon', numa_node=0,
            thread=1, cpu=2,
            allocated_function=None)  # None -> NONE_CPU_TYPE
        host.cpus = [cpu0, cpu1, cpu2]
        host.nodes = [mock.MagicMock()]
        host.subfunctions = 'controller,worker'
        icpu.restructure_host_cpu_data(host)
        self.assertEqual(host.hyperthreading, 'Yes')
        self.assertGreater(host.physical_cores, 0)

    def test_check_core_no_app_worker(self):
        cpus = (
            [_make_resource(allocated_function=icpu.PLATFORM_CPU_TYPE),
             _make_resource(
                allocated_function=icpu.VSWITCH_CPU_TYPE
            )]
        )
        r = icpu.check_core_functions('worker', cpus)
        self.assertIn(icpu.APPLICATION_CPU_TYPE_FORMAT, r)

    def test_check_core_no_platform(self):
        cpus = [
            _make_resource(
                allocated_function=(
                    icpu.APPLICATION_CPU_TYPE
                )
            )
        ]
        r = icpu.check_core_functions('controller', cpus)
        self.assertIn(icpu.PLATFORM_CPU_TYPE_FORMAT, r)


# --- ethernetport_shell, port_shell: not-found branches ---
@_patch_print
class TestPortBranches(unittest.TestCase):
    @mock.patch('cgtsclient.v1.ihost._find_ihost')
    def test_ethernet_port_not_found(self, mock_find_host, *_):
        cc = mock.MagicMock()
        mock_find_host.return_value = _make_resource(
            uuid='h1',
            id=1,
            hostname='c0'
        )
        cc.ethernet_port.list.return_value = []
        self.assertRaises(exc.CommandError, ethernetport_shell._find_port,
                          cc, mock_find_host.return_value, 'missing')

    @mock.patch('cgtsclient.v1.ihost._find_ihost')
    def test_port_not_found(self, mock_find_host, *_):
        cc = mock.MagicMock()
        mock_find_host.return_value = _make_resource(
            uuid='h1',
            id=1,
            hostname='c0'
        )
        cc.port.list.return_value = []
        self.assertRaises(exc.CommandError, port_shell._find_port, cc,
                          mock_find_host.return_value, 'missing')


if __name__ == '__main__':
    unittest.main()
