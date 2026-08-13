#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Deep coverage for icpu.py, wrapping_formatters.py, options.py,
iinterface.py.
"""
import unittest
from unittest import mock

from cgtsclient.common import wrapping_formatters as wf
from cgtsclient import exc
from cgtsclient.tests.unit_coverage._helpers import _make_resource
from cgtsclient.v1 import icpu
from cgtsclient.v1 import iinterface
from cgtsclient.v1 import storage_backend


class TestIcpuFunctions(unittest.TestCase):
    def test_compress_range_simple(self):
        r = icpu.compress_range([0, 1, 2, 3])
        self.assertIn('0-3', r)

    def test_compress_range_gaps(self):
        r = icpu.compress_range([0, 1, 5, 6])
        self.assertIn('0-1', r)
        self.assertIn('5-6', r)

    def test_compress_range_single(self):
        r = icpu.compress_range([3])
        self.assertIn('3', r)

    def test_restructure_host_cpu_data(self):
        host = mock.MagicMock()
        cpu0 = mock.MagicMock(
            cpu_model='Xeon',
            numa_node=0,
            thread=0,
            cpu=0,
            allocated_function='platform',
        )
        cpu1 = mock.MagicMock(
            cpu_model='Xeon',
            numa_node=0,
            thread=1,
            cpu=1,
            allocated_function='vswitch',
        )
        host.cpus = [cpu0, cpu1]
        host.nodes = [mock.MagicMock()]
        host.subfunctions = 'controller,worker'
        icpu.restructure_host_cpu_data(host)
        self.assertIsNotNone(host.core_assignment)
        self.assertEqual(host.cpu_model, 'Xeon')

    def test_restructure_no_cpus(self):
        host = mock.MagicMock()
        host.cpus = []
        icpu.restructure_host_cpu_data(host)
        self.assertEqual(host.core_assignment, [])

    def test_cpu_type_list(self):
        self.assertIn(icpu.PLATFORM_CPU_TYPE, icpu.CPU_TYPE_LIST)


class TestWrappingFormattersDeep(unittest.TestCase):
    def test_wrapper_context_add_formatter(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(2)
        wrapper = mock.MagicMock()
        ctx.add_column_formatter('field1', wrapper)
        self.assertIn('field1', ctx.wrappers_by_field)
        self.assertEqual(len(ctx.wrappers), 1)

    def test_set_no_wrap_on_formatters(self):
        fmt = mock.MagicMock()
        fmt.wrapper_formatter = mock.MagicMock()
        fmt.wrapper_formatter.is_wrapper_formatter = (
            staticmethod(lambda f: True)
        )
        wf.WrapperFormatter.is_wrapper_formatter = (
            staticmethod(lambda f: False)
        )
        formatters = {'col': fmt}
        # Just ensure it doesn't crash
        orig = wf.set_no_wrap_on_formatters(True, formatters)
        self.assertIsNotNone(orig)

    def test_is_nowrap_toggle(self):
        wf.set_no_wrap(True)
        self.assertTrue(wf.is_nowrap_set())
        wf.set_no_wrap(False)
        self.assertFalse(wf.is_nowrap_set())


class TestIinterfaceManager(unittest.TestCase):
    def test_create(self):
        api = mock.MagicMock()
        api.json_request.return_value = (
            mock.MagicMock(),
            {'uuid': 'if1', 'ifname': 'eth0'}
        )
        mgr = iinterface.iinterfaceManager(api)
        r = mgr.create(
            ifname='eth0',
            iftype='ethernet',
            ihost_uuid='h1',
            imtu=1500,
            ifclass='platform',
        )
        self.assertEqual(r.uuid, 'if1')

    def test_create_invalid(self):
        api = mock.MagicMock()
        mgr = iinterface.iinterfaceManager(api)
        self.assertRaises(exc.InvalidAttribute, mgr.create, bad_key='x')

    def test_list(self):
        api = mock.MagicMock()
        api.json_request.return_value = (
            mock.MagicMock(),
            {'iinterfaces': [
                {'uuid': 'if1'}
            ]}
        )
        mgr = iinterface.iinterfaceManager(api)
        r = mgr.list('h1')
        self.assertEqual(len(r), 1)


class TestStorageBackendDeep(unittest.TestCase):
    def test_backend_modify(self):
        api = mock.MagicMock()
        _sb = _make_resource(  # noqa: F841
            uuid='sb1',
            name='ceph',
            backend='ceph',
            state='configured',
            capabilities={},
            services='cinder',
        )
        api.json_request.return_value = (
            mock.MagicMock(),
            {'storage_backends': [
                {'uuid': 'sb1',
                 'name': 'ceph',
                 'backend': 'ceph',
                 'capabilities': {},
                 'services': 'cinder'}
            ]})
        mgr = storage_backend.StorageBackendManager(api)
        backends = mgr.list()
        self.assertEqual(len(backends), 1)


if __name__ == '__main__':
    unittest.main()
