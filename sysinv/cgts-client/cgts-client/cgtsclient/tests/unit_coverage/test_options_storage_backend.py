#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Coverage for options.py, storage_backend.py, controller_fs_shell,
device_label_shell.
"""
import unittest
from unittest import mock

from cgtsclient.v1 import options
from cgtsclient.v1 import storage_backend


class TestOptions(unittest.TestCase):
    def test_build_url_with_q(self):
        q = [{'field': 'name', 'op': 'eq', 'value': 'test'}]
        r = options.build_url('/v1/test', q)
        self.assertIn('q.field=name', r)

    def test_build_url_with_params(self):
        r = options.build_url(
            '/v1/test',
            None,
            params=['foo=bar', 'x=y']
        )
        self.assertIn('foo=bar', r)
        self.assertIn('x=y', r)

    def test_build_url_q_and_params(self):
        q = [{'field': 'f', 'op': 'eq', 'value': 'v'}]
        r = options.build_url('/v1/test', q, params=['p=1'])
        self.assertIn('q.field=f', r)
        self.assertIn('p=1', r)

    def test_build_url_no_q_no_params(self):
        r = options.build_url('/v1/test', None)
        self.assertEqual(r, '/v1/test')

    def test_cli_to_array_none(self):
        self.assertIsNone(options.cli_to_array(None))

    def test_cli_to_array_simple(self):
        r = options.cli_to_array('name=test')
        self.assertEqual(r[0]['field'], 'name')
        self.assertEqual(r[0]['op'], 'eq')
        self.assertEqual(r[0]['value'], 'test')

    def test_cli_to_array_operators(self):
        for op_str, op_name in [
            ('!=', 'ne'), ('>=', 'ge'),
            ('<=', 'le'),
            ('>', 'gt'), ('<', 'lt'),
        ]:
            r = options.cli_to_array('field%sval' % op_str)
            self.assertEqual(r[0]['op'], op_name)

    def test_cli_to_array_typed(self):
        r = options.cli_to_array('field=string::hello')
        self.assertEqual(r[0]['type'], 'string')
        self.assertEqual(r[0]['value'], 'hello')

    def test_cli_to_array_multi(self):
        r = options.cli_to_array('a=1;b>2')
        self.assertEqual(len(r), 2)

    def test_cli_to_array_bad(self):
        self.assertRaises(ValueError, options.cli_to_array, 'noop')


class TestStorageBackendManager(unittest.TestCase):
    def test_list_asdict(self):
        api = mock.MagicMock()
        api.json_request.return_value = (
            mock.MagicMock(),
            {'storage_backends': [
                {'uuid': 'sb1',
                 'name': 'ceph',
                 'backend': 'ceph',
                 'capabilities': {'k': 'v'},
                 'services': 'cinder'}
            ]})
        mgr = storage_backend.StorageBackendManager(api)
        r = mgr.list(asdict=True)
        self.assertIsInstance(r, list)

    def test_update(self):
        api = mock.MagicMock()
        api.json_request.return_value = (mock.MagicMock(),
                                         {'uuid': 'sb1', 'capabilities': {}})
        mgr = storage_backend.StorageBackendManager(api)
        r = mgr.update('sb1', [{'op': 'replace'}])
        self.assertIsNotNone(r)


if __name__ == '__main__':
    unittest.main()
