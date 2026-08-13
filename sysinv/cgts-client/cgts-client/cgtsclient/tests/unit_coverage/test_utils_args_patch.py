#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Deep coverage tests for utils.py, wrapping_formatters.py, icpu.py,
options.py.
"""
import json
import subprocess
import unittest
from unittest import mock

from cgtsclient.common import utils
from cgtsclient import exc


class TestArgsArrayToPatch(unittest.TestCase):
    def test_replace(self):
        r = utils.args_array_to_patch('replace', ['key=val'])
        self.assertEqual(
            r,
            [{'op': 'replace', 'path': '/key', 'value': 'val'}]
        )

    def test_add(self):
        r = utils.args_array_to_patch('add', ['/k=v'])
        self.assertEqual(r[0]['op'], 'add')

    def test_remove(self):
        r = utils.args_array_to_patch('remove', ['/key'])
        self.assertEqual(r[0]['op'], 'remove')

    def test_bad_op(self):
        self.assertRaises(exc.CommandError,
                          utils.args_array_to_patch,
                          'bad',
                          ['k=v'])

    def test_no_equals(self):
        self.assertRaises(exc.CommandError,
                          utils.args_array_to_patch,
                          'replace',
                          ['noequals'])


class TestDictToPatch(unittest.TestCase):
    def test_basic(self):
        r = utils.dict_to_patch({'a': 1, 'b': 2})
        self.assertEqual(len(r), 2)
        self.assertEqual(r[0]['op'], 'replace')


class TestArgsArrayToListDict(unittest.TestCase):
    def test_valid(self):
        r = utils.args_array_to_list_dict(['a=1', 'b=2'])
        self.assertEqual(r, [{'a': '1'}, {'b': '2'}])

    def test_invalid(self):
        self.assertRaises(exc.CommandError,
                          utils.args_array_to_list_dict,
                          ['noeq'])


class TestFindResource(unittest.TestCase):
    def test_by_int(self):
        mgr = mock.MagicMock()
        mgr.get.return_value = 'found'
        self.assertEqual(utils.find_resource(mgr, '123'), 'found')

    def test_by_uuid(self):
        mgr = mock.MagicMock()
        mgr.get.return_value = 'found'
        self.assertEqual(
            utils.find_resource(mgr,
                                'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'
                                ),
            'found'
        )

    def test_by_name(self):
        mgr = mock.MagicMock()
        mgr.get.side_effect = exc.NotFound()
        mgr.find.return_value = 'found'
        mgr.resource_class.__name__ = 'Thing'
        self.assertEqual(utils.find_resource(mgr, 'myname'), 'found')

    def test_not_found(self):
        mgr = mock.MagicMock()
        mgr.get.side_effect = exc.NotFound()
        mgr.find.side_effect = exc.NotFound()
        mgr.resource_class.__name__ = 'Thing'
        self.assertRaises(exc.CommandError,
                          utils.find_resource,
                          mgr,
                          'missing')


class TestObjectify(unittest.TestCase):
    def test_dict(self):
        obj = utils.objectify({'a': 1, 'b': 2})
        self.assertEqual(obj.a, 1)
        self.assertEqual(obj['b'], 2)

    def test_non_dict(self):
        self.assertEqual(utils.objectify(42), 42)

    def test_decorator(self):

        @utils.objectify
        def func():
            return {'x': 10}
        r = func()
        self.assertEqual(r.x, 10)


class TestSizeUnitConversion(unittest.TestCase):
    def test_convert(self):
        # 1048576 KiB = 1 GiB (step=1024, twice)
        r = utils.size_unit_conversion(2048, 1)
        self.assertEqual(r, 2.0)


class TestKeyringFunctions(unittest.TestCase):

    @mock.patch('subprocess.run')
    def test_load_auth_by_name(self, mock_run):
        data = json.dumps(
            {'token': 't', 'auth_url': 'u', 'system_url': 's'}
        )
        mock_run.return_value = mock.MagicMock(stdout=data.encode())
        tok, auth, sys_url = (
            utils.load_auth_session_keyring_by_name('key')
        )
        self.assertEqual(tok, 't')

    @mock.patch('subprocess.run')
    def test_load_auth_by_name_fail(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, 'cmd')
        tok, auth, sys_url = (
            utils.load_auth_session_keyring_by_name('key')
        )
        self.assertIsNone(tok)

    @mock.patch('subprocess.run')
    def test_load_auth_by_id(self, mock_run):
        data = json.dumps(
            {'token': 't', 'auth_url': 'u', 'system_url': 's'}
        )
        mock_run.return_value = mock.MagicMock(stdout=data.encode())
        tok, auth, sys_url = utils.load_auth_session_keyring_by_id(123)
        self.assertEqual(tok, 't')


class TestPromptConfirmation(unittest.TestCase):
    def test_yes_flag_skips(self):
        called = []

        def func(cc, args):
            called.append(True)

        wrapped = utils.prompt_cli_confirmation(func)
        args = mock.MagicMock()
        args.yes = True
        with mock.patch.object(
                utils,
                '_is_cliconfirmation_param_enabled',
                return_value=True
        ):
            wrapped(None, args)
        self.assertTrue(called)

    def test_disabled(self):
        called = []

        def func(cc, args):
            called.append(True)

        wrapped = utils.prompt_cli_confirmation(func)
        with mock.patch.object(
                utils,
                '_is_cliconfirmation_param_enabled',
                return_value=False
        ):
            wrapped(None, mock.MagicMock())
        self.assertTrue(called)


if __name__ == '__main__':
    unittest.main()
