#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for cgtsclient/common/utils.py and wrapping_formatters.py."""
import argparse
import os
import unittest
from unittest import mock

from cgtsclient.common import utils
from cgtsclient.common import wrapping_formatters as wf


class FakeObj:
    def __init__(self, **kwargs):
        for key, val in kwargs.items():
            setattr(self, key, val)


class TestUtilsMisc(unittest.TestCase):
    def test_is_uuid_like_valid(self):
        self.assertTrue(
            utils.is_uuid_like('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11')
        )

    def test_is_uuid_like_invalid(self):
        self.assertFalse(utils.is_uuid_like('not-a-uuid'))

    def test_get_terminal_size(self):
        w, h = utils.get_terminal_size()
        self.assertGreater(w, 0)
        self.assertGreater(h, 0)

    def test_env_default(self):
        self.assertEqual(utils.env('_NONEXISTENT_12345', default='fb'),
                         'fb')

    def test_env_set(self):
        os.environ['_TEST_CGTS_99'] = 'val'
        try:
            self.assertEqual(utils.env('_TEST_CGTS_99'), 'val')
        finally:
            del os.environ['_TEST_CGTS_99']

    def test_arg_decorator(self):

        @utils.arg('pos', help='h')
        @utils.arg('--opt', default='d')
        def func():
            pass
        self.assertEqual(len(func.arguments), 2)

    def test_import_versioned_module(self):
        mod = utils.import_versioned_module('1', 'shell')
        self.assertTrue(hasattr(mod, 'enhance_parser'))

    def test_pretty_choice_list(self):
        r = utils.pretty_choice_list(['a', 'b'])
        self.assertIn("'a'", r)

    def test_parse_date_non_string(self):
        self.assertEqual(utils.parse_date(42), 42)

    def test_parse_date_no_date(self):
        self.assertEqual(utils.parse_date('hello'), 'hello')

    def test_parse_date_with_date(self):
        r = utils.parse_date('2024-01-01T12:00:00')
        self.assertIsInstance(r, str)

    def test_get_debian_codename(self):
        utils.get_debian_codename.cache_clear()
        with mock.patch('builtins.open', mock.mock_open(
                read_data='ID=debian\nVERSION_CODENAME=bullseye\n')):
            r = utils.get_debian_codename()
            self.assertEqual(r, 'bullseye')
        utils.get_debian_codename.cache_clear()

    def test_get_debian_codename_not_found(self):
        utils.get_debian_codename.cache_clear()
        with mock.patch('builtins.open', side_effect=FileNotFoundError):
            r = utils.get_debian_codename()
            self.assertIsNone(r)
        utils.get_debian_codename.cache_clear()

    def test_is_debian_bullseye(self):
        utils.get_debian_codename.cache_clear()
        with mock.patch('builtins.open', mock.mock_open(
                read_data='VERSION_CODENAME=bullseye\n')):
            self.assertTrue(utils.is_debian_bullseye())
        utils.get_debian_codename.cache_clear()

    def test_does_command_need_no_wrap_list(self):
        cb = mock.MagicMock()
        cb.__name__ = 'do_host_list'
        self.assertTrue(utils._does_command_need_no_wrap(cb))

    def test_does_command_need_no_wrap_other(self):
        cb = mock.MagicMock()
        cb.__name__ = 'do_host_show'
        self.assertFalse(utils._does_command_need_no_wrap(cb))

    def test_does_command_need_no_wrap_special(self):
        cb = mock.MagicMock()
        cb.__name__ = 'do_host_cpu_modify'
        self.assertTrue(utils._does_command_need_no_wrap(cb))

    def test_define_command(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        cmd_mapper = {}

        def do_test(cc, args):
            """Test cmd."""
        utils.define_command(subparsers, 'test', do_test, cmd_mapper)
        self.assertIn('test', cmd_mapper)

    def test_define_commands_from_module(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        cmd_mapper = {}

        class M:
            @staticmethod
            def do_my_cmd(cc, args):
                """My cmd."""
        utils.define_commands_from_module(subparsers, M, cmd_mapper)
        self.assertIn('my-cmd', cmd_mapper)

    def test_sort_for_list_no_sort(self):
        objs = [FakeObj(name='b'), FakeObj(name='a')]
        r = utils._sort_for_list(objs, ['name'], sortby=None)
        self.assertEqual(r[0].name, 'b')

    def test_sort_for_list_with_sort(self):
        objs = [FakeObj(name='b'), FakeObj(name='a')]
        r = utils._sort_for_list(objs, ['name'], sortby=0)
        self.assertEqual(r[0].name, 'a')

    def test_row_height(self):
        self.assertEqual(utils.row_height(['a', 'b']), 1)
        self.assertEqual(utils.row_height(['a\nb', 'c']), 2)

    def test_build_row_from_object(self):
        obj = FakeObj(name='test', id=1)
        row = utils._build_row_from_object(['name', 'id'], {}, obj)
        self.assertEqual(row, ['test', 1])

    def test_build_row_with_formatter(self):
        obj = FakeObj(name='test')
        fmts = {'name': lambda o: o.name.upper()}
        row = utils._build_row_from_object(['name'], fmts, obj)
        self.assertEqual(row, ['TEST'])


class TestWrappingFormatters(unittest.TestCase):
    def test_get_width_none(self):
        self.assertEqual(wf._get_width(None), 0)

    def test_get_width_string(self):
        self.assertGreater(wf._get_width('hello'), 0)

    def test_is_uuid_field_true(self):
        self.assertTrue(wf.is_uuid_field('uuid'))
        self.assertTrue(wf.is_uuid_field('host_uuid'))

    def test_is_uuid_field_false(self):
        self.assertFalse(wf.is_uuid_field('name'))

    def test_wrapper_context(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(3)
        self.assertEqual(ctx.num_columns, 3)
        self.assertEqual(ctx.non_data_chrs_used_by_table, 10)

    def test_wrapper_context_terminal_width(self):
        ctx = wf.WrapperContext()
        w = ctx.get_terminal_width()
        self.assertGreater(w, 0)

    def test_set_no_wrap(self):
        wf.set_no_wrap(True)
        self.assertTrue(wf.is_nowrap_set())
        wf.set_no_wrap(False)
        self.assertFalse(wf.is_nowrap_set())

    def test_prettytable_builder(self):
        pt = utils.prettytable_builder(['Col1', 'Col2'])
        self.assertIsNotNone(pt)

    def test_wordwrap_header_nowrap(self):
        wf.set_no_wrap(True)
        r = utils.wordwrap_header('field', 'My Header', None)
        self.assertEqual(r, 'My Header')
        wf.set_no_wrap(False)

    def test_wordwrap_header_no_formatter(self):
        r = utils.wordwrap_header('field', 'My Header', None)
        self.assertEqual(r, 'My Header')


class TestIsServiceImpacting(unittest.TestCase):
    def test_impacting_commands(self):
        for cmd in ['host-swact', 'host-lock', 'host-power-off',
                    'host-reboot', 'host-reinstall', 'host-reset']:
            self.assertTrue(utils._is_service_impacting_command(cmd),
                            f'{cmd} should be service impacting')

    def test_non_impacting(self):
        self.assertFalse(
            utils._is_service_impacting_command('host-list')
        )
        self.assertFalse(
            utils._is_service_impacting_command('host-show')
        )
        self.assertFalse(
            utils._is_service_impacting_command('host-unlock')
        )


if __name__ == '__main__':
    unittest.main()
