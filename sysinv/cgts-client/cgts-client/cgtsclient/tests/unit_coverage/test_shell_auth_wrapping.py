#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Coverage for shell.py main() auth flow and wrapping_formatters.py."""
import unittest
from unittest import mock

from cgtsclient.common import wrapping_formatters as wf


class TestWrappingFormattersDeep(unittest.TestCase):
    def test_wrapper_formatter_is_wrapper(self):
        self.assertFalse(wf.WrapperFormatter.is_wrapper_formatter(None))
        self.assertFalse(
            wf.WrapperFormatter.is_wrapper_formatter(lambda x: x)
        )

    def test_wrapper_context_full(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(3)
        w = mock.MagicMock()
        ctx.add_column_formatter('col1', w)
        ctx.add_column_formatter('col2', w)
        self.assertEqual(len(ctx.wrappers), 2)
        tw = ctx.get_terminal_width()
        self.assertGreater(tw, 0)
        # Second call uses cached value
        tw2 = ctx.get_terminal_width()
        self.assertEqual(tw, tw2)

    def test_get_width_various(self):
        self.assertEqual(wf._get_width(None), 0)
        self.assertEqual(wf._get_width(''), 0)
        self.assertGreater(wf._get_width('hello world'), 0)

    def test_is_uuid_field_various(self):
        self.assertTrue(wf.is_uuid_field('uuid'))
        self.assertTrue(wf.is_uuid_field('UUID'))
        self.assertTrue(wf.is_uuid_field('host_uuid'))
        self.assertFalse(wf.is_uuid_field('hostname'))

    def test_set_no_wrap_on_formatters(self):
        # With empty formatters
        orig = wf.set_no_wrap_on_formatters(True, {})
        self.assertIsNotNone(orig)
        wf.unset_no_wrap_on_formatters(orig)

    def test_get_terminal_width(self):
        w = wf._get_terminal_width()
        self.assertGreater(w, 0)


if __name__ == '__main__':
    unittest.main()
