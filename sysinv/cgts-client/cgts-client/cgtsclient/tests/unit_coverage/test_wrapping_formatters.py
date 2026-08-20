#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Deep coverage for wrapping_formatters.py."""
import unittest

from cgtsclient.common import wrapping_formatters as wf


class TestWrapperFormatter(unittest.TestCase):
    def _make_context(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(3)
        ctx.terminal_width = 120
        return ctx

    def test_init_with_field(self):
        ctx = self._make_context()
        w = wf.WrapperFormatter(ctx, 'name')
        self.assertEqual(w.field, 'name')
        self.assertEqual(w.min_width, 0)

    def test_init_no_field(self):
        ctx = self._make_context()
        w = wf.WrapperFormatter(ctx, None)
        self.assertEqual(w.get_field_value('data'), 'data')

    def test_get_basic_desired_width(self):
        ctx = self._make_context()
        w = wf.WrapperFormatter(ctx, None)
        w.min_width = 20
        self.assertEqual(w.get_basic_desired_width(), 20)

    def test_get_calculated_desired_width(self):
        ctx = self._make_context()
        w = wf.WrapperFormatter(ctx, None)
        w.min_width = 10
        w.header_width = 20
        self.assertEqual(w.get_calculated_desired_width(), 20)

    def test_set_min_width(self):
        ctx = self._make_context()
        w = wf.WrapperFormatter(ctx, None)
        w.set_min_width(15)
        self.assertEqual(w.min_width, 15)

    def test_text_wrap(self):
        ctx = self._make_context()
        w = wf.WrapperFormatter(ctx, None)
        w.no_wrap = False
        r = w.text_wrap('hello world this is a test', 20)
        self.assertIsInstance(r, str)

    def test_text_wrap_nowrap(self):
        ctx = self._make_context()
        w = wf.WrapperFormatter(ctx, None)
        w.no_wrap = True
        r = w.text_wrap('hello', 10)
        self.assertEqual(r, 'hello')

    def test_format(self):
        ctx = self._make_context()
        w = wf.WrapperFormatter(ctx, None)
        self.assertEqual(w.format('test'), 'test')

    def test_get_unwrapped_field_value(self):
        ctx = self._make_context()
        w = wf.WrapperFormatter(ctx, None)
        self.assertEqual(w.get_unwrapped_field_value('val'), 'val')

    def test_is_wrapper_formatter(self):
        ctx = self._make_context()
        wf.WrapperFormatter(ctx, None)
        self.assertFalse(wf.WrapperFormatter.is_wrapper_formatter(None))
        self.assertFalse(
            wf.WrapperFormatter.is_wrapper_formatter(lambda x: x)
        )

    def test_get_actual_column_char_len(self):
        ctx = self._make_context()
        w = wf.WrapperFormatter(ctx, None)
        r = w.get_actual_column_char_len(20)
        self.assertGreater(r, 0)

    def test_set_actual_column_len(self):
        ctx = self._make_context()
        w = wf.WrapperFormatter(ctx, None)
        w.set_actual_column_len(30)
        self.assertEqual(w.actual_column_char_len, 30)

    def test_textwrap_fill(self):
        ctx = self._make_context()
        w = wf.WrapperFormatter(ctx, None)
        r = w._textwrap_fill('hello world', 20)
        self.assertIsInstance(r, str)
        # Call again to test cached textWrapper
        r2 = w._textwrap_fill('another text', 25)
        self.assertIsInstance(r2, str)

    def test_text_wrap_with_blank_line(self):
        ctx = self._make_context()
        w = wf.WrapperFormatter(ctx, None)
        w.add_blank_line = True
        r = w.text_wrap('a ' * 50, 10)
        self.assertIsInstance(r, str)


class TestWrapperLambdaFormatter(unittest.TestCase):
    def test_basic(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(2)
        ctx.terminal_width = 80

        class Obj:
            name = 'test'
        w = wf.WrapperLambdaFormatter(ctx, 'name', lambda d: str(d))
        r = w.format(Obj())
        self.assertIsInstance(r, str)


class TestWrapperFixedWidthFormatter(unittest.TestCase):
    def test_basic(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(2)
        ctx.terminal_width = 80
        w = wf.WrapperFixedWidthFormatter(ctx, 'name', 20)
        self.assertEqual(w.get_basic_desired_width(), 20)


class TestWrapperPercentWidthFormatter(unittest.TestCase):
    def test_basic(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(2)
        ctx.terminal_width = 100
        w = wf.WrapperPercentWidthFormatter(ctx, 'name', 0.5)
        dw = w.get_basic_desired_width()
        self.assertGreater(dw, 0)


class TestWrapperFormatterFactory(unittest.TestCase):
    def _make_context(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(2)
        ctx.terminal_width = 80
        return ctx

    def test_already_wrapper(self):
        ctx = self._make_context()
        w = wf.WrapperFormatter(ctx, 'f')
        r = wf.wrapper_formatter_factory(ctx, 'f', w)
        self.assertIs(r, w)

    def test_callable(self):
        ctx = self._make_context()
        r = wf.wrapper_formatter_factory(ctx, 'f', lambda d: str(d))
        self.assertIsInstance(r, wf.WrapperLambdaFormatter)

    def test_int(self):
        ctx = self._make_context()
        r = wf.wrapper_formatter_factory(ctx, 'f', 20)
        self.assertIsInstance(r, wf.WrapperFixedWidthFormatter)

    def test_float(self):
        ctx = self._make_context()
        r = wf.wrapper_formatter_factory(ctx, 'f', 0.5)
        self.assertIsInstance(r, wf.WrapperPercentWidthFormatter)

    def test_dict_with_formatter(self):
        ctx = self._make_context()
        r = wf.wrapper_formatter_factory(ctx, 'f',
                                         {'formatter': lambda d: str(d), 'hard_width': 20})
        self.assertIsInstance(r, wf.WrapperWithCustomFormatter)

    def test_dict_with_wrapper_formatter(self):
        ctx = self._make_context()
        r = wf.wrapper_formatter_factory(ctx, 'f',
                                         {'wrapperFormatter': 20, 'formatter': lambda d: str(d)})
        self.assertIsInstance(r, wf.WrapperWithCustomFormatter)

    def test_dict_no_formatter(self):
        ctx = self._make_context()
        r = wf.wrapper_formatter_factory(ctx, 'f', {'hard_width': 15})
        self.assertIsInstance(r, wf.WrapperFixedWidthFormatter)

    def test_dict_noop(self):
        ctx = self._make_context()
        r = wf.wrapper_formatter_factory(ctx, 'f', {})
        self.assertIsInstance(r, wf.WrapperFormatter)

    def test_unknown_raises(self):
        ctx = self._make_context()
        self.assertRaises(Exception,  # noqa: H202
                          wf.wrapper_formatter_factory,
                          ctx,
                          'f',
                          [1, 2])


class TestWrapperWithCustomFormatter(unittest.TestCase):
    def test_setattr_propagation(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(2)
        ctx.terminal_width = 80
        inner = wf.WrapperFixedWidthFormatter(ctx, 'f', 20)
        w = wf.WrapperWithCustomFormatter(
            ctx,
            'f',
            lambda d: str(d),
            inner
        )
        w.no_wrap = True
        self.assertTrue(inner.no_wrap)
        w.add_blank_line = True
        self.assertTrue(inner.add_blank_line)
        w.header_width = 15
        self.assertEqual(inner.header_width, 15)

    def test_set_min_width(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(2)
        ctx.terminal_width = 80
        inner = wf.WrapperFixedWidthFormatter(ctx, 'f', 20)
        w = wf.WrapperWithCustomFormatter(
            ctx,
            'f',
            lambda d: str(d),
            inner
        )
        w.set_min_width(25)
        self.assertEqual(inner.min_width, 25)

    def test_set_actual_column_len(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(2)
        ctx.terminal_width = 80
        inner = wf.WrapperFixedWidthFormatter(ctx, 'f', 20)
        w = wf.WrapperWithCustomFormatter(
            ctx,
            'f',
            lambda d: str(d),
            inner
        )
        w.set_actual_column_len(30)
        self.assertEqual(inner.actual_column_char_len, 30)

    def test_get_unwrapped(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(2)
        ctx.terminal_width = 80
        inner = wf.WrapperFixedWidthFormatter(ctx, 'f', 20)
        w = wf.WrapperWithCustomFormatter(
            ctx,
            'f',
            lambda d: d.upper(),
            inner
        )
        self.assertEqual(w.get_unwrapped_field_value('hello'), 'HELLO')

    def test_get_basic_desired_width(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(2)
        ctx.terminal_width = 80
        inner = wf.WrapperFixedWidthFormatter(ctx, 'f', 20)
        w = wf.WrapperWithCustomFormatter(
            ctx,
            'f',
            lambda d: str(d),
            inner
        )
        self.assertEqual(w.get_basic_desired_width(), 20)


class TestFieldValueFunctionFactory(unittest.TestCase):
    def test_dict_data(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(1)
        w = wf.WrapperFormatter(ctx, 'name')
        r = w.get_field_value({'name': 'test'})
        self.assertEqual(r, 'test')

    def test_obj_data(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(1)
        w = wf.WrapperFormatter(ctx, 'name')

        class Obj:
            name = 'hello'
        r = w.get_field_value(Obj())
        self.assertEqual(r, 'hello')


class TestBuildColumnStats(unittest.TestCase):
    def test_basic(self):

        class FakeObj:
            def __init__(self, **kwargs):
                for key, val in kwargs.items():
                    setattr(self, key, val)

        objs = (
            [FakeObj(name='short'), FakeObj(name='a longer name here')]
        )
        r = wf.build_column_stats_for_best_guess_formatting(
            objs, ['name'], ['Name'])
        self.assertIsNotNone(r)


class TestSetNoWrapOnFormatters(unittest.TestCase):
    def test_with_wrapper_formatters(self):
        ctx = wf.WrapperContext()
        ctx.set_num_columns(1)
        ctx.terminal_width = 80
        wf.WrapperFormatter(ctx, 'f')
        fmt = wf.WrapperLambdaFormatter(ctx, 'f', lambda d: str(d))
        formatters = {'f': fmt}
        orig = wf.set_no_wrap_on_formatters(True, formatters)
        self.assertIsNotNone(orig)
        wf.unset_no_wrap_on_formatters(orig)


if __name__ == '__main__':
    unittest.main()
