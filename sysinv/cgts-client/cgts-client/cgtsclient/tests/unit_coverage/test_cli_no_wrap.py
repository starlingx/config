#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for cgtsclient.common.cli_no_wrap module."""

import unittest

from cgtsclient.common import cli_no_wrap


class TestCliNoWrap(unittest.TestCase):
    """Tests for cli_no_wrap module."""

    def setUp(self):
        cli_no_wrap._no_wrap[0] = False

    def test_is_nowrap_set_default_false(self):
        self.assertFalse(cli_no_wrap.is_nowrap_set())

    def test_is_nowrap_set_explicit_true(self):
        self.assertTrue(cli_no_wrap.is_nowrap_set(no_wrap=True))

    def test_is_nowrap_set_explicit_false(self):
        self.assertFalse(cli_no_wrap.is_nowrap_set(no_wrap=False))

    def test_is_nowrap_set_reads_global(self):
        cli_no_wrap._no_wrap[0] = True
        self.assertTrue(cli_no_wrap.is_nowrap_set())

    def test_set_no_wrap_true(self):
        result = cli_no_wrap.set_no_wrap(True)
        self.assertTrue(result)
        self.assertTrue(cli_no_wrap._no_wrap[0])

    def test_set_no_wrap_false(self):
        cli_no_wrap._no_wrap[0] = True
        result = cli_no_wrap.set_no_wrap(False)
        self.assertFalse(result)
        self.assertFalse(cli_no_wrap._no_wrap[0])

    def test_set_no_wrap_none_no_change(self):
        cli_no_wrap._no_wrap[0] = True
        result = cli_no_wrap.set_no_wrap(None)
        self.assertTrue(result)
        self.assertTrue(cli_no_wrap._no_wrap[0])


if __name__ == "__main__":
    unittest.main()
