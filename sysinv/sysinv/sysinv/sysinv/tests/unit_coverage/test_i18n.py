#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for sysinv._i18n module."""

import unittest
from sysinv import _i18n


class TestI18n(unittest.TestCase):
    def test_domain(self):
        self.assertEqual(_i18n.DOMAIN, "sysinv")

    def test_primary_translator(self):
        result = _i18n._("test string")
        self.assertIsInstance(result, str)

    def test_get_available_languages(self):
        langs = _i18n.get_available_languages()
        self.assertIsInstance(langs, list)


if __name__ == "__main__":
    unittest.main()
