#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for sysinv.version module."""

import unittest
from sysinv import version


class TestVersion(unittest.TestCase):
    def test_sysinv_version_list(self):
        self.assertIsInstance(version.SYSINV_VERSION, list)
        self.assertEqual(len(version.SYSINV_VERSION), 2)

    def test_year_and_count(self):
        self.assertEqual(version.YEAR, version.SYSINV_VERSION[0])
        self.assertEqual(version.COUNT, version.SYSINV_VERSION[1])

    def test_canonical_version_string(self):
        result = version.canonical_version_string()
        self.assertIn(".", result)
        self.assertEqual(result,
                         "%s.%s" % (version.YEAR, version.COUNT))

    def test_version_string_dev(self):
        if not version.FINAL:
            result = version.version_string()
            self.assertIn("-dev", result)

    def test_vcs_version_string(self):
        result = version.vcs_version_string()
        self.assertIn(":", result)

    def test_version_string_with_vcs(self):
        result = version.version_string_with_vcs()
        self.assertIn("-", result)


if __name__ == "__main__":
    unittest.main()
