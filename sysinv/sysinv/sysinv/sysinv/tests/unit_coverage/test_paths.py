#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for sysinv.common.paths module."""

import os
import unittest
from sysinv.common import paths


class TestPaths(unittest.TestCase):
    def test_basedir_def(self):
        result = paths.basedir_def("sub", "dir")
        self.assertTrue(result.startswith("$pybasedir"))
        self.assertIn("sub", result)

    def test_bindir_def(self):
        result = paths.bindir_def("script")
        self.assertTrue(result.startswith("$bindir"))

    def test_state_path_def(self):
        result = paths.state_path_def("data")
        self.assertTrue(result.startswith("$state_path"))

    def test_basedir_rel(self):
        result = paths.basedir_rel("sub")
        self.assertTrue(os.path.isabs(result) or "$" in result)

    def test_bindir_rel(self):
        result = paths.bindir_rel("script")
        self.assertIsInstance(result, str)

    def test_state_path_rel(self):
        result = paths.state_path_rel("data")
        self.assertIsInstance(result, str)


if __name__ == "__main__":
    unittest.main()
