#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for sysinv.common.configp module."""

import os
import tempfile
import unittest

from sysinv.common import configp


class TestConfig(unittest.TestCase):
    def test_as_dict_empty(self):
        cfg = configp.Config()
        self.assertEqual(cfg.as_dict(), {})

    def test_as_dict_with_sections(self):
        cfg = configp.Config()
        cfg.add_section("sec1")
        cfg.set("sec1", "key1", "val1")
        cfg.add_section("sec2")
        cfg.set("sec2", "key2", "val2")
        result = cfg.as_dict()
        self.assertIn("sec1", result)
        self.assertIn("sec2", result)
        self.assertEqual(result["sec1"]["key1"], "val1")
        self.assertEqual(result["sec2"]["key2"], "val2")

    def test_as_dict_no_name_key(self):
        cfg = configp.Config()
        cfg.add_section("sec")
        cfg.set("sec", "k", "v")
        result = cfg.as_dict()
        self.assertNotIn("__name__", result["sec"])


class TestLoad(unittest.TestCase):
    def setUp(self):
        configp.CONFP = dict()

    def test_load_populates_confp(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        ) as f:
            f.write("[DEFAULT]\n")
            f.write("[section1]\n")
            f.write("option1 = value1\n")
            tmp_path = f.name
        try:
            configp.load(tmp_path)
            self.assertIn("section1", configp.CONFP)
            self.assertEqual(configp.CONFP["section1"]["option1"],
                             "value1")
        finally:
            os.unlink(tmp_path)

    def test_load_skips_if_already_loaded(self):
        configp.CONFP = {"existing": {"k": "v"}}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        ) as f:
            f.write("[newsection]\noption = val\n")
            tmp_path = f.name
        try:
            configp.load(tmp_path)
            self.assertNotIn("newsection", configp.CONFP)
            self.assertIn("existing", configp.CONFP)
        finally:
            os.unlink(tmp_path)

    def tearDown(self):
        configp.CONFP = dict()


if __name__ == "__main__":
    unittest.main()
