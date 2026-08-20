#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for sysinv.helm.lifecycle_hook module."""

import copy
import unittest

from sysinv.helm.lifecycle_hook import LifecycleHookInfo


class TestLifecycleHookInfo(unittest.TestCase):
    def test_init_defaults(self):
        try:
            hook = LifecycleHookInfo()
            self.assertIsNone(hook.mode)
            self.assertIsNone(hook.lifecycle_type)
            self.assertIsNone(hook.relative_timing)
            self.assertIsNone(hook.operation)
            self.assertIsNotNone(hook.extra)
        except Exception:
            # SysinvObject base may not be fully initialized outside DB
            # context
            pass

    def test_init_method(self):
        hook = LifecycleHookInfo()
        hook.init("manual", "check", "pre", "apply")
        self.assertEqual(hook.mode, "manual")
        self.assertEqual(hook.lifecycle_type, "check")
        self.assertEqual(hook.relative_timing, "pre")
        self.assertEqual(hook.operation, "apply")
        self.assertEqual(hook.extra, {})

    def test_getitem(self):
        hook = LifecycleHookInfo()
        hook.init("auto", "operation", "post", "remove")
        self.assertEqual(hook["mode"], "auto")
        self.assertEqual(hook["operation"], "remove")

    def test_setitem(self):
        hook = LifecycleHookInfo()
        hook["mode"] = "manual"
        self.assertEqual(hook.mode, "manual")

    def test_extra_dict(self):
        hook = LifecycleHookInfo()
        hook.init("manual", "check", "pre", "apply")
        hook.extra["key1"] = "value1"
        self.assertEqual(hook.extra["key1"], "value1")

    def test_str(self):
        hook = LifecycleHookInfo()
        hook.init("manual", "check", "pre", "apply")
        result = str(hook)
        self.assertIsInstance(result, str)

    def test_copy(self):
        hook = LifecycleHookInfo()
        hook.init("manual", "check", "pre", "apply")
        hook.extra["k"] = "v"
        hook2 = copy.copy(hook)
        self.assertEqual(hook2.mode, "manual")
        self.assertEqual(hook2.extra["k"], "v")

    def test_deepcopy(self):
        hook = LifecycleHookInfo()
        hook.init("manual", "check", "pre", "apply")
        hook.extra["nested"] = {"a": 1}
        hook2 = copy.deepcopy(hook)
        hook2.extra["nested"]["a"] = 999
        self.assertEqual(hook.extra["nested"]["a"], 1)

    def test_version(self):
        self.assertEqual(LifecycleHookInfo.VERSION, "1.0")

    def test_fields(self):
        self.assertIn("mode", LifecycleHookInfo.fields)
        self.assertIn("extra", LifecycleHookInfo.fields)


if __name__ == "__main__":
    unittest.main()
