#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for sysinv.common.exception module."""

import unittest
from sysinv.common import exception


class TestProcessExecutionError(unittest.TestCase):
    def test_basic_creation(self):
        e = exception.ProcessExecutionError(
            stdout="out", stderr="err", exit_code=1, cmd="ls"
        )
        self.assertEqual(e.exit_code, 1)
        self.assertEqual(e.stdout, "out")
        self.assertEqual(e.stderr, "err")
        self.assertEqual(e.cmd, "ls")

    def test_default_description(self):
        e = exception.ProcessExecutionError()
        self.assertIn("Unexpected error", str(e))

    def test_custom_description(self):
        e = exception.ProcessExecutionError(description="custom error")
        self.assertIn("custom error", str(e))

    def test_default_exit_code_dash(self):
        e = exception.ProcessExecutionError()
        self.assertIn("-", str(e))

    def test_inherits_ioerror(self):
        self.assertTrue(
            issubclass(exception.ProcessExecutionError, IOError)
        )


class TestCleanseDict(unittest.TestCase):
    def test_removes_pass_keys(self):
        d = {
            "user": "admin",
            "admin_pass": "secret",
            "new_pass": "s3cret"
        }
        result = exception._cleanse_dict(d)
        self.assertIn("user", result)
        self.assertNotIn("admin_pass", result)
        self.assertNotIn("new_pass", result)

    def test_keeps_non_pass_keys(self):
        d = {"name": "test", "value": 42}
        result = exception._cleanse_dict(d)
        self.assertEqual(result, d)

    def test_empty_dict(self):
        self.assertEqual(exception._cleanse_dict({}), {})


class TestSysinvException(unittest.TestCase):
    def test_default_message(self):
        e = exception.SysinvException()
        self.assertIn("unknown exception", str(e).lower())

    def test_custom_message_string(self):
        e = exception.SysinvException(message="custom error")
        self.assertIn("custom error", str(e))

    def test_default_code(self):
        e = exception.SysinvException()
        self.assertEqual(e.code, 500)

    def test_inherits_exception(self):
        self.assertTrue(
            issubclass(exception.SysinvException, Exception)
        )

    def test_subclass_with_format(self):
        """Subclass with printf-style message formatting."""
        class TestExc(exception.SysinvException):
            message = "Error on %(host)s"
        e = TestExc(host="controller-0")
        self.assertIn("controller-0", str(e))


if __name__ == "__main__":
    unittest.main()
