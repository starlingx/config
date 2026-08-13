#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for controllerconfig.common.exceptions module."""

import unittest

from controllerconfig.common.exceptions import ConfigError
from controllerconfig.common.exceptions import KeystoneFail
from controllerconfig.common.exceptions import TidyStorageFail
from controllerconfig.common.exceptions import UpgradeFail
from controllerconfig.common.exceptions import ValidateFail


class TestConfigError(unittest.TestCase):
    """Tests for ConfigError exception class."""

    def test_config_error_with_message(self):
        """ConfigError stores and returns its message."""
        err = ConfigError("test error")
        self.assertEqual(str(err), "test error")
        self.assertEqual(err.message, "test error")

    def test_config_error_no_message(self):
        """ConfigError with no message returns empty string."""
        err = ConfigError()
        self.assertEqual(str(err), "")
        self.assertIsNone(err.message)

    def test_config_error_is_exception(self):
        """ConfigError inherits from Exception."""
        self.assertTrue(issubclass(ConfigError, Exception))

    def test_config_error_raise_catch(self):
        """ConfigError can be raised and caught."""
        with self.assertRaises(ConfigError):
            raise ConfigError("boom")


class TestValidateFail(unittest.TestCase):
    """Tests for ValidateFail exception class."""

    def test_validate_fail_inherits_config_error(self):
        """ValidateFail is a subclass of ConfigError."""
        self.assertTrue(issubclass(ValidateFail, ConfigError))

    def test_validate_fail_message(self):
        """ValidateFail stores its message."""
        err = ValidateFail("bad input")
        self.assertEqual(str(err), "bad input")

    def test_validate_fail_caught_as_config_error(self):
        """ValidateFail can be caught as ConfigError."""
        with self.assertRaises(ConfigError):
            raise ValidateFail("validation failed")


class TestUpgradeFail(unittest.TestCase):
    """Tests for UpgradeFail exception class."""

    def test_upgrade_fail_inherits_config_error(self):
        """UpgradeFail is a subclass of ConfigError."""
        self.assertTrue(issubclass(UpgradeFail, ConfigError))

    def test_upgrade_fail_message(self):
        """UpgradeFail stores its message."""
        err = UpgradeFail("upgrade broken")
        self.assertEqual(str(err), "upgrade broken")


class TestKeystoneFail(unittest.TestCase):
    """Tests for KeystoneFail exception class."""

    def test_keystone_fail_inherits_config_error(self):
        """KeystoneFail is a subclass of ConfigError."""
        self.assertTrue(issubclass(KeystoneFail, ConfigError))

    def test_keystone_fail_message(self):
        """KeystoneFail stores its message."""
        err = KeystoneFail("auth failed")
        self.assertEqual(str(err), "auth failed")


class TestTidyStorageFail(unittest.TestCase):
    """Tests for TidyStorageFail exception class."""

    def test_tidy_storage_fail_inherits_config_error(self):
        """TidyStorageFail is a subclass of ConfigError."""
        self.assertTrue(issubclass(TidyStorageFail, ConfigError))

    def test_tidy_storage_fail_message(self):
        """TidyStorageFail stores its message."""
        err = TidyStorageFail("storage error")
        self.assertEqual(str(err), "storage error")


if __name__ == "__main__":
    unittest.main()
