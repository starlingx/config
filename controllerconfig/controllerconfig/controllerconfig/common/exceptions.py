#
# Copyright (c) 2014-2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Configuration Errors
"""


class ConfigError(Exception):
    """Base class for configuration exceptions."""

    def __init__(self, message=None):
        self.message = message
        super(ConfigError, self).__init__(message)

    def __str__(self):
        return self.message or ""


class ValidateFail(ConfigError):
    """Validation of data failed."""
    pass


class UpgradeFail(ConfigError):
    """Upgrade error."""
    pass


class KeystoneFail(ConfigError):
    """Keystone error."""
    pass


class TidyStorageFail(ConfigError):
    """Tidy storage error."""
    pass
