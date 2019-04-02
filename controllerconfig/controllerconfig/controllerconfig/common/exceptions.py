#
# Copyright (c) 2014-2019 Wind River Systems, Inc.
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


class ConfigFail(ConfigError):
    """General configuration error."""
    pass


class ValidateFail(ConfigError):
    """Validation of data failed."""
    pass


class BackupFail(ConfigError):
    """Backup error."""
    pass


class UpgradeFail(ConfigError):
    """Upgrade error."""
    pass


class BackupWarn(ConfigError):
    """Backup warning."""
    pass


class RestoreFail(ConfigError):
    """Backup error."""
    pass


class KeystoneFail(ConfigError):
    """Keystone error."""
    pass


class SysInvFail(ConfigError):
    """System Inventory error."""
    pass


class UserQuit(ConfigError):
    """User initiated quit operation."""
    pass


class CloneFail(ConfigError):
    """Clone error."""
    pass


class TidyStorageFail(ConfigError):
    """Tidy storage error."""
    pass
