#
# Copyright (c) 2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Configuration Errors
"""

from configutilities import ConfigError


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
