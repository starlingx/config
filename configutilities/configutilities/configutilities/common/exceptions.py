#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


class ConfigError(Exception):
    """Base class for configuration exceptions."""

    def __init__(self, message=None):
        self.message = message

    def __str__(self):
        return self.message or ""


class ConfigFail(ConfigError):
    """General configuration error."""
    pass


class ValidateFail(ConfigError):
    """Validation of data failed."""
    pass
