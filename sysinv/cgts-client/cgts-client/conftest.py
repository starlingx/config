#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Root conftest — patch is_debian_bullseye for prettytable compat."""
import inspect
import prettytable
from unittest.mock import patch

# Detect installed prettytable signature to pick the right code path
_nparams = len(
    inspect.signature(prettytable.PrettyTable._stringify_row).parameters
)
_is_bullseye_sig = (_nparams == 3)  # self, row, options

# If the prettytable has the bullseye signature, force
# is_debian_bullseye=True
# so the application code uses the matching 2-arg call.
if _is_bullseye_sig:
    _patcher = patch(
        'cgtsclient.common.utils.is_debian_bullseye',
        return_value=True
    )
    _patcher.start()
