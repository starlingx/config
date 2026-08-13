#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Root conftest for sysinv unit_coverage tests.

Mocks system dependencies that are unavailable in the test environment:
- fm_core, rpm: C-extension modules not installed outside STX
- pwd/grp lookup: sysinv user/group don't exist on dev machines;
  check_lock_path() in sysinv.common.utils calls pwd.getpwnam('sysinv')
  at import time via the @synchronized decorator on API controllers.
"""
import pwd
import sys
import unittest.mock as mock

sys.modules.setdefault('fm_core', mock.MagicMock())
sys.modules.setdefault('rpm', mock.MagicMock())

# Patch pwd.getpwnam/grp.getgrnam so check_lock_path() doesn't crash
# when the 'sysinv' user/group doesn't exist in the test environment.
_real_getpwnam = pwd.getpwnam


def _safe_getpwnam(name):
    try:
        return _real_getpwnam(name)
    except KeyError:
        pw = mock.MagicMock()
        pw.pw_uid = 1000
        pw.pw_gid = 1000
        return pw


mock.patch('pwd.getpwnam', side_effect=_safe_getpwnam).start()
mock.patch('grp.getgrnam', return_value=mock.MagicMock(gr_gid=1000)).start()
