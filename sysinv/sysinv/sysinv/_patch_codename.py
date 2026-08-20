#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Patch get_debian_codename for test environments.

Reads the actual codename from /etc/os-release so tests
work on both bullseye and trixie.
"""
import functools
import sysinv.common.utils as _u


def _read_codename():
    """Read Debian codename from /etc/os-release."""
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("VERSION_CODENAME="):
                    return line.strip().split("=")[1]
    except FileNotFoundError:
        pass
    return "bullseye"


_u.get_debian_codename.cache_clear()
_u.get_debian_codename = (
    functools.lru_cache(maxsize=None)(_read_codename)
)
