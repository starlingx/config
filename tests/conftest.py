#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Shared test fixtures and configuration for config project tests."""

import os
import tempfile

import pytest


@pytest.fixture()
def tmp_dir():
    """Provide a temporary directory that is cleaned up after the test.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture()
def fake_platform_dir(tmp_dir):
    """Create a fake /etc/platform structure for testing."""
    platform_dir = os.path.join(tmp_dir, "etc", "platform")
    os.makedirs(platform_dir, exist_ok=True)
    return platform_dir
