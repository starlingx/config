#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for controllerconfig.common.usm_log module."""

import logging
import os
import tempfile
import unittest
from unittest import mock

from controllerconfig.common import usm_log


class TestConfigureLogging(unittest.TestCase):
    """Tests for configure_logging function."""

    @mock.patch.object(usm_log, "read_log_config")
    def test_configure_logging_sets_level(self, mock_read):
        """configure_logging sets the log level."""
        usm_log.logging_default_format_string = "%(message)s"
        with tempfile.NamedTemporaryFile(suffix=".log",
                                         delete=False
                                         ) as f:
            fname = f.name
        try:
            usm_log.configure_logging(
                filename=fname, log_level=logging.DEBUG
            )
            self.assertEqual(usm_log.LOG.level, logging.DEBUG)
        finally:
            os.unlink(fname)


class TestReadLogConfig(unittest.TestCase):
    """Tests for read_log_config function."""

    def test_read_log_config_reads_conf(self):
        """read_log_config reads the software.conf file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        ) as f:
            f.write("[DEFAULT]\n")
            f.write("logging_default_format_string = %(message)s\n")
            fname = f.name
        try:
            original_conf = usm_log.software_conf
            usm_log.software_conf = fname
            usm_log.software_conf_mtime = 0
            usm_log.read_log_config()
            self.assertEqual(
                usm_log.logging_default_format_string, "%(message)s"
            )
        finally:
            usm_log.software_conf = original_conf
            os.unlink(fname)

    def test_read_log_config_uses_fallback(self):
        """read_log_config uses fallback when key missing."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        ) as f:
            f.write("[DEFAULT]\n")
            fname = f.name
        try:
            original_conf = usm_log.software_conf
            usm_log.software_conf = fname
            usm_log.software_conf_mtime = 0
            usm_log.read_log_config()
            from controllerconfig.common import constants
            self.assertEqual(
                usm_log.logging_default_format_string,
                constants.LOG_DEFAULT_FORMAT,
            )
        finally:
            usm_log.software_conf = original_conf
            os.unlink(fname)

    def test_read_log_config_skips_unchanged(self):
        """read_log_config skips re-read if mtime unchanged."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        ) as f:
            f.write("[DEFAULT]\n")
            fname = f.name
        try:
            original_conf = usm_log.software_conf
            usm_log.software_conf = fname
            mtime = os.stat(fname).st_mtime
            usm_log.software_conf_mtime = mtime
            old_fmt = usm_log.logging_default_format_string
            usm_log.read_log_config()
            # Should not change since mtime matches
            self.assertEqual(
                usm_log.logging_default_format_string, old_fmt
            )
        finally:
            usm_log.software_conf = original_conf
            os.unlink(fname)


if __name__ == "__main__":
    unittest.main()
