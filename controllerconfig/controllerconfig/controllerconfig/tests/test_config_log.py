#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for controllerconfig.common.log module."""

import logging
import unittest
from unittest import mock

from controllerconfig.common import log


class TestGetLogger(unittest.TestCase):
    """Tests for get_logger function."""

    def setUp(self):
        # Clear the internal logger cache before each test
        log._loggers.clear()

    def test_get_logger_creates_new(self):
        """get_logger creates a new logger for unknown name."""
        logger = log.get_logger("test_new")
        self.assertIsInstance(logger, logging.Logger)

    def test_get_logger_returns_same(self):
        """get_logger returns the same logger for the same name."""
        logger1 = log.get_logger("test_same")
        logger2 = log.get_logger("test_same")
        self.assertIs(logger1, logger2)

    def test_get_logger_different_names(self):
        """get_logger returns different loggers for different names."""
        logger1 = log.get_logger("name_a")
        logger2 = log.get_logger("name_b")
        self.assertIsNot(logger1, logger2)


class TestSetupLogger(unittest.TestCase):
    """Tests for setup_logger function."""

    def test_setup_logger_adds_handler(self):
        """setup_logger adds a SysLogHandler to the logger."""
        logger = logging.getLogger("test_setup")
        initial_count = len(logger.handlers)
        with mock.patch(
            "logging.handlers.SysLogHandler.__init__", return_value=None
        ):
            with mock.patch(
                "logging.handlers.SysLogHandler.setLevel"
            ):
                with mock.patch(
                    "logging.handlers.SysLogHandler.setFormatter"
                ):
                    log.setup_logger(logger)
        self.assertGreater(len(logger.handlers), initial_count)

    def test_setup_logger_sets_info_level(self):
        """setup_logger sets logger level to INFO."""
        logger = logging.getLogger("test_level")
        with mock.patch(
            "logging.handlers.SysLogHandler.__init__", return_value=None
        ):
            with mock.patch(
                "logging.handlers.SysLogHandler.setLevel"
            ):
                with mock.patch(
                    "logging.handlers.SysLogHandler.setFormatter"
                ):
                    log.setup_logger(logger)
        self.assertEqual(logger.level, logging.INFO)


class TestConfigure(unittest.TestCase):
    """Tests for configure function."""

    def test_configure_calls_setup_for_all_loggers(self):
        """configure calls setup_logger for each registered logger."""
        log._loggers.clear()
        log.get_logger("conf_a")
        log.get_logger("conf_b")
        with mock.patch.object(log, "setup_logger") as mock_setup:
            log.configure()
        self.assertEqual(mock_setup.call_count, 2)


if __name__ == "__main__":
    unittest.main()
