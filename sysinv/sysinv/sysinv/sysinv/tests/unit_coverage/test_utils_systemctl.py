#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for sysinv.common.utils uncovered functions."""
import sys
import unittest
from unittest import mock

for _m in ['fm_core', 'rpm']:
    sys.modules.setdefault(_m, mock.MagicMock())

from sysinv.common import utils
from sysinv.common import exception


class TestSystemctlFunctions(unittest.TestCase):
    @mock.patch.object(utils, 'execute')
    def test_systemctl_is_active(self, mock_exec):
        mock_exec.return_value = ('active\n', '')
        self.assertTrue(utils.systemctl_is_active_service('svc'))

    @mock.patch.object(utils, 'execute')
    def test_systemctl_is_active_false(self, mock_exec):
        mock_exec.side_effect = exception.ProcessExecutionError()
        self.assertFalse(utils.systemctl_is_active_service('svc'))

    @mock.patch.object(utils, 'execute')
    def test_systemctl_is_active_exception(self, mock_exec):
        mock_exec.side_effect = exception.SysinvException()
        self.assertRaises(exception.SysinvException,
                          utils.systemctl_is_active_service, 'svc')

    @mock.patch.object(utils, 'execute')
    def test_systemctl_is_enabled(self, mock_exec):
        mock_exec.return_value = ('enabled\n', '')
        self.assertTrue(utils.systemctl_is_enabled_service('svc'))

    @mock.patch.object(utils, 'execute')
    def test_systemctl_is_enabled_false(self, mock_exec):
        mock_exec.side_effect = exception.ProcessExecutionError()
        self.assertFalse(utils.systemctl_is_enabled_service('svc'))

    @mock.patch.object(utils, 'execute')
    def test_systemctl_is_enabled_exception(self, mock_exec):
        mock_exec.side_effect = exception.SysinvException()
        self.assertRaises(exception.SysinvException,
                          utils.systemctl_is_enabled_service, 'svc')


class TestMiscUtils(unittest.TestCase):
    def test_is_valid_mac(self):
        self.assertTrue(utils.is_valid_mac('aa:bb:cc:dd:ee:ff'))
        self.assertFalse(utils.is_valid_mac('invalid'))

    def test_is_valid_ip(self):
        self.assertTrue(utils.is_valid_ip('10.0.0.1'))
        self.assertTrue(utils.is_valid_ip('::1'))
        self.assertFalse(utils.is_valid_ip('not-an-ip'))

    def test_is_valid_ipv4(self):
        self.assertTrue(utils.is_valid_ipv4('10.0.0.1'))
        self.assertFalse(utils.is_valid_ipv4('::1'))

    def test_is_valid_ipv6(self):
        self.assertTrue(utils.is_valid_ipv6('::1'))
        self.assertFalse(utils.is_valid_ipv6('10.0.0.1'))

    def test_is_valid_boolstr(self):
        self.assertTrue(utils.is_valid_boolstr('true'))
        self.assertTrue(utils.is_valid_boolstr('false'))
        self.assertFalse(utils.is_valid_boolstr('maybe'))

    def test_is_int_like(self):
        self.assertTrue(utils.is_int_like('42'))
        self.assertTrue(utils.is_int_like(42))
        self.assertFalse(utils.is_int_like('abc'))

    def test_format_url_address(self):
        self.assertEqual(utils.format_url_address('10.0.0.1'),
                         '10.0.0.1')
        self.assertEqual(utils.format_url_address('::1'), '[::1]')

    def test_bytes_to_GiB(self):
        self.assertEqual(utils.bytes_to_GiB(1073741824), 1.0)

    def test_bytes_to_MiB(self):
        self.assertEqual(utils.bytes_to_MiB(1048576), 1.0)


if __name__ == '__main__':
    unittest.main()
