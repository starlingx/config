#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for sysinv.netconf module."""

import socket
import unittest
from unittest import mock

from sysinv import netconf


class TestGetMyIp(unittest.TestCase):
    @mock.patch('socket.socket')
    def test_get_my_ip_success(self, mock_socket):
        mock_sock = mock.MagicMock()
        mock_sock.getsockname.return_value = ('10.0.0.1', 12345)
        mock_socket.return_value = mock_sock
        result = netconf._get_my_ip()
        self.assertEqual(result, '10.0.0.1')

    @mock.patch('socket.socket', side_effect=socket.error("no network"))
    def test_get_my_ip_fallback(self, mock_socket):
        result = netconf._get_my_ip()
        self.assertEqual(result, '127.0.0.1')


class TestNetconfOpts(unittest.TestCase):
    def test_netconf_opts_exist(self):
        self.assertIsInstance(netconf.netconf_opts, list)
        self.assertGreater(len(netconf.netconf_opts), 0)

    def test_my_ip_opt(self):
        names = [o.name for o in netconf.netconf_opts]
        self.assertIn('my_ip', names)

    def test_use_ipv6_opt(self):
        names = [o.name for o in netconf.netconf_opts]
        self.assertIn('use_ipv6', names)


if __name__ == "__main__":
    unittest.main()
