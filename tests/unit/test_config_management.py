#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for controllerconfig.config_management module."""

import unittest
from unittest import mock

import netaddr

from controllerconfig import config_management


class TestIsValidManagementAddress(unittest.TestCase):
    """Tests for is_valid_management_address function."""

    def _subnet(self, cidr="192.168.1.0/24"):
        return netaddr.IPNetwork(cidr)

    def test_valid_address(self):
        """Valid address in subnet returns True."""
        subnet = self._subnet()
        ip = netaddr.IPAddress("192.168.1.10")
        self.assertTrue(
            config_management.is_valid_management_address(ip, subnet)
        )

    def test_network_address_rejected(self):
        """Network address returns False."""
        subnet = self._subnet()
        ip = subnet.network
        self.assertFalse(
            config_management.is_valid_management_address(ip, subnet)
        )

    def test_broadcast_address_rejected(self):
        """Broadcast address returns False for IPv4."""
        subnet = self._subnet()
        ip = subnet.broadcast
        self.assertFalse(
            config_management.is_valid_management_address(ip, subnet)
        )

    def test_multicast_address_rejected(self):
        """Multicast address returns False."""
        subnet = self._subnet()
        ip = netaddr.IPAddress("239.0.0.1")
        self.assertFalse(
            config_management.is_valid_management_address(ip, subnet)
        )

    def test_loopback_address_rejected(self):
        """Loopback address returns False."""
        subnet = self._subnet()
        ip = netaddr.IPAddress("127.0.0.1")
        self.assertFalse(
            config_management.is_valid_management_address(ip, subnet)
        )

    def test_address_outside_subnet_rejected(self):
        """Address outside subnet returns False."""
        subnet = self._subnet()
        ip = netaddr.IPAddress("10.0.0.1")
        self.assertFalse(
            config_management.is_valid_management_address(ip, subnet)
        )

    def test_ipv6_valid_address(self):
        """Valid IPv6 address in subnet returns True."""
        subnet = netaddr.IPNetwork("fd00::/64")
        ip = netaddr.IPAddress("fd00::10")
        self.assertTrue(
            config_management.is_valid_management_address(ip, subnet)
        )


class TestConfigManagementMain(unittest.TestCase):
    """Tests for config_management.main function."""

    @mock.patch.object(config_management, "configure_management")
    @mock.patch("os.geteuid", return_value=1000)
    def test_main_non_root_exits(self, mock_euid, mock_configure):
        """main exits when not running as root."""
        with self.assertRaises(SystemExit):
            config_management.main()
        mock_configure.assert_not_called()


if __name__ == "__main__":
    unittest.main()
