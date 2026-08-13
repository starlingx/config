#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Extended coverage tests for config_management module."""

import json
import unittest
from unittest import mock

import netaddr

from controllerconfig import config_management


class TestConfigureManagement(unittest.TestCase):
    """Tests for configure_management function."""

    @mock.patch("time.sleep")
    @mock.patch("sys.stdout")
    @mock.patch("subprocess.call")
    @mock.patch("subprocess.check_output")
    @mock.patch("controllerconfig.config_management.input")
    def test_configure_management_flow(self, mock_input,
                                       mock_check_output, mock_call,
                                       mock_stdout, mock_sleep):
        """configure_management runs the full configuration flow."""
        ip_output = (
            "1: lo: <LOOPBACK> mtu 65536\n"
            "2: eth0: <BROADCAST> mtu 1500\n"
        )
        lldp_output = json.dumps({
            "lldp": [{"interface": [
                {"name": "eth0", "port": [{"id": [{"value": "port1"}]}]}
            ]}]
        })
        mock_check_output.side_effect = [ip_output, lldp_output]
        mock_input.side_effect = [
            "eth0", "192.168.1.10/24", "", "192.168.100.0/24",
        ]
        config_management.configure_management()
        self.assertTrue(mock_call.call_count > 0)


class TestIsValidManagementAddressExtended(unittest.TestCase):
    """Extended tests for is_valid_management_address."""

    def test_valid_last_address(self):
        """Last usable address in subnet is valid."""
        subnet = netaddr.IPNetwork("192.168.1.0/24")
        ip = netaddr.IPAddress("192.168.1.254")
        self.assertTrue(
            config_management.is_valid_management_address(ip, subnet)
        )

    def test_first_usable_address(self):
        """First usable address in subnet is valid."""
        subnet = netaddr.IPNetwork("192.168.1.0/24")
        ip = netaddr.IPAddress("192.168.1.1")
        self.assertTrue(
            config_management.is_valid_management_address(ip, subnet)
        )


if __name__ == "__main__":
    unittest.main()
