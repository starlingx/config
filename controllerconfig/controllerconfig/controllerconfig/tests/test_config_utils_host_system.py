#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Extended coverage tests for controllerconfig.utils module."""

import subprocess
import unittest
from unittest import mock

from controllerconfig.common.exceptions import ValidateFail
from controllerconfig import utils
import netaddr
import sys


class TestApplyManifest(unittest.TestCase):
    """Tests for apply_manifest function."""

    @mock.patch("subprocess.check_call")
    @mock.patch("builtins.open", mock.mock_open())
    def test_apply_manifest_success(self, mock_call):
        """apply_manifest calls puppet-manifest-apply.sh."""
        utils.apply_manifest("10.0.0.1", "controller", "manifest",
                             "/tmp/hieradata")
        mock_call.assert_called_once()
        args = mock_call.call_args[0][0]
        self.assertIn("/usr/local/bin/puppet-manifest-apply.sh",
                      args[0])

    @mock.patch("subprocess.check_call")
    @mock.patch("builtins.open", mock.mock_open())
    def test_apply_manifest_with_runtime(self, mock_call):
        """apply_manifest passes runtime filename."""
        utils.apply_manifest("10.0.0.1", "controller", "manifest",
                             "/tmp/hieradata",
                             runtime_filename="/tmp/runtime.yaml")
        args = mock_call.call_args[0][0]
        self.assertIn("/tmp/runtime.yaml", args)

    @mock.patch("subprocess.check_call",
                side_effect=subprocess.CalledProcessError(1, "puppet"))
    @mock.patch("builtins.open", mock.mock_open())
    def test_apply_manifest_failure(self, mock_call):
        """apply_manifest raises on failure."""
        with self.assertRaises(Exception) as ctx:  # noqa: H202
            utils.apply_manifest("10.0.0.1", "controller", "manifest",
                                 "/tmp/hieradata")
        self.assertIn("Failed to execute", str(ctx.exception))


class TestCreateSystemConfig(unittest.TestCase):
    """Tests for create_system_config function."""

    @mock.patch("subprocess.check_call")
    def test_create_system_config_success(self, mock_call):
        """create_system_config calls sysinv-puppet."""
        utils.create_system_config()
        args = mock_call.call_args[0][0]
        self.assertEqual(args[0], "/usr/bin/sysinv-puppet")
        self.assertEqual(args[1], "create-system-config")

    @mock.patch("subprocess.check_call",
                side_effect=subprocess.CalledProcessError(1, "sysinv"))
    def test_create_system_config_failure(self, mock_call):
        """create_system_config raises on failure."""
        with self.assertRaises(Exception) as ctx:  # noqa: H202
            utils.create_system_config()
        self.assertIn("Failed to update puppet", str(ctx.exception))


class TestCreateHostConfig(unittest.TestCase):
    """Tests for create_host_config function."""

    @mock.patch("subprocess.check_call")
    def test_create_host_config_no_hostname(self, mock_call):
        """create_host_config without hostname."""
        utils.create_host_config()
        args = mock_call.call_args[0][0]
        self.assertEqual(len(args), 3)

    @mock.patch("subprocess.check_call")
    def test_create_host_config_with_hostname(self, mock_call):
        """create_host_config with hostname appends it."""
        utils.create_host_config(hostname="controller-0")
        args = mock_call.call_args[0][0]
        self.assertEqual(args[-1], "controller-0")

    @mock.patch("subprocess.check_call",
                side_effect=subprocess.CalledProcessError(1, "sysinv"))
    def test_create_host_config_failure(self, mock_call):
        """create_host_config raises on failure."""
        with self.assertRaises(Exception) as ctx:  # noqa: H202
            utils.create_host_config()
        self.assertIn("Failed to update puppet", str(ctx.exception))


class TestWriteSimplexFlag(unittest.TestCase):
    """Tests for write_simplex_flag function."""

    @mock.patch(
        "builtins.open",
        side_effect=IOError("permission denied")
    )
    def test_write_simplex_flag_failure(self, mock_open):
        """write_simplex_flag raises on IOError."""
        with self.assertRaises(Exception) as ctx:  # noqa: H202
            utils.write_simplex_flag()
        self.assertIn("Failed to write", str(ctx.exception))


class TestGetAddressFromHostsFile(unittest.TestCase):
    """Tests for get_address_from_hosts_file function."""

    @mock.patch("builtins.open", mock.mock_open(
        read_data="10.0.0.1 controller-0\n10.0.0.2 controller-1\n"
    ))
    def test_get_address_found(self):
        """get_address_from_hosts_file returns IP for known host."""
        result = utils.get_address_from_hosts_file("controller-0")
        self.assertEqual(result, "10.0.0.1")

    @mock.patch("builtins.open", mock.mock_open(
        read_data="10.0.0.1 controller-0\n"
    ))
    def test_get_address_not_found(self):
        """get_address_from_hosts_file raises for unknown host."""
        with self.assertRaises(Exception) as ctx:  # noqa: H202
            utils.get_address_from_hosts_file("unknown-host")
        self.assertIn("not found", str(ctx.exception))


class TestPersistConfig(unittest.TestCase):
    """Tests for persist_config function."""

    @mock.patch("shutil.move", side_effect=IOError("move failed"))
    @mock.patch("os.path.isdir", return_value=True)
    def test_persist_config_keyring_failure(self,
                                            mock_isdir,
                                            mock_move
                                            ):
        """persist_config raises on keyring move failure."""
        with self.assertRaises(Exception) as ctx:  # noqa: H202
            utils.persist_config()
        self.assertIn("keyring", str(ctx.exception))


class TestMtceRestart(unittest.TestCase):
    """Tests for mtce_restart function."""

    @mock.patch.object(utils, "restart_service")
    def test_mtce_restart_calls_three_services(self, mock_restart):
        """mtce_restart restarts mtcClient, hbsClient, pmon."""
        utils.mtce_restart()
        self.assertEqual(mock_restart.call_count, 3)
        calls = [c[0][0] for c in mock_restart.call_args_list]
        self.assertIn("mtcClient", calls)
        self.assertIn("hbsClient", calls)
        self.assertIn("pmon", calls)


class TestMarkConfigComplete(unittest.TestCase):
    """Tests for mark_config_complete function."""

    @mock.patch("subprocess.check_call",
                side_effect=subprocess.CalledProcessError(1, "touch"))
    def test_mark_config_complete_failure(self, mock_check):
        """mark_config_complete raises on failure."""
        with self.assertRaises(Exception) as ctx:  # noqa: H202
            utils.mark_config_complete()
        self.assertIn("Failed to mark", str(ctx.exception))


class TestConfigureHostnameExtended(unittest.TestCase):
    """Extended tests for configure_hostname function."""

    @mock.patch("subprocess.check_call",
                side_effect=subprocess.CalledProcessError(
                    1,
                    "hostname")
                )
    @mock.patch("builtins.open", mock.mock_open())
    def test_configure_hostname_cmd_failure(self, mock_call):
        """configure_hostname raises when hostname command fails."""
        with self.assertRaises(Exception) as ctx:  # noqa: H202
            utils.configure_hostname("testhost")
        self.assertIn("Failed to configure", str(ctx.exception))

    @mock.patch(
        "builtins.open",
        side_effect=IOError("permission denied")
    )
    def test_configure_hostname_file_failure(self, mock_open):
        """configure_hostname raises when file write fails."""
        with self.assertRaises(Exception) as ctx:  # noqa: H202
            utils.configure_hostname("testhost")
        self.assertIn("Failed to configure", str(ctx.exception))


class TestValidateNetworkStrExtended(unittest.TestCase):
    """Extended tests for validate_network_str."""

    def test_valid_large_ipv4_network(self):
        """Large IPv4 network is accepted."""
        net = utils.validate_network_str("10.0.0.0/8", 16)
        self.assertEqual(net.prefixlen, 8)

    def test_valid_ipv6_64_network(self):
        """IPv6 /64 network is accepted."""
        net = utils.validate_network_str("2001:db8::/64", 16)
        self.assertEqual(net.prefixlen, 64)

    def test_no_overlap_different_subnets(self):
        """Non-overlapping subnets are accepted."""
        existing = [netaddr.IPNetwork("10.0.0.0/24")]
        net = utils.validate_network_str("192.168.1.0/24", 16,
                                         existing_networks=existing)
        self.assertIsNotNone(net)


class TestValidateAddressStrExtended(unittest.TestCase):
    """Extended tests for validate_address_str."""

    def test_valid_ipv6_address(self):
        """Valid IPv6 address in network is accepted."""
        network = netaddr.IPNetwork("fd00::/64")
        addr = utils.validate_address_str("fd00::10", network)
        self.assertEqual(str(addr), "fd00::10")

    def test_ipv4_in_ipv6_network_rejected(self):
        """IPv4 address in IPv6 network raises ValidateFail."""
        network = netaddr.IPNetwork("fd00::/64")
        with self.assertRaises(ValidateFail):
            utils.validate_address_str("192.168.1.1", network)


class TestConnectToPostgresqlExtended(unittest.TestCase):
    """Extended tests for connect_to_postgresql."""

    def test_connect_failure(self):
        """connect_to_postgresql raises on connection failure."""
        mock_mod = mock.MagicMock()
        mock_mod.connect.side_effect = Exception("connection refused")
        with mock.patch.dict(sys.modules, {"psycopg2": mock_mod}):
            with self.assertRaises(Exception) as ctx:  # noqa: H202
                utils.connect_to_postgresql(5432)
            self.assertIn("Failed to connect", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
