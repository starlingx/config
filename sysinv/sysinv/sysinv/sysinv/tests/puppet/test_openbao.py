#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
from unittest import TestCase

from sysinv.common import constants
from sysinv.common import exception
from sysinv.puppet.openbao import OpenbaoHostPuppet


# Fixed management addresses used by the fake address lookup.
_C0_MGMT = '192.168.204.3'
_C1_MGMT = '192.168.204.4'

# Hieradata keys under test.
_KEY_API_PORT = 'platform::openbao::params::api_port'
_KEY_CLUSTER_PORT = 'platform::openbao::params::cluster_port'
_KEY_DATA_PATH = 'platform::openbao::params::data_path'
_KEY_CERT_PATH = 'platform::openbao::params::cert_path'
_KEY_CONFIG_PATH = 'platform::openbao::params::config_path'
_KEY_LOG_LEVEL = 'platform::openbao::params::log_level'
_KEY_LOG_FORMAT = 'platform::openbao::params::log_format'
_KEY_SERVICE_ENABLED = 'platform::openbao::params::service_enabled'
_KEY_INITIAL_START = 'platform::openbao::params::initial_start'
_KEY_NODE_ID = 'platform::openbao::params::node_id'
_KEY_CLUSTER_ADDR_NAME = 'platform::openbao::params::cluster_addr_name'
_KEY_BIND_ADDRESS = 'platform::openbao::params::bind_address'
_KEY_MGMT_LISTEN = 'platform::openbao::params::mgmt_listen_addresses'
_KEY_LUKS_FS_MOUNT = 'platform::openbao::params::luks_fs_mount'
_KEY_RAFT_PEERS = 'platform::openbao::params::raft_peers'


def _make_host(hostname):
    """Build a minimal fake host object with a hostname."""
    host = mock.MagicMock()
    host.hostname = hostname
    return host


def _make_address(address):
    """Build a fake address object exposing .address."""
    obj = mock.MagicMock()
    obj.address = address
    return obj


def _make_puppet():
    """Create an OpenbaoHostPuppet with a mocked operator."""
    operator = mock.MagicMock()
    return OpenbaoHostPuppet(operator)


def _fake_address_by_name(name, networktype):
    """Return the per-host mgmt address for the given hostname.

    Mirrors base._get_address_by_name(name, networktype): keyed on the
    controller hostname, scoped to the mgmt network.
    """
    mapping = {
        constants.CONTROLLER_0_HOSTNAME: _C0_MGMT,
        constants.CONTROLLER_1_HOSTNAME: _C1_MGMT,
    }
    addr = mapping.get(name)
    return _make_address(addr) if addr else None


class TestGetSystemConfig(TestCase):
    """System-wide hieradata: ports and paths."""

    def test_system_config_ports_and_paths(self):
        puppet = _make_puppet()
        config = puppet.get_system_config()
        self.assertEqual(config[_KEY_API_PORT],
                         constants.OPENBAO_API_PORT)
        self.assertEqual(config[_KEY_CLUSTER_PORT],
                         constants.OPENBAO_CLUSTER_PORT)
        self.assertEqual(config[_KEY_DATA_PATH],
                         constants.OPENBAO_DATA_PATH)
        self.assertEqual(config[_KEY_CERT_PATH],
                         constants.OPENBAO_CERT_PATH)
        self.assertEqual(config[_KEY_CONFIG_PATH],
                         constants.OPENBAO_CONFIG_PATH)
        self.assertEqual(config[_KEY_LOG_LEVEL],
                         constants.OPENBAO_LOG_LEVEL)
        self.assertEqual(config[_KEY_LOG_FORMAT],
                         constants.OPENBAO_LOG_FORMAT)

    def test_system_config_does_not_include_host_keys(self):
        """System config must not carry per-host keys."""
        puppet = _make_puppet()
        config = puppet.get_system_config()
        for key in (_KEY_NODE_ID, _KEY_CLUSTER_ADDR_NAME, _KEY_BIND_ADDRESS,
                    _KEY_LUKS_FS_MOUNT, _KEY_RAFT_PEERS, _KEY_SERVICE_ENABLED):
            self.assertNotIn(key, config)


class TestGetHostConfigNonController(TestCase):
    """Non-controller hosts get no openbao hieradata."""

    @mock.patch('sysinv.common.utils.get_personalities',
                return_value=[constants.WORKER])
    def test_worker_returns_empty(self, _mock_pers):
        puppet = _make_puppet()
        config = puppet.get_host_config(_make_host('worker-0'))
        self.assertEqual(config, {})

    @mock.patch('sysinv.common.utils.get_personalities',
                return_value=[constants.STORAGE])
    def test_storage_returns_empty(self, _mock_pers):
        puppet = _make_puppet()
        config = puppet.get_host_config(_make_host('storage-0'))
        self.assertEqual(config, {})


class TestGetHostConfigController0(TestCase):
    """controller-0 per-host hieradata."""

    @mock.patch('sysinv.common.utils.get_personalities',
                return_value=[constants.CONTROLLER])
    def test_controller0_config(self, _mock_pers):
        puppet = _make_puppet()
        puppet._get_address_by_name = mock.Mock(
            side_effect=_fake_address_by_name)

        config = puppet.get_host_config(
            _make_host(constants.CONTROLLER_0_HOSTNAME))

        self.assertTrue(config[_KEY_SERVICE_ENABLED])
        self.assertFalse(config[_KEY_INITIAL_START])
        self.assertEqual(config[_KEY_NODE_ID], 'stx_raft_node_1')
        self.assertEqual(config[_KEY_CLUSTER_ADDR_NAME],
                         constants.CONTROLLER_0_HOSTNAME)
        self.assertEqual(config[_KEY_BIND_ADDRESS], _C0_MGMT)
        # The unlock listener set carries the primary mgmt address only,
        # as a list (secondary mgmt excluded).
        self.assertEqual(config[_KEY_MGMT_LISTEN], [_C0_MGMT])
        self.assertEqual(config[_KEY_LUKS_FS_MOUNT],
                         constants.LUKS_MOUNT_PATH)
        # controller-0's raft peer is controller-1's mgmt address
        self.assertEqual(config[_KEY_RAFT_PEERS], [_C1_MGMT])


class TestGetHostConfigController1(TestCase):
    """controller-1 per-host hieradata."""

    @mock.patch('sysinv.common.utils.get_personalities',
                return_value=[constants.CONTROLLER])
    def test_controller1_config(self, _mock_pers):
        puppet = _make_puppet()
        puppet._get_address_by_name = mock.Mock(
            side_effect=_fake_address_by_name)

        config = puppet.get_host_config(
            _make_host(constants.CONTROLLER_1_HOSTNAME))

        self.assertEqual(config[_KEY_NODE_ID], 'stx_raft_node_2')
        self.assertEqual(config[_KEY_CLUSTER_ADDR_NAME],
                         constants.CONTROLLER_1_HOSTNAME)
        self.assertEqual(config[_KEY_BIND_ADDRESS], _C1_MGMT)
        self.assertEqual(config[_KEY_MGMT_LISTEN], [_C1_MGMT])
        self.assertEqual(config[_KEY_LUKS_FS_MOUNT],
                         constants.LUKS_MOUNT_PATH)
        # controller-1's raft peer is controller-0's mgmt address
        self.assertEqual(config[_KEY_RAFT_PEERS], [_C0_MGMT])


class TestGetHostConfigAddressLookupFailure(TestCase):
    """Address lookup failures are handled gracefully."""

    @mock.patch('sysinv.common.utils.get_personalities',
                return_value=[constants.CONTROLLER])
    def test_bind_address_lookup_exception(self, _mock_pers):
        """If the mgmt address lookup raises, bind_address is omitted but
        the rest of the config is still produced."""
        puppet = _make_puppet()
        puppet._get_address_by_name = mock.Mock(
            side_effect=Exception('no address'))

        config = puppet.get_host_config(
            _make_host(constants.CONTROLLER_0_HOSTNAME))

        # bind_address omitted, but node_id/luks/service still present
        self.assertNotIn(_KEY_BIND_ADDRESS, config)
        # listener list also omitted when the mgmt lookup fails
        self.assertNotIn(_KEY_MGMT_LISTEN, config)
        self.assertEqual(config[_KEY_NODE_ID], 'stx_raft_node_1')
        self.assertIn(_KEY_LUKS_FS_MOUNT, config)
        self.assertTrue(config[_KEY_SERVICE_ENABLED])
        # raft peers also swallow the exception -> empty list
        self.assertEqual(config[_KEY_RAFT_PEERS], [])

    @mock.patch('sysinv.common.utils.get_personalities',
                return_value=[constants.CONTROLLER])
    def test_no_peer_address_aio_sx(self, _mock_pers):
        """AIO-SX: no peer controller -> empty raft_peers, bind_address
        still resolved for the local host."""
        def _only_c0(name, networktype):
            if name == constants.CONTROLLER_0_HOSTNAME:
                return _make_address(_C0_MGMT)
            return None  # controller-1 does not exist

        puppet = _make_puppet()
        puppet._get_address_by_name = mock.Mock(side_effect=_only_c0)

        config = puppet.get_host_config(
            _make_host(constants.CONTROLLER_0_HOSTNAME))

        self.assertEqual(config[_KEY_BIND_ADDRESS], _C0_MGMT)
        self.assertEqual(config[_KEY_MGMT_LISTEN], [_C0_MGMT])
        self.assertEqual(config[_KEY_RAFT_PEERS], [])

    @mock.patch('sysinv.common.utils.get_personalities',
                return_value=[constants.CONTROLLER])
    def test_peer_address_not_found_by_name(self, _mock_pers):
        """AIO-SX: the peer mgmt address lookup raises AddressNotFoundByName
        (the real code path on a simplex where controller-1 has no address)
        -> that specific exception is caught, raft_peers is empty, and the
        local host's bind_address/listener are still resolved."""
        def _c0_ok_peer_missing(name, networktype):
            if name == constants.CONTROLLER_0_HOSTNAME:
                return _make_address(_C0_MGMT)
            # controller-1 has no mgmt address: base._get_address_by_name
            # surfaces this as AddressNotFoundByName (raise_exc=True).
            raise exception.AddressNotFoundByName(
                name='%s-mgmt' % constants.CONTROLLER_1_HOSTNAME)

        puppet = _make_puppet()
        puppet._get_address_by_name = mock.Mock(
            side_effect=_c0_ok_peer_missing)

        config = puppet.get_host_config(
            _make_host(constants.CONTROLLER_0_HOSTNAME))

        # The peer lookup raised AddressNotFoundByName and was caught in
        # _get_raft_peers -> empty peer list, no outer warning path needed.
        self.assertEqual(config[_KEY_RAFT_PEERS], [])
        # Local host config is unaffected by the peer lookup failure.
        self.assertEqual(config[_KEY_BIND_ADDRESS], _C0_MGMT)
        self.assertEqual(config[_KEY_MGMT_LISTEN], [_C0_MGMT])
        self.assertEqual(config[_KEY_NODE_ID], 'stx_raft_node_1')
