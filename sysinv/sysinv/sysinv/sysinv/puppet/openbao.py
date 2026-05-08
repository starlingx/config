#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils
from sysinv.puppet import base

LOG = logging.getLogger(__name__)


class OpenbaoHostPuppet(base.BasePuppet):
    """Encapsulate puppet operations for openbao"""

    def get_system_config(self):
        config = {}
        config['platform::openbao::params::api_port'] = (
            constants.OPENBAO_API_PORT)
        config['platform::openbao::params::cluster_port'] = (
            constants.OPENBAO_CLUSTER_PORT)
        config['platform::openbao::params::data_path'] = (
            constants.OPENBAO_DATA_PATH)
        config['platform::openbao::params::cert_path'] = (
            constants.OPENBAO_CERT_PATH)
        config['platform::openbao::params::config_path'] = (
            constants.OPENBAO_CONFIG_PATH)
        config['platform::openbao::params::log_level'] = (
            constants.OPENBAO_LOG_LEVEL)
        config['platform::openbao::params::log_format'] = (
            constants.OPENBAO_LOG_FORMAT)
        return config

    def get_host_config(self, host):
        config = {}

        if constants.CONTROLLER not in utils.get_personalities(host):
            return config

        config['platform::openbao::params::service_enabled'] = True
        config['platform::openbao::params::initial_start'] = False

        # Determine node_id based on hostname
        if host.hostname == constants.CONTROLLER_0_HOSTNAME:
            config['platform::openbao::params::node_id'] = 'stx_raft_node_1'
        else:
            config['platform::openbao::params::node_id'] = 'stx_raft_node_2'

        # Advertise this host's own DNS name as the raft cluster_addr
        config['platform::openbao::params::cluster_addr_name'] = (
            host.hostname)

        # Get this host's own management address for bind (not floating)
        try:
            host_address = self._get_address_by_name(
                host.hostname, constants.NETWORK_TYPE_MGMT)
            if host_address:
                config['platform::openbao::params::bind_address'] = (
                    host_address.address)
                config['platform::openbao::params::mgmt_listen_addresses'] = (
                    [host_address.address])
        except Exception:
            LOG.warning("Unable to get host management address for openbao")

        # Set LUKS filesystem path
        config['platform::openbao::params::luks_fs_mount'] = (
            constants.LUKS_MOUNT_PATH)

        # Get raft peers (other controller's management address)
        raft_peers = self._get_raft_peers(host)
        config['platform::openbao::params::raft_peers'] = raft_peers

        return config

    def _get_raft_peers(self, host):
        """Get the management addresses of other controllers for raft join."""
        peers = []
        peer_address = None
        peer_name = None
        try:
            if host.hostname == constants.CONTROLLER_0_HOSTNAME:
                # Controller-0: peer is controller-1's own mgmt address
                peer_name = constants.CONTROLLER_1_HOSTNAME
            else:
                # Controller-1: peer is controller-0's own mgmt address
                peer_name = constants.CONTROLLER_0_HOSTNAME

            try:
                peer_address = self._get_address_by_name(
                    peer_name,
                    constants.NETWORK_TYPE_MGMT)
            except exception.AddressNotFoundByName:
                LOG.debug("Missing %s mgmt address for "
                          "openbao raft peer address", peer_name)

            if peer_address:
                peers.append(peer_address.address)
        except Exception:
            LOG.warning("Unable to get raft peer addresses for openbao")
        return peers
