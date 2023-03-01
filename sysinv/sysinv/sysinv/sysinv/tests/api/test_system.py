# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /isystems/ methods.
"""
import mock

from sysinv.common import constants
from sysinv.db import api as db_api
from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils
from six.moves import http_client


class TestSystem(base.FunctionalTest):
    def setUp(self):
        super(TestSystem, self).setUp()

    def _get_path(self, system_id=None):
        return "/isystems/%s" % system_id if system_id else "/isystems"

    def _patch_and_check(self, path, updates, expect_errors=False,
                         expected_error_message=None):
        patch = []
        for att, val in updates.items():
            patch.append({"path": "/%s" % att,
                          "value": val,
                          "op": "replace"})

        # Updating system attributes
        response = self.patch_json(path, patch,
                                     expect_errors=expect_errors)

        if expect_errors:
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])
            if expected_error_message:
                self.assertIn(expected_error_message, response.json['error_message'])
        else:
            patched_system = response.json

            # Verify if system attributes was changed
            for att, val in updates.items():
                self.assertEqual(val, patched_system[att])


class TestSystemUpdate(TestSystem):

    def setUp(self):
        super(TestSystemUpdate, self).setUp()
        self.system = dbutils.create_test_isystem()

    def test_update_valid_system_values_0(self):
        update = {
            "name": "StarlingX #0",
            "timezone": "UCT",
            "description": "System Description",
            "contact": "John Doe",
            "location": "Earth",
            "latitude": "0.11223344556677",
            "longitude": "-0.11223344556677",
            "security_feature": "spectre_meltdown_v1",
            "capabilities": {},
        }
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    def test_update_valid_system_values_1(self):
        update = {
            "name": "StarlingX #1",
            "timezone": "CET",
            "description": "[System Description!]",
            "contact": "Mr. John Doe",
            "location": "Mars",
            "latitude": None,
            "longitude": None,
            "security_feature": "spectre_meltdown_all",
            "capabilities": {"region_config": False},
        }
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    def test_update_name_invalid_chars(self):
        update = {"name": "Nõt à vªlid nâmë"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)

    def test_update_latitude_longer_than_30_chars(self):
        update = {"latitude": "00.0000000111111111122222222223"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)

    def test_update_latitude_greater_than_90(self):
        update = {"latitude": "95.000002"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)

    def test_update_latitude_longitude_invalid_chars(self):
        update = {
            "latitude": "00.11223344556677 N",
            "longitude": "-00.11223344556677 W",
        }
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)

    def test_update_latitude_less_than_minus_90(self):
        update = {"latitude": "-97.000002"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)

    def test_update_latitude_invalid_chars(self):
        update = {"latitude": u"99.99999° N"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)

    def test_update_longitude_longer_than_30_chars(self):
        update = {"longitude": "00.0000000111111111122222222223"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)

    def test_update_longtitude_greater_than_180(self):
        update = {"longitude": "195.000002"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)

    def test_update_longitude_less_than_minus_180(self):
        update = {"longtitude": "-197.000002"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)

    def test_update_longitude_invalid_chars(self):
        update = {"longitude": u"99.99999° W"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)


class TestNetworkSetup(object):
    def __init__(self, system, controller_administrative_status):
        self.system = system
        self.controller = dbutils.create_test_ihost(
            id='1',
            uuid=None,
            forisystemid=self.system.id,
            hostname='controller-0',
            personality=constants.CONTROLLER,
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=controller_administrative_status
        )

    def _create_mgmt_interface_network(self, interface='mgmt'):
        self.address_pool_mgmt = dbutils.create_test_address_pool(
            id=1,
            network='192.168.204.0',
            name='management',
            ranges=[['192.168.204.2', '192.168.204.254']],
            prefix=24)
        self.mgmt_network = dbutils.create_test_network(
            id=1,
            name='mgmt',
            type=constants.NETWORK_TYPE_MGMT,
            link_capacity=1000,
            vlan_id=2,
            address_pool_id=self.address_pool_mgmt.id)
        self.mgmt_interface = dbutils.create_test_interface(
            ifname=interface,
            id=1,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid,
            networktypelist=[constants.NETWORK_TYPE_MGMT])

        dbutils.create_test_interface_network(
            interface_id=self.mgmt_interface.id,
            network_id=self.mgmt_network.id)

    def _create_cluster_host_interface_network(self, interface='cluster-host'):
        self.address_pool_cluster_host = dbutils.create_test_address_pool(
            id=2,
            network='192.168.206.0',
            name='cluster-host',
            ranges=[['192.168.206.2', '192.168.206.254']],
            prefix=24)
        self.cluster_host_network = dbutils.create_test_network(
            id=2,
            name='cluster-host',
            type=constants.NETWORK_TYPE_CLUSTER_HOST,
            link_capacity=10000,
            vlan_id=3,
            address_pool_id=self.address_pool_cluster_host.id)
        self.cluster_host_interface_controller = dbutils.create_test_interface(
            ifname=interface,
            id=2,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid,
            networktypelist=[constants.NETWORK_TYPE_CLUSTER_HOST])

        dbutils.create_test_interface_network(
            interface_id=self.cluster_host_interface_controller.id,
            network_id=self.cluster_host_network.id)

    def _create_admin_interface_network(self, interface='admin'):
        self.address_pool_admin = dbutils.create_test_address_pool(
            id=3,
            network='192.168.205.0',
            name='admin',
            ranges=[['192.168.205.2', '192.168.205.254']],
            prefix=24)
        self.admin_network = dbutils.create_test_network(
            id=3,
            name='admin',
            type=constants.NETWORK_TYPE_ADMIN,
            link_capacity=10000,
            vlan_id=4,
            address_pool_id=self.address_pool_admin.id)
        self.admin_interface_controller = dbutils.create_test_interface(
            ifname=interface,
            id=3,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid,
            networktypelist=[constants.NETWORK_TYPE_ADMIN])

        dbutils.create_test_interface_network(
            interface_id=self.address_pool_admin.id,
            network_id=self.admin_network.id)


@mock.patch('socket.gethostname', return_value='controller-0')
class TestSystemUpdateModeFromSimplex(TestSystem):

    def setUp(self):
        super(TestSystemUpdateModeFromSimplex, self).setUp()
        self.dbapi = db_api.get_instance()
        self.system = dbutils.create_test_isystem(system_type=constants.TIS_AIO_BUILD,
                                                  system_mode=constants.SYSTEM_MODE_SIMPLEX)
        self.test_network = TestNetworkSetup(self.system,
                                             controller_administrative_status=constants.ADMIN_LOCKED)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex(self, mock_init_config,
                                                  mock_controller):
        self.test_network._create_mgmt_interface_network()
        self.test_network._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_mgmt_on_lo(self,
                                                             mock_init_config,
                                                             mock_controller):
        self.test_network._create_mgmt_interface_network(interface=constants.LOOPBACK_IFNAME)
        self.test_network._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        msg = ("Cannot modify system mode to %s "
               "when the management interface is "
               "configured on loopback. "
               % constants.SYSTEM_MODE_DUPLEX)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_no_mgmt_if(self,
                                                             mock_init_config,
                                                             mock_controller):
        self.test_network._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        msg = ("Cannot modify system mode to %s "
               "without configuring the management "
               "interface." % constants.SYSTEM_MODE_DUPLEX)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_cluster_host_on_lo(self,
                                                                     mock_init_config,
                                                                     mock_controller):
        self.test_network._create_mgmt_interface_network()
        self.test_network._create_cluster_host_interface_network(interface=constants.LOOPBACK_IFNAME)
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        msg = ("Cannot modify system mode to %s "
               "when the cluster-host interface is "
               "configured on loopback. "
               % constants.SYSTEM_MODE_DUPLEX)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_with_admin(self,
                                                             mock_init_config,
                                                             mock_controller):
        self.test_network._create_mgmt_interface_network()
        self.test_network._create_cluster_host_interface_network()
        self.test_network._create_admin_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_admin_on_lo(self,
                                                              mock_init_config,
                                                              mock_controller):
        self.test_network._create_mgmt_interface_network()
        self.test_network._create_cluster_host_interface_network()
        self.test_network._create_admin_interface_network(interface=constants.LOOPBACK_IFNAME)
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        msg = ("Cannot modify system mode to %s "
               "when the admin interface is "
               "configured on loopback. "
               % constants.SYSTEM_MODE_DUPLEX)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_no_cluster_host_if(self,
                                                                     mock_init_config,
                                                                     mock_controller):
        self.test_network._create_mgmt_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        msg = ("Cannot modify system mode to %s "
               "without configuring the cluster-host "
               "interface." % constants.SYSTEM_MODE_DUPLEX)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_direct(self,
                                                         mock_init_config,
                                                         mock_controller):
        self.test_network._create_mgmt_interface_network()
        self.test_network._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_direct_mgmt_on_lo(self,
                                                                    mock_init_config,
                                                                    mock_controller):
        self.test_network._create_mgmt_interface_network(interface=constants.LOOPBACK_IFNAME)
        self.test_network._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        msg = ("Cannot modify system mode to %s "
               "when the management interface is "
               "configured on loopback. "
               % constants.SYSTEM_MODE_DUPLEX_DIRECT)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_direct_no_mgmt_if(self,
                                                                    mock_init_config,
                                                                    mock_controller):
        self.test_network._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        msg = ("Cannot modify system mode to %s "
               "without configuring the management "
               "interface." % constants.SYSTEM_MODE_DUPLEX_DIRECT)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_direct_cluster_host_on_lo(self,
                                                                            mock_init_config,
                                                                            mock_controller):
        self.test_network._create_mgmt_interface_network()
        self.test_network._create_cluster_host_interface_network(interface=constants.LOOPBACK_IFNAME)
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        msg = ("Cannot modify system mode to %s "
               "when the cluster-host interface is "
               "configured on loopback. "
               % constants.SYSTEM_MODE_DUPLEX_DIRECT)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_direct_no_cluster_host_if(self,
                                                                            mock_init_config,
                                                                            mock_controller):
        self.test_network._create_mgmt_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        msg = ("Cannot modify system mode to %s "
               "without configuring the cluster-host "
               "interface." % constants.SYSTEM_MODE_DUPLEX_DIRECT)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_direct_with_admin(self,
                                                                    mock_init_config,
                                                                    mock_controller):
        self.test_network._create_mgmt_interface_network()
        self.test_network._create_cluster_host_interface_network()
        self.test_network._create_admin_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_direct_admin_on_lo(self,
                                                                     mock_init_config,
                                                                     mock_controller):
        self.test_network._create_mgmt_interface_network()
        self.test_network._create_cluster_host_interface_network()
        self.test_network._create_admin_interface_network(interface=constants.LOOPBACK_IFNAME)
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        msg = ("Cannot modify system mode to %s "
               "when the admin interface is "
               "configured on loopback. "
               % constants.SYSTEM_MODE_DUPLEX_DIRECT)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_simplex(self, mock_init_config,
                                                   mock_controller):
        update = {"system_mode": constants.SYSTEM_MODE_SIMPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=False)
    def test_update_system_mode_to_duplex_before_initial_config_complete(self,
                                                                         mock_init_config,
                                                                         mock_controller):
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=False)
    def test_update_system_mode_to_duplex_direct_before_initial_config_complete(self,
                                                                                mock_init_config,
                                                                                mock_controller):
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=False)
    def test_update_system_mode_to_duplex_before_initial_config_complete_only_mgmt_if(self,
                                                                                      mock_init_config,
                                                                                      mock_controller):
        self.test_network._create_mgmt_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=False)
    def test_update_system_mode_to_duplex_direct_before_initial_config_complete_only_mgmt_if(self,
                                                                                             mock_init_config,
                                                                                             mock_controller):
        self.test_network._create_mgmt_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)


@mock.patch('socket.gethostname', return_value='controller-0')
class TestSystemUpdateModeUnlockedController(TestSystem):

    def setUp(self):
        super(TestSystemUpdateModeUnlockedController, self).setUp()
        self.dbapi = db_api.get_instance()
        self.system = dbutils.create_test_isystem(system_type=constants.TIS_AIO_BUILD,
                                                  system_mode=constants.SYSTEM_MODE_SIMPLEX)
        self.controller = dbutils.create_test_ihost(
            id='1',
            uuid=None,
            forisystemid=self.system.id,
            hostname='controller-0',
            personality=constants.CONTROLLER,
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED
        )

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_on_unlocked_controller(self, mock_init_config,
                                                       mock_controller):
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        msg = ("Cannot modify system mode if host '%s' is not "
               "locked." % self.controller.hostname)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)


@mock.patch('socket.gethostname', return_value='controller-0')
class TestSystemUpdateModeFromDuplex(TestSystem):

    def setUp(self):
        super(TestSystemUpdateModeFromDuplex, self).setUp()
        self.system = dbutils.create_test_isystem(system_type=constants.TIS_AIO_BUILD,
                                                  system_mode=constants.SYSTEM_MODE_DUPLEX)
        self.test_network = TestNetworkSetup(self.system,
                                             controller_administrative_status=constants.ADMIN_UNLOCKED)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_duplex_to_simplex(self,
                                                  mock_init_config,
                                                  mock_controller):
        update = {"system_mode": constants.SYSTEM_MODE_SIMPLEX}
        msg = ("Cannot modify system mode from %s "
               "to %s." % (constants.SYSTEM_MODE_DUPLEX, constants.SYSTEM_MODE_SIMPLEX))
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_duplex_to_duplex_direct(self,
                                                        mock_init_config,
                                                        mock_controller):
        self.test_network._create_mgmt_interface_network()
        self.test_network._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_duplex_to_duplex_direct_mgmt_on_lo(self,
                                                                   mock_init_config,
                                                                   mock_controller):
        self.test_network._create_mgmt_interface_network(interface=constants.LOOPBACK_IFNAME)
        self.test_network._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        msg = ("Cannot modify system mode to %s "
               "when the management interface is "
               "configured on loopback. "
               % constants.SYSTEM_MODE_DUPLEX_DIRECT)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_duplex_to_duplex_direct_no_mgmt_if(self,
                                                                   mock_init_config,
                                                                   mock_controller):
        self.test_network._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        msg = ("Cannot modify system mode to %s "
               "without configuring the management "
               "interface." % constants.SYSTEM_MODE_DUPLEX_DIRECT)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_duplex_to_duplex_direct_cluster_host_on_lo(self,
                                                                           mock_init_config,
                                                                           mock_controller):
        self.test_network._create_mgmt_interface_network()
        self.test_network._create_cluster_host_interface_network(interface=constants.LOOPBACK_IFNAME)
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        msg = ("Cannot modify system mode to %s "
               "when the cluster-host interface is "
               "configured on loopback. "
               % constants.SYSTEM_MODE_DUPLEX_DIRECT)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_duplex_to_duplex_direct_no_cluster_host_if(self,
                                                                           mock_init_config,
                                                                           mock_controller):
        self.test_network._create_mgmt_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        msg = ("Cannot modify system mode to %s "
               "without configuring the cluster-host "
               "interface." % constants.SYSTEM_MODE_DUPLEX_DIRECT)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_duplex_to_duplex(self, mock_init_config,
                                                 mock_controller):
        self.test_network._create_mgmt_interface_network()
        self.test_network._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=False)
    def test_update_system_mode_to_simplex_before_initial_config_complete(self,
                                                                          mock_init_config,
                                                                          mock_controller):
        update = {"system_mode": constants.SYSTEM_MODE_SIMPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=False)
    def test_update_system_mode_to_duplex_direct_before_initial_config_complete(self,
                                                                                mock_init_config,
                                                                                mock_controller):
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=False)
    def test_update_system_mode_to_duplex_direct_before_initial_config_complete_only_mgmt_if(self,
                                                                                             mock_init_config,
                                                                                             mock_controller):
        self.test_network._create_mgmt_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=False)
    def test_update_system_mode_to_simplex_before_initial_config_complete_only_mgmt_if(self,
                                                                                       mock_init_config,
                                                                                       mock_controller):
        self.test_network._create_mgmt_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_SIMPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)


@mock.patch('socket.gethostname', return_value='controller-0')
class TestSystemUpdateModeFromDuplexDirect(TestSystem):

    def setUp(self):
        super(TestSystemUpdateModeFromDuplexDirect, self).setUp()
        self.system = dbutils.create_test_isystem(system_type=constants.TIS_AIO_BUILD,
                                                  system_mode=constants.SYSTEM_MODE_DUPLEX_DIRECT)
        self.test_network = TestNetworkSetup(self.system,
                                             controller_administrative_status=constants.ADMIN_UNLOCKED)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_duplex_direct_to_simplex(self,
                                                         mock_init_config,
                                                         mock_controller):
        update = {"system_mode": constants.SYSTEM_MODE_SIMPLEX}
        msg = ("Cannot modify system mode from %s "
               "to %s." % (constants.SYSTEM_MODE_DUPLEX_DIRECT, constants.SYSTEM_MODE_SIMPLEX))
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_duplex_direct_to_duplex(self,
                                                        mock_init_config,
                                                        mock_controller):
        self.test_network._create_mgmt_interface_network()
        self.test_network._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_duplex_direct_to_duplex_mgmt_on_lo(self,
                                                                   mock_init_config,
                                                                   mock_controller):
        self.test_network._create_mgmt_interface_network(interface=constants.LOOPBACK_IFNAME)
        self.test_network._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        msg = ("Cannot modify system mode to %s "
               "when the management interface is "
               "configured on loopback. "
               % constants.SYSTEM_MODE_DUPLEX)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_duplex_direct_to_duplex_no_mgmt_if(self,
                                                                   mock_init_config,
                                                                   mock_controller):
        self.test_network._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        msg = ("Cannot modify system mode to %s "
               "without configuring the management "
               "interface." % constants.SYSTEM_MODE_DUPLEX)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_duplex_direct_to_duplex_cluster_host_on_lo(self,
                                                                           mock_init_config,
                                                                           mock_controller):
        self.test_network._create_mgmt_interface_network()
        self.test_network._create_cluster_host_interface_network(interface=constants.LOOPBACK_IFNAME)
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        msg = ("Cannot modify system mode to %s "
               "when the cluster-host interface is "
               "configured on loopback. "
               % constants.SYSTEM_MODE_DUPLEX)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_duplex_direct_to_duplex_no_cluster_host_if(self,
                                                                           mock_init_config,
                                                                           mock_controller):
        self.test_network._create_mgmt_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        msg = ("Cannot modify system mode to %s "
               "without configuring the cluster-host "
               "interface." % constants.SYSTEM_MODE_DUPLEX)
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True,
                              expected_error_message=msg)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_duplex_direct_to_duplex_direct(self,
                                                               mock_init_config,
                                                               mock_controller):
        self.test_network._create_mgmt_interface_network()
        self.test_network._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX_DIRECT}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=False)
    def test_update_system_mode_to_simplex_before_initial_config_complete(self,
                                                                          mock_init_config,
                                                                          mock_controller):
        update = {"system_mode": constants.SYSTEM_MODE_SIMPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=False)
    def test_update_system_mode_to_duplex_before_initial_config_complete(self,
                                                                         mock_init_config,
                                                                         mock_controller):
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=False)
    def test_update_system_mode_to_simplex_before_initial_config_complete_only_mgmt_if(self,
                                                                                       mock_init_config,
                                                                                       mock_controller):
        self.test_network._create_mgmt_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_SIMPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=False)
    def test_update_system_mode_to_duplex_before_initial_config_complete_only_mgmt_if(self,
                                                                                      mock_init_config,
                                                                                      mock_controller):
        self.test_network._create_mgmt_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)
