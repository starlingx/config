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

    def _patch_and_check(self, path, updates, expect_errors=False):
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


class TestSystemUpdateModeFromSimplex(TestSystem):

    def setUp(self):
        super(TestSystemUpdateModeFromSimplex, self).setUp()
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
            administrative=constants.ADMIN_LOCKED
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
        self.cluster_host_interface = dbutils.create_test_interface(
            ifname=interface,
            id=2,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid,
            networktypelist=[constants.NETWORK_TYPE_CLUSTER_HOST])

        dbutils.create_test_interface_network(
            interface_id=self.cluster_host_interface.id,
            network_id=self.cluster_host_network.id)

    @mock.patch('socket.gethostname',
                return_value='controller-0')
    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex(self, mock_init_config,
                                                  mock_controller):
        self._create_mgmt_interface_network()
        self._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)
        system = self.dbapi.isystem_get_one()
        system_dict = system.as_dict()
        self.assertIn('simplex_to_duplex_migration', system_dict['capabilities'])

    @mock.patch('socket.gethostname',
                return_value='controller-0')
    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_mgmt_on_lo(self,
                                                             mock_init_config,
                                                             mock_controller):
        self._create_mgmt_interface_network(interface=constants.LOOPBACK_IFNAME)
        self._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)
        system = self.dbapi.isystem_get_one()
        system_dict = system.as_dict()
        self.assertNotIn('simplex_to_duplex_migration', system_dict['capabilities'])

    @mock.patch('socket.gethostname',
                return_value='controller-0')
    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_no_mgmt_if(self,
                                                             mock_init_config,
                                                             mock_controller):
        self._create_cluster_host_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)
        system = self.dbapi.isystem_get_one()
        system_dict = system.as_dict()
        self.assertNotIn('simplex_to_duplex_migration', system_dict['capabilities'])

    @mock.patch('socket.gethostname',
                return_value='controller-0')
    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_cluster_host_on_lo(self,
                                                                     mock_init_config,
                                                                     mock_controller):
        self._create_mgmt_interface_network()
        self._create_cluster_host_interface_network(interface=constants.LOOPBACK_IFNAME)
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)
        system = self.dbapi.isystem_get_one()
        system_dict = system.as_dict()
        self.assertNotIn('simplex_to_duplex_migration', system_dict['capabilities'])

    @mock.patch('socket.gethostname',
                return_value='controller-0')
    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_duplex_no_cluster_host_if(self,
                                                                     mock_init_config,
                                                                     mock_controller):
        self._create_mgmt_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)
        system = self.dbapi.isystem_get_one()
        system_dict = system.as_dict()
        self.assertNotIn('simplex_to_duplex_migration', system_dict['capabilities'])

    @mock.patch('socket.gethostname',
                return_value='controller-0')
    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_simplex_to_simplex(self, mock_init_config,
                                                         mock_controller):
        update = {"system_mode": constants.SYSTEM_MODE_SIMPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)
        system = self.dbapi.isystem_get_one()
        system_dict = system.as_dict()
        self.assertNotIn('simplex_to_duplex_migration', system_dict['capabilities'])

    @mock.patch('socket.gethostname',
                return_value='controller-0')
    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=False)
    def test_update_system_mode_before_initial_config_complete(self,
                                                               mock_init_config,
                                                               mock_controller):
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)
        system = self.dbapi.isystem_get_one()
        system_dict = system.as_dict()
        self.assertNotIn('simplex_to_duplex_migration', system_dict['capabilities'])

    @mock.patch('socket.gethostname',
                return_value='controller-0')
    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=False)
    def test_update_system_mode_before_initial_config_complete_only_mgmt_if(self,
                                                                            mock_init_config,
                                                                            mock_controller):
        self._create_mgmt_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)
        system = self.dbapi.isystem_get_one()
        system_dict = system.as_dict()
        self.assertNotIn('simplex_to_duplex_migration', system_dict['capabilities'])


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

    @mock.patch('socket.gethostname',
                return_value='controller-0')
    @mock.patch('sysinv.common.utils.is_initial_config_complete',
                return_value=True)
    def test_update_system_mode_on_unlocked_controller(self, mock_init_config,
                                                       mock_controller):
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)
        system = self.dbapi.isystem_get_one()
        system_dict = system.as_dict()
        self.assertNotIn('simplex_to_duplex_migration', system_dict['capabilities'])


class TestSystemUpdateModeFromDuplex(TestSystem):

    def setUp(self):
        super(TestSystemUpdateModeFromDuplex, self).setUp()
        self.system = dbutils.create_test_isystem(system_type=constants.TIS_AIO_BUILD,
                                                  system_mode=constants.SYSTEM_MODE_DUPLEX)

    @mock.patch('sysinv.common.utils.is_initial_config_complete', return_value=True)
    def test_update_system_mode_duplex_to_simplex(self, mock_exists):
        update = {"system_mode": constants.SYSTEM_MODE_SIMPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)
