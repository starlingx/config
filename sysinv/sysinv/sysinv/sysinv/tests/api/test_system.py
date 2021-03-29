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

    def test_update_latitude_longer_than_30_chars(self):
        update = {"latitude": "00.0000000111111111122222222223"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)

    def test_update_latitude_valid_length(self):
        update = {"latitude": "00.11223344556677"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    def test_update_latitude_null_value(self):
        update = {"latitude": None}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    def test_update_longitude_longer_than_30_chars(self):
        update = {"longitude": "00.0000000111111111122222222223"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)

    def test_update_longitude_valid_length(self):
        update = {"longitude": "-00.11223344556677"}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)

    def test_update_longitude_null_value(self):
        update = {"longitude": None}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)


class TestSystemUpdateModeFromSimplex(TestSystem):

    def setUp(self):
        super(TestSystemUpdateModeFromSimplex, self).setUp()
        self.dbapi = db_api.get_instance()
        self.system = dbutils.create_test_isystem(system_type=constants.TIS_AIO_BUILD,
                                                  system_mode=constants.SYSTEM_MODE_SIMPLEX)

    def _create_mgmt_interface_network(self, interface='mgmt'):
        self.controller = dbutils.create_test_ihost(
            id='1',
            uuid=None,
            forisystemid=self.system.id,
            hostname='controller-0',
            personality=constants.CONTROLLER,
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
        )
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

        self.mgmt_interface = dbutils.create_test_interface(ifname=interface,
                                      id=1,
                                      ifclass=constants.INTERFACE_CLASS_PLATFORM,
                                      forihostid=self.controller.id,
                                      ihost_uuid=self.controller.uuid,
                                      networktypelist=[constants.NETWORK_TYPE_MGMT])

        dbutils.create_test_interface_network(
            interface_id=self.mgmt_interface.id,
            network_id=self.mgmt_network.id)

    @mock.patch('sysinv.common.utils.is_initial_config_complete', return_value=True)
    def test_update_system_mode_simplex_to_duplex_with_mgmt_if(self, mock_exists):
        self._create_mgmt_interface_network()
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)
        system = self.dbapi.isystem_get_one()
        system_dict = system.as_dict()
        self.assertIn('simplex_to_duplex_migration', system_dict['capabilities'])

    @mock.patch('sysinv.common.utils.is_initial_config_complete', return_value=True)
    def test_update_system_mode_simplex_to_duplex_mgmt_on_lo(self, mock_exists):
        self._create_mgmt_interface_network(interface=constants.LOOPBACK_IFNAME)
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)

    @mock.patch('sysinv.common.utils.is_initial_config_complete', return_value=True)
    def test_update_system_mode_simplex_to_duplex_no_mgmt_if(self, mock_exists):
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update, expect_errors=True)

    @mock.patch('sysinv.common.utils.is_initial_config_complete', return_value=True)
    def test_update_system_mode_simplex_to_simplex(self, mock_exists):
        update = {"system_mode": constants.SYSTEM_MODE_SIMPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)
        system = self.dbapi.isystem_get_one()
        system_dict = system.as_dict()
        self.assertNotIn('simplex_to_duplex_migration', system_dict['capabilities'])

    @mock.patch('sysinv.common.utils.is_initial_config_complete', return_value=False)
    def test_update_system_mode_before_initial_config_complete(self, mock_exists):
        update = {"system_mode": constants.SYSTEM_MODE_DUPLEX}
        self._patch_and_check(self._get_path(self.system.uuid),
                              update)
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
