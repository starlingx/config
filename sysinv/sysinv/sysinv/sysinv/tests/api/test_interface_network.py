# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
#
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
from six.moves import http_client

from sysinv.api.controllers.v1 import interface as api_if_v1
from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils


class InterfaceNetworkTestCase(base.FunctionalTest):
    def setUp(self):
        super(InterfaceNetworkTestCase, self).setUp()

        p = mock.patch.object(api_if_v1, '_get_lower_interface_macs')
        self.mock_lower_macs = p.start()
        self.mock_lower_macs.return_value = {'enp0s18': '08:00:27:8a:87:48',
                                             'enp0s19': '08:00:27:ea:93:8e'}
        self.addCleanup(p.stop)

        self.system = dbutils.create_test_isystem()
        self.load = dbutils.create_test_load()
        self.controller = dbutils.create_test_ihost(
            id='1',
            uuid=None,
            forisystemid=self.system.id,
            hostname='controller-0',
            personality=constants.CONTROLLER,
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
        )
        self.worker = dbutils.create_test_ihost(
            id='2',
            uuid=None,
            forisystemid=self.system.id,
            hostname='worker-0',
            personality=constants.WORKER,
            subfunctions=constants.WORKER,
            mgmt_mac='01:02.03.04.05.C0',
            mgmt_ip='192.168.24.12',
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
        self.address_pool_oam = dbutils.create_test_address_pool(
            id=3,
            network='128.224.150.0',
            name='oam',
            ranges=[['128.224.150.1', '128.224.151.254']],
            prefix=23)
        self.oam_network = dbutils.create_test_network(
            id=3,
            name='oam',
            type=constants.NETWORK_TYPE_OAM,
            address_pool_id=self.address_pool_oam.id)
        self.oam_address = dbutils.create_test_address(
                family=2,
                address='10.10.10.3',
                prefix=24,
                name='controller-0-oam',
                address_pool_id=self.address_pool_oam.id)
        self.address_pool_pxeboot = dbutils.create_test_address_pool(
            id=4,
            network='192.168.202.0',
            name='pxeboot',
            ranges=[['192.168.202.2', '192.168.202.254']],
            prefix=23)
        self.pxeboot_network = dbutils.create_test_network(
            id=4,
            type=constants.NETWORK_TYPE_PXEBOOT,
            address_pool_id=self.address_pool_pxeboot.id)
        self.pxeboot_address = dbutils.create_test_address(
                family=2,
                address='192.168.202.3',
                prefix=24,
                name='controller-0-pxeboot',
                address_pool_id=self.address_pool_pxeboot.id)

    def _post_and_check(self, ndict, expect_errors=False):
        response = self.post_json('%s' % self._get_path(), ndict,
                                  expect_errors)
        if expect_errors:
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])
        else:
            self.assertEqual(http_client.OK, response.status_int)
        return response

    def _get_path(self, path=None):
        if path:
            return '/interface_networks/' + path
        else:
            return '/interface_networks'


class InterfaceNetworkCreateTestCase(InterfaceNetworkTestCase):

    def setUp(self):
        super(InterfaceNetworkCreateTestCase, self).setUp()

    def test_create_mgmt_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.mgmt_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.mgmt_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=False)

    def test_create_cluster_host_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.cluster_host_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.cluster_host_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=False)

    def test_create_oam_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.oam_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.oam_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=True)

    def test_create_pxeboot_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.pxeboot_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.pxeboot_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=False)

    def test_create_mgmt_cluster_host_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        dbutils.create_test_interface_network(
            interface_id=controller_interface.id,
            network_id=self.mgmt_network.id)

        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)
        dbutils.create_test_interface_network(
            interface_id=worker_interface.id,
            network_id=self.mgmt_network.id)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.cluster_host_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=False)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.cluster_host_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=False)

    # Expected error:
    # You cannot assign a network of type 'oam' to an interface
    # which is already assigned with a different network
    def test_create_invalid_mgmt_oam_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        dbutils.create_test_interface_network(
            interface_id=controller_interface.id,
            network_id=self.mgmt_network.id)

        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)
        dbutils.create_test_interface_network(
            interface_id=worker_interface.id,
            network_id=self.mgmt_network.id)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.oam_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=True)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.oam_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=True)

    # Expected error:
    # You cannot assign a network of type 'pxeboot' to an interface
    # which is already assigned with a different network
    def test_create_invalid_mgmt_pxeboot_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        dbutils.create_test_interface_network(
            interface_id=controller_interface.id,
            network_id=self.mgmt_network.id)

        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)
        dbutils.create_test_interface_network(
            interface_id=worker_interface.id,
            network_id=self.mgmt_network.id)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.pxeboot_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=True)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.pxeboot_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=True)

    # Expected error:
    # Interface network with interface ID '%s' and
    # network ID '%s' already exists."
    def test_create_invalid_duplicate_mgmt_interface_network(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        dbutils.create_test_interface_network(
            interface_id=controller_interface.id,
            network_id=self.mgmt_network.id)

        worker_interface = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.worker.id)
        dbutils.create_test_interface_network(
            interface_id=worker_interface.id,
            network_id=self.mgmt_network.id)

        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.mgmt_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=True)

        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.mgmt_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=True)

    # Expected error: The oam network type is only supported on controller nodes
    def test_invalid_oam_on_worker(self):
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s3',
            forihostid=self.worker.id)
        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.oam_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=True)

    # Expected message: An interface with \'oam\' network type is already
    # provisioned on this node
    def test_create_invalid_duplicate_networktype(self):
        controller_interface1 = dbutils.create_test_interface(
            ifname='enp0s3',
            forihostid=self.controller.id)
        dbutils.create_test_interface_network(
            interface_id=controller_interface1.id,
            network_id=self.oam_network.id)
        controller_interface2 = dbutils.create_test_interface(
            ifname='enp0s8',
            forihostid=self.controller.id)
        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface2.uuid,
            network_uuid=self.oam_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=True)

    # Expected error: Interface ___ does not have associated cluster-host
    # interface on controller.
    def test_no_cluster_host_on_controller(self):
        worker_interface = dbutils.create_test_interface(
            ifname='enp0s3',
            forihostid=self.worker.id)
        worker_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=worker_interface.uuid,
            network_uuid=self.cluster_host_network.uuid)
        self._post_and_check(worker_interface_network, expect_errors=True)

    # Expected error: An interface with interface class data cannot
    # assign platform networks.
    def test_create_invalid_network_on_data_interface(self):
        controller_interface = dbutils.create_test_interface(
            ifname='enp0s3',
            ifclass=constants.NETWORK_TYPE_DATA,
            forihostid=self.controller.id)
        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.cluster_host_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=True)

    # Expected error: Device interface with network type ___, and interface type
    #  'aggregated ethernet' must be in mode '802.3ad'
    def test_aemode_invalid_mgmt(self):
        controller_interface = dbutils.create_test_interface(
            ifname='name',
            forihostid=self.controller.id,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='balanced',
            txhashpolicy='layer2')
        controller_interface_network = dbutils.post_get_test_interface_network(
            interface_uuid=controller_interface.uuid,
            network_uuid=self.mgmt_network.uuid)
        self._post_and_check(controller_interface_network, expect_errors=True)
