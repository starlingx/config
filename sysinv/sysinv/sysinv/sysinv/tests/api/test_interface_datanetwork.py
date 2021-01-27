# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
#
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
from six.moves import http_client
import uuid

from sysinv.api.controllers.v1 import interface as api_if_v1
from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils


class InterfaceDataNetworkTestCase(base.FunctionalTest):
    def setUp(self):
        super(InterfaceDataNetworkTestCase, self).setUp()

        p = mock.patch.object(api_if_v1, '_get_lower_interface_macs')
        self.mock_lower_macs = p.start()
        self.mock_lower_macs.return_value = {'enp0s18': '08:00:27:8a:87:48',
                                             'enp0s19': '08:00:27:ea:93:8e'}
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.common.utils.is_aio_simplex_system')
        self.mock_utils_is_aio_simplex_system = p.start()
        self.mock_utils_is_aio_simplex_system.return_value = True
        self.addCleanup(p.stop)

        self.system = dbutils.create_test_isystem()
        self.load = dbutils.create_test_load()
        self.controller = dbutils.create_test_ihost(
            id='1',
            uuid=None,
            forisystemid=self.system.id,
            hostname='controller-0',
            personality=constants.CONTROLLER,
            subfunctions=constants.WORKER,
            administrative=constants.ADMIN_UNLOCKED,
            invprovision=constants.PROVISIONED,
        )
        self.datanetwork = dbutils.create_test_datanetwork(
            name='test1',
            uuid=str(uuid.uuid4()),
            network_type=constants.DATANETWORK_TYPE_VLAN,
            mtu=1500)
        self.if_sriov0 = dbutils.create_test_interface(
            ifname='sriov0',
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid)
        self.if_data0 = dbutils.create_test_interface(
            ifname='data0',
            ifclass=constants.INTERFACE_CLASS_DATA,
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid)
        self.if_sriov1 = dbutils.create_test_interface(
            ifname='sriov1',
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid)

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
            return '/interface_datanetworks/' + path
        else:
            return '/interface_datanetworks'


class InterfaceDataNetworkCreateTestCase(InterfaceDataNetworkTestCase):
    def setUp(self):
        super(InterfaceDataNetworkCreateTestCase, self).setUp()

    def test_assign_interface_datanetwork(self):
        # system interface-datanetwork-assign controller-0 sriov0 test1
        sriov0_assign_dn = dbutils.post_get_test_interface_datanetwork(
                interface_uuid=self.if_sriov0.uuid,
                datanetwork_uuid=self.datanetwork.uuid)
        self._post_and_check(sriov0_assign_dn, expect_errors=False)

        # system interface-datanetwork-list controller-0
        if_dn_list = self.get_json('/ihosts/%s/interface_datanetworks'
                                 % self.controller.uuid, expect_errors=False)
        self.assertEqual('test1', if_dn_list['interface_datanetworks'][0]['datanetwork_name'])
        self.assertEqual('sriov0', if_dn_list['interface_datanetworks'][0]['ifname'])

        # system interface-datanetwork-remove {uuid}
        self.delete('/interface_datanetworks/%s'
                    % if_dn_list['interface_datanetworks'][0]['uuid'],
                    expect_errors=False)

    def test_assign_interface_datanetwork_error_non_sriov(self):
        # system interface-datanetwork-assign controller-0 data0 test1
        # rejected because host is unlocked
        data0_assign_dn = dbutils.post_get_test_interface_datanetwork(
                interface_uuid=self.if_data0.uuid,
                datanetwork_uuid=self.datanetwork.uuid)
        self._post_and_check(data0_assign_dn, expect_errors=True)

    def test_assign_interface_datanetwork_error_non_aio_sx(self):
        self.mock_utils_is_aio_simplex_system.return_value = False

        # system interface-datanetwork-assign controller-0 sriov1 test1
        # rejected because system is not AIO-SX
        sriov1_assign_dn = dbutils.post_get_test_interface_datanetwork(
                interface_uuid=self.if_sriov1.uuid,
                datanetwork_uuid=self.datanetwork.uuid)
        self._post_and_check(sriov1_assign_dn, expect_errors=True)

        self.mock_utils_is_aio_simplex_system.return_value = True
