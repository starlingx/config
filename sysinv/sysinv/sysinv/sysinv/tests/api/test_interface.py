# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
#
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /interfaces/ methods.
"""

import mock
from six.moves import http_client

from sysinv.api.controllers.v1 import interface as api_if_v1
from sysinv.api.controllers.v1 import utils as api_utils
from sysinv.common import constants
from sysinv.conductor import rpcapi
from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils
from sysinv.db import api as db_api
from sysinv.db.sqlalchemy import api as dbsql_api
from sysinv.openstack.common.rpc import common as rpc_common


providernet_list = {
            'group0-data1': {
                "status": "ACTIVE", "description": None,
                "mtu": 1500,
                "ranges": [
                    {"minimum": 700,
                     "name": "group0-data1-r3-0",
                     "tenant_id": "7e0ec7688fb64cf89c9c4fc2e2bd4c94",
                     "shared": False,
                     "id": "54a6eb56-fa1d-42fe-b32e-de2055bab591",
                     "maximum": 715,
                     "description": None
                     }],
                "vlan_transparent": False,
                "type": "vlan",
                "id": "237848e3-4f7b-4f74-bf35-d4da470be228",
                "name": "group0-data1"},
            'group0-data0': {
                "status": "ACTIVE", "description": None,
                "mtu": 1500,
                "ranges": [
                    {"minimum": 600, "name": "group0-data0-r1-0",
                     "tenant_id": "3103030ac5a64dc6a6f0c05da79c5c3c",
                     "shared": False,
                     "id": "62b0d1aa-a4c7-47a3-9363-6726720c89a9",
                     "maximum": 615, "description": None}],
                "vlan_transparent": False,
                "type": "vlan",
                "id": "3dee9198-fc3c-4313-a5c5-7b72a4bad57e",
                "name": "group0-data0"},
            'group0-data0b': {
                "status": "ACTIVE", "description": None,
                "mtu": 1500,
                "ranges": [
                    {"minimum": 616, "name": "group0-data0b-r2-0",
                     "tenant_id": None, "shared": True,
                     "id": "7a133887-fe6d-4976-a006-d12948c9498d",
                     "maximum": 631, "description": None}],
                "vlan_transparent": False,
                "type": "vlan",
                "id": "83aa5122-49fb-4b97-8cd8-a201dd2d5b0e",
                "name": "group0-data0b"},
            'group0-ext0': {
                "status": "ACTIVE", "description": None,
                "mtu": 1500,
                "ranges": [{"description": None, "minimum": 4,
                            "id": "72f21b11-6d17-486e-a4e6-4eaf5f00f23e",
                            "name": "group0-ext0-r0-0",
                            "tenant_id": None, "maximum": 4,
                            "shared": True,
                            "vxlan": {"group": "239.0.2.1",
                                      "port": 8472, "ttl": 10}}],
                "vlan_transparent": False,
                "type": "vxlan",
                "id": "da9f7bb1-2114-4ffd-8a4c-9ca215d98fa2",
                "name": "group0-ext0"},
            'group0-ext1': {
                "status": "ACTIVE", "description": None,
                "mtu": 1500,
                "ranges": [{"description": None, "minimum": 4,
                            "id": "72f21b11-6d17-486e-a4e6-4eaf5f00f23e",
                            "name": "group0-ext1-r0-0",
                            "tenant_id": None, "maximum": 4,
                            "shared": True,
                            "vxlan": {"group": "239.0.2.1",
                                      "port": 8472, "ttl": 10}}],
                "vlan_transparent": False,
                "type": "vxlan",
                "id": "da9f7bb1-2114-4ffd-8a4c-9ca215d98fa3",
                "name": "group0-ext1"},
            'group0-ext2': {
                "status": "ACTIVE", "description": None,
                "mtu": 1500,
                "ranges": [{"description": None, "minimum": 4,
                            "id": "72f21b11-6d17-486e-a4e6-4eaf5f00f23e",
                            "name": "group0-ext2-r0-0",
                            "tenant_id": None, "maximum": 4,
                            "shared": True,
                            "vxlan": {"group": "239.0.2.1",
                                      "port": 8472, "ttl": 10}}],
                "vlan_transparent": False,
                "type": "vxlan",
                "id": "da9f7bb1-2114-4ffd-8a4c-9ca215d98fa2",
                "name": "group0-ext2"},
            'group0-ext3': {
                "status": "ACTIVE", "description": None,
                "mtu": 1500,
                "ranges": [{"description": None, "minimum": 4,
                            "id": "72f21b11-6d17-486e-a4e6-4eaf5f00f23e",
                            "name": "group0-ext2-r0-0",
                            "tenant_id": None, "maximum": 4,
                            "shared": True,
                            "vxlan": {"group": "239.0.2.1",
                                      "port": 8472, "ttl": 10}}],
                "vlan_transparent": False,
                "type": "vxlan",
                "id": "da9f7bb1-2114-4ffd-8a4c-9ca215d98fa2",
                "name": "group0-ext3"},
            'group0-flat': {
                "status": "ACTIVE", "description": None,
                "mtu": 1500,
                "ranges": [{"description": None, "minimum": 4,
                            "id": "72f21b11-6d17-486e-a4e6-4eaf5f00f23e",
                            "name": "group0-flat-r0-0",
                            "tenant_id": None, "maximum": 4,
                            "tenant_id": None, "maximum": 4,
                            "shared": True,
                            "vxlan": {"group": "239.0.2.1",
                                      "port": 8472, "ttl": 10}}],
                "vlan_transparent": False,
                "type": "flat",
                "id": "da9f7bb1-2114-4ffd-8a4c-9ca215d98fa3",
                "name": "group0-flat"}
    }


class InterfaceTestCase(base.FunctionalTest):
    def _setup_configuration(self):
        pass

    def setUp(self):
        super(InterfaceTestCase, self).setUp()

        p = mock.patch.object(api_if_v1, '_get_lower_interface_macs')
        self.mock_lower_macs = p.start()
        self.mock_lower_macs.return_value = {'enp0s18': '08:00:27:8a:87:48',
                                             'enp0s19': '08:00:27:ea:93:8e'}
        self.addCleanup(p.stop)

        p = mock.patch.object(rpcapi.ConductorAPI,
                              'iinterface_get_providernets')
        self.mock_iinterface_get_providernets = p.start()
        self.mock_iinterface_get_providernets.return_value = providernet_list
        self.addCleanup(p.stop)

        p = mock.patch.object(api_utils, 'get_sdn_l3_mode_enabled')
        self.mock_sdn_l3_mode_enabled = p.start()
        self.mock_sdn_l3_mode_enabled.return_value = True
        self.addCleanup(p.stop)

        self._setup_context()

    def _get_path(self, path=None):
        if path:
            return '/iinterfaces/' + path
        else:
            return '/iinterfaces'

    def _create_host(self, personality, subfunction=None,
                     mgmt_mac=None, mgmt_ip=None,
                     sdn_enabled=True, admin=None,
                     invprovision=constants.PROVISIONED):
        if personality == constants.CONTROLLER:
            self.system = dbutils.create_test_isystem(sdn_enabled=sdn_enabled)
            self.address_pool1 = dbutils.create_test_address_pool(
                id=1,
                network='192.168.204.0',
                name='management',
                ranges=[['192.168.204.2', '192.168.204.254']],
                prefix=24)
            self.address_pool2 = dbutils.create_test_address_pool(
                id=2,
                network='192.168.205.0',
                name='infrastructure',
                ranges=[['192.168.205.2', '192.168.205.254']],
                prefix=24)
            self.address_pool_oam = dbutils.create_test_address_pool(
                id=3,
                network='128.224.150.0',
                name='oam',
                ranges=[['128.224.150.1', '128.224.151.254']],
                prefix=23)
            self.address_pool_v6 = dbutils.create_test_address_pool(
                id=4,
                network='abde::',
                name='ipv6',
                ranges=[['abde::2', 'abde::ffff:ffff:ffff:fffe']],
                prefix=64)
            self.address_pool_pxeboot = dbutils.create_test_address_pool(
                id=5,
                network='192.168.202.0',
                name='pxeboot',
                ranges=[['192.168.202.2', '192.168.202.254']],
                prefix=23)
            self.mgmt_network = dbutils.create_test_network(
                id=1,
                type=constants.NETWORK_TYPE_MGMT,
                link_capacity=1000,
                vlan_id=2,
                address_pool_id=self.address_pool1.id)
            self.infra_network = dbutils.create_test_network(
                id=2,
                type=constants.NETWORK_TYPE_INFRA,
                link_capacity=10000,
                vlan_id=3,
                address_pool_id=self.address_pool2.id)
            self.oam_network = dbutils.create_test_network(
                id=3,
                type=constants.NETWORK_TYPE_OAM,
                address_pool_id=self.address_pool_oam.id)
            self.oam_address = dbutils.create_test_address(
                family=2,
                address='10.10.10.3',
                prefix=24,
                name='controller-0-oam',
                address_pool_id=self.address_pool_oam.id)
            self.pxeboot_address = dbutils.create_test_address(
                family=2,
                address='192.168.202.3',
                prefix=24,
                name='controller-0-pxeboot',
                address_pool_id=self.address_pool_pxeboot.id)

        host = dbutils.create_test_ihost(
            hostname='%s-0' % personality,
            forisystemid=self.system.id,
            personality=personality,
            subfunctions=subfunction or personality,
            mgmt_mac=mgmt_mac,
            mgmt_ip=mgmt_ip,
            administrative=admin or constants.ADMIN_UNLOCKED,
            invprovision=invprovision
        )
        if personality == constants.CONTROLLER:
            self.controller = host
        else:
            self.compute = host
        return

    def _create_ethernet(self, ifname=None, networktype=None,
                         providernetworks=None, host=None, expect_errors=False):
        if isinstance(networktype, list):
            networktype = ','.join(networktype)
        interface_id = len(self.profile['interfaces']) + 1
        if not ifname:
            ifname = (networktype or 'eth') + str(interface_id)
        if not host:
            host = self.controller

        port_id = len(self.profile['ports'])
        port = dbutils.create_test_ethernet_port(
            id=port_id,
            name='eth' + str(port_id),
            host_id=host.id,
            interface_id=interface_id,
            pciaddr='0000:00:00.' + str(port_id + 1),
            dev_id=0)

        interface_uuid = None
        if not networktype:
            interface = dbutils.create_test_interface(ifname=ifname,
                                                      forihostid=host.id,
                                                      ihost_uuid=host.uuid)
            interface_uuid = interface.uuid
        else:
            interface = dbutils.post_get_test_interface(
                ifname=ifname,
                networktype=networktype,
                providernetworks=providernetworks,
                forihostid=host.id, ihost_uuid=host.uuid)

            response = self._post_and_check(interface, expect_errors)
            if expect_errors is False:
                interface_uuid = response.json['uuid']
                interface['uuid'] = interface_uuid

        self.profile['interfaces'].append(interface)
        self.profile['ports'].append(port)

        return port, interface

    def _create_bond(self, ifname, networktype=None,
                     providernetworks=None, host=None, expect_errors=False):
        if not host:
            host = self.controller
        port1, iface1 = self._create_ethernet(host=host)
        port2, iface2 = self._create_ethernet(host=host)
        interface_id = len(self.profile['interfaces'])
        if not ifname:
            ifname = (networktype or 'eth') + str(interface_id)
        interface = dbutils.post_get_test_interface(
            id=interface_id,
            ifname=ifname,
            iftype=constants.INTERFACE_TYPE_AE,
            networktype=networktype,
            uses=[iface1['ifname'], iface2['ifname']],
            txhashpolicy='layer2',
            providernetworks=providernetworks,
            forihostid=host.id, ihost_uuid=host.uuid)

        lacp_types = [constants.NETWORK_TYPE_MGMT,
                      constants.NETWORK_TYPE_PXEBOOT]
        if networktype in lacp_types:
            interface['aemode'] = '802.3ad'
        else:
            interface['aemode'] = 'balanced'

        response = self._post_and_check(interface, expect_errors)
        if expect_errors is False:
            interface_uuid = response.json['uuid']
            interface['uuid'] = interface_uuid

        iface1['used_by'].append(interface['ifname'])
        iface2['used_by'].append(interface['ifname'])
        self.profile['interfaces'].append(interface)
        return interface

    def _create_compute_bond(self, ifname, networktype=None,
                             providernetworks=None, expect_errors=False):
        return self._create_bond(ifname, networktype, providernetworks,
                                 self.compute, expect_errors)

    def _create_vlan(self, ifname, networktype, vlan_id,
                     lower_iface=None, providernetworks=None, host=None,
                     expect_errors=False):
        if not host:
            host = self.controller
        if not lower_iface:
            lower_port, lower_iface = self._create_ethernet(host=host)
        if not ifname:
            ifname = 'vlan' + str(vlan_id)
        interface = dbutils.post_get_test_interface(
            ifname=ifname,
            iftype=constants.INTERFACE_TYPE_VLAN,
            networktype=networktype,
            vlan_id=vlan_id,
            uses=[lower_iface['ifname']],
            providernetworks=providernetworks,
            forihostid=host.id, ihost_uuid=host.uuid)

        self._post_and_check(interface, expect_errors)
        self.profile['interfaces'].append(interface)
        return interface

    def _create_compute_vlan(self, ifname, networktype, vlan_id,
                             lower_iface=None, providernetworks=None,
                             host=None, expect_errors=False):
        return self._create_vlan(ifname, networktype, vlan_id, lower_iface,
                                 providernetworks, self.compute, expect_errors)

    def _post_and_check_success(self, ndict):
        response = self.post_json('%s' % self._get_path(), ndict)
        self.assertEqual(http_client.OK, response.status_int)
        return response

    def _post_and_check_failure(self, ndict):
        response = self.post_json('%s' % self._get_path(), ndict,
                                  expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

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

    def _create_and_apply_profile(self, host):
        ifprofile = {
            'ihost_uuid': host.uuid,
            'profilename': 'ifprofile-node1',
            'profiletype': constants.PROFILE_TYPE_INTERFACE
        }
        response = self.post_json('/iprofile', ifprofile)
        self.assertEqual(http_client.OK, response.status_int)

        list_data = self.get_json('/iprofile')
        profile_uuid = list_data['iprofiles'][0]['uuid']

        self.get_json('/iprofile/%s/iinterfaces' % profile_uuid)
        self.get_json('/iprofile/%s/ethernet_ports' % profile_uuid)

        result = self.patch_dict_json('/ihosts/%s' % host.id,
                                      headers={'User-Agent': 'sysinv'},
                                      action=constants.APPLY_PROFILE_ACTION,
                                      iprofile_uuid=profile_uuid)
        self.assertEqual(http_client.OK, result.status_int)

    def is_interface_equal(self, first, second):
        for key in first:
            if key in second:
                self.assertEqual(first[key], second[key])

    def _setup_context(self):
        self.profile = {'host':
                        {'personality': constants.CONTROLLER,
                         'hostname': constants.CONTROLLER_0_HOSTNAME},
                        'interfaces': [],
                        'ports': [],
                        'addresses': [],
                        'routes': []}
        self.system = None
        self.controller = None
        self.compute = None
        self._setup_configuration()

    def test_interface(self):
        if len(self.profile['interfaces']) == 0:
            self.assertFalse(False)


class InterfaceControllerEthernet(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # ethernet interfaces.
        self._create_host(constants.CONTROLLER, admin=constants.ADMIN_LOCKED)
        self._create_ethernet('oam', constants.NETWORK_TYPE_OAM)
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_ethernet('infra', constants.NETWORK_TYPE_INFRA)
        self.get_json('/ihosts/%s/iinterfaces' % self.controller.uuid)

    def setUp(self):
        super(InterfaceControllerEthernet, self).setUp()

    def test_controller_ethernet_profile(self):
        self._create_and_apply_profile(self.controller)


class InterfaceControllerBond(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # aggregated ethernet interfaces.
        self._create_host(constants.CONTROLLER, admin=constants.ADMIN_LOCKED)
        self._create_bond('oam', constants.NETWORK_TYPE_OAM)
        self._create_bond('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_bond('infra', constants.NETWORK_TYPE_INFRA)

    def setUp(self):
        super(InterfaceControllerBond, self).setUp()

    def test_controller_bond_profile(self):
        self._create_and_apply_profile(self.controller)


class InterfaceControllerVlanOverBond(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # vlan interfaces over aggregated ethernet interfaces
        self._create_host(constants.CONTROLLER, admin=constants.ADMIN_LOCKED)
        bond = self._create_bond('pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM, 1, bond)
        self._create_vlan('mgmt', constants.NETWORK_TYPE_MGMT, 2, bond)
        self._create_vlan('infra', constants.NETWORK_TYPE_INFRA, 3, bond)
        # self._create_ethernet('none')

    def setUp(self):
        super(InterfaceControllerVlanOverBond, self).setUp()

    def test_controller_vlan_over_bond_profile(self):
        self._create_and_apply_profile(self.controller)


class InterfaceControllerVlanOverEthernet(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # vlan interfaces over ethernet interfaces
        self._create_host(constants.CONTROLLER, admin=constants.ADMIN_LOCKED)
        port, iface = self._create_ethernet(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM, 1, iface)
        self._create_vlan('mgmt', constants.NETWORK_TYPE_MGMT, 2, iface)
        self._create_vlan('infra', constants.NETWORK_TYPE_INFRA, 3, iface)
        # self._create_ethernet_profile('none')

    def setUp(self):
        super(InterfaceControllerVlanOverEthernet, self).setUp()

    def test_controller_vlan_over_ethernet_profile(self):
        self._create_and_apply_profile(self.controller)


class InterfaceComputeEthernet(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # compute and all interfaces are ethernet interfaces.
        self._create_host(constants.CONTROLLER, admin=constants.ADMIN_UNLOCKED)
        self._create_ethernet('oam', constants.NETWORK_TYPE_OAM)
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_ethernet('infra', constants.NETWORK_TYPE_INFRA)

        self._create_host(constants.COMPUTE, constants.COMPUTE,
                          mgmt_mac='01:02.03.04.05.C0',
                          mgmt_ip='192.168.24.12',
                          admin=constants.ADMIN_LOCKED)
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.compute)
        self._create_ethernet('infra', constants.NETWORK_TYPE_INFRA,
                              host=self.compute)
        # self._create_ethernet('vrs', constants.NETWORK_TYPE_DATA_VRS,
        #                       host=self.compute)
        self._create_ethernet('data', constants.NETWORK_TYPE_DATA,
                              'group0-data0', host=self.compute)
        self._create_ethernet('sriov', constants.NETWORK_TYPE_PCI_SRIOV,
                              'group0-data1', host=self.compute)
        self._create_ethernet('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              'group0-ext0', host=self.compute)
        port, iface = (
            self._create_ethernet('slow', constants.NETWORK_TYPE_DATA,
                                  'group0-ext1', host=self.compute))
        port['dpdksupport'] = False
        port, iface = (
            self._create_ethernet('mlx4', constants.NETWORK_TYPE_DATA,
                                  'group0-ext2', host=self.compute))
        port['driver'] = 'mlx4_core'
        port, iface = (
            self._create_ethernet('mlx5', constants.NETWORK_TYPE_DATA,
                                  'group0-ext3', host=self.compute))
        port['driver'] = 'mlx5_core'

    def setUp(self):
        super(InterfaceComputeEthernet, self).setUp()

    def test_compute_ethernet_profile(self):
        self._create_and_apply_profile(self.compute)


class InterfaceComputeVlanOverEthernet(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller and all interfaces are vlan interfaces over ethernet
        # interfaces.
        self._create_host(constants.CONTROLLER)
        port, iface = self._create_ethernet(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM, 1, iface)
        self._create_vlan('mgmt', constants.NETWORK_TYPE_MGMT, 2, iface)
        self._create_vlan('infra', constants.NETWORK_TYPE_INFRA, 3, iface)

        # Setup a sample configuration where the personality is set to a
        # compute and all interfaces are vlan interfaces over ethernet
        # interfaces.
        self._create_host(constants.COMPUTE, admin=constants.ADMIN_LOCKED)
        port, iface = self._create_ethernet(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT, host=self.compute)
        self._create_compute_vlan('mgmt', constants.NETWORK_TYPE_MGMT, 2, iface)
        self._create_compute_vlan('infra', constants.NETWORK_TYPE_INFRA, 3)
        # self._create_vlan('vrs', constants.NETWORK_TYPE_DATA_VRS, 4, host=self.compute)
        self._create_compute_vlan('data', constants.NETWORK_TYPE_DATA, 5,
                                  providernetworks='group0-ext0')
        self._create_ethernet('sriov', constants.NETWORK_TYPE_PCI_SRIOV,
                              'group0-data0', host=self.compute)
        self._create_ethernet('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              'group0-data1', host=self.compute)

    def setUp(self):
        super(InterfaceComputeVlanOverEthernet, self).setUp()

    def test_compute_vlan_over_ethernet_profile(self):
        self._create_and_apply_profile(self.compute)


class InterfaceComputeBond(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # aggregated ethernet interfaces.
        self._create_host(constants.CONTROLLER, admin=constants.ADMIN_UNLOCKED)
        self._create_bond('oam', constants.NETWORK_TYPE_OAM)
        self._create_bond('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_bond('infra', constants.NETWORK_TYPE_INFRA)

        # Setup a sample configuration where the personality is set to a
        # compute and all interfaces are aggregated ethernet interfaces.
        self._create_host(constants.COMPUTE, admin=constants.ADMIN_LOCKED)
        self._create_compute_bond('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_compute_bond('infra', constants.NETWORK_TYPE_INFRA)
        # self._create_bond('vrs', constants.NETWORK_TYPE_DATA_VRS, host=self.compute)
        self._create_compute_bond('data', constants.NETWORK_TYPE_DATA,
                                  providernetworks='group0-data0')
        self._create_ethernet('sriov', constants.NETWORK_TYPE_PCI_SRIOV,
                              'group0-ext0', host=self.compute)
        self._create_ethernet('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              'group0-ext1', host=self.compute)

    def setUp(self):
        super(InterfaceComputeBond, self).setUp()

    def test_compute_bond_profile(self):
        self._create_and_apply_profile(self.compute)


class InterfaceComputeVlanOverBond(InterfaceTestCase):

    def _setup_configuration(self):
        self._create_host(constants.CONTROLLER)
        bond = self._create_bond('pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM, 1, bond)
        self._create_vlan('mgmt', constants.NETWORK_TYPE_MGMT, 2, bond)
        self._create_vlan('infra', constants.NETWORK_TYPE_INFRA, 3, bond)

        # Setup a sample configuration where the personality is set to a
        # compute and all interfaces are vlan interfaces over aggregated
        # ethernet interfaces.
        self._create_host(constants.COMPUTE, admin=constants.ADMIN_LOCKED)
        bond = self._create_compute_bond('pxeboot',
                                         constants.NETWORK_TYPE_PXEBOOT)
        self._create_compute_vlan('mgmt', constants.NETWORK_TYPE_MGMT, 2, bond)
        self._create_compute_vlan('infra', constants.NETWORK_TYPE_INFRA, 3,
                                  bond)
        # bond1 = self._create_bond('bond3', providernetworks='group0-data0',
        #                           host=self.compute)
        # self._create_vlan('vrs', constants.NETWORK_TYPE_DATA_VRS, 4, bond1,
        #                   host=self.compute)
        bond2 = self._create_compute_bond('bond2', constants.NETWORK_TYPE_NONE)
        self._create_compute_vlan('data', constants.NETWORK_TYPE_DATA, 5, bond2,
                                  providernetworks='group0-ext0')

        bond3 = self._create_compute_bond('bond3', constants.NETWORK_TYPE_NONE)

        self._create_ethernet('sriov', constants.NETWORK_TYPE_PCI_SRIOV,
                              'group0-data0', host=self.compute)
        self._create_ethernet('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              'group0-data1', host=self.compute)

    def setUp(self):
        super(InterfaceComputeVlanOverBond, self).setUp()

    def test_compute_vlan_over_bond_profile(self):
        self._create_and_apply_profile(self.compute)


class InterfaceComputeVlanOverDataEthernet(InterfaceTestCase):

    def _setup_configuration(self):
        self._create_host(constants.CONTROLLER)
        bond = self._create_bond('pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM, 1, bond)
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_ethernet('infra', constants.NETWORK_TYPE_INFRA)

        # Setup a sample configuration where the personality is set to a
        # compute and all interfaces are vlan interfaces over data ethernet
        # interfaces.
        self._create_host(constants.COMPUTE, admin=constants.ADMIN_LOCKED)
        port, iface = (
            self._create_ethernet('data',
                                  [constants.NETWORK_TYPE_DATA],
                                  'group0-data0', host=self.compute))
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.compute)
        self._create_ethernet('infra', constants.NETWORK_TYPE_INFRA,
                              host=self.compute)

        # self._create_vlan('vrs', constants.NETWORK_TYPE_DATA_VRS, 4,
        #                   lower_iface=iface, host=self.compute)
        self._create_compute_vlan('data2', constants.NETWORK_TYPE_DATA, 5,
                                  iface, providernetworks='group0-ext0')
        self._create_ethernet('sriov', constants.NETWORK_TYPE_PCI_SRIOV,
                              'group0-ext1', host=self.compute)
        self._create_ethernet('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              'group0-ext2', host=self.compute)

    def setUp(self):
        super(InterfaceComputeVlanOverDataEthernet, self).setUp()

    def test_compute_vlan_over_data_ethernet_profile(self):
        self._create_and_apply_profile(self.compute)


class InterfaceCpeEthernet(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a compute subfunction and all interfaces are
        # ethernet interfaces.
        self._create_host(constants.CONTROLLER, constants.COMPUTE,
                          admin=constants.ADMIN_LOCKED)
        self._create_ethernet('oam', constants.NETWORK_TYPE_OAM)
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_ethernet('infra', constants.NETWORK_TYPE_INFRA)
        # self._create_ethernet('vrs', constants.NETWORK_TYPE_DATA_VRS)
        self._create_ethernet('data', constants.NETWORK_TYPE_DATA,
                              'group0-data0')
        self._create_ethernet('sriov', constants.NETWORK_TYPE_PCI_SRIOV,
                              'group0-data1')
        self._create_ethernet('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              'group0-ext0')
        self._create_ethernet('ptsriov',
                              constants.NETWORK_TYPE_PCI_PASSTHROUGH + ',' +
                              constants.NETWORK_TYPE_PCI_SRIOV,
                              'group0-ext0')
        port, iface = (
            self._create_ethernet('slow', constants.NETWORK_TYPE_DATA,
                                  'group0-ext1'))
        port['dpdksupport'] = False
        port, iface = (
            self._create_ethernet('mlx4', constants.NETWORK_TYPE_DATA,
                                  'group0-ext2'))
        port['driver'] = 'mlx4_core'
        port, iface = (
            self._create_ethernet('mlx5', constants.NETWORK_TYPE_DATA,
                                  'group0-ext3'))

    def setUp(self):
        super(InterfaceCpeEthernet, self).setUp()

    def test_cpe_ethernet_profile(self):
        self._create_and_apply_profile(self.controller)


class InterfaceCpeVlanOverEthernet(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a compute subfunction and all interfaces are
        # vlan interfaces over ethernet interfaces.
        self._create_host(constants.CONTROLLER, constants.COMPUTE,
                          admin=constants.ADMIN_LOCKED)
        port, iface = self._create_ethernet(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM, 1, iface)
        self._create_vlan('mgmt', constants.NETWORK_TYPE_MGMT, 2, iface)
        self._create_vlan('infra', constants.NETWORK_TYPE_INFRA, 3)
        # self._create_vlan('vrs', constants.NETWORK_TYPE_DATA_VRS, 4)

        self._create_ethernet('data', constants.NETWORK_TYPE_DATA,
                              providernetworks='group0-ext0')
        self._create_ethernet('sriov', constants.NETWORK_TYPE_PCI_SRIOV,
                              'group0-ext1')
        self._create_ethernet('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              'group0-ext2')

    def setUp(self):
        super(InterfaceCpeVlanOverEthernet, self).setUp()

    def test_cpe_vlan_over_ethernet_profile(self):
        self._create_and_apply_profile(self.controller)


class InterfaceCpeBond(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a compute subfunction and all interfaces are
        # aggregated ethernet interfaces.
        self._create_host(constants.CONTROLLER,
                          subfunction=constants.COMPUTE,
                          admin=constants.ADMIN_LOCKED)
        self._create_bond('oam', constants.NETWORK_TYPE_OAM)
        self._create_bond('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_bond('infra', constants.NETWORK_TYPE_INFRA)
        # self._create_bond('vrs', constants.NETWORK_TYPE_DATA_VRS)
        self._create_bond('data', constants.NETWORK_TYPE_DATA,
                          providernetworks='group0-data0')
        self._create_ethernet('sriov', constants.NETWORK_TYPE_PCI_SRIOV,
                              providernetworks='group0-ext0')
        self._create_ethernet('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              providernetworks='group0-ext1')

    def setUp(self):
        super(InterfaceCpeBond, self).setUp()

    def test_cpe_bond_profile(self):
        self._create_and_apply_profile(self.controller)


class InterfaceCpeVlanOverBond(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a compute subfunction and all interfaces are
        # vlan interfaces over aggregated ethernet interfaces.
        self._create_host(constants.CONTROLLER, constants.COMPUTE,
                          admin=constants.ADMIN_LOCKED)
        bond = self._create_bond('pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM, 1, bond)
        self._create_vlan('mgmt', constants.NETWORK_TYPE_MGMT, 2, bond)
        self._create_vlan('infra', constants.NETWORK_TYPE_INFRA, 3, bond)
        # bond1 = self._create_bond('bond3')
        # self._create_vlan('vrs', constants.NETWORK_TYPE_DATA_VRS, 4, bond1)
        bond2 = self._create_bond('bond4', constants.NETWORK_TYPE_NONE)
        self._create_vlan('data', constants.NETWORK_TYPE_DATA, 5, bond2,
                          providernetworks='group0-ext0')
        self._create_ethernet('sriov', constants.NETWORK_TYPE_PCI_SRIOV,
                              'group0-ext1')
        self._create_ethernet('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              'group0-ext2')

    def setUp(self):
        super(InterfaceCpeVlanOverBond, self).setUp()

    def test_cpe_vlan_over_bond_profile(self):
        self._create_and_apply_profile(self.controller)


# Test that the unsupported config is rejected
class InterfaceCpeVlanOverDataEthernet(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a compute subfunction and all interfaces are
        # vlan interfaces over data ethernet interfaces.
        self._create_host(constants.CONTROLLER, constants.COMPUTE,
                          admin=constants.ADMIN_LOCKED)
        port, iface = (
            self._create_ethernet('data',
                                  constants.NETWORK_TYPE_DATA,
                                  'group0-data0'))
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM, 1, iface,
                          expect_errors=True)
        self._create_vlan('mgmt', constants.NETWORK_TYPE_MGMT, 2, iface,
                          expect_errors=True)
        self._create_vlan('infra', constants.NETWORK_TYPE_INFRA, 3, iface,
                          expect_errors=True)
        # self._create_vlan('vrs', constants.NETWORK_TYPE_DATA_VRS, 4, iface)
        self._create_vlan('data2', constants.NETWORK_TYPE_DATA, 5, iface,
                          providernetworks='group0-ext0',
                          expect_errors=False)
        self._create_ethernet('sriov', constants.NETWORK_TYPE_PCI_SRIOV,
                              providernetworks='group0-ext1',
                              expect_errors=False)
        self._create_ethernet('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              providernetworks='group0-ext2',
                              expect_errors=False)

    def setUp(self):
        super(InterfaceCpeVlanOverDataEthernet, self).setUp()


class TestList(InterfaceTestCase):

    def setUp(self):
        super(TestList, self).setUp()
        self.system = dbutils.create_test_isystem()
        self.load = dbutils.create_test_load()
        self.host = dbutils.create_test_ihost(forisystemid=self.system.id)
        self.port = dbutils.create_test_ethernet_port(host_id=self.host.id)

    def test_list_interface(self):
        interface = dbutils.create_test_interface(forihostid='1')
        data = self.get_json('/ihosts/%s/iinterfaces' % self.host['uuid'])
        self.assertIn('ifname', data['iinterfaces'][0])
        self.assertEqual(interface.uuid, data['iinterfaces'][0]["uuid"])
        self.is_interface_equal(interface.as_dict(), data['iinterfaces'][0])


class TestPatch(InterfaceTestCase):
    def setUp(self):
        super(TestPatch, self).setUp()
        self._create_host(constants.CONTROLLER)
        self._create_host(constants.COMPUTE, admin=constants.ADMIN_LOCKED)

    def test_modify_ifname(self):
        interface = dbutils.create_test_interface(forihostid='1')
        response = self.patch_dict_json(
            '%s' % self._get_path(interface.uuid),
            ifname='new_name')
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual('new_name', response.json['ifname'])

    def test_modify_mtu(self):
        interface = dbutils.create_test_interface(forihostid='1')
        response = self.patch_dict_json(
            '%s' % self._get_path(interface.uuid),
            imtu=1600)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual(1600, response.json['imtu'])

    def test_interface_usesmodify_success(self):
        data_bond = self._create_bond('data', constants.NETWORK_TYPE_DATA,
                                      providernetworks='group0-data0',
                                      host=self.compute)

        port, new_ethernet = self._create_ethernet(
            'new', constants.NETWORK_TYPE_NONE, host=self.compute)
        # Modify AE interface to add another port
        uses = ','.join(data_bond['uses'])
        patch_result = self.patch_dict_json(
            '%s' % self._get_path(data_bond['uuid']),
            usesmodify=uses + ',' + new_ethernet['uuid'])
        self.assertEqual('application/json', patch_result.content_type)
        self.assertEqual(http_client.OK, patch_result.status_code)

    # Expected error: Interface MTU (%s) cannot be smaller than the interface
    # MTU (%s) using this interface
    def test_mtu_smaller_than_users(self):
        port, lower_interface = self._create_ethernet(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT, host=self.compute)
        upper = dbutils.create_test_interface(
            forihostid='2',
            ihost_uuid=self.compute.uuid,
            ifname='data0',
            networktype=constants.NETWORK_TYPE_DATA,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            providernetworks='group0-data0',
            aemode='balanced',
            txhashpolicy='layer2',
            uses=['pxeboot'],
            imtu=1600)
        response = self.patch_dict_json(
            '%s' % self._get_path(lower_interface['uuid']), imtu=1400,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    # Expected error: VLAN MTU ___ cannot be larger than MTU of underlying
    # interface ___
    def test_vlan_mtu_smaller_than_users(self):
        port, lower_interface = self._create_ethernet(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT, host=self.compute)
        upper = dbutils.create_test_interface(
            forihostid='2',
            ihost_uuid=self.compute.uuid,
            ifname='data0',
            networktype=constants.NETWORK_TYPE_DATA,
            iftype=constants.INTERFACE_TYPE_VLAN,
            vlan_id=100,
            providernetworks='group0-ext0',
            aemode='balanced',
            txhashpolicy='layer2',
            uses=['pxeboot'],
            imtu=1500)
        response = self.patch_dict_json(
            '%s' % self._get_path(upper['uuid']), imtu=1800,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    # Expected error: The network type of an interface cannot be changed without
    # first being reset back to none
    def test_invalid_change_networktype(self):
        port, interface = self._create_ethernet('oam',
                                                constants.NETWORK_TYPE_OAM)
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            networktype=constants.NETWORK_TYPE_MGMT, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])


class TestPost(InterfaceTestCase):
    def setUp(self):
        super(TestPost, self).setUp()
        self._create_host(constants.CONTROLLER)
        self._create_host(constants.COMPUTE, admin=constants.ADMIN_LOCKED)

    # Expected error: The oam network type is only supported on controller nodes
    def test_invalid_oam_on_compute(self):
        self._create_ethernet('oam', constants.NETWORK_TYPE_OAM,
                              host=self.compute, expect_errors=True)

    # Expected error: The pci-passthrough, pci-sriov network types are only
    # valid on Ethernet interfaces
    def test_invalid_iftype_for_pci_network_type(self):
        self._create_bond('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                          host=self.compute, expect_errors=True)

    # Expected error: The ___ network type is only supported on nodes supporting
    # compute functions
    def test_invalid_network_type_on_noncompute(self):
        self._create_ethernet('data0', constants.NETWORK_TYPE_DATA,
                              providernetworks='group0-ext0',
                              expect_errors=True)

    # Expected error: Interface name cannot be whitespace.
    def test_invalid_whitespace_interface_name(self):
        self._create_ethernet('   ', constants.NETWORK_TYPE_DATA,
                              providernetworks='group0-ext0',
                              expect_errors=True)

    # Expected error: Interface name must be in lower case.
    def test_invalid_uppercase_interface_name(self):
        self._create_ethernet('miXedCaSe', constants.NETWORK_TYPE_DATA,
                              providernetworks='group0-ext0',
                              expect_errors=True)

    # Expected error: Cannot use special characters in interface name.
    def test_invalid_character_interface_name(self):
        self._create_ethernet('bad-name', constants.NETWORK_TYPE_DATA,
                              providernetworks='group0-ext0',
                              expect_errors=True)

    # Expected error: Interface ___ has name length greater than 10.
    def test_invalid_interface_name_length(self):
        self._create_ethernet('0123456789a', constants.NETWORK_TYPE_OAM,
                              expect_errors=True)

    # Expected message: Name must be unique
    def test_create_duplicate_interface_name(self):
        self._create_ethernet('data0', constants.NETWORK_TYPE_DATA,
                              providernetworks='group0-data0',
                              host=self.compute)
        self._create_ethernet('data0', constants.NETWORK_TYPE_DATA,
                              providernetworks='group0-ext0',
                              host=self.compute,
                              expect_errors=True)

    def test_ipv4_mode_valid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.controller.uuid,
            ifname='name',
            networktype=constants.NETWORK_TYPE_MGMT,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_POOL,
            ipv4_pool=self.address_pool1.uuid)
        self._post_and_check_success(ndict)

    # Expected error: Address mode attributes only supported on
    # mgmt, infra, data, data-vrs interfaces
    def test_ipv4_mode_networktype_invalid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            ifname='name',
            networktype=constants.NETWORK_TYPE_PCI_PASSTHROUGH,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_STATIC,
            ipv6_mode=constants.IPV6_STATIC,
            ipv4_pool=self.address_pool1.uuid,
            ipv6_pool=self.address_pool2.uuid)
        self._post_and_check_failure(ndict)

    # Expected error: Infrastructure static addressing is configured; IPv4
    # address mode must be static
    def test_ipv4_mode_infra_invalid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.controller.uuid,
            ifname='name',
            networktype=constants.NETWORK_TYPE_INFRA,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_DISABLED,
            ipv6_mode=constants.IPV6_DISABLED,
            ipv4_pool=self.address_pool1.uuid)
        self._post_and_check_failure(ndict)

    # Expected error: Specifying an IPv4 address pool requires setting the
    # address mode to pool
    def test_ipv4_mode_invalid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.controller.uuid,
            ifname='name',
            networktype=constants.NETWORK_TYPE_MGMT,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_DISABLED,
            ipv4_pool=self.address_pool1.uuid)
        self._post_and_check_failure(ndict)

    # Expected error: Specifying an IPv6 address pool requires setting the
    # address mode to pool
    def test_ipv6_mode_invalid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.controller.uuid,
            ifname='name',
            networktype=constants.NETWORK_TYPE_MGMT,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv6_mode=constants.IPV6_DISABLED,
            ipv6_pool=self.address_pool1.uuid)
        self._post_and_check_failure(ndict)

    # Expected error: IPv4 address pool name not specified
    def test_ipv4_mode_no_pool_invalid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            ifname='name',
            networktype=constants.NETWORK_TYPE_MGMT,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_POOL,
            ipv6_mode=constants.IPV6_POOL)
        self._post_and_check_failure(ndict)

    # Expected error: IPv6 address pool name not specified
    def test_ipv6_mode_no_pool_invalid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            ifname='name',
            networktype=constants.NETWORK_TYPE_MGMT,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_POOL,
            ipv6_mode=constants.IPV6_POOL,
            ipv4_pool=self.address_pool_v6.uuid)
        self._post_and_check_failure(ndict)

    # Expected error: Address pool IP family does not match requested family
    def test_ipv4_pool_family_mismatch_invalid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            ifname='name',
            networktype=constants.NETWORK_TYPE_MGMT,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_POOL,
            ipv6_mode=constants.IPV6_POOL,
            ipv4_pool=self.address_pool_v6.uuid,
            ipv6_pool=self.address_pool_v6.uuid)
        self._post_and_check_failure(ndict)

    # Expected error: Address pool IP family does not match requested family
    def test_ipv6_pool_family_mismatch_invalid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            ifname='name',
            networktype=constants.NETWORK_TYPE_MGMT,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_POOL,
            ipv6_mode=constants.IPV6_POOL,
            ipv4_pool=self.address_pool1.uuid,
            ipv6_pool=self.address_pool1.uuid)
        self._post_and_check_failure(ndict)

    # Expected error: Device interface type must be 'aggregated ethernet' or
    # 'vlan' or 'ethernet'.
    def test_aemode_invalid_iftype(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            providernetworks='group0-data0',
            ifname='name',
            networktype=constants.NETWORK_TYPE_DATA,
            iftype='AE',
            aemode='active_standby',
            txhashpolicy='layer2')
        self._post_and_check_failure(ndict)

    # Expected error: Device interface with interface type 'aggregated ethernet'
    #  in ___ mode should not specify a Tx Hash Policy.
    def test_aemode_no_txhash(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            providernetworks='group0-data0',
            ifname='name',
            networktype=constants.NETWORK_TYPE_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='active_standby',
            txhashpolicy='layer2')
        self._post_and_check_failure(ndict)

    # Device interface with network type ___, and interface type
    # 'aggregated ethernet' must have a Tx Hash Policy of 'layer2'.
    def test_aemode_invalid_txhash(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            ifname='name',
            networktype=constants.NETWORK_TYPE_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='balanced',
            txhashpolicy='layer2+3')
        self._post_and_check_failure(ndict)

    # Expected error: Device interface with interface type 'aggregated ethernet'
    #  in 'balanced' or '802.3ad' mode require a valid Tx Hash Policy
    def test_aemode_invalid_txhash_none(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            providernetworks='group0-data0',
            ifname='name',
            networktype=constants.NETWORK_TYPE_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='802.3ad',
            txhashpolicy=None)
        self._post_and_check_failure(ndict)

        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            providernetworks='group0-data0',
            ifname='name',
            networktype=constants.NETWORK_TYPE_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='balanced',
            txhashpolicy=None)
        self._post_and_check_failure(ndict)

    # Expected error: Device interface with network type ___, and interface type
    #  'aggregated ethernet' must be in mode '802.3ad'
    def test_aemode_invalid_mgmt(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            providernetworks='group0-data0',
            ifname='name',
            networktype=constants.NETWORK_TYPE_MGMT,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='balanced',
            txhashpolicy='layer2')
        self._post_and_check_failure(ndict)

    # Device interface with network type ___, and interface type
    # 'aggregated ethernet' must be in mode 'active_standby' or 'balanced' or
    # '802.3ad'.
    def test_aemode_invalid_data(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            providernetworks='group0-data0',
            ifname='name',
            networktype=constants.NETWORK_TYPE_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='bad_aemode',
            txhashpolicy='layer2')
        self._post_and_check_failure(ndict)

    def test_aemode_invalid_oam(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.controller.uuid,
            ifname='name',
            networktype=constants.NETWORK_TYPE_OAM,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='bad_aemode',
            txhashpolicy='layer2')
        self._post_and_check_failure(ndict)

    def test_aemode_invalid_infra(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            ifname='name',
            networktype=constants.NETWORK_TYPE_INFRA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='bad_aemode',
            txhashpolicy='layer2')
        self._post_and_check_failure(ndict)

    # Expected error: Interface ___ does not have associated infra interface
    # on controller.
    def test_no_infra_on_controller(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            ifname='name',
            networktype=constants.NETWORK_TYPE_INFRA,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            aemode='balanced',
            txhashpolicy='layer2')
        self._post_and_check_failure(ndict)

    # Expected: Setting of ___ interface MTU is not supported
    def test_setting_mgmt_mtu_disallowed(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.controller.uuid,
            ifname='mgmt0',
            networktype=constants.NETWORK_TYPE_MGMT,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            imtu=1600)
        self._post_and_check_failure(ndict)

    # Expected: Setting of infra interface MTU is not supported
    def test_setting_infra_mtu_disallowed(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.controller.uuid,
            ifname='infra0',
            networktype=constants.NETWORK_TYPE_INFRA,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            imtu=1600)
        self._post_and_check_failure(ndict)

    # Expected message: Interface eth0 is already used by another AE interface
    # bond0
    def test_create_bond_invalid_overlap_ae(self):
        bond_iface = self._create_compute_bond('bond0',
            constants.NETWORK_TYPE_DATA, providernetworks='group0-data0')
        port, iface1 = self._create_ethernet()

        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            providernetworks='group0-ext1',
            ifname='bond1',
            networktype=constants.NETWORK_TYPE_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='balanced',
            txhashpolicy='layer2',
            uses=[bond_iface['uses'][0], iface1.uuid])
        self._post_and_check_failure(ndict)

    # Expected message: VLAN id must be between 1 and 4094.
    def test_create_invalid_vlan_id(self):
        self._create_compute_vlan('vlan0', constants.NETWORK_TYPE_DATA, 4095,
                                  providernetworks='group0-ext0',
                                  expect_errors=True)

    # Expected message: Interface eth0 is already used by another VLAN
    # interface vlan0
    def test_create_bond_invalid_overlap_vlan(self):
        vlan_iface = self._create_compute_vlan('vlan0',
            constants.NETWORK_TYPE_DATA, 10, providernetworks='group0-ext0')
        port, iface1 = self._create_ethernet()

        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            providernetworks='group0-ext1',
            ifname='bond0',
            networktype=constants.NETWORK_TYPE_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='balanced',
            txhashpolicy='layer2',
            uses=[vlan_iface['uses'][0], iface1.uuid])
        self._post_and_check_failure(ndict)

    # Expected message: Can only have one interface for vlan type.
    def test_create_vlan_invalid_uses(self):
        bond_iface = self._create_compute_bond('bond0',
            constants.NETWORK_TYPE_DATA, providernetworks='group0-data0')
        port, iface1 = self._create_ethernet()

        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.compute.uuid,
            providernetworks='group0-ext1',
            ifname='bond1',
            networktype=constants.NETWORK_TYPE_DATA,
            iftype=constants.INTERFACE_TYPE_VLAN,
            aemode='balanced',
            txhashpolicy='layer2',
            uses=[bond_iface['uses'][0], iface1.uuid])
        self._post_and_check_failure(ndict)

    # Expected message: VLAN interfaces cannot be created over existing VLAN
    # interfaces
    def test_create_invalid_vlan_over_vlan(self):
        vlan_iface = self._create_compute_vlan(
            'vlan1', constants.NETWORK_TYPE_DATA, 1,
            providernetworks='group0-ext0')
        vlan_iface2 = self._create_compute_vlan('vlan2',
            constants.NETWORK_TYPE_DATA, 2,
            lower_iface=vlan_iface, providernetworks='group0-ext1',
            expect_errors=True)

    # Expected message: data VLAN cannot be created over a LAG interface with
    # network type pxeboot
    def test_create_data_vlan_over_pxeboot_lag(self):
        bond_iface = self._create_compute_bond(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        vlan_iface = self._create_compute_vlan('vlan2',
            constants.NETWORK_TYPE_DATA, 2,
            lower_iface=bond_iface, providernetworks='group0-ext1',
            expect_errors=True)

    # Expected message: data VLAN cannot be created over a LAG interface with
    # network type mgmt
    def test_create_data_vlan_over_mgmt_lag(self):
        bond_iface = self._create_compute_bond(
            'mgmt', constants.NETWORK_TYPE_MGMT)
        vlan_iface = self._create_compute_vlan(
            'vlan2', constants.NETWORK_TYPE_DATA, 2,
            lower_iface=bond_iface, providernetworks='group0-ext1',
            expect_errors=True)

    # Expected message: mgmt VLAN cannot be created over a LAG interface with
    # network type data
    def test_create_mgmt_vlan_over_data_lag(self):
        bond_iface = self._create_compute_bond(
            'data', constants.NETWORK_TYPE_DATA, providernetworks='group0-ext1')
        vlan_iface = self._create_compute_vlan(
            'mgmt', constants.NETWORK_TYPE_MGMT, 2,
            lower_iface=bond_iface, providernetworks='group0-ext1',
            expect_errors=True)

    # Expected message: The management VLAN configured on this system is 2,
    # so the VLAN configured for the mgmt interface must match.
    def test_mgmt_vlan_not_matching_in_network(self):
        vlan_iface = self._create_compute_vlan(
            'vlan2', constants.NETWORK_TYPE_MGMT, 12,
            providernetworks='group0-ext1', expect_errors=True)

    # Expected message: The management VLAN was not configured on this system,
    #  so configuring the %s interface over a VLAN is not allowed.
    def test_mgmt_vlan_not_configured_in_network(self):
        dbapi = db_api.get_instance()
        mgmt_network = dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        values = {'vlan_id': None}
        dbapi.network_update(mgmt_network.uuid, values)
        vlan_iface = self._create_compute_vlan(
            'vlan2', constants.NETWORK_TYPE_MGMT, 12,
            providernetworks='group0-ext1',
            expect_errors=True)

    # Expected message:
    #   Provider network(s) not supported for non-data interfaces.
    def test_create_nondata_provider_network(self):
        bond_iface = self._create_compute_bond(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT,
            providernetworks='group0-data0', expect_errors=True)

    # Expected message: Name must be unique
    def test_create_invalid_ae_name(self):
        self._create_ethernet('enp0s9', constants.NETWORK_TYPE_NONE)
        self._create_bond('enp0s9', constants.NETWORK_TYPE_MGMT,
                          expect_errors=True)

    # Expected message:
    # Only pxeboot,mgmt,infra network types can be combined on a single
    # interface
    def test_create_invalid_oam_data_ethernet(self):
        self._create_ethernet('shared',
            networktype=(constants.NETWORK_TYPE_OAM + ',' +
                         constants.NETWORK_TYPE_DATA),
            expect_errors=True)

    # Expected message:
    # Only pxeboot,mgmt,infra network types can be combined on a single
    # interface
    def test_create_invalid_mgmt_data_ethernet(self):
        self._create_ethernet('shared',
            networktype=(constants.NETWORK_TYPE_MGMT + ',' +
                         constants.NETWORK_TYPE_DATA),
            providernetworks='group0-data0',
            host=self.compute,
            expect_errors=True)

    # Expected message:
    # Only pxeboot,mgmt,infra network types can be combined on a single
    # interface
    def test_create_invalid_pxeboot_data_ethernet(self):
        self._create_ethernet('shared',
                              networktype=(constants.NETWORK_TYPE_DATA + ',' +
                                           constants.NETWORK_TYPE_PXEBOOT),
                              providernetworks='group0-data0',
                              host=self.compute,
                              expect_errors=True)

    # Expected message:
    # Cannot determine primary network type of interface ___ from mgmt,infra
    def test_create_invalid_mgmt_infra_ethernet(self):
        self._create_ethernet('shared',
                              networktype=(constants.NETWORK_TYPE_MGMT + ',' +
                                           constants.NETWORK_TYPE_INFRA),
                              expect_errors=True)


class TestCpePost(InterfaceTestCase):
    def setUp(self):
        super(TestCpePost, self).setUp()
        self._create_host(constants.CONTROLLER, constants.COMPUTE,
                          admin=constants.ADMIN_LOCKED)

    # Expected message:
    # Network type list may only contain at most one type
    def test_create_ae_with_networktypes(self):
        self._create_bond('bond0',
                          networktype=(constants.NETWORK_TYPE_DATA + ',' +
                                       constants.NETWORK_TYPE_PXEBOOT),
                          providernetworks='group0-data0', expect_errors=True)

    # Expected message:
    # Network type list may only contain at most one type
    def test_create_invalid_infra_data_ae(self):
        self._create_bond('shared',
            networktype=(constants.NETWORK_TYPE_INFRA + ',' +
                         constants.NETWORK_TYPE_DATA),
            providernetworks='group0-data0',
            expect_errors=True)

    # Expected message: oam VLAN cannot be created over an interface with
    # network type data
    def test_create_oam_vlan_over_data_lag(self):
        bond_iface = self._create_bond(
            'data', constants.NETWORK_TYPE_DATA, providernetworks='group0-ext1')
        vlan_iface = self._create_vlan(
            'oam', constants.NETWORK_TYPE_OAM, 2,
            lower_iface=bond_iface, providernetworks='group0-ext1',
            expect_errors=True)

    # Expected message: infra VLAN cannot be created over an interface with
    # network type data
    def test_create_infra_vlan_over_data_lag(self):
        bond_iface = self._create_bond(
            'data', constants.NETWORK_TYPE_DATA, providernetworks='group0-ext1')
        vlan_iface = self._create_vlan(
            'infra', constants.NETWORK_TYPE_INFRA, 2,
            lower_iface=bond_iface, providernetworks='group0-ext1',
            expect_errors=True)

    # Expected message: mgmt VLAN cannot be created over an interface with
    # network type data
    def test_create_mgmt_vlan_over_data_ethernet(self):
        port, iface = self._create_ethernet(
            'data', constants.NETWORK_TYPE_DATA, providernetworks='group0-ext1')
        self._create_vlan(
            'mgmt', constants.NETWORK_TYPE_MGMT, 2,
            lower_iface=iface, providernetworks='group0-ext1',
            expect_errors=True)

    # Expected message: An interface with \'oam\' network type is already
    # provisioned on this node
    def test_create_invalid_duplicate_networktype(self):
        self._create_ethernet('oam', constants.NETWORK_TYPE_OAM)
        self._create_ethernet('bad', constants.NETWORK_TYPE_OAM,
                              expect_errors=True)

    # Expected message:  VLAN id ___ already in use on interface ___
    def test_create_vlan_id_already_in_use(self):
        port, iface = self._create_ethernet('eth1', constants.NETWORK_TYPE_NONE)
        self._create_vlan('vlan1', constants.NETWORK_TYPE_DATA, 1,
                          lower_iface=iface, providernetworks='group0-ext0')
        self._create_vlan('vlan2', constants.NETWORK_TYPE_DATA, 1,
                          lower_iface=iface, providernetworks='group0-ext1',
                          expect_errors=True)

    # Expected message: Network type list may only contain at most one type
    def test_create_invalid_vlan_multiple_networktype(self):
        port, lower = self._create_ethernet('eth1', constants.NETWORK_TYPE_NONE)
        self._create_vlan('vlan2',
                          networktype=(constants.NETWORK_TYPE_MGMT + ',' +
                                       constants.NETWORK_TYPE_DATA),
                          vlan_id=2, lower_iface=lower, expect_errors=True)

    # Expected message: VLAN interfaces cannot have a network type of 'none'
    def test_create_invalid_vlan_networktype_none(self):
        port, lower = self._create_ethernet('eth1', constants.NETWORK_TYPE_NONE)
        self._create_vlan('vlan2', networktype='none',
                          vlan_id=2, lower_iface=lower, expect_errors=True)

    # Expected error: VLAN based provider network group0-data0 cannot be
    # assigned to a VLAN interface
    def test_create_invalid_vlan_with_vlan_provider_network(self):
        port, lower = self._create_ethernet('eth1', constants.NETWORK_TYPE_NONE)
        self._create_vlan('vlan2', networktype=constants.NETWORK_TYPE_DATA,
                          providernetworks='group0-data0',
                          vlan_id=2, lower_iface=lower, expect_errors=True)

    @mock.patch.object(dbsql_api.Connection, 'iinterface_destroy')
    @mock.patch.object(rpcapi.ConductorAPI, 'neutron_bind_interface')
    def test_create_neutron_bind_failed(self, mock_neutron_bind_interface,
                                        mock_iinterface_destroy):
        self._create_ethernet('enp0s9', constants.NETWORK_TYPE_NONE)
        mock_neutron_bind_interface.side_effect = [
            None,
            rpc_common.RemoteError(
                mock.Mock(status=404), 'not found')
        ]
        ndict = dbutils.post_get_test_interface(
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid,
            providernetworks='group0-ext1',
            ifname='data1',
            networktype=constants.NETWORK_TYPE_DATA,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            uses=['enp0s9'])
        self._post_and_check_failure(ndict)
        mock_neutron_bind_interface.assert_called_with(
            mock.ANY, mock.ANY, mock.ANY, constants.NETWORK_TYPE_DATA,
            mock.ANY, mock.ANY, vlans=mock.ANY, test=mock.ANY)
        mock_iinterface_destroy.assert_called_once_with(mock.ANY)

    # Expected error: At least one provider network must be selected.
    def test_create_invalid_no_provider_network(self):
        self._create_ethernet('data',
                              networktype=constants.NETWORK_TYPE_DATA,
                              expect_errors=True)

    # Expected error: Data interface data0 is already attached to this
    # Provider Network: group0-data0.
    def test_create_invalid_provider_network_used(self):
        self._create_ethernet('data0',
                              networktype=constants.NETWORK_TYPE_DATA,
                              providernetworks='group0-data0')
        self._create_ethernet('data1',
                              networktype=constants.NETWORK_TYPE_DATA,
                              providernetworks='group0-data0',
                              expect_errors=True)

    # Expected error: Provider network \'group0-dataXX\' does not exist.
    def test_create_invalid_provider_network_not_exist(self):
        self._create_ethernet('data0',
                              networktype=constants.NETWORK_TYPE_DATA,
                              providernetworks='group0-dataXX',
                              expect_errors=True)

    # Expected error: Specifying duplicate provider network 'group0-data1'
    # is not permitted
    def test_create_invalid_duplicate_provider_network(self):
        self._create_ethernet('data0',
                              networktype=constants.NETWORK_TYPE_DATA,
                              providernetworks='group0-data1,group0-data1',
                              expect_errors=True)

    # Expected error: Unexpected interface network type list data
    @mock.patch.object(api_if_v1, '_neutron_providernet_extension_supported')
    def test_create_invalid_non_vswitch(self,
                                        mock_providernet_extension_supported):
        mock_providernet_extension_supported.return_value = False
        self._create_ethernet('data0',
                              networktype=constants.NETWORK_TYPE_DATA,
                              providernetworks='group0-data1',
                              expect_errors=True)


class TestCpePatch(InterfaceTestCase):
    def setUp(self):
        super(TestCpePatch, self).setUp()
        self._create_host(constants.CONTROLLER, constants.COMPUTE,
                          admin=constants.ADMIN_LOCKED)

    def test_create_invalid_infra_data_ethernet(self):
        self._create_ethernet('shared',
                              networktype=(constants.NETWORK_TYPE_INFRA + ',' +
                                           constants.NETWORK_TYPE_DATA),
                              providernetworks='group0-data0',
                              expect_errors=True)

    @mock.patch.object(rpcapi.ConductorAPI, 'neutron_bind_interface')
    def test_patch_neutron_bind_failed(self, mock_neutron_bind_interface):
        port, interface = self._create_ethernet(
            'data0', networktype=constants.NETWORK_TYPE_DATA,
            providernetworks='group0-data0')

        mock_neutron_bind_interface.side_effect = [
            None,
            rpc_common.RemoteError(
                mock.Mock(return_value={'status': 404}), 'not found'),
            None]

        patch_result = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            imtu=2000, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_result.status_int)
        self.assertEqual('application/json', patch_result.content_type)
        self.assertTrue(patch_result.json['error_message'])

    # Expected error: Value for number of SR-IOV VFs must be > 0.
    def test_invalid_sriov_numvfs(self):
        port, interface = self._create_ethernet('eth0',
                                                constants.NETWORK_TYPE_NONE)
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            networktype=constants.NETWORK_TYPE_PCI_SRIOV, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)

    # Expected error: At most one port must be enabled.
    def test_invalid_sriov_no_port(self):
        interface = dbutils.create_test_interface(forihostid='1')
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']), sriov_numvfs=1,
            networktype=constants.NETWORK_TYPE_PCI_SRIOV, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)

    # Expected error: SR-IOV can't be configured on this interface
    def test_invalid_sriov_totalvfs_zero(self):
        interface = dbutils.create_test_interface(forihostid='1')
        port = dbutils.create_test_ethernet_port(
            id=1, name='eth1', host_id=1, interface_id=interface.id,
            pciaddr='0000:00:00.11', dev_id=0, sriov_totalvfs=0, sriov_numvfs=1)
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            networktype=constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=1,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)

    # Expected error: The interface support a maximum of ___ VFs
    def test_invalid_sriov_exceeded_totalvfs(self):
        interface = dbutils.create_test_interface(forihostid='1')
        port = dbutils.create_test_ethernet_port(
            id=1, name='eth1', host_id=1, interface_id=interface.id,
            pciaddr='0000:00:00.11', dev_id=0, sriov_totalvfs=1, sriov_numvfs=1,
            driver=None)
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            networktype=constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=2,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)

    # Expected error: Corresponding port has invalid driver
    def test_invalid_driver_for_sriov(self):
        interface = dbutils.create_test_interface(forihostid='1')
        port = dbutils.create_test_ethernet_port(
            id=1, name='eth1', host_id=1, interface_id=interface.id,
            pciaddr='0000:00:00.11', dev_id=0, sriov_totalvfs=1, sriov_numvfs=1,
            driver=None)
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            networktype=constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=1,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
