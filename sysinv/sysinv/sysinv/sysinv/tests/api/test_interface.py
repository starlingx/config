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
from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils
from sysinv.db import api as db_api


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
                "id": "da9f7bb1-2114-4ffd-8a4c-9ca215d98fa4",
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
                "id": "da9f7bb1-2114-4ffd-8a4c-9ca215d98fa5",
                "name": "group0-ext3"},
            'group0-flat': {
                "status": "ACTIVE", "description": None,
                "mtu": 1500,
                "ranges": [{"description": None, "minimum": 4,
                            "id": "72f21b11-6d17-486e-a4e6-4eaf5f00f23e",
                            "name": "group0-flat-r0-0",
                            "tenant_id": None, "maximum": 4,
                            "shared": True,
                            "vxlan": {"group": "239.0.2.1",
                                      "port": 8472, "ttl": 10}}],
                "vlan_transparent": False,
                "type": "flat",
                "id": "da9f7bb1-2114-4ffd-8a4c-9ca215d98fa6",
                "name": "group0-flat"}
}


class InterfaceTestCase(base.FunctionalTest):
    def _setup_configuration(self):
        pass

    def setUp(self):
        super(InterfaceTestCase, self).setUp()
        self.dbapi = db_api.get_instance()

        p = mock.patch.object(api_if_v1, '_get_lower_interface_macs')
        self.mock_lower_macs = p.start()
        self.mock_lower_macs.return_value = {'enp0s18': '08:00:27:8a:87:48',
                                             'enp0s19': '08:00:27:ea:93:8e'}
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
                network='192.168.206.0',
                name='cluster-host',
                ranges=[['192.168.206.2', '192.168.206.254']],
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
                family='6',
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
                name='mgmt',
                type=constants.NETWORK_TYPE_MGMT,
                link_capacity=1000,
                vlan_id=2,
                address_pool_id=self.address_pool1.id)
            self.cluster_host_network = dbutils.create_test_network(
                id=2,
                name='cluster-host',
                type=constants.NETWORK_TYPE_CLUSTER_HOST,
                link_capacity=10000,
                vlan_id=3,
                address_pool_id=self.address_pool2.id)
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
            self.worker = host
        return

    def _create_datanetworks(self):
        for name, v in providernet_list.items():
            dn_values = {
                'name': name,
                'uuid': v.get('id', None),
                'network_type': v['type'],
                'mtu': v['mtu']}
            if v['type'] == constants.DATANETWORK_TYPE_VXLAN:
                for r in v['ranges']:
                    dn_values.update(
                        {'multicast_group': r['vxlan'].get('group'),
                         'port_num': r['vxlan'].get('port'),
                         'ttl': r['vxlan'].get('ttl'),
                         'mode': r['vxlan'].get('mode', 'dynamic'),
                         })

            dbutils.create_test_datanetwork(**dn_values)

    def _create_ethernet(self, ifname=None, networktype=None, ifclass=None,
                         datanetworks=None, host=None, expect_errors=False):
        interface_id = len(self.profile['interfaces']) + 1
        if not ifname:
            ifname = (networktype or 'eth') + str(interface_id)
        if not host:
            host = self.controller
        if not ifclass and networktype in constants.PLATFORM_NETWORK_TYPES:
            ifclass = constants.INTERFACE_CLASS_PLATFORM
        port_id = len(self.profile['ports'])
        port = dbutils.create_test_ethernet_port(
            id=port_id,
            name='eth' + str(port_id),
            host_id=host.id,
            interface_id=interface_id,
            pciaddr='0000:00:00.' + str(port_id + 1),
            dev_id=0)

        if not networktype:
            interface = dbutils.create_test_interface(ifname=ifname,
                                                      forihostid=host.id,
                                                      ihost_uuid=host.uuid)
        else:
            interface = dbutils.post_get_test_interface(
                ifname=ifname,
                ifclass=ifclass,
                forihostid=host.id, ihost_uuid=host.uuid)
            response = self._post_and_check(interface, expect_errors)
            if expect_errors is False:
                interface['uuid'] = response.json['uuid']
                iface = self.dbapi.iinterface_get(interface['uuid'])
                if ifclass == constants.INTERFACE_CLASS_PLATFORM and networktype:
                    network = self.dbapi.network_get_by_type(networktype)
                    dbutils.create_test_interface_network(
                        interface_id=iface.id,
                        network_id=network.id)
                elif ifclass in [constants.INTERFACE_CLASS_DATA,
                                 constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                                 constants.INTERFACE_CLASS_PCI_SRIOV] \
                        and datanetworks:
                    for dn_name in datanetworks:
                        dn = self.dbapi.datanetworks_get_all({'name': dn_name})
                        if dn:
                            dbutils.create_test_interface_datanetwork(
                                interface_id=iface.id,
                                datanetwork_id=dn.id)

        self.profile['interfaces'].append(interface)
        self.profile['ports'].append(port)

        return port, interface

    def _create_bond(self, ifname, networktype=None, ifclass=None,
                     datanetworks=None, host=None, expect_errors=False):
        if not host:
            host = self.controller
        port1, iface1 = self._create_ethernet(host=host)
        port2, iface2 = self._create_ethernet(host=host)
        interface_id = len(self.profile['interfaces'])
        if not ifname:
            ifname = (networktype or 'eth') + str(interface_id)
        if not ifclass and networktype in constants.PLATFORM_NETWORK_TYPES:
            ifclass = constants.INTERFACE_CLASS_PLATFORM
        interface = dbutils.post_get_test_interface(
            id=interface_id,
            ifname=ifname,
            iftype=constants.INTERFACE_TYPE_AE,
            ifclass=ifclass,
            uses=[iface1['ifname'], iface2['ifname']],
            txhashpolicy='layer2',
            forihostid=host.id, ihost_uuid=host.uuid)

        lacp_types = [constants.NETWORK_TYPE_MGMT,
                      constants.NETWORK_TYPE_PXEBOOT]
        if networktype in lacp_types:
            interface['aemode'] = '802.3ad'
        else:
            interface['aemode'] = 'balanced'

        response = self._post_and_check(interface, expect_errors)
        if expect_errors is False:
            interface['uuid'] = response.json['uuid']
            iface = self.dbapi.iinterface_get(interface['uuid'])
            if ifclass == constants.INTERFACE_CLASS_PLATFORM and networktype:
                network = self.dbapi.network_get_by_type(networktype)
                dbutils.create_test_interface_network(
                        interface_id=iface.id,
                        network_id=network.id)
            elif ifclass == constants.INTERFACE_CLASS_DATA and datanetworks:
                for dn_name in datanetworks:
                    dn = self.dbapi.datanetworks_get_all({'name': dn_name})
                    if dn:
                        dbutils.create_test_interface_datanetwork(
                            interface_id=iface.id,
                            datanetwork_id=dn.id)

        iface1['used_by'].append(interface['ifname'])
        iface2['used_by'].append(interface['ifname'])
        self.profile['interfaces'].append(interface)
        return interface

    def _create_worker_bond(self, ifname, networktype=None, ifclass=None,
                             datanetworks=None, expect_errors=False):
        return self._create_bond(ifname, networktype, ifclass, datanetworks,
                                 self.worker, expect_errors)

    def _create_vlan(self, ifname, networktype, ifclass, vlan_id,
                     lower_iface=None, datanetworks=None, host=None,
                     expect_errors=False):
        if not host:
            host = self.controller
        if not lower_iface:
            lower_port, lower_iface = self._create_ethernet(host=host)
        if not ifname:
            ifname = 'vlan' + str(vlan_id)
        if not ifclass and networktype in constants.PLATFORM_NETWORK_TYPES:
            ifclass = constants.INTERFACE_CLASS_PLATFORM
        interface = dbutils.post_get_test_interface(
            ifname=ifname,
            iftype=constants.INTERFACE_TYPE_VLAN,
            ifclass=ifclass,
            vlan_id=vlan_id,
            uses=[lower_iface['ifname']],
            forihostid=host.id, ihost_uuid=host.uuid)
        response = self._post_and_check(interface, expect_errors)
        if expect_errors is False:
            interface['uuid'] = response.json['uuid']
            iface = self.dbapi.iinterface_get(interface['uuid'])
            if ifclass == constants.INTERFACE_CLASS_PLATFORM and networktype:
                network = self.dbapi.network_get_by_type(networktype)
                dbutils.create_test_interface_network(
                        interface_id=iface.id,
                        network_id=network.id)
            elif ifclass == constants.INTERFACE_CLASS_DATA and datanetworks:
                for dn_name in datanetworks:
                    dn = self.dbapi.datanetworks_get_all({'name': dn_name})
                    if dn:
                        dbutils.create_test_interface_datanetwork(
                            interface_id=iface.id,
                            datanetwork_id=dn.id)

        self.profile['interfaces'].append(interface)
        return interface

    def _create_worker_vlan(self, ifname, networktype, ifclass, vlan_id,
                             lower_iface=None, datanetworks=None,
                             host=None, expect_errors=False):
        return self._create_vlan(ifname, networktype, ifclass, vlan_id,
                                 lower_iface,
                                 datanetworks, self.worker, expect_errors)

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
                        'routes': [],
                        'interface_networks': []}
        self.system = None
        self.controller = None
        self.worker = None
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
        self._create_ethernet('cluster', constants.NETWORK_TYPE_CLUSTER_HOST)
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
        self._create_bond('cluster', constants.NETWORK_TYPE_CLUSTER_HOST)

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
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM,
                          constants.INTERFACE_CLASS_PLATFORM, 1, bond)
        self._create_vlan('mgmt', constants.NETWORK_TYPE_MGMT,
                          constants.INTERFACE_CLASS_PLATFORM, 2, bond)
        self._create_vlan('cluster', constants.NETWORK_TYPE_CLUSTER_HOST,
                          constants.INTERFACE_CLASS_PLATFORM, 3, bond)
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
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM,
                          constants.INTERFACE_CLASS_PLATFORM, 1, iface)
        self._create_vlan('mgmt', constants.NETWORK_TYPE_MGMT,
                          constants.INTERFACE_CLASS_PLATFORM, 2, iface)
        self._create_vlan('cluster', constants.NETWORK_TYPE_CLUSTER_HOST,
                          constants.INTERFACE_CLASS_PLATFORM, 3, iface)
        # self._create_ethernet_profile('none')

    def setUp(self):
        super(InterfaceControllerVlanOverEthernet, self).setUp()

    def test_controller_vlan_over_ethernet_profile(self):
        self._create_and_apply_profile(self.controller)


class InterfaceComputeEthernet(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # worker and all interfaces are ethernet interfaces.
        self._create_host(constants.CONTROLLER, admin=constants.ADMIN_UNLOCKED)
        self._create_datanetworks()
        self._create_ethernet('oam', constants.NETWORK_TYPE_OAM)
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_ethernet('cluster', constants.NETWORK_TYPE_CLUSTER_HOST)

        self._create_host(constants.WORKER, constants.WORKER,
                          mgmt_mac='01:02.03.04.05.C0',
                          mgmt_ip='192.168.24.12',
                          admin=constants.ADMIN_LOCKED)
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.worker)
        self._create_ethernet('cluster', constants.NETWORK_TYPE_CLUSTER_HOST,
                              host=self.worker)
        self._create_ethernet('data',
                              constants.NETWORK_TYPE_DATA,
                              constants.INTERFACE_CLASS_DATA,
                              'group0-data0', host=self.worker)
        self._create_ethernet('sriov',
                              constants.NETWORK_TYPE_PCI_SRIOV,
                              constants.INTERFACE_CLASS_PCI_SRIOV,
                              'group0-data1', host=self.worker)
        self._create_ethernet('pthru',
                              constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                              'group0-ext0', host=self.worker)
        port, iface = (
            self._create_ethernet('slow',
                                  constants.NETWORK_TYPE_DATA,
                                  constants.INTERFACE_CLASS_DATA,
                                  'group0-ext1', host=self.worker))
        port['dpdksupport'] = False
        port, iface = (
            self._create_ethernet('mlx4',
                                  constants.NETWORK_TYPE_DATA,
                                  constants.INTERFACE_CLASS_DATA,
                                  'group0-ext2', host=self.worker))
        port['driver'] = 'mlx4_core'
        port, iface = (
            self._create_ethernet('mlx5',
                                  constants.NETWORK_TYPE_DATA,
                                  constants.INTERFACE_CLASS_DATA,
                                  'group0-ext3', host=self.worker))
        port['driver'] = 'mlx5_core'

    def setUp(self):
        super(InterfaceComputeEthernet, self).setUp()

    def test_worker_ethernet_profile(self):
        self._create_and_apply_profile(self.worker)


class InterfaceComputeVlanOverEthernet(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller and all interfaces are vlan interfaces over ethernet
        # interfaces.
        self._create_host(constants.CONTROLLER)
        self._create_datanetworks()
        port, iface = self._create_ethernet(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM,
                          constants.INTERFACE_CLASS_PLATFORM, 1, iface)
        self._create_vlan('mgmt', constants.NETWORK_TYPE_MGMT,
                          constants.INTERFACE_CLASS_PLATFORM, 2, iface)
        self._create_vlan('cluster', constants.NETWORK_TYPE_CLUSTER_HOST,
                          constants.INTERFACE_CLASS_PLATFORM, 3, iface)

        # Setup a sample configuration where the personality is set to a
        # worker and all interfaces are vlan interfaces over ethernet
        # interfaces.
        self._create_host(constants.WORKER, admin=constants.ADMIN_LOCKED)
        port, iface = self._create_ethernet(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT, host=self.worker)
        self._create_worker_vlan('mgmt', constants.NETWORK_TYPE_MGMT,
                                  constants.INTERFACE_CLASS_PLATFORM, 2, iface)
        self._create_worker_vlan('cluster', constants.NETWORK_TYPE_CLUSTER_HOST,
                                  constants.INTERFACE_CLASS_PLATFORM, 3)
        self._create_worker_vlan('data', constants.INTERFACE_CLASS_DATA,
                                  constants.NETWORK_TYPE_DATA, 5,
                                  datanetworks='group0-ext0')
        self._create_ethernet('sriov',
                              constants.NETWORK_TYPE_PCI_SRIOV,
                              constants.INTERFACE_CLASS_PCI_SRIOV,
                              'group0-data0', host=self.worker)
        self._create_ethernet('pthru',
                              constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                              'group0-data1', host=self.worker)

    def setUp(self):
        super(InterfaceComputeVlanOverEthernet, self).setUp()

    def test_worker_vlan_over_ethernet_profile(self):
        self._create_and_apply_profile(self.worker)


class InterfaceComputeBond(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where all platform interfaces are
        # aggregated ethernet interfaces.
        self._create_host(constants.CONTROLLER, admin=constants.ADMIN_UNLOCKED)
        self._create_datanetworks()
        self._create_bond('oam', constants.NETWORK_TYPE_OAM)
        self._create_bond('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_bond('cluster', constants.NETWORK_TYPE_CLUSTER_HOST)

        # Setup a sample configuration where the personality is set to a
        # worker and all interfaces are aggregated ethernet interfaces.
        self._create_host(constants.WORKER, admin=constants.ADMIN_LOCKED)
        self._create_worker_bond('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_worker_bond('cluster', constants.NETWORK_TYPE_CLUSTER_HOST)
        self._create_worker_bond('data',
                                  constants.NETWORK_TYPE_DATA,
                                  constants.INTERFACE_CLASS_DATA,
                                  datanetworks='group0-data0')
        self._create_ethernet('sriov',
                              constants.NETWORK_TYPE_PCI_SRIOV,
                              constants.INTERFACE_CLASS_PCI_SRIOV,
                              'group0-ext0', host=self.worker)
        self._create_ethernet('pthru',
                              constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                              'group0-ext1', host=self.worker)

    def setUp(self):
        super(InterfaceComputeBond, self).setUp()

    def test_worker_bond_profile(self):
        self._create_and_apply_profile(self.worker)


class InterfaceComputeVlanOverBond(InterfaceTestCase):

    def _setup_configuration(self):
        self._create_host(constants.CONTROLLER)
        self._create_datanetworks()
        bond = self._create_bond('pxeboot', constants.NETWORK_TYPE_PXEBOOT,
                                 constants.INTERFACE_CLASS_PLATFORM)
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM,
                          constants.INTERFACE_CLASS_PLATFORM, 1, bond)
        self._create_vlan('mgmt', constants.NETWORK_TYPE_MGMT,
                          constants.INTERFACE_CLASS_PLATFORM, 2, bond)
        self._create_vlan('cluster', constants.NETWORK_TYPE_CLUSTER_HOST,
                          constants.INTERFACE_CLASS_PLATFORM, 3, bond)

        # Setup a sample configuration where the personality is set to a
        # worker and all interfaces are vlan interfaces over aggregated
        # ethernet interfaces.
        self._create_host(constants.WORKER, admin=constants.ADMIN_LOCKED)
        bond = self._create_worker_bond('pxeboot',
                                         constants.NETWORK_TYPE_PXEBOOT,
                                         constants.INTERFACE_CLASS_PLATFORM)
        self._create_worker_vlan('mgmt', constants.NETWORK_TYPE_MGMT,
                                  constants.INTERFACE_CLASS_PLATFORM, 2, bond)
        self._create_worker_vlan('cluster', constants.NETWORK_TYPE_CLUSTER_HOST,
                                  constants.INTERFACE_CLASS_PLATFORM, 3,
                                  bond)
        bond2 = self._create_worker_bond('bond2', constants.NETWORK_TYPE_NONE)
        self._create_worker_vlan('data',
                                  constants.NETWORK_TYPE_DATA,
                                  constants.INTERFACE_CLASS_DATA,
                                  5, bond2,
                                  datanetworks='group0-ext0')

        self._create_worker_bond('bond3', constants.NETWORK_TYPE_NONE)

        self._create_ethernet('sriov',
                              constants.NETWORK_TYPE_PCI_SRIOV,
                              constants.INTERFACE_CLASS_PCI_SRIOV,
                              'group0-data0', host=self.worker)
        self._create_ethernet('pthru',
                              constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                              'group0-data1', host=self.worker)

    def setUp(self):
        super(InterfaceComputeVlanOverBond, self).setUp()

    def test_worker_vlan_over_bond_profile(self):
        self._create_and_apply_profile(self.worker)


class InterfaceComputeVlanOverDataEthernet(InterfaceTestCase):

    def _setup_configuration(self):
        self._create_host(constants.CONTROLLER)
        self._create_datanetworks()
        bond = self._create_bond('pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM,
                          constants.INTERFACE_CLASS_PLATFORM, 1, bond)
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_ethernet('cluster', constants.NETWORK_TYPE_CLUSTER_HOST)

        # Setup a sample configuration where the personality is set to a
        # worker and all interfaces are vlan interfaces over data ethernet
        # interfaces.
        self._create_host(constants.WORKER, admin=constants.ADMIN_LOCKED)
        port, iface = (
            self._create_ethernet('data',
                                  constants.NETWORK_TYPE_DATA,
                                  constants.INTERFACE_CLASS_DATA,
                                  'group0-data0', host=self.worker))
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.worker)
        self._create_ethernet('cluster', constants.NETWORK_TYPE_CLUSTER_HOST,
                              host=self.worker)
        self._create_worker_vlan('data2', constants.NETWORK_TYPE_DATA,
                                  constants.INTERFACE_CLASS_DATA, 5,
                                  iface, datanetworks='group0-ext0')
        self._create_ethernet('sriov',
                              constants.NETWORK_TYPE_PCI_SRIOV,
                              constants.INTERFACE_CLASS_PCI_SRIOV,
                              'group0-ext1', host=self.worker)
        self._create_ethernet('pthru',
                              constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                              'group0-ext2', host=self.worker)

    def setUp(self):
        super(InterfaceComputeVlanOverDataEthernet, self).setUp()

    def test_worker_vlan_over_data_ethernet_profile(self):
        self._create_and_apply_profile(self.worker)


class InterfaceCpeEthernet(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a worker subfunction and all interfaces are
        # ethernet interfaces.
        self._create_host(constants.CONTROLLER, constants.WORKER,
                          admin=constants.ADMIN_LOCKED)
        self._create_datanetworks()
        self._create_ethernet('oam', constants.NETWORK_TYPE_OAM)
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_ethernet('cluster', constants.NETWORK_TYPE_CLUSTER_HOST)
        self._create_ethernet('data', constants.NETWORK_TYPE_DATA,
                              constants.INTERFACE_CLASS_DATA,
                              'group0-data0')
        self._create_ethernet('sriov', constants.NETWORK_TYPE_PCI_SRIOV,
                              constants.INTERFACE_CLASS_PCI_SRIOV,
                              'group0-data1')
        self._create_ethernet('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                              'group0-ext0')
        port, iface = (
            self._create_ethernet('slow', constants.NETWORK_TYPE_DATA,
                                  constants.INTERFACE_CLASS_DATA,
                                  'group0-ext1'))
        port['dpdksupport'] = False
        port, iface = (
            self._create_ethernet('mlx4', constants.NETWORK_TYPE_DATA,
                                  constants.INTERFACE_CLASS_DATA,
                                  'group0-ext2'))
        port['driver'] = 'mlx4_core'
        port, iface = (
            self._create_ethernet('mlx5', constants.NETWORK_TYPE_DATA,
                                  constants.INTERFACE_CLASS_DATA,
                                  'group0-ext3'))

    def setUp(self):
        super(InterfaceCpeEthernet, self).setUp()

    def test_cpe_ethernet_profile(self):
        self._create_and_apply_profile(self.controller)


class InterfaceCpeVlanOverEthernet(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a worker subfunction and all interfaces are
        # vlan interfaces over ethernet interfaces.
        self._create_host(constants.CONTROLLER, constants.WORKER,
                          admin=constants.ADMIN_LOCKED)
        self._create_datanetworks()
        port, iface = self._create_ethernet(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM,
                          constants.INTERFACE_CLASS_PLATFORM, 1, iface)
        self._create_vlan('mgmt', constants.NETWORK_TYPE_MGMT,
                          constants.INTERFACE_CLASS_PLATFORM, 2, iface)
        self._create_vlan('cluster', constants.NETWORK_TYPE_CLUSTER_HOST,
                          constants.INTERFACE_CLASS_PLATFORM, 3)
        self._create_ethernet('data', constants.NETWORK_TYPE_DATA,
                              constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-ext0')
        self._create_ethernet('sriov', constants.NETWORK_TYPE_PCI_SRIOV,
                              constants.INTERFACE_CLASS_PCI_SRIOV,
                              'group0-ext1')
        self._create_ethernet('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                              'group0-ext2')

    def setUp(self):
        super(InterfaceCpeVlanOverEthernet, self).setUp()

    def test_cpe_vlan_over_ethernet_profile(self):
        self._create_and_apply_profile(self.controller)


class InterfaceCpeBond(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a worker subfunction and all interfaces are
        # aggregated ethernet interfaces.
        self._create_host(constants.CONTROLLER,
                          subfunction=constants.WORKER,
                          admin=constants.ADMIN_LOCKED)
        self._create_datanetworks()
        self._create_bond('oam', constants.NETWORK_TYPE_OAM)
        self._create_bond('mgmt', constants.NETWORK_TYPE_MGMT)
        self._create_bond('cluster', constants.NETWORK_TYPE_CLUSTER_HOST)
        self._create_bond('data', constants.NETWORK_TYPE_DATA,
                          constants.INTERFACE_CLASS_DATA,
                          datanetworks='group0-data0')
        self._create_ethernet('sriov', constants.NETWORK_TYPE_PCI_SRIOV,
                              constants.INTERFACE_CLASS_PCI_SRIOV,
                              datanetworks='group0-ext0')
        self._create_ethernet('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                              datanetworks='group0-ext1')

    def setUp(self):
        super(InterfaceCpeBond, self).setUp()

    def test_cpe_bond_profile(self):
        self._create_and_apply_profile(self.controller)


class InterfaceCpeVlanOverBond(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a worker subfunction and all interfaces are
        # vlan interfaces over aggregated ethernet interfaces.
        self._create_host(constants.CONTROLLER, constants.WORKER,
                          admin=constants.ADMIN_LOCKED)
        self._create_datanetworks()
        bond = self._create_bond('pxeboot', constants.NETWORK_TYPE_PXEBOOT)
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM,
                          constants.INTERFACE_CLASS_PLATFORM, 1, bond)
        self._create_vlan('mgmt', constants.NETWORK_TYPE_MGMT,
                          constants.INTERFACE_CLASS_PLATFORM, 2, bond)
        self._create_vlan('cluster', constants.NETWORK_TYPE_CLUSTER_HOST,
                          constants.INTERFACE_CLASS_PLATFORM, 3, bond)
        bond2 = self._create_bond('bond4', constants.NETWORK_TYPE_NONE)
        self._create_vlan('data', constants.NETWORK_TYPE_DATA,
                          constants.INTERFACE_CLASS_DATA,
                          5, bond2,
                          datanetworks='group0-ext0')
        self._create_ethernet('sriov', constants.NETWORK_TYPE_PCI_SRIOV,
                              constants.INTERFACE_CLASS_PCI_SRIOV,
                              'group0-ext1')
        self._create_ethernet('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                              'group0-ext2')

    def setUp(self):
        super(InterfaceCpeVlanOverBond, self).setUp()

    def test_cpe_vlan_over_bond_profile(self):
        self._create_and_apply_profile(self.controller)


# Test that the unsupported config is rejected
class InterfaceCpeVlanOverDataEthernet(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration where the personality is set to a
        # controller with a worker subfunction and all interfaces are
        # vlan interfaces over data ethernet interfaces.
        self._create_host(constants.CONTROLLER, constants.WORKER,
                          admin=constants.ADMIN_LOCKED)
        self._create_datanetworks()
        port, iface = (
            self._create_ethernet('data',
                                  constants.NETWORK_TYPE_DATA,
                                  constants.INTERFACE_CLASS_DATA,
                                  'group0-data0'))
        self._create_vlan('oam', constants.NETWORK_TYPE_OAM,
                          constants.INTERFACE_CLASS_PLATFORM, 1, iface,
                          expect_errors=True)
        self._create_vlan('mgmt', constants.NETWORK_TYPE_MGMT,
                          constants.INTERFACE_CLASS_PLATFORM, 2, iface,
                          expect_errors=True)
        self._create_vlan('cluster', constants.NETWORK_TYPE_CLUSTER_HOST,
                          constants.INTERFACE_CLASS_PLATFORM, 3, iface,
                          expect_errors=True)
        self._create_vlan('data2', constants.NETWORK_TYPE_DATA,
                          constants.INTERFACE_CLASS_DATA,
                          5, iface,
                          datanetworks='group0-ext0',
                          expect_errors=False)
        self._create_ethernet('sriov', constants.NETWORK_TYPE_PCI_SRIOV,
                              ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
                              datanetworks='group0-ext1',
                              expect_errors=False)
        self._create_ethernet('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              ifclass=constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                              datanetworks='group0-ext2',
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
        self._create_host(constants.WORKER, admin=constants.ADMIN_LOCKED)
        self._create_datanetworks()

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
                                      constants.INTERFACE_CLASS_DATA,
                                      datanetworks='group0-data0',
                                      host=self.worker)

        port, new_ethernet = self._create_ethernet(
            'new', constants.NETWORK_TYPE_NONE, host=self.worker)
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
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT, host=self.worker)
        dbutils.create_test_interface(
            forihostid='2',
            ihost_uuid=self.worker.uuid,
            ifname='data0',
            networktype=constants.NETWORK_TYPE_DATA,
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            datanetworks='group0-data0',
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
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT, host=self.worker)
        upper = dbutils.create_test_interface(
            forihostid='2',
            ihost_uuid=self.worker.uuid,
            ifname='data0',
            networktype=constants.NETWORK_TYPE_DATA,
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_VLAN,
            vlan_id=100,
            datanetworks='group0-ext0',
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

    def _create_sriov_vf_driver_valid(self, vf_driver, expect_errors=False):
        interface = dbutils.create_test_interface(forihostid='1',
                                                  datanetworks='group0-data0')
        dbutils.create_test_ethernet_port(
            id=1, name='eth1', host_id=1, interface_id=interface.id,
            pciaddr='0000:00:00.11', dev_id=0, sriov_totalvfs=1, sriov_numvfs=1,
            driver='i40e',
            sriov_vf_driver='i40evf')
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            sriov_numvfs=1,
            sriov_vf_driver=vf_driver,
            expect_errors=expect_errors)
        self.assertEqual('application/json', response.content_type)
        if expect_errors:
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertTrue(response.json['error_message'])
        else:
            self.assertEqual(http_client.OK, response.status_code)
            self.assertEqual(vf_driver, response.json['sriov_vf_driver'])

    def test_create_sriov_vf_driver_netdevice_valid(self):
        self._create_sriov_vf_driver_valid(
            constants.SRIOV_DRIVER_TYPE_NETDEVICE)

    def test_create_sriov_vf_driver_vfio_valid(self):
        self._create_sriov_vf_driver_valid(constants.SRIOV_DRIVER_TYPE_VFIO)

    def test_create_sriov_vf_driver_invalid(self):
        self._create_sriov_vf_driver_valid('bad_driver', expect_errors=True)

    # No longer requires setting the network type back to none
    # Expected error: The network type of an interface cannot be changed without
    # first being reset back to none
    # def test_invalid_change_networktype(self):
    #     port, interface = self._create_ethernet('oam',
    #                                             constants.NETWORK_TYPE_OAM)
    #     response = self.patch_dict_json(
    #         '%s' % self._get_path(interface['uuid']),
    #         networktype=constants.NETWORK_TYPE_MGMT, expect_errors=True)
    #     self.assertEqual(http_client.BAD_REQUEST, response.status_int)
    #     self.assertEqual('application/json', response.content_type)
    #     self.assertTrue(response.json['error_message'])


class TestPost(InterfaceTestCase):
    def setUp(self):
        super(TestPost, self).setUp()
        self._create_host(constants.CONTROLLER)
        self._create_host(constants.WORKER, admin=constants.ADMIN_LOCKED)
        self._create_datanetworks()

    # Expected error: The pci-passthrough, pci-sriov network types are only
    # valid on Ethernet interfaces
    def test_invalid_iftype_for_pci_network_type(self):
        self._create_bond('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                          ifclass=constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                          host=self.worker, expect_errors=True)

    # Expected error: The ___ network type is only supported on nodes supporting
    # worker functions
    def test_invalid_network_type_on_nonworker(self):
        self._create_ethernet('data0', constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-ext0',
                              expect_errors=True)

    # Expected error: Interface name cannot be whitespace.
    def test_invalid_whitespace_interface_name(self):
        self._create_ethernet('   ', constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-ext0',
                              expect_errors=True)

    # Expected error: Interface name must be in lower case.
    def test_invalid_uppercase_interface_name(self):
        self._create_ethernet('miXedCaSe', constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-ext0',
                              expect_errors=True)

    # Expected error: Cannot use special characters in interface name.
    def test_invalid_character_interface_name(self):
        self._create_ethernet('bad-name', constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-ext0',
                              expect_errors=True)

    # Expected error: Interface ___ has name length greater than 10.
    def test_invalid_interface_name_length(self):
        self._create_ethernet('0123456789a', constants.NETWORK_TYPE_OAM,
                              expect_errors=True)

    # Expected message: Name must be unique
    def test_create_duplicate_interface_name(self):
        self._create_ethernet('data0', constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-data0',
                              host=self.worker)
        self._create_ethernet('data0', constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-ext0',
                              host=self.worker,
                              expect_errors=True)

    def test_data_ipv4_mode_valid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_POOL,
            ipv4_pool=self.address_pool1.uuid)
        self._post_and_check_success(ndict)

    def test_data_ipv6_mode_valid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv6_mode=constants.IPV6_POOL,
            ipv6_pool=self.address_pool_v6.uuid)
        self._post_and_check_success(ndict)

    def test_platform_ipv4_mode_valid(self):
        port, interface = self._create_ethernet(
            'mgmt', constants.NETWORK_TYPE_MGMT,
            ifclass=constants.INTERFACE_CLASS_PLATFORM)
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            ipv4_mode=constants.IPV4_STATIC)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual(constants.IPV4_STATIC, response.json['ipv4_mode'])

    def test_platform_ipv6_mode_valid(self):
        port, interface = self._create_ethernet(
            'mgmt', constants.NETWORK_TYPE_MGMT,
            ifclass=constants.INTERFACE_CLASS_PLATFORM)
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            ipv6_mode=constants.IPV6_STATIC)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual(constants.IPV6_STATIC, response.json['ipv6_mode'])

    # Expected error: Address mode attributes only supported on
    # mgmt, oam, cluster-host, data interfaces
    def test_platform_no_network_ipv4_mode(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_STATIC,
            ipv4_pool=self.address_pool1.uuid)
        self._post_and_check_failure(ndict)

    # Expected error: Address mode attributes only supported on
    # mgmt, oam, cluster-host, data interfaces
    def test_ipv4_mode_networktype_invalid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_STATIC,
            ipv6_mode=constants.IPV6_STATIC,
            ipv4_pool=self.address_pool1.uuid,
            ipv6_pool=self.address_pool2.uuid)
        self._post_and_check_failure(ndict)

    # Expected error: Specifying an IPv4 address pool requires setting the
    # address mode to 'pool'
    def test_ipv4_mode_cluster_host_invalid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.controller.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
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
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
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
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv6_mode=constants.IPV6_DISABLED,
            ipv6_pool=self.address_pool1.uuid)
        self._post_and_check_failure(ndict)

    # Expected error: IPv4 address pool name not specified
    def test_ipv4_mode_no_pool_invalid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_POOL,
            ipv6_mode=constants.IPV6_POOL)
        self._post_and_check_failure(ndict)

    # Expected error: IPv6 address pool name not specified
    def test_ipv6_mode_no_pool_invalid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_POOL,
            ipv6_mode=constants.IPV6_POOL,
            ipv4_pool=self.address_pool_v6.uuid)
        self._post_and_check_failure(ndict)

    # Expected error: Address pool IP family does not match requested family
    def test_ipv4_pool_family_mismatch_invalid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_POOL,
            ipv6_mode=constants.IPV6_POOL,
            ipv4_pool=self.address_pool_v6.uuid,
            ipv6_pool=self.address_pool_v6.uuid)
        self._post_and_check_failure(ndict)

    # Expected error: Address pool IP family does not match requested family
    def test_ipv6_pool_family_mismatch_invalid(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_DATA,
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
            ihost_uuid=self.worker.uuid,
            datanetworks='group0-data0',
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype='AE',
            aemode='active_standby',
            txhashpolicy='layer2')
        self._post_and_check_failure(ndict)

    # Expected error: Device interface with interface type 'aggregated ethernet'
    #  in ___ mode should not specify a Tx Hash Policy.
    def test_aemode_no_txhash(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            datanetworks='group0-data0',
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='active_standby',
            txhashpolicy='layer2')
        self._post_and_check_failure(ndict)

    # Device interface with network type ___, and interface type
    # 'aggregated ethernet' must have a Tx Hash Policy of 'layer2'.
    def test_aemode_invalid_txhash(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='balanced',
            txhashpolicy='layer2+3')
        self._post_and_check_failure(ndict)

    # Expected error: Device interface with interface type 'aggregated ethernet'
    #  in 'balanced' or '802.3ad' mode require a valid Tx Hash Policy
    def test_aemode_invalid_txhash_none(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            datanetworks='group0-data0',
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='802.3ad',
            txhashpolicy=None)
        self._post_and_check_failure(ndict)

        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            datanetworks='group0-data0',
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='balanced',
            txhashpolicy=None)
        self._post_and_check_failure(ndict)

    # Device interface with network type ___, and interface type
    # 'aggregated ethernet' must be in mode 'active_standby' or 'balanced' or
    # '802.3ad'.
    def test_aemode_invalid_data(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            datanetworks='group0-data0',
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='bad_aemode',
            txhashpolicy='layer2')
        self._post_and_check_failure(ndict)

    def test_aemode_invalid_platform(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.controller.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='bad_aemode',
            txhashpolicy='layer2')
        self._post_and_check_failure(ndict)

    def test_setting_mgmt_mtu_allowed(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.controller.uuid,
            ifname='mgmt0',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            imtu=1600)
        self._post_and_check_success(ndict)

    def test_setting_cluster_host_mtu_allowed(self):
        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.controller.uuid,
            ifname='cluster0',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            imtu=1600)
        self._post_and_check_success(ndict)

    # Expected message: Interface eth0 is already used by another AE interface
    # bond0
    def test_create_bond_invalid_overlap_ae(self):
        bond_iface = self._create_worker_bond('bond0',
                                               constants.NETWORK_TYPE_DATA,
                                               constants.INTERFACE_CLASS_DATA,
                                               datanetworks='group0-data0')
        port, iface1 = self._create_ethernet()

        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            datanetworks='group0-ext1',
            ifname='bond1',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='balanced',
            txhashpolicy='layer2',
            uses=[bond_iface['uses'][0], iface1['uuid']])
        self._post_and_check_failure(ndict)

    # Expected message: VLAN id must be between 1 and 4094.
    def test_create_invalid_vlan_id(self):
        self._create_worker_vlan('vlan0', constants.NETWORK_TYPE_DATA,
                                  ifclass=constants.INTERFACE_CLASS_DATA,
                                  vlan_id=4095,
                                  datanetworks='group0-ext0',
                                  expect_errors=True)

    # Expected message: Interface eth0 is already used by another VLAN
    # interface vlan0
    def test_create_bond_invalid_overlap_vlan(self):
        vlan_iface = self._create_worker_vlan(
            'vlan0',
            constants.NETWORK_TYPE_DATA,
            ifclass=constants.INTERFACE_CLASS_DATA,
            vlan_id=10, datanetworks='group0-ext0')
        port, iface1 = self._create_ethernet()

        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            datanetworks='group0-ext1',
            ifname='bond0',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='balanced',
            txhashpolicy='layer2',
            uses=[vlan_iface['uses'][0], iface1['uuid']])
        self._post_and_check_failure(ndict)

    # Expected message: Can only have one interface for vlan type.
    def test_create_vlan_invalid_uses(self):
        bond_iface = self._create_worker_bond('bond0',
                                               constants.NETWORK_TYPE_DATA,
                                               constants.INTERFACE_CLASS_DATA,
                                               datanetworks='group0-data0')
        port, iface1 = self._create_ethernet()

        ndict = dbutils.post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            datanetworks='group0-ext1',
            ifname='bond1',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_VLAN,
            aemode='balanced',
            txhashpolicy='layer2',
            uses=[bond_iface['uses'][0], iface1['uuid']])
        self._post_and_check_failure(ndict)

    # Expected message: VLAN interfaces cannot be created over existing VLAN
    # interfaces
    def test_create_invalid_vlan_over_vlan(self):
        vlan_iface = self._create_worker_vlan(
            'vlan1', constants.NETWORK_TYPE_DATA,
            constants.INTERFACE_CLASS_DATA, 1,
            datanetworks='group0-ext0')
        self._create_worker_vlan('vlan2',
                                  constants.NETWORK_TYPE_DATA,
                                  constants.INTERFACE_CLASS_DATA,
                                  vlan_id=2,
                                  lower_iface=vlan_iface,
                                  datanetworks='group0-ext1',
                                  expect_errors=True)

    # Expected message: data VLAN cannot be created over a LAG interface with
    # network type pxeboot
    def test_create_data_vlan_over_pxeboot_lag(self):
        bond_iface = self._create_worker_bond(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT,
            constants.INTERFACE_CLASS_PLATFORM)
        self._create_worker_vlan(
            'vlan2',
            constants.NETWORK_TYPE_DATA, constants.INTERFACE_CLASS_DATA, 2,
            lower_iface=bond_iface, datanetworks='group0-ext1',
            expect_errors=True)

    # Expected message: data VLAN cannot be created over a LAG interface with
    # network type mgmt
    def test_create_data_vlan_over_mgmt_lag(self):
        bond_iface = self._create_worker_bond(
            'mgmt', constants.NETWORK_TYPE_MGMT,
            constants.INTERFACE_CLASS_PLATFORM)
        self._create_worker_vlan(
            'vlan2', constants.NETWORK_TYPE_DATA,
            constants.INTERFACE_CLASS_DATA, 2,
            lower_iface=bond_iface, datanetworks='group0-ext1',
            expect_errors=True)

    # Expected message: mgmt VLAN cannot be created over a LAG interface with
    # network type data
    def test_create_mgmt_vlan_over_data_lag(self):
        bond_iface = self._create_worker_bond(
            'data', constants.NETWORK_TYPE_DATA,
            constants.INTERFACE_CLASS_DATA, datanetworks='group0-ext1')
        self._create_worker_vlan(
            'mgmt', constants.NETWORK_TYPE_MGMT,
            constants.INTERFACE_CLASS_PLATFORM, 2,
            lower_iface=bond_iface, datanetworks='group0-ext1',
            expect_errors=True)

    # Expected message:
    #   An interface with interface class platform cannot assign datanetworks.
    def test_create_nondata_data_network(self):
        bond_iface = self._create_worker_bond(
            'pxeboot', constants.NETWORK_TYPE_PXEBOOT,
            constants.INTERFACE_CLASS_PLATFORM)
        iface = self.dbapi.iinterface_get(bond_iface['uuid'])
        datanetworks = self.dbapi.datanetworks_get_all({'name': 'group0-data0'})
        for dn in datanetworks:
            iface_dn = dbutils.post_get_test_interface_datanetwork(
                interface_uuid=iface.uuid,
                datanetwork_uuid=dn.uuid)
            response = self.post_json('/interface_datanetworks', iface_dn, expect_errors=True)
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])

    # Expected message: Name must be unique
    def test_create_invalid_ae_name(self):
        self._create_ethernet('enp0s9', constants.NETWORK_TYPE_NONE)
        self._create_bond('enp0s9', constants.NETWORK_TYPE_MGMT,
                          constants.INTERFACE_CLASS_PLATFORM,
                          expect_errors=True)

    # Expected message:
    # The data network type is only supported on nodes supporting worker functions
    def test_create_invalid_oam_data_ethernet(self):
        self._create_ethernet('shared',
                              networktype=constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-data0',
                              host=self.controller,
                              expect_errors=True)

    # Expected message:
    # An interface with interface class platform cannot assign datanetworks.
    def test_create_invalid_mgmt_data_ethernet(self):
        port, mgmt_if = self._create_ethernet('shared',
                              networktype=constants.NETWORK_TYPE_MGMT,
                              ifclass=constants.INTERFACE_CLASS_PLATFORM,
                              host=self.worker)
        iface = self.dbapi.iinterface_get(mgmt_if['uuid'])
        datanetworks = self.dbapi.datanetworks_get_all({'name': 'group0-data0'})
        for dn in datanetworks:
            iface_dn = dbutils.post_get_test_interface_datanetwork(
                interface_uuid=iface.uuid,
                datanetwork_uuid=dn.uuid)
            response = self.post_json('/interface_datanetworks', iface_dn,
                                      expect_errors=True)
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])


class TestCpePost(InterfaceTestCase):
    def setUp(self):
        super(TestCpePost, self).setUp()
        self._create_host(constants.CONTROLLER, constants.WORKER,
                          admin=constants.ADMIN_LOCKED)
        self._create_datanetworks()

    # Expected message: oam VLAN cannot be created over an interface with
    # network type data
    def test_create_oam_vlan_over_data_lag(self):
        bond_iface = self._create_bond(
            'data', constants.NETWORK_TYPE_DATA,
            constants.INTERFACE_CLASS_DATA, datanetworks='group0-ext1')
        self._create_vlan(
            'oam', constants.NETWORK_TYPE_OAM,
            constants.INTERFACE_CLASS_PLATFORM, 2,
            lower_iface=bond_iface, datanetworks='group0-ext1',
            expect_errors=True)

    # Expected message: Platform VLAN interface cannot be created over a
    # data interface
    def test_create_cluster_host_vlan_over_data_lag(self):
        bond_iface = self._create_bond(
            'data', constants.NETWORK_TYPE_DATA,
            constants.INTERFACE_CLASS_DATA, datanetworks='group0-ext1')
        self._create_vlan(
            'cluster', constants.NETWORK_TYPE_CLUSTER_HOST,
            constants.INTERFACE_CLASS_PLATFORM, 2,
            lower_iface=bond_iface, datanetworks='group0-ext1',
            expect_errors=True)

    # Expected message: Platform VLAN interface cannot be created over a
    # data interface
    def test_create_mgmt_vlan_over_data_ethernet(self):
        port, iface = self._create_ethernet(
            'data', constants.NETWORK_TYPE_DATA,
            constants.INTERFACE_CLASS_DATA, datanetworks='group0-ext1')
        self._create_vlan(
            'mgmt', constants.NETWORK_TYPE_MGMT,
            constants.INTERFACE_CLASS_PLATFORM, 2,
            lower_iface=iface, datanetworks='group0-ext1',
            expect_errors=True)

    # Expected message:  VLAN id ___ already in use on interface ___
    def test_create_vlan_id_already_in_use(self):
        port, iface = self._create_ethernet('eth1', constants.NETWORK_TYPE_NONE)
        self._create_vlan('vlan1', constants.NETWORK_TYPE_DATA,
                          constants.INTERFACE_CLASS_DATA, vlan_id=1,
                          lower_iface=iface, datanetworks='group0-ext0')
        self._create_vlan('vlan2', constants.NETWORK_TYPE_DATA,
                          constants.INTERFACE_CLASS_DATA, vlan_id=1,
                          lower_iface=iface, datanetworks='group0-ext1',
                          expect_errors=True)

    # Expected error: VLAN based provider network group0-data0 cannot be
    # assigned to a VLAN interface
    def test_create_invalid_vlan_with_vlan_data_network(self):
        port, lower = self._create_ethernet('eth1', constants.NETWORK_TYPE_NONE)
        vlan_if = self._create_vlan('vlan2', networktype=constants.NETWORK_TYPE_DATA,
                          ifclass=constants.INTERFACE_CLASS_DATA,
                          vlan_id=2, lower_iface=lower)
        iface = self.dbapi.iinterface_get(vlan_if['uuid'])
        datanetworks = self.dbapi.datanetworks_get_all({'name': 'group0-data0'})
        for dn in datanetworks:
            iface_dn = dbutils.post_get_test_interface_datanetwork(
                interface_uuid=iface.uuid,
                datanetwork_uuid=dn.uuid)
            response = self.post_json('/interface_datanetworks', iface_dn, expect_errors=True)
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])

    # Expected error: Data interface data0 is already attached to this
    # Data Network: group0-data0.
    def test_create_invalid_data_network_used(self):
        port1, data0_if = self._create_ethernet('data0',
                              networktype=constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA)
        iface = self.dbapi.iinterface_get(data0_if['uuid'])
        datanetworks = self.dbapi.datanetworks_get_all({'name': 'group0-data0'})
        for dn in datanetworks:
            iface_dn = dbutils.post_get_test_interface_datanetwork(
                interface_uuid=iface.uuid,
                datanetwork_uuid=dn.uuid)
            response = self.post_json('/interface_datanetworks', iface_dn,
                                      expect_errors=False)
        port2, data1_if = self._create_ethernet('data1',
                              networktype=constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA)
        iface = self.dbapi.iinterface_get(data1_if['uuid'])
        datanetworks = self.dbapi.datanetworks_get_all({'name': 'group0-data0'})
        for dn in datanetworks:
            iface_dn = dbutils.post_get_test_interface_datanetwork(
                interface_uuid=iface.uuid,
                datanetwork_uuid=dn.uuid)
            response = self.post_json('/interface_datanetworks', iface_dn,
                                      expect_errors=True)
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])

    def test_create_same_data_network_valid(self):
        port2, sriov_if = self._create_ethernet('sriov',
                              networktype=constants.NETWORK_TYPE_PCI_SRIOV,
                              ifclass=constants.INTERFACE_CLASS_PCI_SRIOV)
        iface = self.dbapi.iinterface_get(sriov_if['uuid'])
        datanetworks = self.dbapi.datanetworks_get_all({'name': 'group0-data0'})
        for dn in datanetworks:
            iface_dn = dbutils.post_get_test_interface_datanetwork(
                interface_uuid=iface.uuid,
                datanetwork_uuid=dn.uuid)
            response = self.post_json('/interface_datanetworks', iface_dn,
                                      expect_errors=False)
            self.assertEqual(http_client.OK, response.status_int)

        port1, data0_if = self._create_ethernet('data0',
                              networktype=constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA)
        iface = self.dbapi.iinterface_get(data0_if['uuid'])
        datanetworks = self.dbapi.datanetworks_get_all({'name': 'group0-data0'})
        for dn in datanetworks:
            iface_dn = dbutils.post_get_test_interface_datanetwork(
                interface_uuid=iface.uuid,
                datanetwork_uuid=dn.uuid)
            response = self.post_json('/interface_datanetworks', iface_dn,
                                      expect_errors=False)

        port3, pthru_if = self._create_ethernet('pthru',
                              networktype=constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                              ifclass=constants.INTERFACE_CLASS_PCI_PASSTHROUGH)
        iface = self.dbapi.iinterface_get(pthru_if['uuid'])
        datanetworks = self.dbapi.datanetworks_get_all({'name': 'group0-data0'})
        for dn in datanetworks:
            iface_dn = dbutils.post_get_test_interface_datanetwork(
                interface_uuid=iface.uuid,
                datanetwork_uuid=dn.uuid)
            response = self.post_json('/interface_datanetworks', iface_dn,
                                      expect_errors=False)
            self.assertEqual(http_client.OK, response.status_int)


class TestCpePatch(InterfaceTestCase):
    def setUp(self):
        super(TestCpePatch, self).setUp()
        self._create_host(constants.CONTROLLER, constants.WORKER,
                          admin=constants.ADMIN_LOCKED)
        self._create_datanetworks()

    # Expected error: Value for number of SR-IOV VFs must be > 0.
    def test_invalid_sriov_numvfs(self):
        port, interface = self._create_ethernet('eth0',
                                                constants.NETWORK_TYPE_NONE)
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)

    # Expected error: SR-IOV can't be configured on this interface
    def test_invalid_sriov_totalvfs_zero(self):
        interface = dbutils.create_test_interface(forihostid='1')
        dbutils.create_test_ethernet_port(
            id=1, name='eth1', host_id=1, interface_id=interface.id,
            pciaddr='0000:00:00.11', dev_id=0, sriov_totalvfs=0, sriov_numvfs=1)
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            sriov_numvfs=1,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)

    # Expected error: The interface support a maximum of ___ VFs
    def test_invalid_sriov_exceeded_totalvfs(self):
        interface = dbutils.create_test_interface(forihostid='1')
        dbutils.create_test_ethernet_port(
            id=1, name='eth1', host_id=1, interface_id=interface.id,
            pciaddr='0000:00:00.11', dev_id=0, sriov_totalvfs=1, sriov_numvfs=1,
            driver=None)
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            networktype=constants.NETWORK_TYPE_PCI_SRIOV,
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            sriov_numvfs=2,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)

    # Expected error: Corresponding port has invalid driver
    def test_invalid_driver_for_sriov(self):
        interface = dbutils.create_test_interface(forihostid='1')
        dbutils.create_test_ethernet_port(
            id=1, name='eth1', host_id=1, interface_id=interface.id,
            pciaddr='0000:00:00.11', dev_id=0, sriov_totalvfs=1, sriov_numvfs=1,
            driver=None)
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            networktype=constants.NETWORK_TYPE_PCI_SRIOV,
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            sriov_numvfs=1,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
