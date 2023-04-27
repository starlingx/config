# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
#
#
# Copyright (c) 2013-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /interfaces/ methods.
"""

import mock
from six.moves import http_client

from oslo_utils import uuidutils
from sysinv.api.controllers.v1 import interface as api_if_v1
from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
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


class InterfaceTestCase(base.FunctionalTest, dbbase.BaseHostTestCase):
    def _setup_configuration(self):
        pass

    def setUp(self):
        super(InterfaceTestCase, self).setUp()
        self.dbapi = db_api.get_instance()

        p = mock.patch.object(api_if_v1, '_get_lower_interface_macs')
        self.mock_lower_macs = p.start()
        self.mock_lower_macs.return_value = {'enp0s18': '11:22:33:44:55:66',
                                             'enp0s19': '11:22:33:44:55:67'}
        self.addCleanup(p.stop)
        self._setup_context()

    def _get_path(self, path=None):
        if path:
            return '/iinterfaces/' + path
        else:
            return '/iinterfaces'

    def _post_get_test_interface(self, **kw):
        interface = dbutils.get_test_interface(**kw)

        # When invoking a POST the following fields should not be populated:
        del interface['uuid']
        del interface['id']
        del interface['networktypelist']
        del interface['sriov_vf_pdevice_id']

        return interface

    def _create_host(self, personality, subfunction=None,
                     mgmt_mac=None, mgmt_ip=None,
                     admin=None,
                     invprovision=constants.PROVISIONED, **kw):
        host = self._create_test_host(
            personality=personality,
            subfunction=subfunction,
            administrative=admin or constants.ADMIN_UNLOCKED,
            invprovision=invprovision,
            **kw)
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
                         datanetworks=None, host=None, expect_errors=False,
                         lower_iface=None, ptp_role=None, error_message=None):
        interface_id = len(self.profile['interfaces']) + 1
        port = None
        if not ifname:
            ifname = (networktype or 'eth') + str(interface_id)
        if not host:
            host = self.controller
        if not ifclass and networktype in constants.PLATFORM_NETWORK_TYPES:
            ifclass = constants.INTERFACE_CLASS_PLATFORM
        if not lower_iface:
            port_id = len(self.profile['ports'])
            port = dbutils.create_test_ethernet_port(
                id=port_id,
                name='eth' + str(port_id),
                host_id=host.id,
                interface_id=interface_id,
                pciaddr='0000:00:00.' + str(port_id + 1),
                dev_id=0)
            self.profile['ports'].append(port)
        if not ptp_role:
            ptp_role = constants.INTERFACE_PTP_ROLE_NONE

        if not networktype:
            interface = dbutils.create_test_interface(ifname=ifname,
                                                      forihostid=host.id,
                                                      ihost_uuid=host.uuid,
                                                      ifclass=ifclass,
                                                      ptp_role=ptp_role)
        else:
            if lower_iface:
                uses = [lower_iface['ifname']]
            else:
                uses = None
            interface = self._post_get_test_interface(
                ifname=ifname,
                ifclass=ifclass,
                uses=uses,
                forihostid=host.id,
                ihost_uuid=host.uuid,
                ptp_role=ptp_role)

            if expect_errors and not error_message:
                raise ValueError("If 'expect_errors' is True, 'error_message' "
                                 "must be specified.")

            response = self._post_and_check(interface, expect_errors,
                                            error_message)
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

        return port, interface

    def _create_bond(self, ifname, networktype=None, ifclass=None,
                     datanetworks=None, host=None, expect_errors=False,
                     aemode=None, ptp_role=None, error_message=None,
                     portifclass=None):
        if not ptp_role:
            ptp_role = constants.INTERFACE_PTP_ROLE_NONE
        if not host:
            host = self.controller
        port1, iface1 = self._create_ethernet(host=host, ifclass=portifclass)
        port2, iface2 = self._create_ethernet(host=host, ifclass=portifclass)
        interface_id = len(self.profile['interfaces'])
        if not ifname:
            ifname = (networktype or 'eth') + str(interface_id)
        if not ifclass and networktype in constants.PLATFORM_NETWORK_TYPES:
            ifclass = constants.INTERFACE_CLASS_PLATFORM
        interface = self._post_get_test_interface(
            id=interface_id,
            ifname=ifname,
            iftype=constants.INTERFACE_TYPE_AE,
            ifclass=ifclass,
            uses=[iface1['ifname'], iface2['ifname']],
            forihostid=host.id,
            ihost_uuid=host.uuid,
            ptp_role=ptp_role)

        lacp_types = [constants.NETWORK_TYPE_MGMT,
                      constants.NETWORK_TYPE_PXEBOOT]
        if not aemode:
            if networktype in lacp_types:
                aemode = '802.3ad'
            else:
                aemode = 'balanced'
        if aemode != constants.AE_MODE_ACTIVE_STANDBY:
            interface['txhashpolicy'] = 'layer2'
        interface['aemode'] = aemode

        if expect_errors and not error_message:
            raise ValueError("If 'expect_errors' is True, 'error_message' "
                                "must be specified.")

        response = self._post_and_check(interface, expect_errors, error_message)
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
                     expect_errors=False, error_message=None):
        if not host:
            host = self.controller
        if not lower_iface:
            lower_port, lower_iface = self._create_ethernet(host=host)
        if not ifname:
            ifname = 'vlan' + str(vlan_id)
        if not ifclass and networktype in constants.PLATFORM_NETWORK_TYPES:
            ifclass = constants.INTERFACE_CLASS_PLATFORM
        interface = self._post_get_test_interface(
            ifname=ifname,
            iftype=constants.INTERFACE_TYPE_VLAN,
            ifclass=ifclass,
            vlan_id=vlan_id,
            uses=[lower_iface['ifname']],
            forihostid=host.id, ihost_uuid=host.uuid)

        if expect_errors and not error_message:
            raise ValueError("If 'expect_errors' is True, 'error_message' "
                                "must be specified.")

        response = self._post_and_check(interface, expect_errors, error_message)
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
                             host=None, expect_errors=False,
                             error_message=None):
        return self._create_vlan(ifname, networktype, ifclass, vlan_id,
                                 lower_iface,
                                 datanetworks, self.worker, expect_errors,
                                 error_message)

    def _create_sriov(self, ifname,
                      sriov_totalvfs=None, sriov_numvfs=None,
                      sriov_vf_driver=None,
                      datanetworks=None, host=None, expect_errors=False):
        interface_id = len(self.profile['interfaces']) + 1
        if not ifname:
            ifname = 'sriov' + str(interface_id)
        if not host:
            host = self.controller
        if not sriov_totalvfs:
            sriov_totalvfs = 64
        if not sriov_numvfs:
            sriov_numvfs = 64

        port_id = len(self.profile['ports'])
        port = dbutils.create_test_ethernet_port(
            id=port_id,
            name='eth' + str(port_id),
            host_id=host.id,
            interface_id=interface_id,
            pciaddr='0000:00:00.' + str(port_id + 1),
            dev_id=0,
            sriov_totalvfs=sriov_totalvfs,
            sriov_numvfs=sriov_numvfs,
            driver='i40e',
            sriov_vf_driver='i40evf',
            speed=10000)

        ifclass = constants.INTERFACE_CLASS_PCI_SRIOV
        interface = self._post_get_test_interface(
            ifname=ifname,
            ifclass=ifclass,
            forihostid=host.id, ihost_uuid=host.uuid,
            sriov_numvfs=sriov_numvfs,
            sriov_vf_driver=sriov_vf_driver)
        response = self._post_and_check(interface, expect_errors)
        if expect_errors is False:
            interface['uuid'] = response.json['uuid']
            iface = self.dbapi.iinterface_get(interface['uuid'])
            if datanetworks:
                for dn_name in datanetworks:
                    dn = self.dbapi.datanetworks_get_all({'name': dn_name})
                    if dn:
                        dbutils.create_test_interface_datanetwork(
                            interface_id=iface.id,
                            datanetwork_id=dn.id)

        self.profile['interfaces'].append(interface)
        self.profile['ports'].append(port)

        return port, interface

    def _create_vf(self, ifname, ifclass=None,
                   lower_iface=None, sriov_numvfs=None,
                   sriov_vf_driver=None, datanetworks=None, host=None,
                   expect_errors=False, max_tx_rate=None,
                   error_message=None):
        if not host:
            host = self.controller
        if not lower_iface:
            lower_port, lower_iface = self._create_sriov(
                'sriov', host=host, sriov_numvfs=sriov_numvfs)
        if not ifname:
            ifname = 'vf'
        if not ifclass:
            ifclass = constants.INTERFACE_CLASS_PCI_SRIOV
        if not sriov_numvfs:
            sriov_numvfs = lower_iface['sriov_numvfs'] - 1

        interface = self._post_get_test_interface(
            ifname=ifname,
            iftype=constants.INTERFACE_TYPE_VF,
            ifclass=ifclass,
            uses=[lower_iface['ifname']],
            forihostid=host.id, ihost_uuid=host.uuid,
            sriov_numvfs=sriov_numvfs,
            sriov_vf_driver=sriov_vf_driver,
            max_tx_rate=max_tx_rate)

        if expect_errors and not error_message:
            raise ValueError("If 'expect_errors' is True, 'error_message' "
                                "must be specified.")

        response = self._post_and_check(interface, expect_errors, error_message)
        if expect_errors is False:
            interface['uuid'] = response.json['uuid']
            iface = self.dbapi.iinterface_get(interface['uuid'])
            if ifclass == constants.INTERFACE_CLASS_PCI_SRIOV and datanetworks:
                for dn_name in datanetworks:
                    dn = self.dbapi.datanetworks_get_all({'name': dn_name})
                    if dn:
                        dbutils.create_test_interface_datanetwork(
                            interface_id=iface.id,
                            datanetwork_id=dn.id)

        self.profile['interfaces'].append(interface)
        return interface

    def _create_worker_vf(self, ifname, networktype, ifclass, vlan_id,
                          lower_iface=None, datanetworks=None,
                          host=None, expect_errors=False):
        return self._create_vf(ifname, networktype, ifclass, vlan_id,
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
        return response

    def _post_and_check(self, ndict, expect_errors=False, error_message=None):
        response = self.post_json('%s' % self._get_path(), ndict,
                                  expect_errors)
        if expect_errors:
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])
            if error_message:
                self.assertIn(error_message, response.json['error_message'])
        else:
            self.assertEqual(http_client.OK, response.status_int)
        return response

    def _delete_and_check(self, iface_uuid, expect_errors=False, error_message=None):
        response = self.delete('%s' % self._get_path(iface_uuid),
                                  expect_errors)
        if expect_errors:
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])
            if error_message:
                self.assertIn(error_message, response.json['error_message'])
        else:
            self.assertEqual(http_client.NO_CONTENT, response.status_int)
        return response

    def _patch_and_check(self, data, path, expect_errors=False, error_message=None):
        response = self.patch_dict('%s' % path, expect_errors=expect_errors, data=data)
        if expect_errors:
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])
            if error_message:
                self.assertIn(error_message, response.json['error_message'])
        else:
            self.assertEqual(http_client.OK, response.status_int)
        return response

    def is_interface_equal(self, first, second):
        for key in first:
            if key in second:
                self.assertEqual(first[key], second[key])

    def _find_network_by_type(self, networktype):
        for network in self.networks:
            if network['type'] == networktype:
                return network

    def _find_address_pool_by_uuid(self, pool_uuid):
        for pool in self.address_pools:
            if pool['uuid'] == pool_uuid:
                return pool

    def _setup_context(self):
        self.profile = {'host':
                        {'personality': constants.CONTROLLER,
                         'hostname': constants.CONTROLLER_0_HOSTNAME},
                        'interfaces': [],
                        'ports': [],
                        'addresses': [],
                        'routes': [],
                        'interface_networks': []}
        self.controller = None
        self.worker = None
        self._setup_configuration()


# Test that the unsupported config is rejected
class InterfaceAIOVlanOverDataEthernet(InterfaceTestCase):

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
        super(InterfaceAIOVlanOverDataEthernet, self).setUp()


# Test PTP configs
class InterfacePTP(InterfaceTestCase):

    def _setup_configuration(self):
        # Setup a sample configuration with one controller and one worker
        self._create_host(constants.CONTROLLER)
        self._create_host(constants.WORKER, admin=constants.ADMIN_LOCKED)
        self._create_datanetworks()

    def setUp(self):
        super(InterfacePTP, self).setUp()

    def test_modify_ptp_interface_valid(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.worker)
        port0, if0 = self._create_ethernet('if0', host=self.worker)
        sriovif = dbutils.create_test_interface(forihostid=self.worker.id, datanetworks='group0-data0')
        dbutils.create_test_ethernet_port(
            id=2, name='if1', host_id=self.worker.id, interface_id=sriovif.id, pciaddr='0000:00:00.11', dev_id=0,
            sriov_totalvfs=1, sriov_numvfs=1, driver='i40e', sriov_vf_driver='i40evf'
        )
        if0_uuid = if0['uuid']
        sriov_uuid = sriovif['uuid']

        # Platform interface and master
        data = {
            'ifname': 'ptpif',
            'ptp_role': constants.INTERFACE_PTP_ROLE_MASTER,
            'ifclass': constants.INTERFACE_CLASS_PLATFORM
        }
        self._patch_and_check(data, self._get_path(if0_uuid))

        # Slave role
        data['ptp_role'] = constants.INTERFACE_PTP_ROLE_SLAVE
        self._patch_and_check(data, self._get_path(if0_uuid))

        # SRIOV and master
        sriov_data = {
            'ifname': 'sriovptp',
            'sriov_numvfs': 1,
            'ifclass': constants.INTERFACE_CLASS_PCI_SRIOV,
            'ptp_role': constants.INTERFACE_PTP_ROLE_MASTER
        }
        self._patch_and_check(sriov_data, self._get_path(sriov_uuid))

        # Back to none
        self._patch_and_check({'ptp_role': constants.INTERFACE_PTP_ROLE_NONE}, self._get_path(sriov_uuid))

    def test_modify_ptp_interface_invalid(self):
        port0, if0 = self._create_ethernet('if0', ifclass=constants.INTERFACE_CLASS_PLATFORM, host=self.worker)
        port1, if1 = self._create_ethernet('if1', host=self.worker)
        bond0 = self._create_bond('bond0',
                                  ifclass=constants.INTERFACE_CLASS_PLATFORM,
                                  host=self.worker,
                                  aemode=constants.AE_MODE_ACTIVE_STANDBY,
                                  ptp_role=constants.INTERFACE_PTP_ROLE_SLAVE)

        if0_uuid = if0['uuid']
        if1_uuid = if1['uuid']
        # Invalid PTP role
        data = {
            'ifname': 'ptpif',
            'ptp_role': 'invalid'
        }
        self._patch_and_check(data, self._get_path(if0_uuid), expect_errors=True,
                              error_message="Interface ptp_role must be one of")

        # Valid role, incorrect class
        data['ptp_role'] = constants.INTERFACE_PTP_ROLE_MASTER
        self._patch_and_check(data, self._get_path(if1_uuid), expect_errors=True,
                              error_message="Invalid interface class for ptp_role")

        # Invalid change of slave interface
        ifslave_name = bond0['uses'][0]
        ifslave = self.dbapi.iinterface_get(ifslave_name, self.worker.uuid)
        data = {
            'ifname': 'ptpif',
            'ptp_role': constants.INTERFACE_PTP_ROLE_SLAVE
        }
        self._patch_and_check(data, self._get_path(ifslave['uuid']),
                              expect_errors=True,
                              error_message="role cannot be changed")

        # Invalid AE mode
        data = {
            'ifname': bond0['ifname'],
            'aemode': constants.AE_MODE_BALANCED
        }
        self._patch_and_check(data, self._get_path(bond0['uuid']),
                              expect_errors=True,
                              error_message="PTP isn't supported")

    def test_add_ptp_interface_valid(self):
        self._create_ethernet('if0', host=self.worker)
        self._create_ethernet('if1', host=self.worker)
        self._create_ethernet('if2', host=self.worker)

        # Add master vlan
        vlan_data = {
            'ihost_uuid': self.worker.uuid,
            'ifname': 'vlanptp',
            'iftype': constants.INTERFACE_TYPE_VLAN,
            'ifclass': constants.INTERFACE_CLASS_PLATFORM,
            'vlan_id': 100,
            'uses': ['if0'],
            'ptp_role': constants.INTERFACE_PTP_ROLE_MASTER
        }
        self._post_and_check(vlan_data)

        # Add slave ae
        ae_data = {
            'ihost_uuid': self.worker.uuid,
            'ifname': 'aeptp',
            'iftype': constants.INTERFACE_TYPE_AE,
            'ifclass': constants.INTERFACE_CLASS_PLATFORM,
            'aemode': constants.AE_MODE_ACTIVE_STANDBY,
            'uses': ['if1', 'if2'],
            'ptp_role': constants.INTERFACE_PTP_ROLE_SLAVE
        }
        self._post_and_check(ae_data)

    def test_add_ptp_interface_invalid(self):
        self._create_ethernet('if0', host=self.worker)
        self._create_ethernet('if1', host=self.worker)
        self._create_ethernet('if2', host=self.worker)
        self._create_ethernet('if3', host=self.worker,
                              ifclass=constants.INTERFACE_CLASS_PLATFORM,
                              ptp_role=constants.INTERFACE_PTP_ROLE_SLAVE)

        # Add vlan with invalid ptp_role data
        vlan_data = {
            'ihost_uuid': self.worker.uuid,
            'ifname': 'vlanptp',
            'iftype': constants.INTERFACE_TYPE_VLAN,
            'ifclass': constants.INTERFACE_CLASS_PLATFORM,
            'vlan_id': 100,
            'uses': ['if0'],
            'ptp_role': 'invalid'
        }
        error_message = "Interface ptp_role must be one of"
        self._post_and_check(vlan_data, expect_errors=True, error_message=error_message)
        vlan_data['ptp_role'] = ''
        self._post_and_check(vlan_data, expect_errors=True, error_message=error_message)

        # Add ae with bad mode
        ae_data = {
            'ihost_uuid': self.worker.uuid,
            'ifname': 'aeptp',
            'iftype': constants.INTERFACE_TYPE_AE,
            'ifclass': constants.INTERFACE_CLASS_PLATFORM,
            'aemode': constants.AE_MODE_BALANCED,
            'uses': ['if1', 'if2'],
            'ptp_role': constants.INTERFACE_PTP_ROLE_SLAVE
        }
        error_message = "PTP isn't supported"
        self._post_and_check(ae_data, expect_errors=True,
                             error_message=error_message)

        # Add ae with bad slave ptp role
        ae_data = {
            'ihost_uuid': self.worker.uuid,
            'ifname': 'aeptp',
            'iftype': constants.INTERFACE_TYPE_AE,
            'ifclass': constants.INTERFACE_CLASS_PLATFORM,
            'aemode': constants.AE_MODE_ACTIVE_STANDBY,
            'uses': ['if1', 'if3'],
            'ptp_role': constants.INTERFACE_PTP_ROLE_SLAVE
        }
        error_message = "None of interfaces being used in an 'aggregated ethernet' interface can have a PTP role"
        self._post_and_check(ae_data, expect_errors=True,
                             error_message=error_message)


class TestList(InterfaceTestCase):

    def setUp(self):
        super(TestList, self).setUp()
        self._create_host(constants.CONTROLLER)
        self._create_host(constants.WORKER, admin=constants.ADMIN_LOCKED)

    def test_empty_interface(self):
        data = self.get_json('/ihosts/%s/iinterfaces' % self.worker.uuid)
        self.assertEqual([], data['iinterfaces'])

    def test_one(self):
        ndict = self._post_get_test_interface(ifname='eth0',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=self.worker.id, ihost_uuid=self.worker.uuid)
        data = self.post_json('%s' % self._get_path(), ndict)

        # Verify that the interface was created with the expected attributes
        result = self.get_json('/iinterfaces/%s' %
            (data.json['uuid']))
        assert(uuidutils.is_uuid_like(result['uuid']))
        self.assertEqual(ndict['aemode'], result['aemode'])
        self.assertEqual(ndict['forihostid'], result['forihostid'])
        self.assertEqual(ndict['ifclass'], result['ifclass'])
        self.assertEqual(ndict['ifname'], result['ifname'])
        self.assertEqual(ndict['iftype'], result['iftype'])
        self.assertEqual(ndict['imac'], result['imac'])
        self.assertEqual(ndict['imtu'], result['imtu'])
        self.assertEqual(ndict['used_by'], result['used_by'])
        self.assertEqual(ndict['uses'], result['uses'])
        self.assertEqual(ndict['vlan_id'], result['vlan_id'])
        # Verify that hidden attributes are not returned
        self.assertNotIn('id', result)

    def test_many(self):
        interfaces = []
        for id in range(3):
            ndict = dbutils.get_test_interface(id=id,
                uuid=uuidutils.generate_uuid(),
                ifname='eth%s' % id,
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                imac='03:11:22:33:44:' + str(10 + id),
                forihostid=self.hosts[0].id,
                ihost_uuid=self.hosts[0].uuid)
            s = self.dbapi.iinterface_create(self.hosts[0].id, ndict)
            interfaces.append(s['uuid'])
        data = self.get_json('/ihosts/%s/iinterfaces' % self.hosts[0].uuid)
        self.assertEqual(len(interfaces), len(data['iinterfaces']))

        uuids = [n['uuid'] for n in data['iinterfaces']]
        self.assertEqual(interfaces.sort(), uuids.sort())  # uuids.sort


class TestPatchMixin(object):
    def setUp(self):
        super(TestPatchMixin, self).setUp()
        self._create_host(constants.CONTROLLER)
        self._create_host(constants.WORKER, admin=constants.ADMIN_LOCKED)
        self._create_datanetworks()

    def test_modify_ifname(self):
        interface = dbutils.create_test_interface(forihostid=self.worker.id)
        response = self.patch_dict_json(
            '%s' % self._get_path(interface.uuid),
            ifname='new_name')
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual('new_name', response.json['ifname'])

    # Test AE bond of member interfaces of class pci-sriov
    # modify AE interface to add another port
    def test_ae_pci_sriov_interface_usesmodify_success(self):
        bond0 = self._create_bond('bond0',
                                  ifclass=constants.INTERFACE_CLASS_PLATFORM,
                                  host=self.worker,
                                  portifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
                                  aemode=constants.AE_MODE_ACTIVE_STANDBY,
                                  ptp_role=constants.INTERFACE_PTP_ROLE_NONE)
        port, new_ethernet = self._create_ethernet(
            'new', constants.NETWORK_TYPE_NONE, host=self.worker)
        # Modify AE interface to add another port
        uses = ','.join(bond0['uses'])
        patch_result = self.patch_dict_json(
            '%s' % self._get_path(bond0['uuid']),
            usesmodify=uses + ',' + new_ethernet['uuid'])
        self.assertEqual('application/json', patch_result.content_type)
        self.assertEqual(http_client.OK, patch_result.status_code)

    def test_modify_mtu(self):
        interface = dbutils.create_test_interface(forihostid=self.worker.id)
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

    # Expected error: Interface MTU ___ cannot be larger than MTU of underlying
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

    # Expected error: Interface MTU ___ cannot be larger than MTU of underlying
    # interface ___
    def test_vf_mtu_smaller_than_users(self):
        port, lower_iface = self._create_sriov(
            'sriov', host=self.worker, sriov_numvfs=4)
        upper = dbutils.create_test_interface(
            forihostid='2',
            ihost_uuid=self.worker.uuid,
            ifname='vf0',
            networktype=constants.NETWORK_TYPE_PCI_SRIOV,
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            iftype=constants.INTERFACE_TYPE_VF,
            sriov_numvfs=2,
            sriov_vf_driver='vfio',
            datanetworks='group0-ext0',
            aemode='balanced',
            txhashpolicy='layer2',
            uses=['sriov'],
            imtu=1500)
        response = self.patch_dict_json(
            '%s' % self._get_path(upper['uuid']), imtu=1800,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    # Expected error: Interface MTU ___ cannot be larger than MTU of underlying
    # interface ___
    def test_ethernet_mtu_smaller_than_users(self):
        port, lower_iface = self._create_sriov(
            'sriov', host=self.worker, sriov_numvfs=4)
        upper = dbutils.create_test_interface(
            forihostid='2',
            ihost_uuid=self.worker.uuid,
            ifname='pxeboot0',
            networktype=constants.NETWORK_TYPE_PXEBOOT,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            uses=['sriov'],
            imtu=1500)
        response = self.patch_dict_json(
            '%s' % self._get_path(upper['uuid']), imtu=1800,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    def _create_sriov_vf_driver_valid(self, vf_driver, expect_errors=False):
        interface = dbutils.create_test_interface(forihostid=self.worker.id,
                                                  datanetworks='group0-data0')
        dbutils.create_test_ethernet_port(
            id=1, name='eth1', host_id=self.worker.id, interface_id=interface.id,
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
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT, host=self.worker)
        self._create_sriov_vf_driver_valid(
            constants.SRIOV_DRIVER_TYPE_NETDEVICE)

    def test_create_sriov_vf_driver_vfio_valid(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT, host=self.worker)
        self._create_sriov_vf_driver_valid(constants.SRIOV_DRIVER_TYPE_VFIO)

    def test_create_sriov_vf_driver_invalid(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT, host=self.worker)
        self._create_sriov_vf_driver_valid('bad_driver', expect_errors=True)

    def test_create_sriov_no_mgmt(self):
        self._create_sriov_vf_driver_valid(constants.SRIOV_DRIVER_TYPE_VFIO)


class TestPostMixin(object):
    def setUp(self):
        super(TestPostMixin, self).setUp()
        self._create_host(constants.CONTROLLER, admin=constants.ADMIN_LOCKED)
        self._create_host(constants.WORKER, admin=constants.ADMIN_LOCKED)
        self._create_datanetworks()

    # Expected error: The pci-passthrough, pci-sriov network types are only
    # valid on Ethernet interfaces
    def test_invalid_iftype_for_pci_network_type(self):
        self._create_bond('pthru', constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                          ifclass=constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                          host=self.worker, expect_errors=True,
                          error_message='The pci-passthrough, pci-sriov '
                          'interface class is only valid on Ethernet and '
                          'VF interfaces')

    # Expected error: The ___ network type is only supported on nodes supporting
    # worker functions
    def test_invalid_network_type_on_nonworker(self):
        self._create_ethernet('data0', constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-ext0',
                              expect_errors=True,
                              error_message='The data interface class is only '
                              'supported on nodes supporting worker functions')

    # Expected error: Interface name cannot be whitespace.
    def test_invalid_whitespace_interface_name(self):
        self._create_ethernet('   ', constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-ext0',
                              expect_errors=True,
                              error_message='Interface name cannot be '
                              'whitespace.')

    # Expected error: Interface name must be in lower case.
    def test_invalid_uppercase_interface_name(self):
        self._create_ethernet('miXedCaSe', constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-ext0',
                              expect_errors=True,
                              error_message='Interface name must be in lower '
                              'case.')

    # Expected error: Cannot use '+' as a special character in interface name.
    def test_invalid_plus_character_interface_name(self):
        self._create_ethernet('bad+name', constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-ext0',
                              expect_errors=True,
                              error_message="Cannot use '+' as a special "
                              "character in interface name.")

    # Expected error: Cannot use '=' as a special character in interface name
    def test_invalid_equals_character_interface_name(self):
        self._create_ethernet('bad=name', constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-ext0',
                              expect_errors=True,
                              error_message="Cannot use '=' as a special "
                              "character in interface name.")

    def test_valid_dash_character_interface_name(self):
        self._create_ethernet('good-name', constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-ext0',
                              host=self.worker)

    def test_valid_dot_character_interface_name(self):
        self._create_ethernet('good.name', constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-ext0',
                              host=self.worker)

    def test_valid_underscore_character_interface_name(self):
        self._create_ethernet('good_name', constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-ext0',
                              host=self.worker)

    # Expected error: Interface ___ has name length greater than 15.
    def test_invalid_interface_name_length(self):
        ifname = '0123456789abcdef'
        self._create_ethernet(ifname, constants.NETWORK_TYPE_OAM,
                              expect_errors=True,
                              error_message="Interface %s has name "
                              "length greater than 15." % ifname)

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
                              expect_errors=True,
                              error_message='Interface Name data0 must be '
                              'unique.')

    def test_address_mode_pool_valid(self):
        port, interface = self._create_ethernet(
            'mgmt', constants.NETWORK_TYPE_MGMT,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            host=self.worker)
        network = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        pool = self._find_address_pool_by_uuid(network['pool_uuid'])
        if pool.family == constants.IPV4_FAMILY:
            response = self.patch_dict_json(
                '%s' % self._get_path(interface['uuid']),
                ipv4_mode=constants.IPV4_POOL,
                ipv4_pool=pool.uuid)
            self.assertEqual(constants.IPV4_POOL, response.json['ipv4_mode'])
        else:
            response = self.patch_dict_json(
                '%s' % self._get_path(interface['uuid']),
                ipv6_mode=constants.IPV6_POOL,
                ipv6_pool=pool.uuid)
            self.assertEqual(constants.IPV6_POOL, response.json['ipv6_mode'])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)

    def test_address_mode_static_valid(self):
        port, interface = self._create_ethernet(
            'mgmt', constants.NETWORK_TYPE_MGMT,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            host=self.worker)
        network = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        pool = self._find_address_pool_by_uuid(network['pool_uuid'])
        if pool.family == constants.IPV4_FAMILY:
            response = self.patch_dict_json(
                '%s' % self._get_path(interface['uuid']),
                ipv4_mode=constants.IPV4_STATIC)
        else:
            response = self.patch_dict_json(
                '%s' % self._get_path(interface['uuid']),
                ipv6_mode=constants.IPV6_STATIC)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)

    # Expected error: Address mode attributes only supported on
    # mgmt, oam, cluster-host, data interfaces
    def test_address_mode_no_network(self):
        ndict = self._post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_STATIC,
            ipv4_pool=self.address_pools[0].uuid)
        self._post_and_check_failure(ndict)

    # Expected error: Address mode attributes only supported on
    # mgmt, oam, cluster-host, data interfaces
    def test_address_mode_pci_invalid(self):
        ndict = self._post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            ipv4_mode=constants.IPV4_STATIC,
            ipv6_mode=constants.IPV6_STATIC,
            ipv4_pool=self.address_pools[0].uuid,
            ipv6_pool=self.address_pools[1].uuid)
        self._post_and_check_failure(ndict)

    # Expected error: Specifying an IPv4 address pool requires setting the
    # address mode to pool
    def test_address_mode_disabled_pool_invalid(self):
        network = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        pool = self._find_address_pool_by_uuid(network['pool_uuid'])
        if pool.family == constants.IPV4_FAMILY:
            ndict = self._post_get_test_interface(
                ihost_uuid=self.controller.uuid,
                ifname='name',
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                iftype=constants.INTERFACE_TYPE_ETHERNET,
                ipv4_mode=constants.IPV4_DISABLED,
                ipv4_pool=pool.uuid)
        else:
            ndict = self._post_get_test_interface(
                ihost_uuid=self.controller.uuid,
                ifname='name',
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                iftype=constants.INTERFACE_TYPE_ETHERNET,
                ipv4_mode=constants.IPV4_POOL,
                ipv4_pool=pool.uuid,
                ipv6_mode=constants.IPV6_DISABLED,
                ipv6_pool=pool.uuid)
        self._post_and_check_failure(ndict)

    # Expected error: IPvX address pool name not specified
    def test_address_mode_no_pool_invalid(self):
        network = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        pool = self._find_address_pool_by_uuid(network['pool_uuid'])
        if pool.family == constants.IPV4_FAMILY:
            ndict = self._post_get_test_interface(
                ihost_uuid=self.worker.uuid,
                ifname='name',
                ifclass=constants.INTERFACE_CLASS_DATA,
                iftype=constants.INTERFACE_TYPE_ETHERNET,
                ipv4_mode=constants.IPV4_POOL)
        else:
            ndict = self._post_get_test_interface(
                ihost_uuid=self.worker.uuid,
                ifname='name',
                ifclass=constants.INTERFACE_CLASS_DATA,
                iftype=constants.INTERFACE_TYPE_ETHERNET,
                ipv6_mode=constants.IPV6_POOL)
        self._post_and_check_failure(ndict)

    # Expected error: Address pool IP family does not match requested family
    def test_address_pool_family_mismatch_invalid(self):
        port, interface = self._create_ethernet(
            'mgmt', constants.NETWORK_TYPE_MGMT,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            host=self.worker)
        network = self._find_network_by_type(constants.NETWORK_TYPE_MGMT)
        pool = self._find_address_pool_by_uuid(network['pool_uuid'])
        if pool.family == constants.IPV4_FAMILY:
            response = self.patch_dict_json(
                '%s' % self._get_path(interface['uuid']),
                ipv6_mode=constants.IPV6_POOL,
                ipv6_pool=pool.uuid,
                expect_errors=True)
        else:
            response = self.patch_dict_json(
                '%s' % self._get_path(interface['uuid']),
                ipv4_mode=constants.IPV4_POOL,
                ipv4_pool=pool.uuid,
                expect_errors=True)
        self.assertEqual(http_client.CONFLICT, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Address pool IP family does not match requested family',
                      response.json['error_message'])

    # Expected error: Device interface type must be 'aggregated ethernet' or
    # 'vlan' or 'ethernet'.
    def test_aemode_invalid_iftype(self):
        ndict = self._post_get_test_interface(
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
        ndict = self._post_get_test_interface(
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
        ndict = self._post_get_test_interface(
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
        ndict = self._post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            datanetworks='group0-data0',
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='802.3ad',
            txhashpolicy=None)
        self._post_and_check_failure(ndict)

        ndict = self._post_get_test_interface(
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
        ndict = self._post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            datanetworks='group0-data0',
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='bad_aemode',
            txhashpolicy='layer2')
        self._post_and_check_failure(ndict)

    def test_aemode_invalid_platform(self):
        ndict = self._post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='bad_aemode',
            txhashpolicy='layer2')
        response = self._post_and_check_failure(ndict)
        self.assertIn("Invalid aggregated ethernet mode 'bad_aemode'",
            response.json['error_message'])

    def test_non_aemode_primary_reselect(self):
        ndict = self._post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            aemode=constants.AE_MODE_ACTIVE_STANDBY,
            primary_reselect=constants.PRIMARY_RESELECT_BETTER)
        response = self._post_and_check_failure(ndict)
        self.assertIn("The option primary_reselect is only applicable to bonded interface.",
            response.json['error_message'])

    def test_aemode_balanced_primary_reselect(self):
        ndict = self._post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode=constants.AE_MODE_BALANCED,
            txhashpolicy='layer2',
            primary_reselect=constants.PRIMARY_RESELECT_BETTER)
        response = self._post_and_check_failure(ndict)
        self.assertIn("Device interface with interface type "
                      "\'aggregated ethernet\' in \'balanced\' "
                      "mode should not specify primary_reselect option.",
            response.json['error_message'])

    def test_aemode_invalid_data_primary_reselect(self):
        ndict = self._post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_DATA,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode=constants.AE_MODE_ACTIVE_STANDBY,
            primary_reselect=constants.PRIMARY_RESELECT_FAILURE)
        response = self._post_and_check_failure(ndict)
        self.assertIn("The option primary_reselect must be 'always' for non-platform interfaces.",
            response.json['error_message'])

    def test_aemode_invalid_primary_reselect(self):
        ndict = self._post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='name',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_AE,
            aemode='active_standby',
            primary_reselect='bad_primary_reselect')
        response = self._post_and_check_failure(ndict)
        self.assertIn("Invalid bonding primary reselect option: 'bad_primary_reselect'",
            response.json['error_message'])

    def test_setting_mgmt_mtu_allowed(self):
        ndict = self._post_get_test_interface(
            ihost_uuid=self.worker.uuid,
            ifname='mgmt0',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_ETHERNET,
            imtu=1600)
        self._post_and_check_success(ndict)

    def test_setting_cluster_host_mtu_allowed(self):
        ndict = self._post_get_test_interface(
            ihost_uuid=self.worker.uuid,
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

        ndict = self._post_get_test_interface(
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
                                  expect_errors=True,
                                  error_message='VLAN id must be between '
                                  '1 and 4094.')

    # Expected message: VLAN id must be specified.
    def test_create_without_vlan_id(self):
        self._create_worker_vlan('vlan0', constants.NETWORK_TYPE_DATA,
                                  ifclass=constants.INTERFACE_CLASS_DATA,
                                  vlan_id=None,
                                  datanetworks='group0-ext0',
                                  expect_errors=True,
                                  error_message='VLAN id must be specified.')

    # Expected message: Interface eth0 is already used by another VLAN
    # interface vlan0
    def test_create_bond_invalid_overlap_vlan(self):
        vlan_iface = self._create_worker_vlan(
            'vlan0',
            constants.NETWORK_TYPE_DATA,
            ifclass=constants.INTERFACE_CLASS_DATA,
            vlan_id=10, datanetworks='group0-ext0')
        port, iface1 = self._create_ethernet()

        ndict = self._post_get_test_interface(
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

        ndict = self._post_get_test_interface(
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
                                  expect_errors=True,
                                  error_message='VLAN interfaces cannot be '
                                  'created over existing VLAN interfaces')

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
            expect_errors=True,
            error_message='Data VLAN interface cannot be created over a '
            'platform interface')

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
            expect_errors=True,
            error_message='Data VLAN interface cannot be created over a '
            'platform interface')

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
            expect_errors=True,
            error_message='Platform VLAN interface cannot be created over a '
            'data interface')

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
            self.assertIn("An interface with interface class 'platform' cannot "
                          "assign datanetworks.",
                          response.json['error_message'])

    # Expected message: Name must be unique
    def test_create_invalid_ae_name(self):
        self._create_ethernet('enp0s9', constants.NETWORK_TYPE_NONE,
            host=self.worker)
        self._create_bond('enp0s9', constants.NETWORK_TYPE_MGMT,
                          constants.INTERFACE_CLASS_PLATFORM,
                          host=self.worker,
                          expect_errors=True,
                          error_message='Interface Name enp0s9 must be unique.')

    # Expected message:
    # The data network type is only supported on nodes supporting worker functions
    def test_create_invalid_data_ethernet(self):
        self._create_ethernet('shared',
                              networktype=constants.NETWORK_TYPE_DATA,
                              ifclass=constants.INTERFACE_CLASS_DATA,
                              datanetworks='group0-data0',
                              host=self.controller,
                              expect_errors=True,
                              error_message='The data interface class is only '
                              'supported on nodes supporting worker functions')

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
            self.assertIn("An interface with interface class 'platform' cannot "
                          "assign datanetworks.",
                          response.json['error_message'])

    # Expected message:
    # VF interfaces must be created over an interface of class pci-sriov
    def test_create_vf_over_invalid_interface(self):
        port, lower_iface = self._create_ethernet(
            'data', constants.NETWORK_TYPE_DATA,
            constants.INTERFACE_CLASS_DATA, 'group0-data0', host=self.worker)
        self._create_vf('vf1', lower_iface=lower_iface, sriov_numvfs=1,
            host=self.worker, sriov_vf_driver='vfio',
            datanetworks='group0-data0', expect_errors=True,
            error_message='VF interfaces must be created over an interface of '
            'class pci-sriov')

    # Expected message:
    # VF interfaces must have an interface class of pci-sriov
    def test_create_invalid_vf_interface_class(self):
        self._create_vf('vf1', ifclass=constants.INTERFACE_CLASS_DATA,
            sriov_numvfs=1,
            host=self.worker, sriov_vf_driver='vfio',
            datanetworks='group0-data0', expect_errors=True,
            error_message='VF interfaces must have an interface class of '
            'pci-sriov')

    # Expected message:
    # The number of virtual functions _ must be less than or equal to the
    # available VFs _ available on the underlying interface _
    def test_create_invalid_vf_interface_numvfs(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.worker)
        port, lower_iface = self._create_sriov(
            'sriov', host=self.worker, sriov_numvfs=4)
        self._create_vf('vf1', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=4, expect_errors=True,
            error_message='The number of virtual functions (4) must be less '
            'than or equal to the available VFs (3) available on the '
            'underlying interface (sriov)')

    # Expected message:
    # Value for number of SR-IOV VFs must be > 0.
    def test_create_vf_interface_numvfs_less_than_zero(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.worker)
        port, lower_iface = self._create_sriov(
            'sriov', host=self.worker, sriov_numvfs=4)
        self._create_vf('vf1', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=-1, expect_errors=True,
            error_message='Value for number of SR-IOV VFs must be > 0.')

    # Expected message:
    # The number of virtual functions _ must be less than or equal to the
    # available VFs _ available on the underlying interface _
    def test_create_invalid_vf_interface_numvfs_multiple_children(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.worker)
        port, lower_iface = self._create_sriov(
            'sriov', host=self.worker, sriov_numvfs=4)
        self._create_vf('vf1', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=1, expect_errors=False)
        self._create_vf('vf2', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=3, expect_errors=True,
            error_message='The number of virtual functions (3) must be less '
            'than or equal to the available VFs (2) available on the '
            'underlying interface (sriov)')

    # Expected message:
    # Interface _ is being used by VF interface _ and therefore the interface
    # class cannot be changed from 'pci-sriov'.
    def test_modify_sriov_interface_invalid_class_with_upper_vf(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.worker)
        port, lower_iface = self._create_sriov(
            'sriov', host=self.worker, sriov_numvfs=4)
        self._create_vf('vf1', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=1, expect_errors=False)

        response = self.patch_dict_json(
            '%s' % self._get_path(lower_iface['uuid']),
            ifclass=constants.INTERFACE_CLASS_DATA,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn("the interface class cannot be changed from 'pci-sriov'",
                      response.json['error_message'])

    # Expected message:
    # The number of virtual functions _ must be greater than the number of
    # consumed VFs _ used by the upper VF interfaces _
    def test_modify_sriov_interface_invalid_numvfs_with_upper_vf(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.worker)
        port, lower_iface = self._create_sriov(
            'sriov', host=self.worker, sriov_numvfs=4)
        self._create_vf('vf1', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=3, expect_errors=False)

        response = self.patch_dict_json(
            '%s' % self._get_path(lower_iface['uuid']),
            sriov_numvfs=2,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('must be greater than the number of consumed VFs',
                      response.json['error_message'])

    def test_interface_vf_usesmodify_success(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.worker)
        port, lower_iface = self._create_sriov(
            'sriov', host=self.worker, sriov_numvfs=4)
        vf = self._create_vf('vf1', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=3, expect_errors=False)

        port, new_lower_iface = self._create_sriov(
            'sriov2', host=self.worker, sriov_numvfs=4)
        # Modify VF interface to another SRIOV interface

        patch_result = self.patch_dict_json(
            '%s' % self._get_path(vf['uuid']),
            usesmodify=new_lower_iface['uuid'])
        self.assertEqual('application/json', patch_result.content_type)
        self.assertEqual(http_client.OK, patch_result.status_code)

    def test_interface_vf_usesmodify_invalid(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.worker)
        port, lower_iface = self._create_sriov(
            'sriov1', host=self.worker, sriov_numvfs=4)
        vf = self._create_vf('vf1', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=3, expect_errors=False)

        port, new_lower_iface = self._create_sriov(
            'sriov2', host=self.worker, sriov_numvfs=4)
        uses = ','.join(vf['uses'])
        response = self.patch_dict_json(
            '%s' % self._get_path(vf['uuid']),
            usesmodify=uses + ',' + new_lower_iface['uuid'],
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertIn('VF interfaces can only use one lower',
                      response.json['error_message'])

    def test_create_vf_interface_with_valid_ratelimit(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.worker)
        port, lower_iface = self._create_sriov(
            'sriov', host=self.worker, sriov_numvfs=4)
        # default speed is 10Gbps
        self._create_vf('vf1', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=1,
            expect_errors=False, max_tx_rate=1000)
        self._create_vf('vf2', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=1,
            expect_errors=False, max_tx_rate=8000)

    def test_create_vf_interface_with_invalid_ratelimit(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.worker)
        port, lower_iface = self._create_sriov(
            'sriov', host=self.worker, sriov_numvfs=4)
        # 4Gbps*3 > (10Gbps*0.9)
        self._create_vf('vf0', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=3,
            expect_errors=True, max_tx_rate=4000,
            error_message='Configured (max_tx_rate*sriov_numvfs) exceeds '
            'available link speed bandwidth: 9000 Mbps.')

        self._create_vf('vf1', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=1,
            expect_errors=False, max_tx_rate=1000)
        # 1Gbps+9Gbps > (10Gbps*0.9)
        self._create_vf('vf2', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=1,
            expect_errors=True, max_tx_rate=9000,
            error_message='Configured (max_tx_rate*sriov_numvfs) exceeds '
            'available link speed bandwidth: 8000 Mbps.')
        # rate is not a numeric value
        self._create_vf('vf3', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=1,
            expect_errors=True, max_tx_rate='ratelimit',
            error_message='Invalid input for field/attribute interface. Value:')

    def test_create_vf_interface_with_ratelimit_port_speed_none(self):
        interface_id = len(self.profile['interfaces']) + 1
        port_id = len(self.profile['ports'])
        port = dbutils.create_test_ethernet_port(
            id=port_id,
            name='eth' + str(port_id),
            host_id=self.worker.id,
            interface_id=interface_id,
            sriov_totalvfs=4, sriov_numvfs=4,
            speed=None)
        self.profile['ports'].append(port)

        interface = self._post_get_test_interface(
            ifname='sriov',
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            forihostid=self.worker.id, ihost_uuid=self.worker.uuid,
            sriov_numvfs=4)
        response = self._post_and_check(interface)
        interface['uuid'] = response.json['uuid']
        self.profile['interfaces'].append(interface)

        self._create_vf('vf0', lower_iface=interface,
            host=self.worker, sriov_numvfs=1,
            expect_errors=True, max_tx_rate=1000,
            error_message='Port speed for eth0 could not be determined. Check '
            'if the port is cabled correctly.')

    def test_interface_vf_ratelimit_modify_add_ratelimit(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.worker)
        port, lower_iface = self._create_sriov(
            'sriov', host=self.worker, sriov_numvfs=4)
        vf = self._create_vf('vf1', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=3, expect_errors=False)

        patch_result = self.patch_dict_json(
            '%s' % self._get_path(vf['uuid']),
            max_tx_rate=2000)

        self.assertEqual('application/json', patch_result.content_type)
        self.assertEqual(http_client.OK, patch_result.status_code)
        self.assertEqual(2000, patch_result.json['max_tx_rate'])

    def test_interface_vf_ratelimit_modify_add_ratelimit_port_speed_none(self):
        interface_id = len(self.profile['interfaces']) + 1
        port_id = len(self.profile['ports'])
        port = dbutils.create_test_ethernet_port(
            id=port_id,
            name='eth' + str(port_id),
            host_id=self.worker.id,
            interface_id=interface_id,
            sriov_totalvfs=4, sriov_numvfs=4,
            speed=None)
        self.profile['ports'].append(port)

        interface = self._post_get_test_interface(
            ifname='sriov',
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            forihostid=self.worker.id, ihost_uuid=self.worker.uuid,
            sriov_numvfs=4)
        response = self._post_and_check(interface)
        interface['uuid'] = response.json['uuid']
        self.profile['interfaces'].append(interface)

        vf = self._create_vf('vf0', lower_iface=interface,
            host=self.worker, sriov_numvfs=1,
            expect_errors=False)

        patch_result = self.patch_dict_json(
            '%s' % self._get_path(vf['uuid']),
            max_tx_rate=1000,
            expect_errors=True)

        self.assertEqual('application/json', patch_result.content_type)
        self.assertEqual(http_client.BAD_REQUEST, patch_result.status_code)
        self.assertTrue(patch_result.json['error_message'])
        self.assertIn('Port speed for eth0 could not be determined. Check if '
                      'the port is cabled correctly.',
                      patch_result.json['error_message'])

    def test_interface_vf_ratelimit_modify_adjust_ratelimit(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.worker)
        port, lower_iface = self._create_sriov(
            'sriov', host=self.worker, sriov_numvfs=4)
        vf = self._create_vf('vf1', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=3,
            expect_errors=False, max_tx_rate=1000)

        patch_result = self.patch_dict_json(
            '%s' % self._get_path(vf['uuid']),
            max_tx_rate=2000)

        self.assertEqual('application/json', patch_result.content_type)
        self.assertEqual(http_client.OK, patch_result.status_code)
        self.assertEqual(2000, patch_result.json['max_tx_rate'])

    def test_interface_vf_ratelimit_modify_clear_ratelimit(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT,
                              host=self.worker)
        port, lower_iface = self._create_sriov(
            'sriov', host=self.worker, sriov_numvfs=4)
        vf = self._create_vf('vf1', lower_iface=lower_iface,
            host=self.worker, sriov_numvfs=3,
            expect_errors=False, max_tx_rate=1000)

        patch_result = self.patch_dict_json(
            '%s' % self._get_path(vf['uuid']),
            max_tx_rate=0)

        self.assertEqual('application/json', patch_result.content_type)
        self.assertEqual(http_client.OK, patch_result.status_code)
        self.assertEqual(0, patch_result.json['max_tx_rate'])


class TestAIOPost(InterfaceTestCase):
    def setUp(self):
        super(TestAIOPost, self).setUp()
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
            expect_errors=True,
            error_message='Platform VLAN interface cannot be created over a '
            'data interface')

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
            expect_errors=True,
            error_message='Platform VLAN interface cannot be created over a '
            'data interface')

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
            expect_errors=True,
            error_message='Platform VLAN interface cannot be created over a '
            'data interface')

    # Expected message:  VLAN id ___ already in use on interface ___
    def test_create_vlan_id_already_in_use(self):
        port, iface = self._create_ethernet('eth1', constants.NETWORK_TYPE_NONE)
        self._create_vlan('vlan1', constants.NETWORK_TYPE_DATA,
                          constants.INTERFACE_CLASS_DATA, vlan_id=1,
                          lower_iface=iface, datanetworks='group0-ext0')
        self._create_vlan('vlan2', constants.NETWORK_TYPE_DATA,
                          constants.INTERFACE_CLASS_DATA, vlan_id=1,
                          lower_iface=iface, datanetworks='group0-ext1',
                          expect_errors=True,
                          error_message='VLAN id 1 already in use on interface '
                          'eth1')

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
            self.assertIn("VLAN based data network 'group0-data0' cannot be "
                          "assigned to a VLAN interface",
                          response.json['error_message'])

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
            self.assertIn('Data interface data0 is already attached to this '
                          'Data Network: group0-data0.',
                          response.json['error_message'])

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


class TestAIOPatch(InterfaceTestCase):
    def setUp(self):
        super(TestAIOPatch, self).setUp()
        self._create_host(constants.CONTROLLER, constants.WORKER,
                          admin=constants.ADMIN_LOCKED)
        self._create_datanetworks()

    def _setup_sriov_interface_w_numvfs(self, numvfs=5):
        # create sriov interface
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT)
        interface = dbutils.create_test_interface(forihostid='1')
        dbutils.create_test_ethernet_port(
            id=1, name='eth1', host_id=1, interface_id=interface.id,
            pciaddr='0000:00:00.11', dev_id=0, sriov_totalvfs=5, sriov_numvfs=1,
            driver='i40e',
            sriov_vf_driver='i40evf')

        # patch to set numvfs
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            sriov_numvfs=numvfs,
            expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(response.json['sriov_numvfs'], numvfs)

        return interface

    # Expected error: Value for number of SR-IOV VFs must be > 0.
    def test_invalid_sriov_numvfs(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT)
        port, interface = self._create_ethernet('eth0',
                                                constants.NETWORK_TYPE_NONE)
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertIn('Value for number of SR-IOV VFs must be > 0.',
            response.json['error_message'])

    # Expected error: Number of SR-IOV VFs is specified but
    # interface class is not pci-sriov.
    def test_invalid_numvfs_data_class(self):
        # class data -> class data but with numvfs
        interface = dbutils.create_test_interface(
            forihostid='1',
            ifclass=constants.INTERFACE_CLASS_DATA)

        # case 1: non-sriov class has numvfs
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            ifclass=constants.INTERFACE_CLASS_DATA,
            sriov_numvfs=1,
            expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertIn('Number of SR-IOV VFs is specified but interface '
                      'class is not pci-sriov.',
                      response.json['error_message'])

    def test_invalid_vf_driver_data_class(self):
        # class data -> class data but with sriov_vf_driver
        interface = dbutils.create_test_interface(
            forihostid='1',
            ifclass=constants.INTERFACE_CLASS_DATA)

        # case 2: non-sriov class has vf_driver
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            ifclass=constants.INTERFACE_CLASS_DATA,
            sriov_vf_driver=constants.SRIOV_DRIVER_TYPE_NETDEVICE,
            expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertIn('SR-IOV VF driver is specified but interface '
                      'class is not pci-sriov.',
                      response.json['error_message'])

    def test_invalid_numvfs_sriov_to_data(self):
        interface = self._setup_sriov_interface_w_numvfs()
        # patch to change interface class to data with numvfs, and verify bad numvfs
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            ifclass=constants.INTERFACE_CLASS_DATA,
            sriov_numvfs=5,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertIn('Number of SR-IOV VFs is specified but interface class is not pci-sriov',
            response.json['error_message'])

    def test_invalid_vfdriver_sriov_to_data(self):
        interface = self._setup_sriov_interface_w_numvfs()
        # patch to change interface class to data with sriov_vf_driver,
        # and verify bad sriov_vf_driver
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            ifclass=constants.INTERFACE_CLASS_DATA,
            sriov_vf_driver=constants.SRIOV_DRIVER_TYPE_NETDEVICE,
            expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertIn('SR-IOV VF driver is specified but interface class is not pci-sriov',
            response.json['error_message'])

    def test_clear_numvfs_when_no_longer_sriov_class(self):
        interface = self._setup_sriov_interface_w_numvfs()
        # patch to change interface class to data, and verify numvfs is 0
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            ifclass=constants.INTERFACE_CLASS_DATA,
            expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(response.json["sriov_numvfs"], 0)

    def test_clear_vfdriver_when_no_longer_sriov_class(self):
        interface = self._setup_sriov_interface_w_numvfs()

        # patch to change interface vf driver to netdevice
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            sriov_vf_driver=constants.SRIOV_DRIVER_TYPE_NETDEVICE,
            expect_errors=False)
        self.assertEqual(response.json["sriov_vf_driver"],
            constants.SRIOV_DRIVER_TYPE_NETDEVICE)

        # patch to change interface class to data, and verify numvfs is 0
        response = self.patch_dict_json(
            '%s' % self._get_path(interface['uuid']),
            ifclass=constants.INTERFACE_CLASS_DATA,
            expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(response.json["sriov_vf_driver"], None)

    # Expected error: SR-IOV can't be configured on this interface
    def test_invalid_sriov_totalvfs_zero(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT)
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
        self.assertIn('SR-IOV can\'t be configured on this interface',
            response.json['error_message'])

    # Expected error: The interface support a maximum of ___ VFs
    def test_invalid_sriov_exceeded_totalvfs(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT)
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
        self.assertIn('The interface support a maximum of',
            response.json['error_message'])

    # Expected error: Corresponding port has invalid driver
    def test_invalid_driver_for_sriov(self):
        self._create_ethernet('mgmt', constants.NETWORK_TYPE_MGMT)
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
        self.assertIn('Corresponding port has invalid driver',
            response.json['error_message'])

    def test_modify_platform_class_to_none(self):
        interface = dbutils.create_test_interface(
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid,
            ifname='lo',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            iftype=constants.INTERFACE_TYPE_VIRTUAL)
        with mock.patch.object(self.dbapi, "routes_destroy_by_interface") as route_mock:
            with mock.patch.object(self.dbapi,
                                   "addresses_destroy_by_interface") as addr_mock:
                with mock.patch.object(self.dbapi,
                                       "address_modes_destroy_by_interface") as addrmode_mock:
                    # Reset interface class the first time
                    response = self.patch_dict_json(
                        '%s' % self._get_path(interface['uuid']),
                        ifclass=constants.INTERFACE_CLASS_NONE)
                    self.assertEqual('application/json', response.content_type)
                    self.assertEqual(http_client.OK, response.status_code)
                    route_mock.assert_called()
                    addr_mock.assert_not_called()
                    addrmode_mock.assert_called()

                    # Reset interface class the second time
                    response = self.patch_dict_json(
                        '%s' % self._get_path(interface['uuid']),
                        ifclass=constants.INTERFACE_CLASS_NONE)
                    self.assertEqual('application/json', response.content_type)
                    self.assertEqual(http_client.OK, response.status_code)
                    route_mock.assert_called()
                    addr_mock.assert_not_called()
                    addrmode_mock.assert_called()

    def test_modify_data_class_to_none(self):
        interface = dbutils.create_test_interface(
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid,
            ifclass=constants.INTERFACE_CLASS_DATA)
        with mock.patch.object(self.dbapi, "routes_destroy_by_interface") as route_mock:
            with mock.patch.object(self.dbapi,
                                   "addresses_destroy_by_interface") as addr_mock:
                with mock.patch.object(self.dbapi,
                                       "address_modes_destroy_by_interface") as addrmode_mock:
                    # Reset interface class the first time
                    response = self.patch_dict_json(
                        '%s' % self._get_path(interface['uuid']),
                        ifclass=constants.INTERFACE_CLASS_NONE)
                    self.assertEqual('application/json', response.content_type)
                    self.assertEqual(http_client.OK, response.status_code)
                    route_mock.assert_called()
                    addr_mock.assert_called()
                    addrmode_mock.assert_called()

    def test_modify_vlan_iface_parameters(self):
        iface = self._create_vlan('mgmt', constants.NETWORK_TYPE_MGMT,
                          constants.INTERFACE_CLASS_PLATFORM, 2)
        data = {
            'ifname': 'mgmt0',
        }
        # A VLAN Interface must allow param changes without error
        self._patch_and_check(data, self._get_path(iface['uuid']),
                              expect_errors=False)


class FakeConductorAPI(object):

    def __init__(self):
        self.update_sriov_config = mock.MagicMock()
        self.update_sriov_vf_config = mock.MagicMock()


class TestAIOUnlockedPost(InterfaceTestCase):
    def setUp(self):
        super(TestAIOUnlockedPost, self).setUp()
        p = mock.patch('sysinv.common.utils.is_aio_simplex_system')
        self.mock_utils_is_aio_simplex_system = p.start()
        self.mock_utils_is_aio_simplex_system.return_value = True
        self.addCleanup(p.stop)

        # Mock the conductor API
        self.fake_conductor_api = FakeConductorAPI()
        p = mock.patch('sysinv.conductor.rpcapiproxy.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

        self._create_host(constants.CONTROLLER, constants.WORKER,
                          admin=constants.ADMIN_UNLOCKED)
        self.interfaces = {
            'sriov': dbutils.create_test_interface(
                ifname='sriov', id=1,
                ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
                forihostid=self.controller.id,
                ihost_uuid=self.controller.uuid,
                sriov_numvfs=8),
            'mgmt': dbutils.create_test_interface(
                ifname='mgmt', id=2,
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                forihostid=self.controller.id,
                ihost_uuid=self.controller.uuid,
                networktypelist=[constants.NETWORK_TYPE_MGMT]),
        }
        idx = 1
        self.ports = []
        for interface in self.interfaces.keys():
            port = dbutils.create_test_ethernet_port(
                id=idx, name='eth' + str(idx),
                host_id=self.controller.uuid,
                interface_id=self.interfaces[interface].id,
                interface_uuid=self.interfaces[interface].uuid,
                pciaddr='0000:00:00.' + str(idx),
                dev_id=0,
                sriov_totalvfs=8,
                sriov_vf_driver='mlx5_core',
                driver='mlx5_core')
            self.ports.append(port)
            idx += 1

        self.network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_MGMT)
        self.if_net_mgmt = dbutils.create_test_interface_network(
            interface_id=self.interfaces['mgmt'].id,
            network_id=self.network.id)

    def test_add_interface_sriov_vf(self):
        interface = self._post_get_test_interface(
            ifname='sriov_vf',
            iftype=constants.INTERFACE_TYPE_VF,
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            uses=[self.interfaces['sriov'].ifname],
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid,
            sriov_numvfs=1,
            sriov_vf_driver='vfio',
            max_tx_rate=200)
        # system host-if-add controller-0 sriov_vf vf sriov -c pci-sriov --num-vfs 1
        self._post_and_check(interface, expect_errors=False)
        self.fake_conductor_api.update_sriov_vf_config.assert_called()

    def test_non_aiosx_add_interface_sriov_vf_error(self):
        self.mock_utils_is_aio_simplex_system.return_value = False
        interface = self._post_get_test_interface(
            ifname='sriov_vf',
            iftype=constants.INTERFACE_TYPE_VF,
            ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
            uses=[self.interfaces['sriov'].ifname],
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid,
            sriov_numvfs=1,
            sriov_vf_driver='vfio')
        # system host-if-add controller-0 sriov_vf vf sriov -c pci-sriov --num-vfs 1
        self._post_and_check(interface, expect_errors=True,
                             error_message="Host must be locked")
        self.mock_utils_is_aio_simplex_system.return_value = True

    def test_del_interface_sriov_vf(self):
        sriov_vf = dbutils.create_test_interface(
                        ifname='sriov_vf', id=3,
                        uses=[self.interfaces['sriov'].ifname],
                        ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
                        iftype=constants.INTERFACE_TYPE_VF,
                        forihostid=self.controller.id,
                        ihost_uuid=self.controller.uuid,
                        sriov_numvfs=1)
        # system host-if-delete controller-0 sriov_vf
        self._delete_and_check(sriov_vf.uuid, expect_errors=False)

    def test_non_aiosx_del_interface_sriov_vf(self):
        self.mock_utils_is_aio_simplex_system.return_value = False
        sriov_vf = dbutils.create_test_interface(
                        ifname='sriov_vf', id=3,
                        uses=[self.interfaces['sriov'].ifname],
                        ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
                        iftype=constants.INTERFACE_TYPE_VF,
                        forihostid=self.controller.id,
                        ihost_uuid=self.controller.uuid,
                        sriov_numvfs=1)
        # system host-if-delete controller-0 sriov_vf
        self._delete_and_check(sriov_vf.uuid, expect_errors=True,
                    error_message="Host must be locked")
        self.mock_utils_is_aio_simplex_system.return_value = True


class TestAIOUnlockedPatch(InterfaceTestCase):
    def setUp(self):
        super(TestAIOUnlockedPatch, self).setUp()
        p = mock.patch('sysinv.common.utils.is_aio_simplex_system')
        self.mock_utils_is_aio_simplex_system = p.start()
        self.mock_utils_is_aio_simplex_system.return_value = True
        self.addCleanup(p.stop)

        # Mock the conductor API
        self.fake_conductor_api = FakeConductorAPI()
        p = mock.patch('sysinv.conductor.rpcapiproxy.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

        self._create_host(constants.CONTROLLER, constants.WORKER,
                          admin=constants.ADMIN_UNLOCKED)

        self.interfaces = {
            'data0': dbutils.create_test_interface(
                ifname='data0', id=1,
                ifclass=constants.INTERFACE_CLASS_DATA,
                forihostid=self.controller.id,
                ihost_uuid=self.controller.uuid),
            'pass0': dbutils.create_test_interface(
                ifname='pass0', id=2,
                ifclass=constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                forihostid=self.controller.id,
                ihost_uuid=self.controller.uuid),
            'plat0': dbutils.create_test_interface(
                ifname='plat0', id=3,
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                forihostid=self.controller.id,
                ihost_uuid=self.controller.uuid),
            'sriov': dbutils.create_test_interface(
                ifname='sriov', id=4,
                ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
                forihostid=self.controller.id,
                ihost_uuid=self.controller.uuid,
                sriov_numvfs=8),
            'mgmt': dbutils.create_test_interface(
                ifname='mgmt', id=5,
                ifclass=constants.INTERFACE_CLASS_PLATFORM,
                forihostid=self.controller.id,
                ihost_uuid=self.controller.uuid,
                networktypelist=[constants.NETWORK_TYPE_MGMT])
        }

        idx = 1
        self.ports = []
        for interface in self.interfaces.keys():
            port = dbutils.create_test_ethernet_port(
                id=idx, name='eth' + str(idx),
                host_id=self.controller.uuid,
                interface_id=self.interfaces[interface].id,
                interface_uuid=self.interfaces[interface].uuid,
                pciaddr='0000:00:00.' + str(idx),
                dev_id=0, sriov_totalvfs=8,
                sriov_vf_driver='mlx5_core', driver='mlx5_core')
            self.ports.append(port)
            idx += 1

        self.network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_MGMT)
        self.if_net_mgmt = dbutils.create_test_interface_network(
            interface_id=self.interfaces['mgmt'].id,
            network_id=self.network.id)

    def test_interface_data_conversion_to_sriov(self):
        data = {
            'ifname': 'sriov0',
            'ifclass': 'pci-sriov',
            'sriov_numvfs': 8,
            'sriov_vf_driver': 'vfio',
        }
        # system host-if-modify controller-0 data0 -c pci-sriov -n sriov0 -N 8
        self._patch_and_check(data, self._get_path(self.interfaces['data0'].uuid),
                              expect_errors=False)
        self.fake_conductor_api.update_sriov_config.assert_called()

    def test_interface_platform_conversion_to_sriov(self):
        data = {
            'ifname': 'sriov1',
            'ifclass': 'pci-sriov',
            'sriov_numvfs': 8,
        }
        # system host-if-modify controller-0 plat0 -c pci-sriov -n sriov1 -N 8
        self._patch_and_check(data, self._get_path(self.interfaces['plat0'].uuid),
                              expect_errors=False)
        self.fake_conductor_api.update_sriov_config.assert_called()

    def test_interface_pcipasstrough_conversion_to_sriov(self):
        data = {
            'ifname': 'sriov2',
            'ifclass': 'pci-sriov',
            'sriov_numvfs': 8,
        }
        # system host-if-modify controller-0 pass0 -c pci-sriov -n sriov2 -N 8
        self._patch_and_check(data, self._get_path(self.interfaces['pass0'].uuid),
                              expect_errors=False)
        self.fake_conductor_api.update_sriov_config.assert_called()

    def test_non_aiosx_interface_conversion_to_sriov_error(self):
        self.mock_utils_is_aio_simplex_system.return_value = False
        data = {
            'ifname': 'sriov2',
            'ifclass': 'pci-sriov',
            'sriov_numvfs': 8,
        }
        self._patch_and_check(data, self._get_path(self.interfaces['data0'].uuid),
                              expect_errors=True,
                              error_message="Host must be locked")
        self._patch_and_check(data, self._get_path(self.interfaces['plat0'].uuid),
                              expect_errors=True,
                              error_message="Host must be locked")
        self._patch_and_check(data, self._get_path(self.interfaces['pass0'].uuid),
                              expect_errors=True,
                              error_message="Host must be locked")
        self.mock_utils_is_aio_simplex_system.return_value = True

    def test_interface_sriov_modify_error(self):
        data = {'sriov_numvfs': 4}
        # system host-if-modify controller-0 sriov -N 4
        self._patch_and_check(data, self._get_path(self.interfaces['sriov'].uuid),
                              expect_errors=True,
                              error_message="Host must be locked")

        data = {'ifname': 'new_name'}
        # system host-if-modify controller-0 sriov -n new_name
        self._patch_and_check(data, self._get_path(self.interfaces['sriov'].uuid),
                              expect_errors=True,
                              error_message="Host must be locked")

    def test_interface_sriov_vf_modify_error(self):
        sriov_vf = dbutils.create_test_interface(
                        ifname='sriov_vf', uses=['sriov'],
                        ifclass=constants.INTERFACE_CLASS_PCI_SRIOV,
                        iftype=constants.INTERFACE_TYPE_VF,
                        forihostid=self.controller.id,
                        ihost_uuid=self.controller.uuid,
                        sriov_numvfs=1)
        data = {'sriov_numvfs': 2}
        # system host-if-modify controller-0 sriov_vf -N 2
        self._patch_and_check(data, self._get_path(sriov_vf.uuid),
                              expect_errors=True,
                              error_message="Host must be locked")


class IPv4TestPost(TestPostMixin,
                   InterfaceTestCase):
    pass


class IPv6TestPost(TestPostMixin,
                   dbbase.BaseIPv6Mixin,
                   InterfaceTestCase):
    pass


class IPv4TestPatch(TestPatchMixin,
                    InterfaceTestCase):
    pass


class IPv6TestPatch(TestPatchMixin,
                    dbbase.BaseIPv6Mixin,
                    InterfaceTestCase):
    pass
