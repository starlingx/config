# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
#
#
# Copyright (c) 2013-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /ihosts/ methods.
"""

import mock
import webtest.app
from six.moves import http_client

from sysinv.common import constants
from sysinv.openstack.common import uuidutils

from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils


class FakeConductorAPI(object):

    def __init__(self, dbapi):
        self.dbapi = dbapi
        self.create_controller_filesystems = mock.MagicMock()
        self.configure_ihost = mock.MagicMock()
        self.unconfigure_ihost = mock.MagicMock()
        self.remove_host_config = mock.MagicMock()
        self.delete_barbican_secret = mock.MagicMock()
        self.iplatform_update_by_ihost = mock.MagicMock()
        self.evaluate_app_reapply = mock.MagicMock()
        self.update_clock_synchronization_config = mock.MagicMock()

    def create_ihost(self, context, values):
        # Create the host in the DB as the code under test expects this
        ihost = self.dbapi.ihost_create(values)
        return ihost


class TestHost(base.FunctionalTest):

    def setUp(self):
        super(TestHost, self).setUp()

        # Mock the conductor API
        self.fake_conductor_api = FakeConductorAPI(self.dbapi)
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

        # Mock the maintenance API
        p = mock.patch('sysinv.api.controllers.v1.mtce_api.host_add')
        self.mock_mtce_api_host_add = p.start()
        self.mock_mtce_api_host_add.return_value = {'status': 'pass'}
        self.addCleanup(p.stop)
        p = mock.patch('sysinv.api.controllers.v1.mtce_api.host_modify')
        self.mock_mtce_api_host_modify = p.start()
        self.mock_mtce_api_host_modify.return_value = {'status': 'pass'}
        self.addCleanup(p.stop)
        p = mock.patch('sysinv.api.controllers.v1.mtce_api.host_delete')
        self.mock_mtce_api_host_delete = p.start()
        self.mock_mtce_api_host_delete.return_value = {'status': 'pass'}
        self.addCleanup(p.stop)

        # Mock the VIM API
        p = mock.patch('sysinv.api.controllers.v1.vim_api.vim_host_add')
        self.mock_vim_api_host_add = p.start()
        self.addCleanup(p.stop)
        p = mock.patch('sysinv.api.controllers.v1.vim_api.vim_host_delete')
        self.mock_vim_api_host_delete = p.start()
        self.addCleanup(p.stop)
        p = mock.patch('sysinv.api.controllers.v1.vim_api.vim_host_action')
        self.mock_vim_api_host_action = p.start()
        self.addCleanup(p.stop)

        # Mock the SM API
        p = mock.patch('sysinv.api.controllers.v1.sm_api.lock_pre_check')
        self.mock_sm_api_lock_pre_check = p.start()
        self.mock_sm_api_lock_pre_check.return_value = {'error_code': '0'}
        self.addCleanup(p.stop)
        p = mock.patch('sysinv.api.controllers.v1.sm_api.swact_pre_check')
        self.mock_sm_api_swact_pre_check = p.start()
        self.mock_sm_api_swact_pre_check.return_value = {'error_code': '0'}
        self.addCleanup(p.stop)

        # Mock the patch API
        p = mock.patch('sysinv.api.controllers.v1.patch_api.patch_drop_host')
        self.mock_patch_api_drop_host = p.start()
        self.addCleanup(p.stop)

        # Behave as if the API is running on controller-0
        p = mock.patch('socket.gethostname')
        self.mock_socket_gethostname = p.start()
        self.mock_socket_gethostname.return_value = 'controller-0'
        self.addCleanup(p.stop)

        # Behave as if running on a virtual system
        p = mock.patch('sysinv.common.utils.is_virtual')
        self.mock_utils_is_virtual = p.start()
        self.mock_utils_is_virtual.return_value = True
        self.addCleanup(p.stop)

        # Create an isystem and load
        self.system = dbutils.create_test_isystem(
            capabilities={"cinder_backend": constants.CINDER_BACKEND_CEPH,
                          "vswitch_type": constants.VSWITCH_TYPE_NONE,
                          "region_config": False,
                          "sdn_enabled": False,
                          "shared_services": "[]"}
        )
        self.load = dbutils.create_test_load()

    def _configure_networks(self):
        mgmt_address_pool = dbutils.create_test_address_pool(
            id=1,
            network='192.168.204.0',
            name='management',
            ranges=[['192.168.204.2', '192.168.204.254']],
            prefix=24)
        dbutils.create_test_network(
            id=1,
            name='mgmt',
            type=constants.NETWORK_TYPE_MGMT,
            link_capacity=1000,
            vlan_id=2,
            address_pool_id=mgmt_address_pool.id)
        cluster_address_pool = dbutils.create_test_address_pool(
            id=2,
            network='192.168.206.0',
            name='cluster-host',
            ranges=[['192.168.206.2', '192.168.206.254']],
            prefix=24)
        dbutils.create_test_network(
            id=2,
            name='cluster-host',
            type=constants.NETWORK_TYPE_CLUSTER_HOST,
            link_capacity=10000,
            vlan_id=3,
            address_pool_id=cluster_address_pool.id)
        address_pool_oam = dbutils.create_test_address_pool(
            id=3,
            network='128.224.150.0',
            name='oam',
            ranges=[['128.224.150.1', '128.224.151.254']],
            prefix=23)
        dbutils.create_test_network(
            id=3,
            name='oam',
            type=constants.NETWORK_TYPE_OAM,
            address_pool_id=address_pool_oam.id)
        dbutils.create_test_address(
            family=2,
            address='10.10.10.3',
            prefix=24,
            name='controller-0-oam',
            address_pool_id=address_pool_oam.id)

    def _create_controller_0(self, **kw):
        ihost = dbutils.create_test_ihost(
            hostname='controller-0',
            mgmt_mac='01:34:67:9A:CD:F0',
            mgmt_ip='192.168.204.3',
            serialid='serial1',
            bm_ip='128.224.150.193',
            config_target='e4ec5ee2-967d-4b2d-8de8-f0a390fcbd35',
            config_applied='e4ec5ee2-967d-4b2d-8de8-f0a390fcbd35',
            **kw)

        dbutils.create_test_ethernet_port(
            id=1,
            name='eth1',
            host_id=ihost['id'],
            interface_id=1,
            pciaddr='0000:00:00.1',
            dev_id=0)
        interface = dbutils.create_test_interface(
            id=1,
            ifname='oam',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=ihost['id'],
            ihost_uuid=ihost['uuid'])
        iface = self.dbapi.iinterface_get(interface['uuid'])
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_OAM)
        dbutils.create_test_interface_network(
            interface_id=iface.id,
            network_id=network.id)

        dbutils.create_test_ethernet_port(
            id=2,
            name='eth2',
            host_id=ihost['id'],
            interface_id=2,
            pciaddr='0000:00:00.2',
            dev_id=0)
        interface = dbutils.create_test_interface(
            id=2,
            ifname='mgmt',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=ihost['id'],
            ihost_uuid=ihost['uuid'])
        iface = self.dbapi.iinterface_get(interface['uuid'])
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        dbutils.create_test_interface_network(
            interface_id=iface.id,
            network_id=network.id)

        dbutils.create_test_ethernet_port(
            id=3,
            name='eth3',
            host_id=ihost['id'],
            interface_id=3,
            pciaddr='0000:00:00.3',
            dev_id=0)
        interface = dbutils.create_test_interface(
            id=3,
            ifname='cluster',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=ihost['id'],
            ihost_uuid=ihost['uuid'])
        iface = self.dbapi.iinterface_get(interface['uuid'])
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        dbutils.create_test_interface_network(
            interface_id=iface.id,
            network_id=network.id)

        return ihost

    def _create_controller_1(self, **kw):
        ihost = dbutils.create_test_ihost(
            hostname='controller-1',
            mgmt_mac='01:34:67:9A:CD:F1',
            mgmt_ip='192.168.204.4',
            serialid='serial2',
            bm_ip='128.224.150.194',
            config_target='89fbefe7-7b43-4bd2-9500-663b33df2e57',
            config_applied='89fbefe7-7b43-4bd2-9500-663b33df2e57',
            **kw)

        dbutils.create_test_ethernet_port(
            id=4,
            name='eth1',
            host_id=ihost['id'],
            interface_id=4,
            pciaddr='0000:00:00.1',
            dev_id=0)
        interface = dbutils.create_test_interface(
            id=4,
            ifname='oam',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=ihost['id'],
            ihost_uuid=ihost['uuid'])
        iface = self.dbapi.iinterface_get(interface['uuid'])
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_OAM)
        dbutils.create_test_interface_network(
            interface_id=iface.id,
            network_id=network.id)

        dbutils.create_test_ethernet_port(
            id=5,
            name='eth2',
            host_id=ihost['id'],
            interface_id=5,
            pciaddr='0000:00:00.2',
            dev_id=0)
        interface = dbutils.create_test_interface(
            id=5,
            ifname='mgmt',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=ihost['id'],
            ihost_uuid=ihost['uuid'])
        iface = self.dbapi.iinterface_get(interface['uuid'])
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        dbutils.create_test_interface_network(
            interface_id=iface.id,
            network_id=network.id)

        dbutils.create_test_ethernet_port(
            id=6,
            name='eth3',
            host_id=ihost['id'],
            interface_id=6,
            pciaddr='0000:00:00.3',
            dev_id=0)
        interface = dbutils.create_test_interface(
            id=6,
            ifname='cluster',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=ihost['id'],
            ihost_uuid=ihost['uuid'])
        iface = self.dbapi.iinterface_get(interface['uuid'])
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        dbutils.create_test_interface_network(
            interface_id=iface.id,
            network_id=network.id)

        return ihost

    def _create_worker_0(self, **kw):
        ihost = dbutils.create_test_ihost(
            personality=constants.WORKER,
            hostname='worker-0',
            mgmt_mac='01:34:67:9A:CD:F2',
            mgmt_ip='192.168.204.5',
            serialid='serial3',
            bm_ip='128.224.150.195',
            config_target='0ed92b98-261e-48bc-b48c-f2cdd1ec2b42',
            config_applied='0ed92b98-261e-48bc-b48c-f2cdd1ec2b42',
            **kw)

        node = self.dbapi.inode_create(ihost['id'],
                                       dbutils.get_test_node(id=1))
        cpu = self.dbapi.icpu_create(
            ihost['id'],
            dbutils.get_test_icpu(id=1, cpu=0,
                                  forihostid=ihost['id'],
                                  forinodeid=node.id,))
        self.dbapi.imemory_create(
            ihost['id'],
            dbutils.get_test_imemory(id=1,
                                     hugepages_configured=True,
                                     vm_hugepages_nr_1G_pending=0,
                                     forinodeid=cpu.forinodeid))

        dbutils.create_test_ethernet_port(
            id=7,
            name='eth1',
            host_id=ihost['id'],
            interface_id=7,
            pciaddr='0000:00:00.1',
            dev_id=0)
        interface = dbutils.create_test_interface(
            id=7,
            ifname='mgmt',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=ihost['id'],
            ihost_uuid=ihost['uuid'])
        iface = self.dbapi.iinterface_get(interface['uuid'])
        network = self.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)
        dbutils.create_test_interface_network(
            interface_id=iface.id,
            network_id=network.id)

        dbutils.create_test_ethernet_port(
            id=8,
            name='eth2',
            host_id=ihost['id'],
            interface_id=5,
            pciaddr='0000:00:00.2',
            dev_id=0)
        interface = dbutils.create_test_interface(
            id=8,
            ifname='cluster',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=ihost['id'],
            ihost_uuid=ihost['uuid'])
        iface = self.dbapi.iinterface_get(interface['uuid'])
        network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        dbutils.create_test_interface_network(
            interface_id=iface.id,
            network_id=network.id)

        return ihost


class TestPost(TestHost):

    def test_create_ihost_controller_0(self):
        # Test creation of controller-0
        ndict = dbutils.post_get_test_ihost(hostname='controller-0',
                                            mgmt_ip=None,
                                            serialid='serial1')
        self.post_json('/ihosts', ndict,
                       headers={'User-Agent': 'sysinv-test'})

        # Verify that the root filesystem was created
        self.fake_conductor_api.create_controller_filesystems.\
            assert_called_with(mock.ANY, ndict['rootfs_device'])
        # Verify that the host was configured
        self.fake_conductor_api.configure_ihost.assert_called_once()
        # Verify that the host was created and some basic attributes match
        result = self.get_json('/ihosts/%s' % ndict['hostname'])
        self.assertEqual(ndict['personality'], result['personality'])
        self.assertEqual(ndict['serialid'], result['serialid'])

    def test_create_ihost_controller_1(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0()

        # Test creation of controller-1
        ndict = dbutils.post_get_test_ihost(hostname='controller-1',
                                            mgmt_ip=None,
                                            serialid='serial2',
                                            bm_ip="128.224.150.194")
        self.post_json('/ihosts', ndict,
                       headers={'User-Agent': 'sysinv-test'})

        # Verify that the root filesystem was not created
        self.fake_conductor_api.create_controller_filesystems.\
            assert_not_called()
        # Verify that the host was configured
        self.fake_conductor_api.configure_ihost.assert_called_once()
        # Verify that the host was added to maintenance
        self.mock_mtce_api_host_add.assert_called_once()
        # Verify that the host was added to the VIM
        self.mock_vim_api_host_add.assert_called_once()
        # Verify that the host was created and some basic attributes match
        result = self.get_json('/ihosts/%s' % ndict['hostname'])
        self.assertEqual(ndict['personality'], result['personality'])
        self.assertEqual(ndict['serialid'], result['serialid'])

    def test_create_ihost_worker(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0()

        # Test creation of worker
        ndict = dbutils.post_get_test_ihost(hostname='worker-0',
                                            personality='worker',
                                            subfunctions=None,
                                            mgmt_ip=None,
                                            serialid='serial2',
                                            bm_ip="128.224.150.195")
        self.post_json('/ihosts', ndict,
                       headers={'User-Agent': 'sysinv-test'})

        # Verify that the root filesystem was not created
        self.fake_conductor_api.create_controller_filesystems.\
            assert_not_called()
        # Verify that the host was configured
        self.fake_conductor_api.configure_ihost.assert_called_once()
        # Verify that the host was added to maintenance
        self.mock_mtce_api_host_add.assert_called_once()
        # Verify that the host was added to the VIM
        self.mock_vim_api_host_add.assert_called_once()
        # Verify that the host was created and some basic attributes match
        result = self.get_json('/ihosts/%s' % ndict['hostname'])
        self.assertEqual(ndict['personality'], result['personality'])
        self.assertEqual(ndict['serialid'], result['serialid'])

    def test_create_ihost_valid_extra(self):
        # Test creation of host with a valid location
        ndict = dbutils.post_get_test_ihost(hostname='controller-0',
                                            location={'Country': 'Canada',
                                                      'City': 'Ottawa'})
        self.post_json('/ihosts', ndict,
                       headers={'User-Agent': 'sysinv-test'})

        # Verify that the host was created with the specified location
        result = self.get_json('/ihosts/%s' % ndict['hostname'])
        self.assertEqual(ndict['location'], result['location'])

    def test_create_ihost_invalid_extra(self):
        # Test creation of host with an invalid location
        ndict = dbutils.post_get_test_ihost(hostname='controller-0',
                                            location={'foo': 0.123})
        self.assertRaises(webtest.app.AppError,
                          self.post_json, '/ihosts', ndict,
                          headers={'User-Agent': 'sysinv-test'})

    def test_create_ihost_missing_mgmt_mac(self):
        # Test creation of a second node with missing management MAC
        self._configure_networks()
        # Create controller-0
        self._create_controller_0()

        ndict = dbutils.post_get_test_ihost(hostname='controller-1',
                                            personality='controller',
                                            subfunctions=None,
                                            mgmt_mac=None,
                                            mgmt_ip=None,
                                            serialid='serial2',
                                            bm_ip="128.224.150.195")

        self.assertRaises(webtest.app.AppError,
                          self.post_json, '/ihosts', ndict,
                          headers={'User-Agent': 'sysinv-test'})

    def test_create_ihost_invalid_mgmt_mac_format(self):
        # Test creation of a second node with an invalid management MAC format
        self._configure_networks()
        # Create controller-0
        self._create_controller_0()

        ndict = dbutils.post_get_test_ihost(hostname='controller-1',
                                            personality='controller',
                                            subfunctions=None,
                                            mgmt_mac='52:54:00:59:02:9',
                                            mgmt_ip=None,
                                            serialid='serial2',
                                            bm_ip="128.224.150.195")

        self.assertRaises(webtest.app.AppError,
                          self.post_json, '/ihosts', ndict,
                          headers={'User-Agent': 'sysinv-test'})


class TestDelete(TestHost):

    def test_delete_ihost(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0()
        # Create a worker host
        ndict = dbutils.post_get_test_ihost(hostname='worker-0',
                                            personality='worker',
                                            subfunctions=None,
                                            mgmt_ip=None,
                                            serialid='serial2',
                                            bm_ip="128.224.150.195")
        self.post_json('/ihosts', ndict,
                       headers={'User-Agent': 'sysinv-test'})

        # Delete the worker host
        self.delete('/ihosts/%s' % ndict['hostname'],
                    headers={'User-Agent': 'sysinv-test'})

        # Verify that the host was deleted from the VIM
        self.mock_vim_api_host_delete.assert_called_once()
        # Verify that the host was deleted from maintenance
        self.mock_mtce_api_host_delete.assert_called_once()
        # Verify that the host was unconfigured
        self.fake_conductor_api.unconfigure_ihost.assert_called_once()
        # Verify that the host was deleted from barbican
        self.fake_conductor_api.delete_barbican_secret.assert_called_once()
        # Verify that the host was dropped from patching
        self.mock_patch_api_drop_host.assert_called_once()
        # Verify the host no longer exists
        response = self.get_json('/ihosts/%s' % ndict['hostname'],
                                 expect_errors=True)
        self.assertEqual(response.status_int, 404)
        self.assertEqual(response.content_type, 'application/json')
        self.assertTrue(response.json['error_message'])


class TestListHosts(TestHost):

    def test_empty_ihost(self):
        data = self.get_json('/ihosts')
        self.assertEqual([], data['ihosts'])

    def test_one(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0()

        # Test creation of worker
        ndict = dbutils.post_get_test_ihost(hostname='worker-0',
                                            personality='worker',
                                            subfunctions=None,
                                            mgmt_ip=None,
                                            serialid='serial2',
                                            bm_ip='128.224.150.195')
        self.post_json('/ihosts', ndict,
                       headers={'User-Agent': 'sysinv-test'})

        # Verify that the host was created with the expected attributes
        result = self.get_json('/ihosts/%s' % ndict['hostname'])
        self.assertEqual(ndict['id'], result['id'])
        assert(uuidutils.is_uuid_like(result['uuid']))
        self.assertEqual(ndict['hostname'], result['hostname'])
        self.assertEqual(ndict['personality'], result['personality'])
        self.assertEqual('worker', result['subfunctions'])
        self.assertEqual(ndict['invprovision'], result['invprovision'])
        self.assertEqual(ndict['mgmt_mac'].lower(), result['mgmt_mac'])
        self.assertEqual(ndict['location'], result['location'])
        self.assertEqual(ndict['bm_ip'], result['bm_ip'])
        self.assertEqual(ndict['bm_type'], result['bm_type'])
        self.assertEqual(ndict['bm_username'], result['bm_username'])
        self.assertEqual(ndict['capabilities'], result['capabilities'])
        self.assertEqual(ndict['serialid'], result['serialid'])
        self.assertEqual(ndict['boot_device'], result['boot_device'])
        self.assertEqual(ndict['rootfs_device'], result['rootfs_device'])
        self.assertEqual(ndict['install_output'], result['install_output'])
        self.assertEqual(ndict['console'], result['console'])
        self.assertEqual(ndict['tboot'], result['tboot'])
        self.assertEqual(ndict['ttys_dcd'], result['ttys_dcd'])
        self.assertEqual(ndict['install_output'], result['install_output'])
        # Verify that hidden attributes are not returned
        self.assertNotIn('bm_password', result)

    def test_many(self):
        ihosts = []
        for hostid in range(1000):  # there is a limit of 1000 returned by json
            ndict = dbutils.get_test_ihost(
                id=hostid, hostname=hostid, mgmt_mac=hostid,
                forisystemid=self.system.id,
                mgmt_ip="%s.%s.%s.%s" % (hostid, hostid, hostid, hostid),
                uuid=uuidutils.generate_uuid())
            s = self.dbapi.ihost_create(ndict)
            ihosts.append(s['uuid'])
        data = self.get_json('/ihosts')
        self.assertEqual(len(ihosts), len(data['ihosts']))

        uuids = [n['uuid'] for n in data['ihosts']]
        self.assertEqual(ihosts.sort(), uuids.sort())  # uuids.sort

    def test_ihost_links(self):
        uuid = uuidutils.generate_uuid()
        ndict = dbutils.get_test_ihost(id=1, uuid=uuid,
                                       forisystemid=self.system.id)
        self.dbapi.ihost_create(ndict)
        data = self.get_json('/ihosts/1')
        self.assertIn('links', data.keys())
        self.assertEqual(len(data['links']), 2)
        self.assertIn(uuid, data['links'][0]['href'])

    def test_collection_links(self):
        ihosts = []
        for hostid in range(100):
            ndict = dbutils.get_test_ihost(
                id=hostid, hostname=hostid, mgmt_mac=hostid,
                forisystemid=self.system.id,
                mgmt_ip="%s.%s.%s.%s" % (hostid, hostid, hostid, hostid),
                uuid=uuidutils.generate_uuid())
            ihost = self.dbapi.ihost_create(ndict)
            ihosts.append(ihost['uuid'])
        data = self.get_json('/ihosts/?limit=100')
        self.assertEqual(len(data['ihosts']), 100)

        next_marker = data['ihosts'][-1]['uuid']
        self.assertIn(next_marker, data['next'])

    def test_ports_subresource_link(self):
        ndict = dbutils.get_test_ihost(forisystemid=self.system.id)
        self.dbapi.ihost_create(ndict)

        data = self.get_json('/ihosts/%s' % ndict['uuid'])
        self.assertIn('ports', data.keys())

    def test_ports_subresource(self):
        ndict = dbutils.get_test_ihost(forisystemid=self.system.id)
        self.dbapi.ihost_create(ndict)

        for portid in range(2):
            pdict = dbutils.get_test_port(id=portid,
                                          host_id=ndict['id'],
                                          pciaddr=portid,
                                          uuid=uuidutils.generate_uuid())
            ihost_id = ndict['id']
            self.dbapi.ethernet_port_create(ihost_id, pdict)

        data = self.get_json('/ihosts/%s/ports' % ndict['uuid'])
        self.assertEqual(len(data['ports']), 2)
        self.assertNotIn('next', data.keys())

        # Test collection pagination
        data = self.get_json(
                '/ihosts/%s/ports?limit=1' % ndict['uuid'])
        self.assertEqual(len(data['ports']), 1)
        self.assertIn('next', data.keys())


class TestPatch(TestHost):

    def _patch_host_action(
            self, hostname, action, user_agent, expect_errors=False):
        return self.patch_json('/ihosts/%s' % hostname,
                               [{'path': '/action',
                                 'value': action,
                                 'op': 'replace'}],
                               headers={'User-Agent': user_agent},
                               expect_errors=expect_errors)

    def test_update_optimizable(self):
        # Create controller-0
        ndict = dbutils.post_get_test_ihost(hostname='controller-0',
                                            mgmt_ip=None,
                                            serialid='serial1')
        self.post_json('/ihosts', ndict,
                       headers={'User-Agent': 'sysinv-test'})

        # Update location
        new_location = {'Country': 'Canada', 'City': 'Ottaasdfwa'}
        response = self.patch_json('/ihosts/%s' % ndict['hostname'],
                                   [{'path': '/location',
                                     'value': new_location,
                                     'op': 'replace'}],
                                   headers={'User-Agent': 'sysinv-test'})
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the host was updated with the specified location
        result = self.get_json('/ihosts/%s' % ndict['hostname'])
        self.assertEqual(new_location, result['location'])

    def test_update_clock_synchronization(self):
        # Create controller-0
        ndict = dbutils.post_get_test_ihost(hostname='controller-0',
                                            mgmt_ip=None,
                                            serialid='serial1')
        self.post_json('/ihosts', ndict,
                       headers={'User-Agent': 'sysinv-test'})

        # Update clock_synchronization

        response = self.patch_json('/ihosts/%s' % ndict['hostname'],
                                   [{'path': '/clock_synchronization',
                                     'value': constants.PTP,
                                     'op': 'replace'}],
                                   headers={'User-Agent': 'sysinv-test'})
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the host was configured
        self.fake_conductor_api.configure_ihost.assert_called_once()

        # Verify that the app reapply was checked
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()

        # Verify that update_clock_synchronization_config was called
        self.fake_conductor_api.update_clock_synchronization_config.\
            assert_called_once()

        # Verify that the host was updated with the new clock_synchronization
        result = self.get_json('/ihosts/%s' % ndict['hostname'])
        self.assertEqual(constants.PTP, result['clock_synchronization'])

    def test_unlock_action_controller(self):
        self._configure_networks()
        # Create controller-0
        c0_host = self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Unlock host
        response = self._patch_host_action(c0_host['hostname'],
                                           constants.UNLOCK_ACTION,
                                           'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the unlock was sent to the VIM
        self.mock_vim_api_host_action.assert_called_with(
            mock.ANY,
            c0_host['uuid'],
            c0_host['hostname'],
            constants.UNLOCK_ACTION,
            mock.ANY)
        # Verify that the host was configured
        self.fake_conductor_api.configure_ihost.assert_called_once()
        # Verify that the app reapply was checked
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was added to maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c0_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_force_unlock_action_controller(self):
        self._configure_networks()
        # Create controller-0 - make it offline so force unlock required
        c0_host = self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_OFFLINE)

        # Force unlock host
        response = self._patch_host_action(c0_host['hostname'],
                                           constants.FORCE_UNLOCK_ACTION,
                                           'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the unlock was sent to the VIM
        self.mock_vim_api_host_action.assert_called_with(
            mock.ANY,
            c0_host['uuid'],
            c0_host['hostname'],
            constants.UNLOCK_ACTION,
            mock.ANY)
        # Verify that the host was configured
        self.fake_conductor_api.configure_ihost.assert_called_once()
        # Verify that the app reapply was checked
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was modified in maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c0_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_unlock_action_controller_inventory_not_complete(self):
        self._configure_networks()
        # Create controller-0 without inv_state initial inventory complete
        c0_host = self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            inv_state=None, clock_synchronization=constants.NTP)

        # Unlock host
        response = self._patch_host_action(c0_host['hostname'],
                                           constants.UNLOCK_ACTION,
                                           'sysinv-test',
                                           expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json['error_message'])

    def test_lock_action_controller(self):
        self._configure_networks()
        # Create controller-0

        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Lock host
        response = self._patch_host_action(c1_host['hostname'],
                                           constants.LOCK_ACTION,
                                           'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the SM lock pre check was done
        self.mock_sm_api_lock_pre_check.assert_called_with(c1_host['hostname'],
                                                           timeout=mock.ANY)
        # Verify that the lock was sent to the VIM
        self.mock_vim_api_host_action.assert_called_with(
            mock.ANY,
            c1_host['uuid'],
            c1_host['hostname'],
            constants.LOCK_ACTION,
            mock.ANY)
        # Verify that the host was not configured
        self.fake_conductor_api.configure_ihost.assert_not_called()
        # Verify that the app reapply evaluate was not configured
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was not modified in maintenance
        self.mock_mtce_api_host_modify.assert_not_called()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_force_lock_action_controller(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Lock host
        response = self._patch_host_action(c1_host['hostname'],
                                           constants.FORCE_LOCK_ACTION,
                                           'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the SM lock pre check was not done
        self.mock_sm_api_lock_pre_check.assert_not_called()
        # Verify that the force lock was sent to the VIM
        self.mock_vim_api_host_action.assert_called_with(
            mock.ANY,
            c1_host['uuid'],
            c1_host['hostname'],
            constants.FORCE_LOCK_ACTION,
            mock.ANY)
        # Verify that the host was not configured
        self.fake_conductor_api.configure_ihost.assert_not_called()
        # Verify that the host was not modified in maintenance
        self.mock_mtce_api_host_modify.assert_not_called()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_unlock_action_worker(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create worker-0
        w0_host = self._create_worker_0(
            subfunctions=constants.WORKER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Unlock worker host
        response = self._patch_host_action(w0_host['hostname'],
                                           constants.UNLOCK_ACTION,
                                           'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the unlock was sent to the VIM
        self.mock_vim_api_host_action.assert_called_with(
            mock.ANY,
            w0_host['uuid'],
            w0_host['hostname'],
            constants.UNLOCK_ACTION,
            mock.ANY)
        # Verify that the host was configured
        self.fake_conductor_api.configure_ihost.assert_called_once()
        # Verify that the app reapply was checked
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was added to maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % w0_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_lock_action_worker(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create worker-0
        w0_host = self._create_worker_0(
            subfunctions=constants.WORKER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Lock worker host
        response = self._patch_host_action(w0_host['hostname'],
                                           constants.LOCK_ACTION,
                                           'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the SM lock pre check was not done
        self.mock_sm_api_lock_pre_check.assert_not_called()
        # Verify that the lock was sent to the VIM
        self.mock_vim_api_host_action.assert_called_with(
            mock.ANY,
            w0_host['uuid'],
            w0_host['hostname'],
            constants.LOCK_ACTION,
            mock.ANY)
        # Verify that the host was not configured
        self.fake_conductor_api.configure_ihost.assert_not_called()
        # Verify that the app reapply evaluate was not configured
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was not modified in maintenance
        self.mock_mtce_api_host_modify.assert_not_called()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % w0_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_unlock_action_storage(self):
        # Note: Can't do storage host testcases yet because additional code
        # is required to populate the storage (OSDs) for the host.
        self.skipTest("Not yet implemented")

    def test_lock_action_storage(self):
        # Note: Can't do storage host testcases yet because additional code
        # is required to populate the storage (OSDs) for the host.
        self.skipTest("Not yet implemented")

    def test_swact_action(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Swact to controller-0
        response = self._patch_host_action(c1_host['hostname'],
                                           constants.SWACT_ACTION,
                                           'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the SM swact pre check was done
        self.mock_sm_api_swact_pre_check.assert_called_with(c1_host['hostname'],
                                                            timeout=mock.ANY)
        # Verify that the swact was not sent to the VIM
        self.mock_vim_api_host_action.assert_not_called()
        # Verify that the host was not configured
        self.fake_conductor_api.configure_ihost.assert_not_called()
        # Verify that the app reapply evaluate was not configured
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was modified in maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_force_swact_action(self):
        self._configure_networks()
        # Create controller-0 in disabled state so force swact is required
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Swact to controller-0
        response = self._patch_host_action(c1_host['hostname'],
                                           constants.FORCE_SWACT_ACTION,
                                           'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the SM swact pre check was not done
        self.mock_sm_api_swact_pre_check.assert_not_called()
        # Verify that the swact was not sent to the VIM
        self.mock_vim_api_host_action.assert_not_called()
        # Verify that the host was not configured
        self.fake_conductor_api.configure_ihost.assert_not_called()
        # Verify that the app reapply evaluate was not configured
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was modified in maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_reset_action(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Reset controller-1
        response = self._patch_host_action(c1_host['hostname'],
                                           constants.RESET_ACTION,
                                           'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the reset was not sent to the VIM
        self.mock_vim_api_host_action.assert_not_called()
        # Verify that the host was not configured
        self.fake_conductor_api.configure_ihost.assert_not_called()
        # Verify that the app reapply evaluate was not configured
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was modified in maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_reboot_action(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Reboot controller-1
        response = self._patch_host_action(c1_host['hostname'],
                                           constants.REBOOT_ACTION,
                                           'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the reboot was not sent to the VIM
        self.mock_vim_api_host_action.assert_not_called()
        # Verify that the host was not configured
        self.fake_conductor_api.configure_ihost.assert_not_called()
        # Verify that the app reapply evaluate was not configured
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was modified in maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_reinstall_action(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Reinstall controller-1
        response = self._patch_host_action(c1_host['hostname'],
                                           constants.REINSTALL_ACTION,
                                           'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the host config was removed
        self.fake_conductor_api.remove_host_config.assert_called_with(
            mock.ANY, c1_host['uuid'])
        # Verify that the reinstall was not sent to the VIM
        self.mock_vim_api_host_action.assert_not_called()
        # Verify that the app reapply evaluate was not configured
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was configured
        self.fake_conductor_api.configure_ihost.assert_called_once()
        # Verify that the host was modified in maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_poweron_action(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Poweron controller-1
        response = self._patch_host_action(c1_host['hostname'],
                                           constants.POWERON_ACTION,
                                           'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the poweron was not sent to the VIM
        self.mock_vim_api_host_action.assert_not_called()
        # Verify that the host was not configured
        self.fake_conductor_api.configure_ihost.assert_not_called()
        # Verify that the app reapply evaluate was not configured
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was modified in maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_poweroff_action(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Poweroff controller-1
        response = self._patch_host_action(c1_host['hostname'],
                                           constants.POWEROFF_ACTION,
                                           'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the poweroff was not sent to the VIM
        self.mock_vim_api_host_action.assert_not_called()
        # Verify that the host was not configured
        self.fake_conductor_api.configure_ihost.assert_not_called()
        # Verify that the app reapply evaluate was not configured
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was modified in maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_vim_services_enabled_action(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            vim_progress_status='')

        # Enable services on controller-1
        response = self._patch_host_action(c1_host['hostname'],
                                           constants.VIM_SERVICES_ENABLED,
                                           'vim')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the services enabled was not sent to the VIM
        self.mock_vim_api_host_action.assert_not_called()
        # Verify that the host was not configured
        self.fake_conductor_api.configure_ihost.assert_not_called()
        # Verify that the app reapply evaluate was not configured
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was not modified in maintenance
        self.mock_mtce_api_host_modify.assert_not_called()
        # Verify that the host was updated
        self.fake_conductor_api.iplatform_update_by_ihost.assert_called_with(
            mock.ANY, c1_host['uuid'], mock.ANY)
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])
        # Verify that the vim_progress_status was updated
        self.assertEqual(constants.VIM_SERVICES_ENABLED,
                         result['vim_progress_status'])

    def test_vim_services_disabled_action(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            vim_progress_status='',
            ihost_action=constants.LOCK_ACTION)

        # Disable services on controller-1
        response = self._patch_host_action(c1_host['hostname'],
                                           constants.VIM_SERVICES_DISABLED,
                                           'vim')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the services disabled was not sent to the VIM
        self.mock_vim_api_host_action.assert_not_called()
        # Verify that the host was not configured
        self.fake_conductor_api.configure_ihost.assert_not_called()
        # Verify that the app reapply evaluate was not configured
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was modified in maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host was updated
        self.fake_conductor_api.iplatform_update_by_ihost.assert_called_with(
            mock.ANY, c1_host['uuid'], mock.ANY)
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])
        # Verify that the vim_progress_status was updated
        self.assertEqual(constants.VIM_SERVICES_DISABLED,
                         result['vim_progress_status'])

    def test_vim_services_disable_failed_action(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            vim_progress_status='',
            ihost_action=constants.LOCK_ACTION)

        # Disable fail services on controller-1
        response = self._patch_host_action(
            c1_host['hostname'],
            constants.VIM_SERVICES_DISABLE_FAILED,
            'vim')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the services disable failed was not sent to the VIM
        self.mock_vim_api_host_action.assert_not_called()
        # Verify that the host was not configured
        self.fake_conductor_api.configure_ihost.assert_not_called()
        # Verify that the app reapply evaluate was not configured
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was not modified in maintenance
        self.mock_mtce_api_host_modify.assert_not_called()
        # Verify that the host was not updated
        self.fake_conductor_api.iplatform_update_by_ihost.assert_not_called()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])
        # Verify that the vim_progress_status was updated
        self.assertEqual(constants.VIM_SERVICES_DISABLE_FAILED,
                         result['vim_progress_status'])

    def test_vim_services_disable_extend_action(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            vim_progress_status='',
            ihost_action=constants.LOCK_ACTION)

        # Disable extend services on controller-1
        response = self._patch_host_action(
            c1_host['hostname'],
            constants.VIM_SERVICES_DISABLE_EXTEND,
            'vim')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the services disable extend was not sent to the VIM
        self.mock_vim_api_host_action.assert_not_called()
        # Verify that the host was not configured
        self.fake_conductor_api.configure_ihost.assert_not_called()
        # Verify that the app reapply evaluate was not configured
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was not modified in maintenance
        self.mock_mtce_api_host_modify.assert_not_called()
        # Verify that the host was not updated
        self.fake_conductor_api.iplatform_update_by_ihost.assert_not_called()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])
        # Verify that the vim_progress_status was not updated
        self.assertEqual('', result['vim_progress_status'])

    def test_vim_services_delete_failed_action(self):
        self._configure_networks()
        # Create controller-0
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            vim_progress_status='',
            ihost_action=constants.LOCK_ACTION)

        # Delete fail services on controller-1
        response = self._patch_host_action(
            c1_host['hostname'],
            constants.VIM_SERVICES_DELETE_FAILED,
            'vim')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the services disable failed was not sent to the VIM
        self.mock_vim_api_host_action.assert_not_called()
        # Verify that the host was not configured
        self.fake_conductor_api.configure_ihost.assert_not_called()
        # Verify that the app reapply evaluate was not configured
        self.fake_conductor_api.evaluate_app_reapply.assert_not_called()
        # Verify that the host was not modified in maintenance
        self.mock_mtce_api_host_modify.assert_not_called()
        # Verify that the host was not updated
        self.fake_conductor_api.iplatform_update_by_ihost.assert_not_called()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])
        # Verify that the vim_progress_status was updated
        self.assertEqual(constants.VIM_SERVICES_DELETE_FAILED,
                         result['vim_progress_status'])

    def test_apply_profile_action_bad_profile_id(self):
        # Note: Including this testcase for completeness (wanted to cover each
        # action. The testcases in test_interface.py cover the success case.

        self._configure_networks()
        # Create controller-0
        self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Apply profile to controller-1 and verify it was rejected
        self.assertRaises(webtest.app.AppError,
                          self.patch_json,
                          '/ihosts/%s' % c1_host['hostname'],
                          [{'path': '/action',
                            'value': constants.APPLY_PROFILE_ACTION,
                            'op': 'replace'},
                           {'path': '/iprofile_uuid',
                            'value': 'notarealuuid',
                            'op': 'replace'}
                           ],
                          headers={'User-Agent': 'sysinv-test'})

    def test_subfunction_config_action(self):
        self._configure_networks()
        # Create controller-0 (AIO)
        c0_host = self._create_controller_0(
            subfunctions=constants.WORKER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        # Configure nova-local LVG
        disk = self.dbapi.idisk_create(
            c0_host['id'],
            dbutils.get_test_idisk(device_node='/dev/sdb',
                                   device_type=constants.DEVICE_TYPE_HDD))
        self.dbapi.ilvg_create(
            c0_host['id'],
            dbutils.get_test_lvg(lvm_vg_name=constants.LVG_NOVA_LOCAL))
        self.dbapi.ipv_create(
            c0_host['id'],
            dbutils.get_test_pv(lvm_vg_name=constants.LVG_NOVA_LOCAL,
                                disk_or_part_uuid=disk.uuid))

        # Configure subfunction
        response = self._patch_host_action(
            c0_host['hostname'],
            constants.SUBFUNCTION_CONFIG_ACTION,
            'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the configure was not sent to the VIM
        self.mock_vim_api_host_action.assert_not_called()
        # Verify that the host was configured
        self.fake_conductor_api.configure_ihost.assert_called_once()
        # Verify that the host was not modified in maintenance
        self.mock_mtce_api_host_modify.assert_not_called()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c0_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_bad_action(self):
        self._configure_networks()
        # Create controller-0
        ihost = self._create_controller_0(
            subfunctions=constants.CONTROLLER,
            availability=constants.AVAILABILITY_ONLINE)

        # Verify that the action was rejected
        self.assertRaises(webtest.app.AppError,
                          self.patch_json,
                          '/ihosts/%s' % ihost['hostname'],
                          [{'path': '/action',
                            'value': 'badaction',
                            'op': 'replace'}],
                          headers={'User-Agent': 'sysinv-test'})
