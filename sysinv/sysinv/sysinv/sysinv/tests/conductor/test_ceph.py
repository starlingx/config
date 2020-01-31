# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8

# Copyright (c) 2017-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Test class for Sysinv Storage Peer groups."""

import mock

from cephclient import wrapper as ceph
from oslo_utils import uuidutils

from sysinv.common import ceph as cceph
from sysinv.common import constants
from sysinv.conductor import manager
from sysinv.conductor import ceph as iceph
from sysinv.db import api as dbapi
from sysinv.openstack.common import context
from sysinv.tests.db import base
from sysinv.tests.db import utils


class UpdateCephCluster(base.DbTestCase):

    # Current tests:
    #  Tests for cluster ID updates
    #  - test_init_fsid_none
    #  - test_init_fsid_available
    #  - test_init_fsid_update_on_unlock
    # Tests for initial provisioning
    #  - test_add_storage_0_no_fsid
    #  - test_add_storage_0_fsid
    #  - test_add_storage_0
    #  - test_add_storage_1
    #  - test_add_3_storage_backing
    # Tests for specific failure cases
    #  - test_cgts_7208
    # Tests for adding patterns of hosts based on subtype:
    #  - test_add_valid_mix_tiers
    #  - test_add_4_mix_bbbb

    upgrade_downgrade_kube_components_patcher = mock.patch.object(
        manager.ConductorManager, '_upgrade_downgrade_kube_components')
    fix_crushmap_patcher = mock.patch.object(
        cceph, 'fix_crushmap')

    def setUp(self):
        super(UpdateCephCluster, self).setUp()
        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()
        self.context = context.get_admin_context()
        self.dbapi = dbapi.get_instance()
        self.system = utils.create_test_isystem()
        self.load = utils.create_test_load()
        self.host_index = -1

        self.mock_upgrade_downgrade_kube_components = self.upgrade_downgrade_kube_components_patcher.start()
        self.mock_fix_crushmap = self.fix_crushmap_patcher.start()
        self.mock_fix_crushmap.return_value = True

    def tearDown(self):
        super(UpdateCephCluster, self).tearDown()
        self.upgrade_downgrade_kube_components_patcher.stop()
        self.fix_crushmap_patcher.stop()

    def _create_storage_ihost(self, hostname):
        self.host_index += 1
        ihost_dict = utils.get_test_ihost(
            id=self.host_index,
            forisystemid=self.system.id,
            hostname=hostname,
            uuid=uuidutils.generate_uuid(),
            mgmt_mac="{}-{}".format(hostname, self.host_index),
            mgmt_ip="{}-{}".format(hostname, self.host_index),
            personality='storage',
            administrative='unlocked',
            operational='enabled',
            availability='available',
            invprovision='unprovisioned')
        return self.dbapi.ihost_create(ihost_dict)

    def test_init_fsid_none(self):
        # Mock the fsid call so that we don't have to wait for the timeout
        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            mock_fsid.return_value = (mock.MagicMock(ok=False), None)
            self.service.start()
            self.service._init_ceph_cluster_info()
            mock_fsid.assert_called()
        self.assertIsNone(self.service._ceph.cluster_ceph_uuid)
        self.assertIsNotNone(self.service._ceph.cluster_db_uuid)
        self.assertIsNotNone(self.service._ceph.cluster_id)

    def test_init_fsid_available(self):
        # Mock fsid with a faux cluster_uuid
        cluster_uuid = uuidutils.generate_uuid()
        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            mock_fsid.return_value = (mock.MagicMock(ok=True), cluster_uuid)
            self.service.start()
            self.service._init_ceph_cluster_info()
            mock_fsid.assert_called()
        self.assertIsNotNone(self.service._ceph.cluster_ceph_uuid)
        self.assertIsNotNone(self.service._ceph.cluster_db_uuid)
        self.assertIsNotNone(self.service._ceph.cluster_id)
        self.assertEqual(self.service._ceph.cluster_ceph_uuid,
                         self.service._ceph.cluster_db_uuid)

    def test_init_fsid_update_on_unlock(self):
        storage_0 = self._create_storage_ihost('storage-0')

        # Mock the fsid call so that we don't have to wait for the timeout
        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            mock_fsid.return_value = (mock.MagicMock(ok=False), None)
            self.service.start()
            self.service._init_ceph_cluster_info()
            mock_fsid.assert_called()
        self.assertIsNone(self.service._ceph.cluster_ceph_uuid)
        self.assertIsNotNone(self.service._ceph.cluster_db_uuid)

        # save the current values
        saved_db_uuid = self.service._ceph.cluster_db_uuid

        # Add host
        cluster_uuid = uuidutils.generate_uuid()
        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            mock_fsid.return_value = (mock.MagicMock(ok=True), cluster_uuid)
            self.service._ceph.update_ceph_cluster(storage_0)
        self.assertIsNotNone(self.service._ceph.cluster_ceph_uuid)
        self.assertIsNotNone(self.service._ceph.cluster_db_uuid)
        self.assertEqual(saved_db_uuid, self.service._ceph.cluster_db_uuid)
        # self.assertEqual(self.service._ceph._cluster_ceph_uuid, self.service._ceph._cluster_db_uuid)

        # make sure the host addition produces the correct peer
        ihost_0 = self.dbapi.ihost_get(storage_0.id)
        self.assertEqual(storage_0.id, ihost_0.id)
        peer = self.dbapi.peer_get(ihost_0.peer_id)
        self.assertEqual(peer.name, 'group-0')
        self.assertEqual(peer.hosts, [storage_0.hostname])

    def test_add_storage_0_no_fsid(self):
        # Mock the fsid call so that we don't have to wait for the timeout
        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            mock_fsid.return_value = (mock.MagicMock(ok=False), None)
            self.service.start()
            self.service._init_ceph_cluster_info()
            mock_fsid.assert_called()

        self.assertIsNone(self.service._ceph.cluster_ceph_uuid)
        self.assertNotEqual(self.dbapi.clusters_get_all(type=constants.CINDER_BACKEND_CEPH), [])

        storage_0 = self._create_storage_ihost('storage-0')

        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            self.assertIsNone(self.service._ceph.cluster_ceph_uuid)
            self.service._ceph.update_ceph_cluster(storage_0)
            mock_fsid.assert_called()

        clusters = self.dbapi.clusters_get_all(type=constants.CINDER_BACKEND_CEPH)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0].cluster_uuid, self.service._ceph.cluster_ceph_uuid)

        ihost = self.dbapi.ihost_get(storage_0.id)
        self.assertEqual(storage_0.id, ihost.id)

        peer = self.dbapi.peer_get(ihost.peer_id)
        self.assertEqual(peer.name, 'group-0')
        self.assertEqual(peer.hosts, [ihost.hostname])

    def test_add_storage_0_fsid(self):
        # Mock the fsid call so that we don't have to wait for the timeout
        cluster_uuid = uuidutils.generate_uuid()
        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            mock_fsid.return_value = (mock.MagicMock(ok=True), cluster_uuid)
            self.service.start()
            self.service._init_ceph_cluster_info()
            mock_fsid.assert_called()

        clusters = self.dbapi.clusters_get_all(type=constants.CINDER_BACKEND_CEPH)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0].cluster_uuid, cluster_uuid)

        storage_0 = self._create_storage_ihost('storage-0')
        self.service._ceph.update_ceph_cluster(storage_0)
        ihost = self.dbapi.ihost_get(storage_0.id)
        self.assertEqual(storage_0.id, ihost.id)
        peer = self.dbapi.peer_get(ihost.peer_id)
        self.assertEqual(peer.name, 'group-0')
        self.assertIn(ihost.hostname, peer.hosts)

        peers = self.dbapi.peers_get_all_by_cluster(clusters[0].id)
        self.assertEqual(
            set([(p.name, tuple(sorted(p.hosts))) for p in peers]),
            {('group-0', ('storage-0',))})

    def test_add_storage_0(self):
        # Mock the fsid call so that we don't have to wait for the timeout
        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            mock_fsid.return_value = (mock.MagicMock(ok=False), None)
            self.service.start()
            self.service._init_ceph_cluster_info()
            mock_fsid.assert_called()

        self.assertIsNone(self.service._ceph.cluster_ceph_uuid)
        self.assertNotEqual(self.dbapi.clusters_get_all(type=constants.CINDER_BACKEND_CEPH), [])

        storage_0 = self._create_storage_ihost('storage-0')

        cluster_uuid = uuidutils.generate_uuid()
        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            mock_fsid.return_value = (mock.MagicMock(ok=True), cluster_uuid)
            self.service._ceph.update_ceph_cluster(storage_0)
            mock_fsid.assert_called()

        self.assertEqual(cluster_uuid, self.service._ceph.cluster_ceph_uuid)

        clusters = self.dbapi.clusters_get_all(type=constants.CINDER_BACKEND_CEPH)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0].cluster_uuid, cluster_uuid)

        ihost = self.dbapi.ihost_get(storage_0.id)
        self.assertEqual(storage_0.id, ihost.id)
        peer = self.dbapi.peer_get(ihost.peer_id)
        self.assertEqual(peer.name, 'group-0')
        self.assertIn(ihost.hostname, peer.hosts)

        # check no other (unexpected) peers exist
        peers = self.dbapi.peers_get_all_by_cluster(clusters[0].id)
        self.assertEqual(
            set([(p.name, tuple(sorted(p.hosts))) for p in peers]),
            {('group-0', ('storage-0',))})

    def test_add_storage_1(self):
        # Mock fsid with a faux cluster_uuid
        cluster_uuid = uuidutils.generate_uuid()
        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            mock_fsid.return_value = (mock.MagicMock(ok=True), cluster_uuid)
            self.service.start()
            self.service._init_ceph_cluster_info()
            mock_fsid.assert_called()

        clusters = self.dbapi.clusters_get_all(type=constants.CINDER_BACKEND_CEPH)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0].cluster_uuid, cluster_uuid)

        storage_0 = self._create_storage_ihost('storage-0')
        self.service._ceph.update_ceph_cluster(storage_0)

        peers = self.dbapi.peers_get_all_by_cluster(clusters[0].id)
        self.assertEqual(
            set([(p.name, tuple(sorted(p.hosts))) for p in peers]),
            {('group-0', ('storage-0',))})

        storage_1 = self._create_storage_ihost('storage-1')
        self.service._ceph.update_ceph_cluster(storage_1)
        ihost = self.dbapi.ihost_get(storage_1.id)
        self.assertEqual(storage_1.id, ihost.id)
        peer = self.dbapi.peer_get(ihost.peer_id)
        self.assertEqual(peer.name, 'group-0')
        self.assertIn(ihost.hostname, peer.hosts)

        # check no other (unexpected) peers exist
        peers = self.dbapi.peers_get_all_by_cluster(clusters[0].id)
        self.assertEqual(
            set([(p.name, tuple(sorted(p.hosts))) for p in peers]),
            {('group-0', ('storage-0', 'storage-1'))})

    def test_add_3_storage_backing(self):
        # Mock fsid with a faux cluster_uuid
        cluster_uuid = uuidutils.generate_uuid()
        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            mock_fsid.return_value = (mock.MagicMock(ok=True), cluster_uuid)
            self.service.start()
            self.service._init_ceph_cluster_info()
            mock_fsid.assert_called()

        clusters = self.dbapi.clusters_get_all(type=constants.CINDER_BACKEND_CEPH)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0].cluster_uuid, cluster_uuid)

        storage_0 = self._create_storage_ihost('storage-0')
        self.service._ceph.update_ceph_cluster(storage_0)
        ihost = self.dbapi.ihost_get(storage_0.id)
        self.assertEqual(storage_0.id, ihost.id)
        peer = self.dbapi.peer_get(ihost.peer_id)
        self.assertEqual(peer.name, 'group-0')
        self.assertIn(ihost.hostname, peer.hosts)

        peers = self.dbapi.peers_get_all_by_cluster(cluster_uuid)
        self.assertEqual(
            set([(p.name, tuple(sorted(p.hosts))) for p in peers]),
            {('group-0', ('storage-0',)), })

        storage_1 = self._create_storage_ihost('storage-1')
        self.service._ceph.update_ceph_cluster(storage_1)
        ihost = self.dbapi.ihost_get(storage_1.id)
        self.assertEqual(storage_1.id, ihost.id)
        peer = self.dbapi.peer_get(ihost.peer_id)
        self.assertEqual(peer.name, 'group-0')
        self.assertIn(ihost.hostname, peer.hosts)

        peers = self.dbapi.peers_get_all_by_cluster(cluster_uuid)
        self.assertEqual(
            set([(p.name, tuple(sorted(p.hosts))) for p in peers]),
            {('group-0', ('storage-0', 'storage-1')), })

        storage_2 = self._create_storage_ihost('storage-2')
        self.service._ceph.update_ceph_cluster(storage_2)
        ihost = self.dbapi.ihost_get(storage_2.id)
        self.assertEqual(storage_2.id, ihost.id)
        peer = self.dbapi.peer_get(ihost.peer_id)
        self.assertEqual(peer.name, "group-1")
        self.assertIn(ihost.hostname, peer.hosts)

        peers = self.dbapi.peers_get_all_by_cluster(cluster_uuid)
        self.assertEqual(
            set([(p.name, tuple(sorted(p.hosts))) for p in peers]),
            {('group-0', ('storage-0', 'storage-1')),
             ('group-1', ('storage-2',))})

    def test_cgts_7208(self):
        hosts = [self._create_storage_ihost('storage-0'),
                 self._create_storage_ihost('storage-1'),
                 self._create_storage_ihost('storage-2'),
                 self._create_storage_ihost('storage-3')]

        expected_groups = {'storage-0': 'group-0', 'storage-1': 'group-0',
                           'storage-2': 'group-1', 'storage-3': 'group-1'}

        expected_peer_hosts = {'storage-0': {'storage-0'}, 'storage-1': {'storage-0', 'storage-1'},
                               'storage-2': {'storage-2'}, 'storage-3': {'storage-2', 'storage-3'}}

        saved_ihosts = []
        expected_peer_hosts2 = {'storage-0': {'storage-0', 'storage-1'}, 'storage-1': {'storage-0', 'storage-1'},
                                'storage-2': {'storage-2', 'storage-3'}, 'storage-3': {'storage-2', 'storage-3'}}

        # Mock fsid with a faux cluster_uuid
        cluster_uuid = uuidutils.generate_uuid()
        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            mock_fsid.return_value = (mock.MagicMock(ok=True), cluster_uuid)
            self.service.start()
            self.service._init_ceph_cluster_info()
            mock_fsid.assert_called()

        for h in hosts:
            # unlock host
            self.service._ceph.update_ceph_cluster(h)
            ihost = self.dbapi.ihost_get(h.id)
            self.assertEqual(h.id, ihost.id)
            peer = self.dbapi.peer_get(ihost.peer_id)
            self.assertEqual(peer.name, expected_groups[h.hostname])
            self.assertEqual(set(peer.hosts), expected_peer_hosts[h.hostname])
            saved_ihosts.append(ihost)

        # On a swact we get a new conductor and an fresh CephOperator
        saved_ceph_uuid = self.service._ceph.cluster_ceph_uuid
        saved_db_uuid = self.service._ceph.cluster_db_uuid
        saved_cluster_id = self.service._ceph.cluster_id

        del self.service._ceph
        self.service._ceph = iceph.CephOperator(self.service.dbapi)
        self.assertEqual(self.service._ceph.cluster_ceph_uuid, saved_ceph_uuid)
        self.assertEqual(self.service._ceph.cluster_db_uuid, saved_db_uuid)
        self.assertEqual(self.service._ceph.cluster_id, saved_cluster_id)

        for h in saved_ihosts:
            # unlock host
            self.service._ceph.update_ceph_cluster(h)
            peer = self.dbapi.peer_get(h.peer_id)
            self.assertEqual(peer.name, expected_groups[h.hostname])
            self.assertEqual(set(peer.hosts), expected_peer_hosts2[h.hostname])

    def test_add_valid_mix_tiers(self):
        hosts = [self._create_storage_ihost('storage-0'),
                 self._create_storage_ihost('storage-1'),
                 self._create_storage_ihost('storage-2'),
                 self._create_storage_ihost('storage-3'),
                 self._create_storage_ihost('storage-4'),
                 self._create_storage_ihost('storage-5'),
                 self._create_storage_ihost('storage-6'),
                 self._create_storage_ihost('storage-7')]

        expected_groups = {'storage-0': 'group-0', 'storage-1': 'group-0',
                           'storage-2': 'group-1', 'storage-3': 'group-1',
                           'storage-4': 'group-2', 'storage-5': 'group-2',
                           'storage-6': 'group-3', 'storage-7': 'group-3'}

        expected_peer_hosts = {'storage-0': {'storage-0'}, 'storage-1': {'storage-0', 'storage-1'},
                               'storage-2': {'storage-2'}, 'storage-3': {'storage-2', 'storage-3'},
                               'storage-4': {'storage-4'}, 'storage-5': {'storage-4', 'storage-5'},
                               'storage-6': {'storage-6'}, 'storage-7': {'storage-6', 'storage-7'}}

        # Mock fsid with a faux cluster_uuid
        cluster_uuid = uuidutils.generate_uuid()
        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            mock_fsid.return_value = (mock.MagicMock(ok=True), cluster_uuid)
            self.service.start()
            self.service._init_ceph_cluster_info()
            mock_fsid.assert_called()

        for h in hosts:
            # unlock host
            self.service._ceph.update_ceph_cluster(h)
            ihost = self.dbapi.ihost_get(h.id)
            self.assertEqual(h.id, ihost.id)
            peer = self.dbapi.peer_get(ihost.peer_id)
            self.assertEqual(peer.name, expected_groups[h.hostname])
            self.assertEqual(set(peer.hosts), expected_peer_hosts[h.hostname])

    def test_add_4_mix_bbbb(self):
        # Mock fsid with a faux cluster_uuid
        cluster_uuid = uuidutils.generate_uuid()
        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            mock_fsid.return_value = (mock.MagicMock(ok=True), cluster_uuid)
            self.service.start()
            self.service._init_ceph_cluster_info()
            mock_fsid.assert_called()

        storage_0 = self._create_storage_ihost('storage-0')
        self.service._ceph.update_ceph_cluster(storage_0)
        ihost = self.dbapi.ihost_get(storage_0.id)
        self.assertEqual(storage_0.id, ihost.id)
        peer = self.dbapi.peer_get(ihost.peer_id)
        self.assertEqual(peer.name, 'group-0')
        self.assertIn(ihost.hostname, peer.hosts)

        peers = self.dbapi.peers_get_all_by_cluster(cluster_uuid)
        self.assertEqual(
            set([(p.name, tuple(sorted(p.hosts))) for p in peers]),
            {('group-0', ('storage-0',)), })

        storage_1 = self._create_storage_ihost('storage-1')
        self.service._ceph.update_ceph_cluster(storage_1)
        ihost = self.dbapi.ihost_get(storage_1.id)
        self.assertEqual(storage_1.id, ihost.id)
        peer = self.dbapi.peer_get(ihost.peer_id)
        self.assertEqual(peer.name, 'group-0')
        self.assertIn(ihost.hostname, peer.hosts)

        peers = self.dbapi.peers_get_all_by_cluster(cluster_uuid)
        self.assertEqual(
            set([(p.name, tuple(sorted(p.hosts))) for p in peers]),
            {('group-0', ('storage-0', 'storage-1')), })

        storage_2 = self._create_storage_ihost('storage-2')
        self.service._ceph.update_ceph_cluster(storage_2)
        ihost = self.dbapi.ihost_get(storage_2.id)
        self.assertEqual(storage_2.id, ihost.id)
        peer = self.dbapi.peer_get(ihost.peer_id)
        self.assertEqual(peer.name, 'group-1')
        self.assertIn(ihost.hostname, peer.hosts)

        peers = self.dbapi.peers_get_all_by_cluster(cluster_uuid)
        self.assertEqual(
            set([(p.name, tuple(sorted(p.hosts))) for p in peers]),
            {('group-0', ('storage-0', 'storage-1')),
             ('group-1', ('storage-2',))})

        storage_3 = self._create_storage_ihost('storage-3')
        self.service._ceph.update_ceph_cluster(storage_3)
        ihost = self.dbapi.ihost_get(storage_3.id)
        self.assertEqual(storage_3.id, ihost.id)
        peer = self.dbapi.peer_get(ihost.peer_id)
        self.assertEqual(peer.name, 'group-1')
        self.assertIn(ihost.hostname, peer.hosts)

        peers = self.dbapi.peers_get_all_by_cluster(cluster_uuid)
        self.assertEqual(
            set([(p.name, tuple(sorted(p.hosts))) for p in peers]),
            {('group-0', ('storage-0', 'storage-1')),
             ('group-1', ('storage-2', 'storage-3'))})
