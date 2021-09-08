#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /kube_host_upgrades/ methods.
"""

import mock

from oslo_utils import uuidutils

from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class TestKubeHostUpgrade(base.FunctionalTest, dbbase.BaseHostTestCase):

    def setUp(self):
        super(TestKubeHostUpgrade, self).setUp()

        # Mock the KubeOperator
        self.kube_get_control_plane_versions_result = {
            'controller-0': 'v1.42.1',
            'controller-1': 'v1.42.1'}

        def mock_kube_get_control_plane_versions(obj):
            return self.kube_get_control_plane_versions_result
        self.mocked_kube_get_control_plane_versions = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
            mock_kube_get_control_plane_versions)
        self.mocked_kube_get_control_plane_versions.start()
        self.addCleanup(self.mocked_kube_get_control_plane_versions.stop)

        self.kube_get_kubelet_versions_result = {
            'controller-0': 'v1.42.2',
            'controller-1': 'v1.42.2',
            'worker-0': 'v1.42.2'}

        def mock_kube_get_kubelet_versions(obj):
            return self.kube_get_kubelet_versions_result
        self.mocked_kube_get_kubelet_versions = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
            mock_kube_get_kubelet_versions)
        self.mocked_kube_get_kubelet_versions.start()
        self.addCleanup(self.mocked_kube_get_kubelet_versions.stop)

    def _create_controller_0(self, subfunction=None, numa_nodes=1, **kw):
        return self._create_test_host(
            personality=constants.CONTROLLER,
            subfunction=subfunction,
            numa_nodes=numa_nodes,
            unit=0,
            **kw)

    def _create_controller_1(self, subfunction=None, numa_nodes=1, **kw):
        return self._create_test_host(
            personality=constants.CONTROLLER,
            subfunction=subfunction,
            numa_nodes=numa_nodes,
            unit=1,
            **kw)

    def _create_worker(self, unit=0, numa_nodes=1, **kw):
        return self._create_test_host(
            personality=constants.WORKER,
            numa_nodes=numa_nodes,
            unit=unit,
            **kw)

    def _create_storage(self, unit=0, numa_nodes=1, **kw):
        return self._create_test_host(
            personality=constants.STORAGE,
            numa_nodes=numa_nodes,
            unit=unit,
            **kw)


class TestListKubeHostUpgrade(TestKubeHostUpgrade):

    def test_empty_host(self):
        self.kube_get_control_plane_versions_result = dict()
        self.kube_get_kubelet_versions_result = dict()
        data = self.get_json('/kube_host_upgrades')
        self.assertEqual([], data['kube_host_upgrades'])

    def test_one(self):
        # Create host
        self._create_controller_0()

        # Verify that the kube_host_upgrade was created
        result = self.get_json('/kube_host_upgrades/1')

        self.assertIn('id', result)
        assert(uuidutils.is_uuid_like(result['uuid']))
        self.assertEqual(result['target_version'], None)
        self.assertEqual(result['status'], None)
        self.assertEqual(result['control_plane_version'], 'v1.42.1')
        self.assertEqual(result['kubelet_version'], 'v1.42.2')
        self.assertEqual(result['host_id'], 1)

        # Verify that hidden attributes are not returned
        self.assertNotIn('reserved_1', result)
        self.assertNotIn('reserved_2', result)
        self.assertNotIn('reserved_3', result)
        self.assertNotIn('reserved_4', result)

    def test_one_no_dynamic_info(self):
        # Create host
        self._create_worker(unit=42)

        # Verify that the kube_host_upgrade was created
        result = self.get_json('/kube_host_upgrades/1')

        self.assertIn('id', result)
        assert(uuidutils.is_uuid_like(result['uuid']))
        self.assertEqual(result['target_version'], None)
        self.assertEqual(result['status'], None)
        self.assertEqual(result['control_plane_version'], 'N/A')
        self.assertEqual(result['kubelet_version'], 'unknown')
        self.assertEqual(result['host_id'], 1)

    def test_one_no_kubernetes(self):
        # Create host
        self._create_storage()

        # Verify that the kube_host_upgrade was created
        result = self.get_json('/kube_host_upgrades/1')

        self.assertIn('id', result)
        assert(uuidutils.is_uuid_like(result['uuid']))
        self.assertEqual(result['target_version'], None)
        self.assertEqual(result['status'], None)
        self.assertEqual(result['control_plane_version'], 'N/A')
        self.assertEqual(result['kubelet_version'], 'N/A')
        self.assertEqual(result['host_id'], 1)

    def test_all(self):
        # Create hosts
        self._create_controller_0()
        self._create_controller_1()
        worker = self._create_worker(mgmt_ip='192.168.24.12')
        data = self.get_json('/kube_host_upgrades')
        self.assertEqual(3, len(data['kube_host_upgrades']))
        host_id = 1
        for upgrade in data['kube_host_upgrades']:
            self.assertIn('id', upgrade)
            assert (uuidutils.is_uuid_like(upgrade['uuid']))
            self.assertEqual(upgrade['target_version'], None)
            self.assertEqual(upgrade['status'], None)
            if upgrade['host_id'] == worker.id:
                self.assertEqual(upgrade['control_plane_version'], 'N/A')
            else:
                self.assertEqual(upgrade['control_plane_version'], 'v1.42.1')
            self.assertEqual(upgrade['kubelet_version'], 'v1.42.2')
            self.assertEqual(upgrade['host_id'], host_id)
            host_id += 1

    def test_all_no_dynamic_info(self):
        # Create hosts
        self._create_controller_0()
        self._create_controller_1()
        worker = self._create_worker(mgmt_ip='192.168.24.12')
        worker_42 = self._create_worker(unit=42, mgmt_ip='192.168.24.13')
        data = self.get_json('/kube_host_upgrades')
        self.assertEqual(4, len(data['kube_host_upgrades']))
        host_id = 1
        for upgrade in data['kube_host_upgrades']:
            self.assertIn('id', upgrade)
            assert (uuidutils.is_uuid_like(upgrade['uuid']))
            self.assertEqual(upgrade['target_version'], None)
            self.assertEqual(upgrade['status'], None)
            if upgrade['host_id'] == worker_42.id:
                self.assertEqual(upgrade['control_plane_version'], 'N/A')
                self.assertEqual(upgrade['kubelet_version'], 'unknown')
            elif upgrade['host_id'] == worker.id:
                self.assertEqual(upgrade['control_plane_version'], 'N/A')
                self.assertEqual(upgrade['kubelet_version'], 'v1.42.2')
            else:
                self.assertEqual(upgrade['control_plane_version'], 'v1.42.1')
                self.assertEqual(upgrade['kubelet_version'], 'v1.42.2')
            self.assertEqual(upgrade['host_id'], host_id)
            host_id += 1

    def test_all_no_kubernetes(self):
        # Create hosts
        self._create_controller_0()
        self._create_controller_1()
        worker = self._create_worker(mgmt_ip='192.168.24.12')
        storage = self._create_storage(mgmt_ip='192.168.24.13')
        data = self.get_json('/kube_host_upgrades')
        self.assertEqual(4, len(data['kube_host_upgrades']))
        host_id = 1
        for upgrade in data['kube_host_upgrades']:
            self.assertIn('id', upgrade)
            assert (uuidutils.is_uuid_like(upgrade['uuid']))
            self.assertEqual(upgrade['target_version'], None)
            self.assertEqual(upgrade['status'], None)
            if upgrade['host_id'] == storage.id:
                self.assertEqual(upgrade['control_plane_version'], 'N/A')
                self.assertEqual(upgrade['kubelet_version'], 'N/A')
            elif upgrade['host_id'] == worker.id:
                self.assertEqual(upgrade['control_plane_version'], 'N/A')
                self.assertEqual(upgrade['kubelet_version'], 'v1.42.2')
            else:
                self.assertEqual(upgrade['control_plane_version'], 'v1.42.1')
                self.assertEqual(upgrade['kubelet_version'], 'v1.42.2')
            self.assertEqual(upgrade['host_id'], host_id)
            host_id += 1

    def test_host_links(self):
        uuid = uuidutils.generate_uuid()
        ndict = dbutils.get_test_ihost(id=1, uuid=uuid,
                                       forisystemid=self.system.id)
        self.dbapi.ihost_create(ndict)
        data = self.get_json('/kube_host_upgrades/1')
        upgrade_uuid = data['uuid']
        self.assertIn('links', data.keys())
        self.assertEqual(len(data['links']), 2)
        self.assertIn(upgrade_uuid, data['links'][0]['href'])

    def test_collection_links(self):
        hosts = []
        for hostid in range(100):
            ndict = dbutils.get_test_ihost(
                id=hostid, hostname=hostid, mgmt_mac=hostid,
                forisystemid=self.system.id,
                mgmt_ip="%s.%s.%s.%s" % (hostid, hostid, hostid, hostid),
                uuid=uuidutils.generate_uuid())
            host = self.dbapi.ihost_create(ndict)
            hosts.append(host['uuid'])
        data = self.get_json('/kube_host_upgrades/?limit=100')
        self.assertEqual(len(data['kube_host_upgrades']), 100)

        next_marker = data['kube_host_upgrades'][-1]['uuid']
        self.assertIn(next_marker, data['next'])
