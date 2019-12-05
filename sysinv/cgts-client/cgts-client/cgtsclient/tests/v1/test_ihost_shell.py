#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from cgtsclient.tests import test_shell
from cgtsclient.v1.ihost import ihost
from cgtsclient.v1.kube_host_upgrade import KubeHostUpgrade

FAKE_KUBE_HOST_UPGRADE = {
    'id': 100,
    'uuid': '65d3fa7e-1414-4a1d-83b1-42c6bcac48bf',
    'target_version': 'v1.42.3',
    'status': 'fake status',
    'control_plane_version': 'v1.42.2',
    'kubelet_version': 'v1.42.2',
    'host_id': 67,
}

FAKE_KUBE_HOST_UPGRADE_2 = {
    'id': 101,
    'uuid': '2044b22a-9fb3-4b62-9894-dcc6c0d0f791',
    'target_version': 'v1.42.3',
    'status': 'fake status',
    'control_plane_version': 'v1.42.3',
    'kubelet_version': 'v1.42.2',
    'host_id': 68,
}

FAKE_KUBE_HOST_UPGRADE_3 = {
    'id': 102,
    'uuid': '0061fd45-0545-48e5-aa1b-fc3c809dfd3c',
    'target_version': None,
    'status': None,
    'control_plane_version': 'N/A',
    'kubelet_version': 'N/A',
    'host_id': 69,
}

FAKE_IHOST = {
    'id': 67,
    'uuid': '7c4b5408-7097-4ab8-88fe-b8db156b1a8a',
    'hostname': 'controller-0',
    'personality': 'controller',
}

FAKE_IHOST_2 = {
    'id': 68,
    'uuid': '62adea84-4fd5-4c78-b59a-a8eda2f2861c',
    'hostname': 'controller-1',
    'personality': 'controller',
}

FAKE_IHOST_3 = {
    'id': 69,
    'uuid': '3a966002-14b9-4b96-bcf5-345ff50086b8',
    'hostname': 'storage-0',
    'personality': 'storage',
}


class HostTest(test_shell.ShellTest):

    def setUp(self):
        super(HostTest, self).setUp()

        # Mock the client
        p = mock.patch('cgtsclient.client._get_endpoint')
        self.mock_cgtsclient_client_get_endpoint = p.start()
        self.mock_cgtsclient_client_get_endpoint.return_value = \
            'http://fakelocalhost:6385/v1'
        self.addCleanup(p.stop)
        p = mock.patch('cgtsclient.client._get_ksclient')
        self.mock_cgtsclient_client_get_ksclient = p.start()
        self.addCleanup(p.stop)

        # Mock the KubeHostUpgradeManager
        self.kube_host_upgrade_manager_list_result = [
            KubeHostUpgrade(None, FAKE_KUBE_HOST_UPGRADE, True)]

        def mock_kube_host_upgrade_manager_list(obj):
            return self.kube_host_upgrade_manager_list_result
        self.mocked_kube_host_upgrade_manager_list = mock.patch(
            'cgtsclient.v1.kube_host_upgrade.KubeHostUpgradeManager.list',
            mock_kube_host_upgrade_manager_list)
        self.mocked_kube_host_upgrade_manager_list.start()
        self.addCleanup(self.mocked_kube_host_upgrade_manager_list.stop)

        # Mock the ihostManager
        self.ihost_manager_list_result = [ihost(None, FAKE_IHOST, True)]

        def mock_ihost_manager_list(obj):
            return self.ihost_manager_list_result
        self.mocked_ihost_manager_list = mock.patch(
            'cgtsclient.v1.ihost.ihostManager.list',
            mock_ihost_manager_list)
        self.mocked_ihost_manager_list.start()
        self.addCleanup(self.mocked_ihost_manager_list.stop)

        self.ihost_manager_kube_upgrade_control_plane_result = \
            [ihost(None, FAKE_IHOST, True)]

        def mock_ihost_manager_kube_upgrade_control_plane(obj, hostid, force):
            return self.ihost_manager_kube_upgrade_control_plane_result
        self.mocked_ihost_manager_kube_upgrade_control_plane = mock.patch(
            'cgtsclient.v1.ihost.ihostManager.kube_upgrade_control_plane',
            mock_ihost_manager_kube_upgrade_control_plane)
        self.mocked_ihost_manager_kube_upgrade_control_plane.start()
        self.addCleanup(
            self.mocked_ihost_manager_kube_upgrade_control_plane.stop)

        def mock_ihost_manager_kube_upgrade_kubelet(obj, hostid, force):
            return self.ihost_manager_kube_upgrade_kubelet_result

        self.mocked_ihost_manager_kube_upgrade_kubelet = mock.patch(
            'cgtsclient.v1.ihost.ihostManager.kube_upgrade_kubelet',
            mock_ihost_manager_kube_upgrade_kubelet)
        self.mocked_ihost_manager_kube_upgrade_kubelet.start()
        self.addCleanup(
            self.mocked_ihost_manager_kube_upgrade_kubelet.stop)

    def test_kube_host_upgrade_list(self):
        self.make_env()

        # Use --nowrap to prevent failure when test run with small terminal
        results = self.shell("kube-host-upgrade-list --nowrap")
        self.assertIn(str(FAKE_IHOST['id']), results)
        self.assertIn(str(FAKE_IHOST['hostname']), results)
        self.assertIn(str(FAKE_IHOST['personality']), results)
        self.assertIn(str(FAKE_KUBE_HOST_UPGRADE['target_version']), results)
        self.assertIn(str(FAKE_KUBE_HOST_UPGRADE['control_plane_version']),
                      results)
        self.assertIn(str(FAKE_KUBE_HOST_UPGRADE['kubelet_version']), results)
        self.assertIn(str(FAKE_KUBE_HOST_UPGRADE['status']), results)

    def test_kube_host_upgrade_list_multiple(self):
        self.make_env()
        self.kube_host_upgrade_manager_list_result = [
            KubeHostUpgrade(None, FAKE_KUBE_HOST_UPGRADE, True),
            KubeHostUpgrade(None, FAKE_KUBE_HOST_UPGRADE_2, True),
            KubeHostUpgrade(None, FAKE_KUBE_HOST_UPGRADE_3, True),
        ]
        self.ihost_manager_list_result = [
            ihost(None, FAKE_IHOST, True),
            ihost(None, FAKE_IHOST_2, True),
            ihost(None, FAKE_IHOST_3, True),
        ]

        # Use --nowrap to prevent failure when test run with small terminal
        results = self.shell("kube-host-upgrade-list --nowrap")

        for fake_ihost in [FAKE_IHOST, FAKE_IHOST_2, FAKE_IHOST_3]:
            self.assertIn(str(fake_ihost['id']), results)
            self.assertIn(str(fake_ihost['hostname']), results)
            self.assertIn(str(fake_ihost['personality']), results)

        for fake_kube_host_upgrade in [FAKE_KUBE_HOST_UPGRADE,
                                       FAKE_KUBE_HOST_UPGRADE_2,
                                       FAKE_KUBE_HOST_UPGRADE_3]:
            self.assertIn(str(fake_kube_host_upgrade['target_version']),
                          results)
            self.assertIn(str(fake_kube_host_upgrade['control_plane_version']),
                          results)
            self.assertIn(str(fake_kube_host_upgrade['kubelet_version']),
                          results)
            self.assertIn(str(fake_kube_host_upgrade['status']),
                          results)

    def test_kube_host_upgrade_control_plane(self):
        self.make_env()
        self.kube_host_upgrade_manager_list_result = [
            KubeHostUpgrade(None, FAKE_KUBE_HOST_UPGRADE, True),
            KubeHostUpgrade(None, FAKE_KUBE_HOST_UPGRADE_2, True),
            KubeHostUpgrade(None, FAKE_KUBE_HOST_UPGRADE_3, True),
        ]
        self.ihost_manager_kube_upgrade_control_plane_result = \
            ihost(None, FAKE_IHOST_2, True)

        results = self.shell("kube-host-upgrade controller-1 control-plane")

        self.assertIn(str(FAKE_IHOST_2['id']), results)
        self.assertIn(str(FAKE_IHOST_2['hostname']), results)
        self.assertIn(str(FAKE_IHOST_2['personality']), results)

        self.assertIn(str(FAKE_KUBE_HOST_UPGRADE_2['target_version']),
                      results)
        self.assertIn(str(FAKE_KUBE_HOST_UPGRADE_2['control_plane_version']),
                      results)
        self.assertIn(str(FAKE_KUBE_HOST_UPGRADE_2['kubelet_version']),
                      results)
        self.assertIn(str(FAKE_KUBE_HOST_UPGRADE_2['status']),
                      results)

    def test_kube_host_upgrade_kubelet(self):
        self.make_env()
        self.kube_host_upgrade_manager_list_result = [
            KubeHostUpgrade(None, FAKE_KUBE_HOST_UPGRADE, True),
            KubeHostUpgrade(None, FAKE_KUBE_HOST_UPGRADE_2, True),
            KubeHostUpgrade(None, FAKE_KUBE_HOST_UPGRADE_3, True),
        ]
        self.ihost_manager_kube_upgrade_kubelet_result = \
            ihost(None, FAKE_IHOST_2, True)

        results = self.shell("kube-host-upgrade controller-1 kubelet")

        self.assertIn(str(FAKE_IHOST_2['id']), results)
        self.assertIn(str(FAKE_IHOST_2['hostname']), results)
        self.assertIn(str(FAKE_IHOST_2['personality']), results)

        self.assertIn(str(FAKE_KUBE_HOST_UPGRADE_2['target_version']),
                      results)
        self.assertIn(str(FAKE_KUBE_HOST_UPGRADE_2['control_plane_version']),
                      results)
        self.assertIn(str(FAKE_KUBE_HOST_UPGRADE_2['kubelet_version']),
                      results)
        self.assertIn(str(FAKE_KUBE_HOST_UPGRADE_2['status']),
                      results)
