# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
#
#
# Copyright (c) 2013-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /ihosts/ methods.
"""

import mock
import requests
import webtest.app
from six.moves import http_client

from oslo_utils import uuidutils
from sysinv.common import constants
from sysinv.common import device
from sysinv.common import kubernetes

from cephclient import wrapper as ceph

from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
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
        self.evaluate_apps_reapply = mock.MagicMock()
        self.evaluate_app_reapply = mock.MagicMock()
        self.update_clock_synchronization_config = mock.MagicMock()
        self.store_default_config = mock.MagicMock()
        self.kube_upgrade_control_plane = mock.MagicMock()
        self.kube_upgrade_kubelet = mock.MagicMock()
        self.create_barbican_secret = mock.MagicMock()
        self.mtc_action_apps_semantic_checks = mock.MagicMock()
        self.update_host_max_cpu_frequency = mock.MagicMock()

    def create_ihost(self, context, values):
        # Create the host in the DB as the code under test expects this
        ihost = self.dbapi.ihost_create(values)
        return ihost


class TestHost(base.FunctionalTest, dbbase.BaseHostTestCase):

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

        # Mock cephclient API calls
        response = requests.Response()
        response.status_code = requests.codes.ok
        response.reason = "OK"

        p = mock.patch.object(ceph.CephWrapper, 'health')
        self.mock_ceph_health = p.start()
        output = {u'checks': {}, u'status': u'HEALTH_OK'}

        self.mock_ceph_health.return_value = response, dict(output=output)
        self.addCleanup(p.stop)

        p = mock.patch.object(ceph.CephWrapper, 'osd_tree')
        self.mock_ceph_osd_tree = p.start()
        output = \
            {u'nodes':
                 [{u'children': [-2], u'id': -1, u'name': u'storage-tier',
                   u'type': u'root'},
                  {u'children': [-3, -4], u'id': -2, u'name': u'group-0',
                   u'type': u'chassis'},
                  {u'children': [0], u'id': -4, u'name': u'controller-0',
                   u'type': u'host'},
                  {u'id': 0, u'name': u'osd.0', u'type': u'osd'},
                  {u'children': [1], u'id': -3, u'name': u'controller-1',
                   u'type': u'host'},
                  {u'id': 1, u'name': u'osd.1', u'type': u'osd'}]}

        self.mock_ceph_osd_tree.return_value = response, dict(output=output)
        self.addCleanup(p.stop)

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

    def _patch_host_action(
            self, hostname, action, user_agent, expect_errors=False):
        return self.patch_json('/ihosts/%s' % hostname,
                               [{'path': '/action',
                                 'value': action,
                                 'op': 'replace'}],
                               headers={'User-Agent': user_agent},
                               expect_errors=expect_errors)

    def _patch_host(self, hostname, patch, user_agent, expect_errors=False):
        return self.patch_json('/ihosts/%s' % hostname,
                               patch,
                               headers={'User-Agent': user_agent},
                               expect_errors=expect_errors)


class TestPostFirstController(TestHost):

    def test_create_host_controller_0(self):
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

    def test_create_host_valid_extra(self):
        # Test creation of host with a valid location
        ndict = dbutils.post_get_test_ihost(hostname='controller-0',
                                            location={'Country': 'Canada',
                                                      'City': 'Ottawa'})
        self.post_json('/ihosts', ndict,
                       headers={'User-Agent': 'sysinv-test'})

        # Verify that the host was created with the specified location
        result = self.get_json('/ihosts/%s' % ndict['hostname'])
        self.assertEqual(ndict['location'], result['location'])

    def test_create_host_invalid_extra(self):
        # Test creation of host with an invalid location
        ndict = dbutils.post_get_test_ihost(hostname='controller-0',
                                            location={'foo': 0.123})
        self.assertRaises(webtest.app.AppError,
                          self.post_json, '/ihosts', ndict,
                          headers={'User-Agent': 'sysinv-test'})


class TestPostControllerMixin(object):

    def setUp(self):
        super(TestPostControllerMixin, self).setUp()

    def test_create_host_controller_1(self):
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

    def test_create_host_evaluate_apps_reapply(self):
        self.skipTest("Need to allow tests to run from UNPROVISIONED"
                      " to reach host-add evaluate")

        c1 = self._create_controller_1(
            invprovision=constants.UNPROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_ONLINE)

        self._create_test_host_platform_interface(c1)

        # Unlock
        _ = self._patch_host(c1['hostname'],
                             [{'path': '/action',
                               'value': constants.UNLOCK_ACTION,
                               'op': 'replace'},
                              {'path': '/operational',
                               'value': constants.OPERATIONAL_ENABLED,
                               'op': 'replace'},
                              {'path': '/availability',
                               'value': constants.AVAILABILITY_ONLINE,
                               'op': 'replace'}],
                             'mtce')

        # Verify that the apps reapply was called
        # once for unlock and once for host-add
        assert(self.fake_conductor_api.evaluate_apps_reapply.call_count == 2)

    def test_create_host_missing_mgmt_mac(self):
        # Test creation of a second node with missing management MAC
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

    def test_create_host_invalid_mgmt_mac_format(self):
        # Test creation of a second node with an invalid management MAC format
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


class TestPostWorkerMixin(object):

    def setUp(self):
        super(TestPostWorkerMixin, self).setUp()

    def test_create_host_worker(self):
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


class TestPostEdgeworkerMixin(object):

    def setUp(self):
        super(TestPostEdgeworkerMixin, self).setUp()

    def test_create_host_worker(self):
        # Test creation of worker
        ndict = dbutils.post_get_test_ihost(hostname='edgeworker-0',
                                            personality='edgeworker',
                                            subfunctions=None,
                                            mgmt_ip=None,
                                            serialid='serial2',
                                            bm_ip="128.224.150.195")
        self.post_json('/ihosts', ndict,
                       headers={'User-Agent': 'sysinv-test'})

        # Verify that the host was configured
        self.fake_conductor_api.configure_ihost.assert_called_once()
        # Verify that the host was created and some basic attributes match
        result = self.get_json('/ihosts/%s' % ndict['hostname'])
        self.assertEqual(ndict['personality'], result['personality'])
        self.assertEqual(ndict['serialid'], result['serialid'])


class TestPostKubeUpgrades(TestHost):

    def setUp(self):
        super(TestPostKubeUpgrades, self).setUp()

        # Mock the KubeOperator
        self.kube_get_control_plane_versions_result = {
            'controller-0': 'v1.42.1',
            'controller-1': 'v1.42.1',
            'worker-0': 'v1.42.1'}

        def mock_kube_get_control_plane_versions(obj):
            return self.kube_get_control_plane_versions_result
        self.mocked_kube_get_control_plane_versions = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_control_plane_versions',
            mock_kube_get_control_plane_versions)
        self.mocked_kube_get_control_plane_versions.start()
        self.addCleanup(self.mocked_kube_get_control_plane_versions.stop)

        self.kube_get_kubelet_versions_result = {
            'controller-0': 'v1.42.1',
            'controller-1': 'v1.42.1',
            'worker-0': 'v1.42.1'}

        def mock_kube_get_kubelet_versions(obj):
            return self.kube_get_kubelet_versions_result
        self.mocked_kube_get_kubelet_versions = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_kubelet_versions',
            mock_kube_get_kubelet_versions)
        self.mocked_kube_get_kubelet_versions.start()
        self.addCleanup(self.mocked_kube_get_kubelet_versions.stop)

        # Mock the KubeVersion
        self.get_kube_versions_result = [
            {'version': 'v1.42.1',
             'upgrade_from': [],
             'downgrade_to': [],
             'applied_patches': [],
             'available_patches': [],
             },
            {'version': 'v1.42.2',
             'upgrade_from': ['v1.42.1'],
             'downgrade_to': [],
             'applied_patches': [],
             'available_patches': [],
             },
        ]

        def mock_get_kube_versions():
            return self.get_kube_versions_result
        self.mocked_get_kube_versions = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        self.mocked_get_kube_versions.start()
        self.addCleanup(self.mocked_get_kube_versions.stop)

        # Mock the patching API
        self.mock_patch_is_applied_result = True

        def mock_patch_is_applied(token, timeout, region_name, patches):
            return self.mock_patch_is_applied_result
        self.mocked_patch_is_applied = mock.patch(
            'sysinv.api.controllers.v1.patch_api.patch_is_applied',
            mock_patch_is_applied)
        self.mocked_patch_is_applied.start()
        self.addCleanup(self.mocked_patch_is_applied.stop)

        self.mock_patch_is_available_result = True

        def mock_patch_is_available(token, timeout, region_name, patches):
            return self.mock_patch_is_available_result
        self.mocked_patch_is_available = mock.patch(
            'sysinv.api.controllers.v1.patch_api.patch_is_available',
            mock_patch_is_available)
        self.mocked_patch_is_available.start()
        self.addCleanup(self.mocked_patch_is_available.stop)

    def test_kube_upgrade_control_plane_controller_0(self):
        # Test upgrading kubernetes control plane on controller-0

        # Create controller-0
        c0 = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_NETWORKING,
        )

        # Upgrade the control plane
        body = {}
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_control_plane',
            body, headers={'User-Agent': 'sysinv-test'})

        # Verify the host was returned
        self.assertEqual(result.json['hostname'], 'controller-0')

        # Verify the control plane was upgraded
        self.fake_conductor_api.kube_upgrade_control_plane.\
            assert_called_with(mock.ANY, c0.uuid)

        # Verify that the target version and status was updated
        result = self.get_json('/kube_host_upgrades/1')
        self.assertEqual(result['target_version'], 'v1.42.2')
        self.assertEqual(result['status'],
                         kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE)

        # Verify that the upgrade state was updated
        result = self.get_json('/kube_upgrade/%s' % kube_upgrade.uuid)
        self.assertEqual(result['state'],
                         kubernetes.KUBE_UPGRADING_FIRST_MASTER)

    def test_kube_upgrade_control_plane_controller_0_after_failure(self):
        # Test upgrading kubernetes control plane on controller-0 after a
        # failure

        # Create controller-0
        c0 = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER_FAILED,
        )

        # Mark the kube host upgrade as failed
        values = {'target_version': 'v1.42.2',
                  'status': kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE_FAILED}
        self.dbapi.kube_host_upgrade_update(1, values)

        # Upgrade the control plane
        body = {}
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_control_plane',
            body, headers={'User-Agent': 'sysinv-test'})

        # Verify the host was returned
        self.assertEqual(result.json['hostname'], 'controller-0')

        # Verify the control plane was upgraded
        self.fake_conductor_api.kube_upgrade_control_plane.\
            assert_called_with(mock.ANY, c0.uuid)

        # Verify that the target version and status was updated
        result = self.get_json('/kube_host_upgrades/1')
        self.assertEqual(result['target_version'], 'v1.42.2')
        self.assertEqual(result['status'],
                         kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE)

        # Verify that the upgrade state was updated
        result = self.get_json('/kube_upgrade/%s' % kube_upgrade.uuid)
        self.assertEqual(result['state'],
                         kubernetes.KUBE_UPGRADING_FIRST_MASTER)

    def test_kube_upgrade_control_plane_controller_1(self):
        # Test upgrading kubernetes control plane on controller-1

        # Create controllers
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        c1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_NETWORKING,
        )

        # Upgrade the control plane
        body = {}
        result = self.post_json(
            '/ihosts/controller-1/kube_upgrade_control_plane',
            body, headers={'User-Agent': 'sysinv-test'})

        # Verify the host was returned
        self.assertEqual(result.json['hostname'], 'controller-1')

        # Verify the control plane was upgraded
        self.fake_conductor_api.kube_upgrade_control_plane.\
            assert_called_with(mock.ANY, c1.uuid)

        # Verify that the target version and status was updated
        result = self.get_json('/kube_host_upgrades/2')
        self.assertEqual(result['target_version'], 'v1.42.2')
        self.assertEqual(result['status'],
                         kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE)

        # Verify that the upgrade state was updated
        result = self.get_json('/kube_upgrade/%s' % kube_upgrade.uuid)
        self.assertEqual(result['state'],
                         kubernetes.KUBE_UPGRADING_FIRST_MASTER)

    def test_kube_upgrade_control_plane_second_controller(self):
        # Test upgrading kubernetes control plane on the second controller

        # Create controllers
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        c1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_FIRST_MASTER,
        )

        # Mark the first kube host upgrade as OK
        values = {'target_version': 'v1.42.2'}
        self.dbapi.kube_host_upgrade_update(1, values)

        # Upgrade the control plane
        body = {}
        result = self.post_json(
            '/ihosts/controller-1/kube_upgrade_control_plane',
            body, headers={'User-Agent': 'sysinv-test'})

        # Verify the host was returned
        self.assertEqual(result.json['hostname'], 'controller-1')

        # Verify the control plane was upgraded
        self.fake_conductor_api.kube_upgrade_control_plane.\
            assert_called_with(mock.ANY, c1.uuid)

        # Verify that the target version and status was updated
        result = self.get_json('/kube_host_upgrades/2')
        self.assertEqual(result['target_version'], 'v1.42.2')
        self.assertEqual(result['status'],
                         kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE)

        # Verify that the upgrade state was updated
        result = self.get_json('/kube_upgrade/%s' % kube_upgrade.uuid)
        self.assertEqual(result['state'],
                         kubernetes.KUBE_UPGRADING_SECOND_MASTER)

    def test_kube_upgrade_control_plane_second_controller_after_failure(self):
        # Test upgrading kubernetes control plane on the second controller
        # after a failure

        # Create controllers
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        c1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_SECOND_MASTER_FAILED,
        )

        # Mark the first kube host upgrade as OK
        values = {'target_version': 'v1.42.2'}
        self.dbapi.kube_host_upgrade_update(1, values)

        # Mark the second kube host upgrade as failed
        values = {'target_version': 'v1.42.2',
                  'status': kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE_FAILED}
        self.dbapi.kube_host_upgrade_update(2, values)

        # Upgrade the control plane
        body = {}
        result = self.post_json(
            '/ihosts/controller-1/kube_upgrade_control_plane',
            body, headers={'User-Agent': 'sysinv-test'})

        # Verify the host was returned
        self.assertEqual(result.json['hostname'], 'controller-1')

        # Verify the control plane was upgraded
        self.fake_conductor_api.kube_upgrade_control_plane.\
            assert_called_with(mock.ANY, c1.uuid)

        # Verify that the target version and status was updated
        result = self.get_json('/kube_host_upgrades/2')
        self.assertEqual(result['target_version'], 'v1.42.2')
        self.assertEqual(result['status'],
                         kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE)

        # Verify that the upgrade state was updated
        result = self.get_json('/kube_upgrade/%s' % kube_upgrade.uuid)
        self.assertEqual(result['state'],
                         kubernetes.KUBE_UPGRADING_SECOND_MASTER)

    def test_kube_upgrade_control_plane_wrong_controller_after_failure(self):
        # Test upgrading kubernetes control plane on the wrong controller
        # after a failure

        # Create controllers
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER_FAILED,
        )

        # Mark the first kube host upgrade as failed
        values = {'target_version': 'v1.42.2',
                  'status': kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE_FAILED}
        self.dbapi.kube_host_upgrade_update(1, values)

        # Upgrade the second control plane
        result = self.post_json(
            '/ihosts/controller-1/kube_upgrade_control_plane',
            {}, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("The first control plane upgrade must be completed",
                      result.json['error_message'])

    def test_kube_upgrade_control_plane_no_upgrade(self):
        # Test upgrading kubernetes control plane with no upgrade

        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Upgrade the control plane
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_control_plane',
            {}, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("upgrade is not in progress",
                      result.json['error_message'])

    def test_kube_upgrade_control_plane_wrong_upgrade_state(self):
        # Test upgrading kubernetes control plane with wrong upgrade state

        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )

        # Upgrade the control plane
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_control_plane',
            {}, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("The kubernetes upgrade is not in a valid state",
                      result.json['error_message'])

    def test_kube_upgrade_control_plane_controller_0_missing_applied_patches(
            self):
        # Test upgrading kubernetes control plane with missing applied patches

        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_NETWORKING,
        )

        # Fake the missing patches
        self.mock_patch_is_applied_result = False
        self.get_kube_versions_result = [
            {'version': 'v1.42.1',
             'upgrade_from': [],
             'downgrade_to': [],
             'applied_patches': [],
             'available_patches': [],
             },
            {'version': 'v1.42.2',
             'upgrade_from': ['v1.42.1'],
             'downgrade_to': [],
             'applied_patches': ['MISSING_PATCH.1'],
             'available_patches': ['MISSING_PATCH.2'],
             },
        ]

        # Upgrade the control plane
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_control_plane',
            {}, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("The following patches must be applied",
                      result.json['error_message'])

    def test_kube_upgrade_control_plane_controller_0_missing_available_patches(
            self):
        # Test upgrading kubernetes control plane with missing available
        # patches

        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_NETWORKING,
        )

        # Fake the missing patches
        self.mock_patch_is_available_result = False
        self.get_kube_versions_result = [
            {'version': 'v1.42.1',
             'upgrade_from': [],
             'downgrade_to': [],
             'applied_patches': [],
             'available_patches': [],
             },
            {'version': 'v1.42.2',
             'upgrade_from': ['v1.42.1'],
             'downgrade_to': [],
             'applied_patches': [],
             'available_patches': ['MISSING_PATCH.2'],
             },
        ]

        # Upgrade the control plane
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_control_plane',
            {}, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("The following patches must be available",
                      result.json['error_message'])

    def test_kube_upgrade_control_plane_wrong_personality(self):
        # Test upgrading kubernetes control plane with wrong personality

        # Create hosts
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        self._create_worker(
            mgmt_ip='192.168.204.5',
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_NETWORKING,
        )

        # Upgrade the control plane
        result = self.post_json(
            '/ihosts/worker-0/kube_upgrade_control_plane',
            {}, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("does not have a kubernetes control plane",
                      result.json['error_message'])

    def test_kube_upgrade_control_plane_missing_version(self):
        # Test upgrading kubernetes control plane with no control plane version

        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_NETWORKING,
        )

        # No control plane version for this controller
        self.kube_get_control_plane_versions_result = {
            'controller-1': 'v1.42.1',
            'worker-0': 'v1.42.1'}

        # Upgrade the control plane
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_control_plane',
            {}, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("Unable to determine the version",
                      result.json['error_message'])

    def test_kube_upgrade_control_plane_wrong_host_state(self):
        # Test upgrading kubernetes control plane with wrong host state

        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_NETWORKING,
        )

        # Upgrade the control plane
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_control_plane',
            {}, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("must be unlocked and available",
                      result.json['error_message'])

    def test_kube_upgrade_control_plane_already_in_progress(self):
        # Test upgrading kubernetes control plane with upgrade in progress

        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_NETWORKING,
        )

        # Mark the kube host as already upgrading
        values = {'status': kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE}
        self.dbapi.kube_host_upgrade_update(1, values)

        # Upgrade the control plane
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_control_plane',
            {}, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("control plane on this host is already being upgraded",
                      result.json['error_message'])

    def test_kube_upgrade_first_control_plane_after_first_control_plane(self):
        # Test re-upgrading kubernetes first control plane

        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_FIRST_MASTER,
        )

        # The control plane on this host was already upgraded
        # to the new version
        self.kube_get_control_plane_versions_result = {
            'controller-0': 'v1.42.2',
            'controller-1': 'v1.42.1'}

        # Upgrade the first control plane
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_control_plane',
            {}, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("The first control plane was already upgraded",
                      result.json['error_message'])

    def test_kube_upgrade_kubelet_controller_0(self):
        # Test upgrading kubernetes kubelet on controller-0

        # Create controller-0
        c0 = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_SECOND_MASTER,
        )

        # Upgrade the kubelet
        body = {}
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_kubelet',
            body, headers={'User-Agent': 'sysinv-test'})

        # Verify the host was returned
        self.assertEqual(result.json['hostname'], 'controller-0')

        # Verify the kubelet was upgraded
        self.fake_conductor_api.kube_upgrade_kubelet.\
            assert_called_with(mock.ANY, c0.uuid)

        # Verify that the status was updated
        result = self.get_json('/kube_host_upgrades/1')
        self.assertEqual(result['status'],
                         kubernetes.KUBE_HOST_UPGRADING_KUBELET)

        # Verify that the upgrade state was updated
        result = self.get_json('/kube_upgrade/%s' % kube_upgrade.uuid)
        self.assertEqual(result['state'],
                         kubernetes.KUBE_UPGRADING_KUBELETS)

    def test_kube_upgrade_kubelet_controller_1(self):
        # Test upgrading kubernetes kubelet on controller-1

        # Create controllers
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        c1 = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_SECOND_MASTER,
        )

        # Upgrade the kubelet
        body = {}
        result = self.post_json(
            '/ihosts/controller-1/kube_upgrade_kubelet',
            body, headers={'User-Agent': 'sysinv-test'})

        # Verify the host was returned
        self.assertEqual(result.json['hostname'], 'controller-1')

        # Verify the kubelet was upgraded
        self.fake_conductor_api.kube_upgrade_kubelet.\
            assert_called_with(mock.ANY, c1.uuid)

        # Verify that the status was updated
        result = self.get_json('/kube_host_upgrades/2')
        self.assertEqual(result['status'],
                         kubernetes.KUBE_HOST_UPGRADING_KUBELET)

        # Verify that the upgrade state was updated
        result = self.get_json('/kube_upgrade/%s' % kube_upgrade.uuid)
        self.assertEqual(result['state'],
                         kubernetes.KUBE_UPGRADING_KUBELETS)

    def test_kube_upgrade_kubelet_worker(self):
        # Test upgrading kubernetes kubelet on worker

        # Create hosts
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        w0 = self._create_worker(
            mgmt_ip='192.168.204.5',
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )

        # Indicate kubelets on controllers have been upgraded
        self.kube_get_kubelet_versions_result = {
            'controller-0': 'v1.42.2',
            'controller-1': 'v1.42.2',
            'worker-0': 'v1.42.1'}

        # Upgrade the kubelet
        body = {}
        result = self.post_json(
            '/ihosts/worker-0/kube_upgrade_kubelet',
            body, headers={'User-Agent': 'sysinv-test'})

        # Verify the host was returned
        self.assertEqual(result.json['hostname'], 'worker-0')

        # Verify that the target version and status was updated
        result = self.get_json('/kube_host_upgrades/3')
        self.assertEqual(result['target_version'], 'v1.42.2')
        self.assertEqual(result['status'],
                         kubernetes.KUBE_HOST_UPGRADING_KUBELET)

        # Verify the kubelet was upgraded
        self.fake_conductor_api.kube_upgrade_kubelet.\
            assert_called_with(mock.ANY, w0.uuid)

        # Verify that the upgrade state was updated
        result = self.get_json('/kube_upgrade/%s' % kube_upgrade.uuid)
        self.assertEqual(result['state'],
                         kubernetes.KUBE_UPGRADING_KUBELETS)

    def test_kube_upgrade_kubelet_no_upgrade(self):
        # Test upgrading kubernetes kubelet on controller-0 with no upgrade

        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Upgrade the kubelet
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_kubelet',
            {}, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("upgrade is not in progress",
                      result.json['error_message'])

    def test_kube_upgrade_kubelet_no_kubelet(self):
        # Test upgrading kubernetes kubelet where there is no kubelet

        # Create storage-0
        self._create_test_host(
            personality=constants.STORAGE)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_SECOND_MASTER,
        )

        # Upgrade the kubelet
        result = self.post_json(
            '/ihosts/storage-0/kube_upgrade_kubelet',
            {}, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("host does not have a kubelet",
                      result.json['error_message'])

    def test_kube_upgrade_kubelet_controller_0_repeated(self):
        # Test upgrading kubernetes kubelet on controller-0 when it was already
        # done

        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Update the target version
        values = {'target_version': 'v1.42.2'}
        self.dbapi.kube_host_upgrade_update(1, values)

        # Indicate the kubelet is already upgraded
        self.kube_get_kubelet_versions_result = {
            'controller-0': 'v1.42.2'}

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_SECOND_MASTER,
        )

        # Upgrade the kubelet
        body = {}
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_kubelet',
            body, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("kubelet on this host was already upgraded",
                      result.json['error_message'])

    def test_kube_upgrade_kubelet_controller_0_repeated_force(self):
        # Test upgrading kubernetes kubelet on controller-0 when it was already
        # done, but allowed because of the force option

        # Create controller-0
        c0 = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Update the target version
        values = {'target_version': 'v1.42.2'}
        self.dbapi.kube_host_upgrade_update(1, values)

        # Indicate the kubelet is already upgraded
        self.kube_get_kubelet_versions_result = {
            'controller-0': 'v1.42.2'}

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_SECOND_MASTER,
        )

        # Upgrade the kubelet
        body = {'force': True}
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_kubelet',
            body, headers={'User-Agent': 'sysinv-test'})

        # Verify the host was returned
        self.assertEqual(result.json['hostname'], 'controller-0')

        # Verify the kubelet was upgraded
        self.fake_conductor_api.kube_upgrade_kubelet.\
            assert_called_with(mock.ANY, c0.uuid)

        # Verify that the status was updated
        result = self.get_json('/kube_host_upgrades/1')
        self.assertEqual(result['status'],
                         kubernetes.KUBE_HOST_UPGRADING_KUBELET)

        # Verify that the upgrade state was updated
        result = self.get_json('/kube_upgrade/%s' % kube_upgrade.uuid)
        self.assertEqual(result['state'],
                         kubernetes.KUBE_UPGRADING_KUBELETS)

    def test_kube_upgrade_kubelet_controller_0_wrong_upgrade_state(self):
        # Test upgrading kubernetes kubelet on controller-0 with upgrade in
        # the wrong state.

        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADE_DOWNLOADED_IMAGES,
        )

        # Upgrade the kubelet
        body = {}
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_kubelet',
            body, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("upgrade must be in the",
                      result.json['error_message'])

    def test_kube_upgrade_kubelet_controller_0_missing_patches(self):
        # Test upgrading kubernetes kubelet on controller-0 with missing
        # patches.

        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_SECOND_MASTER,
        )

        # Fake the missing patches
        self.mock_patch_is_applied_result = False
        self.get_kube_versions_result = [
            {'version': 'v1.42.1',
             'upgrade_from': [],
             'downgrade_to': [],
             'applied_patches': [],
             'available_patches': [],
             },
            {'version': 'v1.42.2',
             'upgrade_from': ['v1.42.1'],
             'downgrade_to': [],
             'applied_patches': [],
             'available_patches': ['MISSING_PATCH.1', 'MISSING_PATCH.2'],
             },
        ]

        # Upgrade the kubelet
        body = {}
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_kubelet',
            body, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("The following patches must be applied",
                      result.json['error_message'])

    def test_kube_upgrade_kubelet_worker_wrong_order(self):
        # Test upgrading kubernetes kubelet on worker before controllers

        # Create hosts
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        self._create_worker(
            mgmt_ip='192.168.204.5',
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )

        # Indicate kubelets on controllers have not been upgraded
        self.kube_get_kubelet_versions_result = {
            'controller-0': 'v1.42.1',
            'controller-1': 'v1.42.1',
            'worker-0': 'v1.42.1'}

        # Upgrade the kubelet
        body = {}
        result = self.post_json(
            '/ihosts/worker-0/kube_upgrade_kubelet',
            body, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("The kubelets on all controller hosts must be upgraded",
                      result.json['error_message'])

    def test_kube_upgrade_kubelet_controller_0_missing_kubelet(self):
        # Test upgrading kubernetes kubelet on controller-0 with kubelet
        # version missing.

        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Update the target version
        values = {'target_version': 'v1.42.2'}
        self.dbapi.kube_host_upgrade_update(1, values)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_SECOND_MASTER,
        )

        # No kubelet version for controller-0
        self.kube_get_kubelet_versions_result = {
            'controller-1': 'v1.42.1',
            'worker-0': 'v1.42.1'}

        # Upgrade the kubelet
        body = {}
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_kubelet',
            body, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("Unable to determine the version of the kubelet",
                      result.json['error_message'])

    def test_kube_upgrade_kubelet_controller_0_wrong_host_state(self):
        # Test upgrading kubernetes kubelet on controller-0 with controller
        # in the wrong state.

        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_AVAILABLE)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_SECOND_MASTER,
        )

        # Upgrade the kubelet
        body = {}
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_kubelet',
            body, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("The host must be locked and online",
                      result.json['error_message'])

    def test_kube_upgrade_kubelet_already_in_progress(self):
        # Test upgrading kubernetes kubelet with upgrade in progress

        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADED_SECOND_MASTER,
        )

        # Mark the kube host as already upgrading
        values = {'status': kubernetes.KUBE_HOST_UPGRADING_KUBELET}
        self.dbapi.kube_host_upgrade_update(1, values)

        # Upgrade the kubelet
        body = {}
        result = self.post_json(
            '/ihosts/controller-0/kube_upgrade_kubelet',
            body, headers={'User-Agent': 'sysinv-test'},
            expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertTrue(result.json['error_message'])
        self.assertIn("The kubelet on this host is already being upgraded",
                      result.json['error_message'])


class TestDelete(TestHost):

    def test_delete_host(self):
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
        # Verify that the apps reapply was called
        self.fake_conductor_api.evaluate_apps_reapply.assert_called_once()
        # Verify that the host was dropped from patching
        self.mock_patch_api_drop_host.assert_called_once()
        # Verify the host no longer exists
        response = self.get_json('/ihosts/%s' % ndict['hostname'],
                                 expect_errors=True)
        self.assertEqual(response.status_int, 404)
        self.assertEqual(response.content_type, 'application/json')
        self.assertTrue(response.json['error_message'])

    def test_delete_unprovisioned_host(self):
        # Create controller-0
        self._create_controller_0()
        # Create an unprovisioned host (i.e. without hostname or personality)
        ndict = dbutils.post_get_test_ihost(uuid=uuidutils.generate_uuid,
                                            personality=None,
                                            hostname=None,
                                            mgmt_ip='192.168.204.111')
        self.dbapi.ihost_create(ndict)
        # Delete the worker host
        self.delete('/ihosts/%s' % ndict['uuid'],
                    headers={'User-Agent': 'sysinv-test'})

        # Verify that the host was deleted from the VIM
        self.mock_vim_api_host_delete.assert_called_once()
        # Verify that the delete was not sent to maintenance
        self.mock_mtce_api_host_delete.assert_not_called()
        # Verify that the host was unconfigured
        self.fake_conductor_api.unconfigure_ihost.assert_called_once()
        # Verify that the host was deleted from barbican
        self.fake_conductor_api.delete_barbican_secret.assert_called_once()
        # Verify that the patch drop host was not invoked
        self.mock_patch_api_drop_host.assert_not_called()

        # Verify the host no longer exists
        response = self.get_json('/ihosts/%s' % ndict['uuid'],
                                 expect_errors=True)
        self.assertEqual(response.status_int, 404)
        self.assertEqual(response.content_type, 'application/json')
        self.assertTrue(response.json['error_message'])


class TestListHosts(TestHost):

    def test_empty_host(self):
        data = self.get_json('/ihosts')
        self.assertEqual([], data['ihosts'])

    def test_one(self):
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
        hosts = []
        for hostid in range(1000):  # there is a limit of 1000 returned by json
            ndict = dbutils.get_test_ihost(
                id=hostid, hostname=hostid, mgmt_mac=hostid,
                forisystemid=self.system.id,
                mgmt_ip="%s.%s.%s.%s" % (hostid, hostid, hostid, hostid),
                uuid=uuidutils.generate_uuid())
            s = self.dbapi.ihost_create(ndict)
            hosts.append(s['uuid'])
        data = self.get_json('/ihosts')
        self.assertEqual(len(hosts), len(data['ihosts']))

        uuids = [n['uuid'] for n in data['ihosts']]
        self.assertEqual(hosts.sort(), uuids.sort())  # uuids.sort

    def test_host_links(self):
        uuid = uuidutils.generate_uuid()
        ndict = dbutils.get_test_ihost(id=1, uuid=uuid,
                                       forisystemid=self.system.id)
        self.dbapi.ihost_create(ndict)
        data = self.get_json('/ihosts/1')
        self.assertIn('links', data.keys())
        self.assertEqual(len(data['links']), 2)
        self.assertIn(uuid, data['links'][0]['href'])

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
            host_id = ndict['id']
            self.dbapi.ethernet_port_create(host_id, pdict)

        data = self.get_json('/ihosts/%s/ports' % ndict['uuid'])
        self.assertEqual(len(data['ports']), 2)
        self.assertNotIn('next', data.keys())

        # Test collection pagination
        data = self.get_json(
                '/ihosts/%s/ports?limit=1' % ndict['uuid'])
        self.assertEqual(len(data['ports']), 1)
        self.assertIn('next', data.keys())


class TestPatch(TestHost):

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

    def test_controller_first_enabled_notification(self):
        # Create controller-0, provisioning
        c0_host = self._create_controller_0(
            invprovision=constants.PROVISIONING,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_OFFLINE)
        self._create_test_host_platform_interface(c0_host)

        # notify controller-0 enabled/available
        response = self._patch_host(c0_host['hostname'],
                                    [{'path': '/operational',
                                      'value': constants.OPERATIONAL_ENABLED,
                                      'op': 'replace'},
                                     {'path': '/availability',
                                      'value': constants.AVAILABILITY_ONLINE,
                                      'op': 'replace'}],
                                    'mtce')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the default config is to be copied
        self.fake_conductor_api.store_default_config.assert_called_once()

        ihost = self._get_test_host_by_hostname(c0_host['hostname'])
        self.assertEqual(constants.OPERATIONAL_ENABLED, ihost.operational)
        self.assertEqual(constants.AVAILABILITY_ONLINE, ihost.availability)
        self.assertEqual(constants.PROVISIONED, ihost.invprovision)

    def test_controller_subsequent_enabled_notification(self):
        # Create controller-0, provisioned
        c0_host = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_OFFLINE)
        self._create_test_host_platform_interface(c0_host)

        # notify controller-0 enabled/available
        response = self._patch_host(c0_host['hostname'],
                                    [{'path': '/operational',
                                      'value': constants.OPERATIONAL_ENABLED,
                                      'op': 'replace'},
                                     {'path': '/availability',
                                      'value': constants.AVAILABILITY_ONLINE,
                                      'op': 'replace'}],
                                    'mtce')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the default config is not copied again
        self.fake_conductor_api.store_default_config.assert_not_called()

        ihost = self._get_test_host_by_hostname(c0_host['hostname'])
        self.assertEqual(constants.OPERATIONAL_ENABLED, ihost.operational)
        self.assertEqual(constants.AVAILABILITY_ONLINE, ihost.availability)
        self.assertEqual(constants.PROVISIONED, ihost.invprovision)

    def test_update_host_bm_valid(self):
        # Create controller-0, provisioned
        c0_host = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_OFFLINE)
        self._create_test_host_platform_interface(c0_host)

        bm_ip = '128.224.141.222'
        bm_username = 'root'

        for bm_type in constants.HOST_BM_VALID_PROVISIONED_TYPE_LIST:
            bm_password = 'password' + bm_type
            response = self._patch_host(c0_host['hostname'],
                                        [{'path': '/bm_type',
                                          'value': bm_type,
                                          'op': 'replace'},
                                         {'path': '/bm_ip',
                                          'value': bm_ip,
                                          'op': 'replace'},
                                         {'path': '/bm_username',
                                          'value': bm_username,
                                          'op': 'replace'},
                                         {'path': '/bm_password',
                                          'value': bm_password,
                                          'op': 'replace'}],
                                        '')
            self.assertEqual(response.content_type, 'application/json')
            self.assertEqual(response.status_code, http_client.OK)

            ihost = self._get_test_host_by_hostname(c0_host['hostname'])
            self.assertEqual(bm_type, ihost.bm_type)
            self.assertEqual(bm_ip, ihost.bm_ip)
            self.assertEqual(bm_username, ihost.bm_username)

            self.fake_conductor_api.create_barbican_secret.assert_called_with(
                mock.ANY, ihost.uuid, bm_password)

    def test_unlock_action_controller(self):
        # Create controller-0
        c0_host = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        self._create_test_host_platform_interface(c0_host)

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
        # Verify that the apps reapply was called
        self.fake_conductor_api.evaluate_apps_reapply.assert_called_once()
        # Verify that the host was added to maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c0_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_force_unlock_action_controller(self):
        # Create controller-0 - make it offline so force unlock required
        c0_host = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_OFFLINE)
        self._create_test_host_platform_interface(c0_host)

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
        # Verify that the apps reapply was called
        self.fake_conductor_api.evaluate_apps_reapply.assert_called_once()
        # Verify that the host was modified in maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c0_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_unlock_action_controller_inventory_not_complete(self):
        # Create controller-0 without inv_state initial inventory complete
        c0_host = self._create_controller_0(
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

    def test_unlock_action_controller_during_k8s_rootca_pods_update(self):
        # Create controller-0 without inv_state initial inventory complete
        c0_host = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            inv_state=None, clock_synchronization=constants.NTP)

        # Create kube rootca update updating pods on phase trust-both-cas
        dbutils.create_test_kube_rootca_update(state=kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS)

        # Unlock host
        response = self._patch_host_action(c0_host['hostname'],
                                           constants.UNLOCK_ACTION,
                                           'sysinv-test',
                                           expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json['error_message'])

    def _test_lock_action_controller(self):
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
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
        # Verify that the apps reapply was called
        self.fake_conductor_api.evaluate_apps_reapply.assert_called_once()
        # Verify that the host was not modified in maintenance
        self.mock_mtce_api_host_modify.assert_not_called()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_lock_action_controller(self):
        self._test_lock_action_controller()

    def test_lock_action_controller_during_upgrade_starting(self):
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        upgrade = dbutils.create_test_upgrade(
            state=constants.UPGRADE_STARTING
        )
        # Verify the error response on lock controller attempt
        response = self._patch_host_action(c1_host['hostname'],
                                           constants.LOCK_ACTION,
                                           'sysinv-test',
                                           expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json['error_message'])
        self.assertIn("host-lock %s is not allowed during upgrade state '%s'. "
                      "Upgrade state must be '%s'." %
                      (c1_host['hostname'],
                       upgrade.state,
                       constants.UPGRADE_STARTED),
                      response.json['error_message'])

    def test_lock_action_controller_during_upgrade_started(self):
        dbutils.create_test_upgrade(
            state=constants.UPGRADE_STARTED
        )
        self._test_lock_action_controller()

    def test_force_lock_action_controller(self):
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
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
        # Verify that the apps reapply was called
        self.fake_conductor_api.evaluate_apps_reapply.assert_called_once()

    def test_unlock_action_controller_while_upgrading_kubelet(self):
        # Create controller-0
        c0_host = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        self._create_test_host_platform_interface(c0_host)

        # Create a kube upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )

        # Mark the kube host as kubelet upgrading
        values = {'status': kubernetes.KUBE_HOST_UPGRADING_KUBELET}
        self.dbapi.kube_host_upgrade_update(1, values)

        # Unlock host
        response = self._patch_host_action(c0_host['hostname'],
                                           constants.UNLOCK_ACTION,
                                           'sysinv-test',
                                           expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertIn("Can not unlock controller-0 while upgrading "
                      "kubelet", response.json['error_message'])

    def test_force_unlock_action_controller_while_upgrading_kubelet(self):
        # Create controller-0
        c0_host = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        self._create_test_host_platform_interface(c0_host)

        # Create a kube upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )

        # Mark the kube host as kubelet upgrading
        values = {'status': kubernetes.KUBE_HOST_UPGRADING_KUBELET}
        self.dbapi.kube_host_upgrade_update(1, values)

        # Unlock host
        response = self._patch_host_action(c0_host['hostname'],
                                           constants.FORCE_UNLOCK_ACTION,
                                           'sysinv-test',
                                           expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_unlock_action_worker(self):
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create worker-0
        w0_host = self._create_worker(
            mgmt_ip='192.168.204.5',
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        self._create_test_host_platform_interface(w0_host)
        self._create_test_host_cpus(w0_host, platform=1, vswitch=2, application=12)

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
        # Verify that the apps reapply was called
        self.fake_conductor_api.evaluate_apps_reapply.assert_called_once()
        # Verify that the host was added to maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % w0_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_unlock_action_worker_while_locking(self):
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create worker-0
        w0_host = self._create_worker(
            mgmt_ip='192.168.204.5',
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_AVAILABLE,
            ihost_action=constants.LOCK_ACTION)
        self._create_test_host_platform_interface(w0_host)
        self._create_test_host_cpus(
            w0_host, platform=1, vswitch=2, application=12)

        # Unlock worker host while lock action in progress
        response = self._patch_host_action(w0_host['hostname'],
                                           constants.UNLOCK_ACTION,
                                           'sysinv-test',
                                           expect_errors=True)

        # Verify that the unlock was not sent to the VIM
        self.mock_vim_api_host_action.assert_not_called()
        # Verify that the host was not modified in maintenance
        self.mock_mtce_api_host_modify.assert_not_called()

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertIn('Host unlock rejected due to in progress action %s' %
                      constants.LOCK_ACTION,
                      response.json['error_message'])

        result = self.get_json('/ihosts/%s' % w0_host['hostname'])
        self.assertEqual(constants.LOCK_ACTION, result['ihost_action'])

    def test_unlock_action_worker_while_force_locking(self):
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create worker-0
        w0_host = self._create_worker(
            mgmt_ip='192.168.204.5',
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_AVAILABLE,
            ihost_action=constants.FORCE_LOCK_ACTION)
        self._create_test_host_platform_interface(w0_host)
        self._create_test_host_cpus(
            w0_host, platform=1, vswitch=2, application=12)

        # Unlock worker host while lock action in progress
        response = self._patch_host_action(w0_host['hostname'],
                                           constants.UNLOCK_ACTION,
                                           'sysinv-test',
                                           expect_errors=True)

        # Verify that the unlock was not sent to the VIM
        self.mock_vim_api_host_action.assert_not_called()
        # Verify that the host was not modified in maintenance
        self.mock_mtce_api_host_modify.assert_not_called()

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertIn('Host unlock rejected due to in progress action %s' %
                      constants.FORCE_LOCK_ACTION,
                      response.json['error_message'])

        result = self.get_json('/ihosts/%s' % w0_host['hostname'])
        self.assertEqual(constants.FORCE_LOCK_ACTION, result['ihost_action'])

    def test_lock_action_worker(self):
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create worker-0
        w0_host = self._create_worker(
            mgmt_ip='192.168.204.5',
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
        # Verify that the apps reapply was called
        self.fake_conductor_api.evaluate_apps_reapply.assert_called_once()
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


class TestPatchStdDuplexControllerAction(TestHost):

    def test_swact_action(self):
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            config_target='89fbefe7-7b43-4bd2-9500-663b33df2e57',
            config_applied='89fbefe7-7b43-4bd2-9500-663b33df2e57')

        # Create controller-1
        c1_host = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            config_target=None,
            config_applied=None)

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
        # Verify that the apps reapply was called
        self.fake_conductor_api.evaluate_apps_reapply.assert_called_once()
        # Verify that the host was modified in maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_swact_action_config_out_of_date_on_active(self):
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            config_target='89fbefe7-7b43-4bd2-9500-663b33df2e57',
            config_applied='f9fbefe7-7b43-4bd2-9500-663b33df2e57')

        # Create controller-1
        c1_host = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            config_target='b447d703-b581-4bf6-bcbd-f99ddcbe4663',
            config_applied='b447d703-b581-4bf6-bcbd-f99ddcbe4663')

        # controller-0 already active, per comment 'Behave as if the API is
        # running on controller-0'; so swact from controller-1 is allowed
        response = self._patch_host_action(c1_host['hostname'],
                                           constants.SWACT_ACTION,
                                           'sysinv-test',
                                           expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_swact_action_from_config_out_of_date(self):
        # Create active controller-0 with config out of date
        c0_host = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            config_target='89fbefe7-7b43-4bd2-9500-663b33df2e57',
            config_applied='f9fbefe7-7b43-4bd2-9500-663b33df2e57')

        # Create controller-1
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            config_target='b447d703-b581-4bf6-bcbd-f99ddcbe4663',
            config_applied='b447d703-b581-4bf6-bcbd-f99ddcbe4663')

        # Swact from active controller-0 to controller-1
        response = self._patch_host_action(c0_host['hostname'],
                                           constants.SWACT_ACTION,
                                           'sysinv-test')

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_swact_action_to_config_out_of_date(self):
        # Create controller-0
        c0_host = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            config_target='d1fd40ca-9306-44c8-a100-671f22111114',
            config_applied='d1fd40ca-9306-44c8-a100-671f22111114')

        # Create controller-1
        c1_host = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            config_target='89fbefe7-7b43-4bd2-9500-663b33df2e57',
            config_applied='f9fbefe7-7b43-4bd2-9500-663b33df2e57')

        # controller-0 already active, swact from controller-0
        response = self._patch_host_action(c0_host['hostname'],
                                           constants.SWACT_ACTION,
                                           'sysinv-test',
                                           expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json['error_message'])
        self.assertIn("%s target Config %s not yet applied. " % (
                      c1_host['hostname'], c1_host['config_target']),
                      response.json['error_message'])

    def test_force_swact_action(self):
        # Create controller-0 in disabled state so force swact is required
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
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
        # Verify that the apps reapply was called
        self.fake_conductor_api.evaluate_apps_reapply.assert_called_once()
        # Verify that the host was modified in maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_reset_action(self):
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
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
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
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
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
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
        # Verify that the apps reapply was called
        self.fake_conductor_api.evaluate_apps_reapply.assert_called_once()
        # Verify that the host was configured
        self.fake_conductor_api.configure_ihost.assert_called_once()
        # Verify that the host was modified in maintenance
        self.mock_mtce_api_host_modify.assert_called_once()
        # Verify that the host action was cleared
        result = self.get_json('/ihosts/%s' % c1_host['hostname'])
        self.assertEqual(constants.NONE_ACTION, result['action'])

    def test_poweron_action(self):
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
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
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
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

    def test_lock_action_worker_while_updating_device_image(self):
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create worker-0
        w0_host = self._create_worker(
            mgmt_ip='192.168.204.5',
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Set the in-progress flag on the worker node which is normally set
        # by fpga-agent
        values = {'device_image_update': device.DEVICE_IMAGE_UPDATE_IN_PROGRESS}
        self.dbapi.ihost_update(w0_host.uuid, values)

        # Lock worker host
        response = self._patch_host_action(w0_host['hostname'],
                                           constants.LOCK_ACTION,
                                           'sysinv-test',
                                           expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json['error_message'])
        self.assertIn("Rejected: Cannot lock %s while device image update "
                      "is in progress." % w0_host['hostname'],
                      response.json['error_message'])

    def test_swact_action_controller_while_updating_device_image(self):
        # Create controller-0
        c0_host = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Set the in-progress flag on the worker node which is normally set
        # by the fpga-agent
        values = {'device_image_update': device.DEVICE_IMAGE_UPDATE_IN_PROGRESS}
        self.dbapi.ihost_update(c1_host.uuid, values)

        # Swact controller host
        response = self._patch_host_action(c0_host['hostname'],
                                           constants.SWACT_ACTION,
                                           'sysinv-test',
                                           expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json['error_message'])
        self.assertIn("Rejected: Cannot swact %s while %s is updating device "
                      "images." % (c0_host['hostname'], c1_host['hostname']),
                      response.json['error_message'])

    def test_swact_action_controller_while_kube_rootca_pods_update(self):
        # Create controller-0
        c0_host = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create kube rootca update updating pods on phase trust-both-cas
        dbutils.create_test_kube_rootca_update(state=kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS)

        # Swact controller host
        response = self._patch_host_action(c0_host['hostname'],
                                           constants.SWACT_ACTION,
                                           'sysinv-test',
                                           expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json['error_message'])
        self.assertIn("Can not swact %s while kubernetes root ca "
                      "update phase in progress. Wait for update "
                      "phase to complete." % c0_host['hostname'],
                      response.json['error_message'])

    def test_swact_action_controller_while_kube_rootca_host_update(self):
        # Create controller-0
        c0_host = self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create kubernetes rootca update for the host and set it with phase in progress
        dbutils.create_test_kube_rootca_update(state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS)
        dbutils.create_test_kube_rootca_host_update(host_id=c0_host['id'],
                                                    state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS)

        # Swact controller host
        response = self._patch_host_action(c0_host['hostname'],
                                           constants.SWACT_ACTION,
                                           'sysinv-test',
                                           expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json['error_message'])
        self.assertIn("Can not swact %s while kubernetes root ca "
                      "update phase is in progress. Wait for update "
                      "phase to complete on host." % c0_host['hostname'],
                      response.json['error_message'])


class TestPatchStdDuplexControllerVIM(TestHost):

    def test_vim_services_enabled_action(self):
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
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
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
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
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
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
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
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
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
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

    def test_subfunction_config_action(self):
        # Create controller-0 (AIO)
        c0_host = self._create_controller_0(
            subfunction=constants.WORKER,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Get the disk created by _create_test_host
        disk = self.dbapi.idisk_get(1, c0_host['id'])
        # Configure nova-local LVG
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
        # Create controller-0
        host = self._create_controller_0(
            availability=constants.AVAILABILITY_ONLINE)

        # Verify that the action was rejected
        self.assertRaises(webtest.app.AppError,
                          self.patch_json,
                          '/ihosts/%s' % host['hostname'],
                          [{'path': '/action',
                            'value': 'badaction',
                            'op': 'replace'}],
                          headers={'User-Agent': 'sysinv-test'})


class TestHostPTPValidation(TestHost):
    def test_ptp_unlock_valid(self):
        ptp = self.dbapi.ptp_get_one()
        ptp_uuid = ptp.uuid
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create worker-0
        w0_host = self._create_worker(
            mgmt_ip='192.168.204.5',
            clock_synchronization=constants.PTP,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        self._create_test_host_platform_interface(w0_host)
        self._create_test_host_cpus(w0_host, platform=1, vswitch=2, application=12)

        # Host with PTP must have at least one ptp interface
        interface = {
            'forihostid': w0_host['id'],
            'ifname': 'ptpif',
            'iftype': constants.INTERFACE_TYPE_ETHERNET,
            'imac': '02:11:22:33:44:11',
            'ifclass': constants.INTERFACE_CLASS_PLATFORM,
            'ptp_role': constants.INTERFACE_PTP_ROLE_MASTER
        }
        ptp_if = dbutils.create_test_interface(**interface)
        response = self._patch_host_action(
            w0_host['hostname'], constants.UNLOCK_ACTION, 'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # With UDP transport all host PTP interfaces must have an IP

        self.dbapi.ptp_update(ptp_uuid, {'transport': constants.PTP_TRANSPORT_UDP})
        address = {'interface_id': ptp_if.id,
                   'family': 4,
                   'prefix': 24,
                   'address': '192.168.1.2'}
        dbutils.create_test_address(**address)
        response = self._patch_host_action(
            w0_host['hostname'], constants.UNLOCK_ACTION, 'sysinv-test')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_ptp_unlock_invalid(self):
        ptp = self.dbapi.ptp_get_one()
        ptp_uuid = ptp.uuid
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create worker-0
        w0_host = self._create_worker(
            mgmt_ip='192.168.204.5',
            clock_synchronization=constants.PTP,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_LOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)
        self._create_test_host_platform_interface(w0_host)
        self._create_test_host_cpus(w0_host, platform=1, vswitch=2, application=12)

        # Host with PTP must have at least one ptp interface
        response = self._patch_host_action(
            w0_host['hostname'], constants.UNLOCK_ACTION, 'sysinv-test', expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertTrue(response.json['error_message'])
        self.assertIn("Hosts with PTP clock synchronization must have at least one", response.json['error_message'])

        # With UDP transport all host PTP interfaces must have an IP
        interface = {
            'forihostid': w0_host['id'],
            'ifname': 'ptpif',
            'iftype': constants.INTERFACE_TYPE_ETHERNET,
            'imac': '02:11:22:33:44:11',
            'ifclass': constants.INTERFACE_CLASS_PLATFORM,
            'ptp_role': constants.INTERFACE_PTP_ROLE_MASTER
        }
        dbutils.create_test_interface(**interface)
        self.dbapi.ptp_update(ptp_uuid, {'transport': constants.PTP_TRANSPORT_UDP})

        response = self._patch_host_action(
            w0_host['hostname'], constants.UNLOCK_ACTION, 'sysinv-test', expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertTrue(response.json['error_message'])
        self.assertIn("All PTP interfaces must have an associated address", response.json['error_message'])


class PostControllerHostTestCase(TestPostControllerMixin, TestHost,
                                 dbbase.ControllerHostTestCase):
    pass


class PostWorkerHostTestCase(TestPostWorkerMixin, TestHost,
                             dbbase.ControllerHostTestCase):
    pass


class PostEdgeworkerHostTestCase(TestPostEdgeworkerMixin, TestHost,
                             dbbase.ControllerHostTestCase):
    pass


class PostAIOHostTestCase(TestPostControllerMixin, TestHost,
                          dbbase.AIOHostTestCase):
    pass


class PostAIODuplexHostTestCase(TestPostControllerMixin, TestHost,
                                dbbase.AIODuplexHostTestCase):
    pass


class PostAIODuplexDirectHostTestCase(TestPostControllerMixin, TestHost,
                                      dbbase.AIODuplexDirectHostTestCase):
    pass


class PatchControllerHostTestCase(
        TestPatchStdDuplexControllerVIM,
        TestPatchStdDuplexControllerAction,
        TestPatch):
    pass


class PatchAIOHostTestCase(TestPatch):

    system_type = constants.TIS_AIO_BUILD

    def setUp(self):
        super(PatchAIOHostTestCase, self).setUp()


class PatchAIOSimplexHostTestCase(PatchAIOHostTestCase):
    system_mode = constants.SYSTEM_MODE_SIMPLEX


class PatchAIODuplexHostTestCase(PatchAIOHostTestCase):
    system_mode = constants.SYSTEM_MODE_DUPLEX


class PatchAIODuplexDirectHostTestCase(PatchAIOHostTestCase):
    system_mode = constants.SYSTEM_MODE_DUPLEX_DIRECT


class RejectMaintananceActionByAppTestCase(TestHost):
    def an_app_rejected_the_maintanance_action(self, *args):
        from sysinv.openstack.common.rpc import common as rpc_common
        raise rpc_common.RemoteError("")

    def test_lock_rejected_action_controller(self):
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Simulate an app that rejects any action it is asked for
        self.fake_conductor_api.mtc_action_apps_semantic_checks.side_effect = \
            self.an_app_rejected_the_maintanance_action

        # Lock host
        response = self._patch_host_action(c1_host['hostname'],
                                           constants.LOCK_ACTION,
                                           'sysinv-test',
                                           expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertTrue(response.json['error_message'])
        self.assertIn("{} action semantic check failed by app"
                      "".format(constants.LOCK_ACTION.capitalize()),
                      response.json['error_message'])

    def test_force_lock_not_rejected_action_controller(self):
        # Create controller-0
        self._create_controller_0(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        c1_host = self._create_controller_1(
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE)

        # Simulate an app that rejects any action it is asked for
        self.fake_conductor_api.mtc_action_apps_semantic_checks.side_effect = \
            self.an_app_rejected_the_maintanance_action

        # Force lock host
        response = self._patch_host_action(c1_host['hostname'],
                                           constants.FORCE_LOCK_ACTION,
                                           'sysinv-test',
                                           expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)


class TestHostModifyCPUMaxFrequency(TestHost):
    def test_host_max_cpu_frequency_not_configurable(self):
        worker = self._create_worker(
            max_cpu_frequency=None,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            capabilities={constants.IHOST_MAX_CPU_CONFIG:
                          constants.NOT_CONFIGURABLE})

        self.assertRaises(
            webtest.app.AppError,
            self._patch_host,
            worker.get('hostname'),
            [{'path': '/max_cpu_frequency',
            'value': '283487',
            'op': 'replace'}],
            'sysinv-test')

    def test_host_max_cpu_frequency_configurable_bad_values(self):
        worker = self._create_worker(
            max_cpu_frequency=None,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            capabilities={constants.IHOST_MAX_CPU_CONFIG:
                          constants.CONFIGURABLE})

        for bad_value in ['AAAAA', '1A1A1A1', '-1', '0']:
            self.assertRaises(
                webtest.app.AppError,
                self._patch_host,
                worker.get('hostname'),
                [{'path': '/max_cpu_frequency',
                'value': bad_value,
                'op': 'replace'}],
                'sysinv-test')

    def test_host_max_cpu_frequency_default(self):
        max_cpu_default = 1000000

        worker = self._create_worker(
            max_cpu_frequency=None,
            max_cpu_default=max_cpu_default,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            capabilities={constants.IHOST_MAX_CPU_CONFIG:
                          constants.CONFIGURABLE})

        response = self._patch_host(
            worker.get('hostname'),
            [{'path': '/max_cpu_frequency',
            'value': 'max_cpu_default',
            'op': 'replace'}],
            'sysinv-test')

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
