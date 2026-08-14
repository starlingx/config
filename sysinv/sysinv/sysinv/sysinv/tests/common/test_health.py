#
# Copyright (c) 2023, 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the health utilities.
"""

import json
import kubernetes
import mock
import uuid

from oslo_context import context

from sysinv.common import constants
from sysinv.common import health
from sysinv.common import exception

from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class TestHealth(dbbase.BaseHostTestCase):

    def setup_result(self):

        self.patch_current_result = {
            'data': [
                {'hostname': 'controller-0',
                 'patch_current': True,
                 },
                {'hostname': 'controller-1',
                 'patch_current': True,
                 }
            ]
        }

        self.multi_node_result = [
            kubernetes.client.V1Node(
                api_version="v1",
                kind="Node",
                metadata=kubernetes.client.V1ObjectMeta(
                    name="controller-0",
                    namespace="test-namespace-1"),
                status=kubernetes.client.V1NodeStatus(
                    conditions=[
                        kubernetes.client.V1NodeCondition(
                            status="False",
                            type="NetworkUnavailable"),
                        kubernetes.client.V1NodeCondition(
                            status="False",
                            type="MemoryPressure"),
                        kubernetes.client.V1NodeCondition(
                            status="False",
                            type="DiskPressure"),
                        kubernetes.client.V1NodeCondition(
                            status="False",
                            type="PIDPressure"),
                        kubernetes.client.V1NodeCondition(
                            status="True",
                            type="Ready"),
                    ],
                    node_info=kubernetes.client.V1NodeSystemInfo(
                        architecture="fake-architecture",
                        boot_id="fake-boot-id",
                        container_runtime_version="fake-cr-version",
                        kernel_version="fake-kernel-version",
                        kube_proxy_version="fake-proxy-version",
                        kubelet_version="v1.42.4",
                        machine_id="fake-machine-id",
                        operating_system="fake-os",
                        os_image="fake-os-image",
                        system_uuid="fake-system-uuid"))
            ),
            kubernetes.client.V1Node(
                api_version="v1",
                kind="Node",
                metadata=kubernetes.client.V1ObjectMeta(
                    name="controller-1",
                    namespace="test-namespace-1"),
                status=kubernetes.client.V1NodeStatus(
                    conditions=[
                        kubernetes.client.V1NodeCondition(
                            status="False",
                            type="NetworkUnavailable"),
                        kubernetes.client.V1NodeCondition(
                            status="False",
                            type="MemoryPressure"),
                        kubernetes.client.V1NodeCondition(
                            status="False",
                            type="DiskPressure"),
                        kubernetes.client.V1NodeCondition(
                            status="False",
                            type="PIDPressure"),
                        kubernetes.client.V1NodeCondition(
                            status="True",
                            type="Ready"),
                    ],
                    node_info=kubernetes.client.V1NodeSystemInfo(
                        architecture="fake-architecture",
                        boot_id="fake-boot-id",
                        container_runtime_version="fake-cr-version",
                        kernel_version="fake-kernel-version",
                        kube_proxy_version="fake-proxy-version",
                        kubelet_version="v1.42.3",
                        machine_id="fake-machine-id",
                        operating_system="fake-os",
                        os_image="fake-os-image",
                        system_uuid="fake-system-uuid"))
            ),
        ]

        self.cp_pod_ready_status_result = {
            'kube-apiserver-controller-0': 'True',
            'kube-controller-manager-controller-0': 'True',
            'kube-scheduler-controller-0': 'True',
            'kube-apiserver-controller-1': 'True',
            'kube-controller-manager-controller-1': 'True',
            'kube-scheduler-controller-1': 'True',
        }

    def setUp(self):
        super(TestHealth, self).setUp()

        # get_system_health() now checks the etcd cluster, and this test class
        # runs as duplex, so without this the check would shell out to etcdctl
        # and close the gate on every case here. The dedicated coverage for the
        # gate itself is in TestEtcdClusterHealthCheck.
        p = mock.patch('sysinv.common.etcd.get_cluster_health',
                       return_value=(3, 3, []))
        # The kube-path opt-out is covered by the API tests in
        # tests.api.test_kube_upgrade and tests.api.test_kube_rootca_update:
        # those run as duplex and do not stub etcd, so if check_etcd stopped
        # being False on that path they would fail on an unreachable cluster,
        # which is how the scope error was caught in the first place.
        self.mock_etcd_cluster_health = p.start()
        self.addCleanup(p.stop)

        # Mock the KubeOperator
        self.kube_get_nodes_result = None

        def mock_kube_get_nodes(obj):
            return self.kube_get_nodes_result
        self.mocked_kube_get_nodes = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_nodes',
            mock_kube_get_nodes)
        self.mocked_kube_get_nodes.start()
        self.addCleanup(self.mocked_kube_get_nodes.stop)

        self.kube_get_control_plane_pod_ready_status_result = None

        def mock_kube_get_control_plane_pod_ready_status(obj):
            return self.kube_get_control_plane_pod_ready_status_result
        self.mocked_kube_get_control_plane_pod_ready_status = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.'
            'kube_get_control_plane_pod_ready_status',
            mock_kube_get_control_plane_pod_ready_status)
        self.mocked_kube_get_control_plane_pod_ready_status.start()
        self.addCleanup(
            self.mocked_kube_get_control_plane_pod_ready_status.stop)

        self.kube_get_kubernetes_version_result = 'v1.24.0'

        def mock_kube_get_kubernetes_version(obj):
            return self.kube_get_kubernetes_version_result
        self.mocked_kube_get_kubernetes_version = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.'
            'kube_get_kubernetes_version',
            mock_kube_get_kubernetes_version)
        self.mocked_kube_get_kubernetes_version.start()
        self.mocked_kube_get_kubernetes_version.return_value = []
        self.addCleanup(self.mocked_kube_get_kubernetes_version.stop)

        # Mock the fm API
        p = mock.patch('sysinv.common.health.fmclient')
        self.mock_fm_client_alarm_list = p.start()
        self.addCleanup(p.stop)

        # Set up objects for testing
        self.context = context.get_admin_context()
        self.health = health.Health(self.dbapi)

        # Set up results
        self.setup_result()

    def tearDown(self):
        super(TestHealth, self).tearDown()

        pass

    def test_get_system_health(self):
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_host(personality=constants.CONTROLLER,
                               unit=0,
                               config_status=None,
                               config_applied=config_uuid,
                               config_target=config_uuid,
                               invprovision=constants.PROVISIONED,
                               administrative=constants.ADMIN_UNLOCKED,
                               operational=constants.OPERATIONAL_ENABLED,
                               availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        self._create_test_host(personality=constants.CONTROLLER,
                               unit=1,
                               config_status=None,
                               config_applied=config_uuid,
                               config_target=config_uuid,
                               invprovision=constants.PROVISIONED,
                               administrative=constants.ADMIN_UNLOCKED,
                               operational=constants.OPERATIONAL_ENABLED,
                               availability=constants.AVAILABILITY_ONLINE)

        # Set up the mocked results
        self.mock_patch_query_hosts_result = self.patch_current_result
        self.kube_get_nodes_result = self.multi_node_result
        self.kube_get_control_plane_pod_ready_status_result = \
            self.cp_pod_ready_status_result

        # Check system health
        with mock.patch('sysinv.common.usm_service.get_platform_upgrade',
                        side_effect=exception.NotFound()):
            health_ok, output = self.health.get_system_health(self.context)
        assert health_ok is True, "output: %s" % output

    def test_get_system_health_fails_with_vim_service_disabled(self):
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_host(
            personality=constants.CONTROLLER,
            unit=0,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
            vim_progress_status=constants.VIM_SERVICES_DISABLED,
        )

        # Create controller-1
        self._create_test_host(
            personality=constants.CONTROLLER,
            unit=1,
            config_status=None,
            config_applied=config_uuid,
            config_target=config_uuid,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_ONLINE,
        )

        # Set up the mocked results
        self.mock_patch_query_hosts_result = self.patch_current_result
        self.kube_get_nodes_result = self.multi_node_result
        self.kube_get_control_plane_pod_ready_status_result = (
            self.cp_pod_ready_status_result
        )

        # Check system health
        with mock.patch(
            "sysinv.common.usm_service.get_platform_upgrade",
            side_effect=exception.NotFound(),
        ):
            health_ok, output = self.health.get_system_health(self.context)
        assert health_ok is False, "output: %s" % output
        assert "Vim disabled hosts: controller-0" in output, (
            "get_system_health output: %s" % output
        )

    def test_get_system_health_k8s_node_not_ready(self):
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_host(personality=constants.CONTROLLER,
                               unit=0,
                               config_status=None,
                               config_applied=config_uuid,
                               config_target=config_uuid,
                               invprovision=constants.PROVISIONED,
                               administrative=constants.ADMIN_UNLOCKED,
                               operational=constants.OPERATIONAL_ENABLED,
                               availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        self._create_test_host(personality=constants.CONTROLLER,
                               unit=1,
                               config_status=None,
                               config_applied=config_uuid,
                               config_target=config_uuid,
                               invprovision=constants.PROVISIONED,
                               administrative=constants.ADMIN_UNLOCKED,
                               operational=constants.OPERATIONAL_ENABLED,
                               availability=constants.AVAILABILITY_ONLINE)

        # Set up the mocked results
        self.mock_patch_query_hosts_result = self.patch_current_result
        self.kube_get_nodes_result = self.multi_node_result
        # Mark controller-0 as not ready
        self.kube_get_nodes_result[0].status.conditions[4].status = "False"
        self.kube_get_control_plane_pod_ready_status_result = \
            self.cp_pod_ready_status_result

        # Check system health

        with mock.patch('sysinv.common.usm_service.get_platform_upgrade',
                        side_effect=exception.NotFound()):
            health_ok, output = self.health.get_system_health(self.context)
        assert health_ok is False, "output: %s" % output
        assert "Kubernetes nodes not ready: controller-0" in output, \
            "get_system_health output: %s" % output

    def test_get_system_health_k8s_cp_pod_not_ready(self):
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_host(personality=constants.CONTROLLER,
                               unit=0,
                               config_status=None,
                               config_applied=config_uuid,
                               config_target=config_uuid,
                               invprovision=constants.PROVISIONED,
                               administrative=constants.ADMIN_UNLOCKED,
                               operational=constants.OPERATIONAL_ENABLED,
                               availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        self._create_test_host(personality=constants.CONTROLLER,
                               unit=1,
                               config_status=None,
                               config_applied=config_uuid,
                               config_target=config_uuid,
                               invprovision=constants.PROVISIONED,
                               administrative=constants.ADMIN_UNLOCKED,
                               operational=constants.OPERATIONAL_ENABLED,
                               availability=constants.AVAILABILITY_ONLINE)

        # Set up the mocked results
        self.mock_patch_query_hosts_result = self.patch_current_result
        self.kube_get_nodes_result = self.multi_node_result
        self.kube_get_control_plane_pod_ready_status_result = \
            self.cp_pod_ready_status_result
        # Mark a cp pod as not ready
        self.kube_get_control_plane_pod_ready_status_result[
            'kube-controller-manager-controller-1'] = 'False'

        # Check system health
        with mock.patch('sysinv.common.usm_service.get_platform_upgrade',
                        side_effect=exception.NotFound()):
            health_ok, output = self.health.get_system_health(self.context)
        assert health_ok is False, "get_system_health output: %s" % output
        assert "kubernetes control plane pods are ready: [Fail]" in output, \
            "output: %s" % output
        assert "not ready: kube-controller-manager-controller-1" in output, \
            "output: %s" % output

    def test_get_system_health_kube_upgrade(self):
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_host(personality=constants.CONTROLLER,
                               unit=0,
                               config_status=None,
                               config_applied=config_uuid,
                               config_target=config_uuid,
                               invprovision=constants.PROVISIONED,
                               administrative=constants.ADMIN_UNLOCKED,
                               operational=constants.OPERATIONAL_ENABLED,
                               availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        self._create_test_host(personality=constants.CONTROLLER,
                               unit=1,
                               config_status=None,
                               config_applied=config_uuid,
                               config_target=config_uuid,
                               invprovision=constants.PROVISIONED,
                               administrative=constants.ADMIN_UNLOCKED,
                               operational=constants.OPERATIONAL_ENABLED,
                               availability=constants.AVAILABILITY_ONLINE)

        # Create kubernetes apps
        dbutils.create_test_app(name='test-app-1',
                                status=constants.APP_APPLY_SUCCESS)
        dbutils.create_test_app(name='test-app-2',
                                status=constants.APP_APPLY_SUCCESS)
        dbutils.create_test_app(name='test-app-3',
                                status=constants.APP_UPLOAD_SUCCESS)

        # Set up the mocked results
        self.mock_patch_query_hosts_result = self.patch_current_result
        self.kube_get_nodes_result = self.multi_node_result
        self.kube_get_control_plane_pod_ready_status_result = \
            self.cp_pod_ready_status_result

        # Check system health
        with mock.patch('sysinv.common.usm_service.get_platform_upgrade',
                        side_effect=exception.NotFound()):
            health_ok, output = self.health.get_system_health_kube_upgrade(
                self.context)
        assert health_ok is True, "output: %s" % output

    def test_get_system_health_kube_upgrade_k8s_app_invalid_state(self):
        # Create controller-0
        config_uuid = str(uuid.uuid4())
        self._create_test_host(personality=constants.CONTROLLER,
                               unit=0,
                               config_status=None,
                               config_applied=config_uuid,
                               config_target=config_uuid,
                               invprovision=constants.PROVISIONED,
                               administrative=constants.ADMIN_UNLOCKED,
                               operational=constants.OPERATIONAL_ENABLED,
                               availability=constants.AVAILABILITY_ONLINE)

        # Create controller-1
        self._create_test_host(personality=constants.CONTROLLER,
                               unit=1,
                               config_status=None,
                               config_applied=config_uuid,
                               config_target=config_uuid,
                               invprovision=constants.PROVISIONED,
                               administrative=constants.ADMIN_UNLOCKED,
                               operational=constants.OPERATIONAL_ENABLED,
                               availability=constants.AVAILABILITY_ONLINE)

        # Create kubernetes apps
        dbutils.create_test_app(name='test-app-1',
                                status=constants.APP_APPLY_SUCCESS)
        dbutils.create_test_app(name='test-app-2',
                                status=constants.APP_APPLY_IN_PROGRESS)
        dbutils.create_test_app(name='test-app-3',
                                status=constants.APP_UPLOAD_SUCCESS)

        # Set up the mocked results
        self.mock_patch_query_hosts_result = self.patch_current_result
        self.kube_get_nodes_result = self.multi_node_result
        self.kube_get_control_plane_pod_ready_status_result = \
            self.cp_pod_ready_status_result

        # Check system health
        with mock.patch('sysinv.common.usm_service.get_platform_upgrade',
                        side_effect=exception.NotFound()):
            health_ok, output = self.health.get_system_health_kube_upgrade(
                self.context)
        assert health_ok is False, "output: %s" % output
        assert "applications are in a valid state: [Fail]" in output, \
            "output: %s" % output
        assert "applications not in a valid state: test-app-2" in output, \
            "output: %s" % output

    @mock.patch('sysinv.common.health.subprocess.check_output')
    def test_check_trident_compatibility_success(self, mocked_subprocess):
        ''' tests _check_trident_compatibility method '''
        mocked_subprocess.return_value = json.dumps(
            {'server': {'version': '22.01'}}).encode()

        result = self.health._check_trident_compatibility()
        assert result is True

    @mock.patch('sysinv.common.health.subprocess.check_output')
    def test_check_trident_compatibility_fail(self, mocked_subprocess):
        ''' tests _check_trident_compatibility method '''
        mocked_subprocess.return_value = json.dumps(
            {'server': {'version': '21.04'}}).encode()

        result = self.health._check_trident_compatibility()
        assert result is False


class TestEtcdClusterHealthCheck(dbbase.BaseHostTestCase):
    """Tests for the etcd cluster health gate on platform upgrade.

    The gate closes on anything short of every configured member voting
    and answering, because the rolling phase reboots controllers one at a
    time and a cluster that is already short of a member has no headroom
    for that.
    """

    def setUp(self):
        super(TestEtcdClusterHealthCheck, self).setUp()
        self.health = health.Health(self.dbapi)

    def _mock_system_mode(self, system_mode):
        system = mock.MagicMock()
        system.system_mode = system_mode
        p = mock.patch.object(self.health._dbapi, 'isystem_get_one',
                              return_value=system)
        p.start()
        self.addCleanup(p.stop)

    @mock.patch('sysinv.common.etcd.get_cluster_health')
    def test_all_members_healthy(self, mock_health):
        self._mock_system_mode(constants.SYSTEM_MODE_DUPLEX)
        mock_health.return_value = (3, 3, [])

        success, unhealthy = self.health._check_etcd_cluster_health()

        self.assertTrue(success)
        self.assertEqual([], unhealthy)

    @mock.patch('sysinv.common.etcd.get_cluster_health')
    def test_unreachable_member_fails_the_gate(self, mock_health):
        self._mock_system_mode(constants.SYSTEM_MODE_DUPLEX)
        mock_health.return_value = (2, 3, ['fixed-1'])

        success, unhealthy = self.health._check_etcd_cluster_health()

        self.assertFalse(success)
        self.assertEqual(['fixed-1'], unhealthy)

    @mock.patch('sysinv.common.etcd.get_cluster_health')
    def test_learner_fails_the_gate(self, mock_health):
        # A learner replicates but does not vote, so it adds no quorum
        # headroom and must not let the upgrade start.
        self._mock_system_mode(constants.SYSTEM_MODE_DUPLEX)
        mock_health.return_value = (2, 3, ['controller (learner)'])

        success, unhealthy = self.health._check_etcd_cluster_health()

        self.assertFalse(success)
        self.assertIn('controller (learner)', unhealthy)

    @mock.patch('sysinv.common.etcd.get_cluster_health')
    def test_unregistered_member_fails_the_gate(self, mock_health):
        self._mock_system_mode(constants.SYSTEM_MODE_DUPLEX)
        mock_health.return_value = (2, 3, ['1 member(s) not registered'])

        success, unhealthy = self.health._check_etcd_cluster_health()

        self.assertFalse(success)

    @mock.patch('sysinv.common.etcd.get_cluster_health')
    def test_query_failure_closes_the_gate(self, mock_health):
        # An unreachable cluster cannot be shown to be healthy, so the
        # absence of an answer must not read as a pass.
        self._mock_system_mode(constants.SYSTEM_MODE_DUPLEX)
        mock_health.side_effect = Exception('connection refused')

        success, unhealthy = self.health._check_etcd_cluster_health()

        self.assertFalse(success)
        self.assertEqual(1, len(unhealthy))

    @mock.patch('sysinv.common.etcd.get_cluster_health')
    def test_simplex_counts_a_single_member(self, mock_health):
        # The caller skips this check on simplex; the accounting still has
        # to be right for the single-member case.
        self._mock_system_mode(constants.SYSTEM_MODE_SIMPLEX)
        mock_health.return_value = (1, 1, [])

        success, unhealthy = self.health._check_etcd_cluster_health()

        self.assertTrue(success)

    @mock.patch('sysinv.common.etcd.get_cluster_health')
    def test_degraded_etcd_cluster_closes_the_generic_health_gate(
            self, mock_health):
        """A degraded cluster must fail the base health query, not only the
        upgrade one.

        This is what stops a duplex upgrade completing on a single-member
        cluster: the audit defers, 850.003 is raised, and before this the
        deploy carried on regardless because nothing consulted either.
        """
        self._mock_system_mode(constants.SYSTEM_MODE_DUPLEX)
        mock_health.return_value = (1, 3, ['<unnamed> (learner)',
                                           '1 member(s) not registered'])

        success, unhealthy = self.health._check_etcd_cluster_health()

        self.assertFalse(success)
        self.assertIn('<unnamed> (learner)', unhealthy)

    @mock.patch('sysinv.common.etcd.get_cluster_health')
    def test_simplex_skips_the_generic_gate(self, mock_health):
        # A single member has no quorum to protect.
        self._mock_system_mode(constants.SYSTEM_MODE_SIMPLEX)
        mock_health.return_value = (1, 1, [])

        success, unhealthy = self.health._check_etcd_cluster_health()

        self.assertTrue(success)
        self.assertEqual([], unhealthy)
