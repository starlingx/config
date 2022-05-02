#
# Copyright (c) 2019 Wind River Systems, Inc.
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

from sysinv.common import constants
from sysinv.common import health
from sysinv.openstack.common import context

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

        # Mock the patching API
        self.mock_patch_query_hosts_result = None

        def mock_patch_query_hosts(token, timeout, region_name):
            return self.mock_patch_query_hosts_result
        self.mocked_patch_query_hosts = mock.patch(
            'sysinv.api.controllers.v1.patch_api.patch_query_hosts',
            mock_patch_query_hosts)
        self.mocked_patch_query_hosts.start()
        self.addCleanup(self.mocked_patch_query_hosts.stop)

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
        health_ok, output = self.health.get_system_health(self.context)
        assert health_ok is True, "output: %s" % output

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
