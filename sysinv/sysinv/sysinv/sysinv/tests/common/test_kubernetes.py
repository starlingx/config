#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the kubernetes utilities.
"""

import kubernetes
import mock

from sysinv.common import kubernetes as kube

from sysinv.tests import base

FAKE_KUBE_VERSIONS = [
    {'version': 'v1.41.3',
     'upgrade_from': [],
     'downgrade_to': [],
     'applied_patches': [],
     'available_patches': [],
     },
    {'version': 'v1.42.0',
     'upgrade_from': ['v1.41.3'],
     'downgrade_to': [],
     'applied_patches': [],
     'available_patches': [],
     },
    {'version': 'v1.42.1',
     'upgrade_from': ['v1.42.0'],
     'downgrade_to': ['v1.42.0'],
     'applied_patches': [],
     'available_patches': [],
     },
    {'version': 'v1.42.3',
     'upgrade_from': ['v1.42.1'],
     'downgrade_to': [],
     'applied_patches': ['KUBE.1', 'KUBE.2'],
     'available_patches': ['KUBE.3'],
     },
    {'version': 'v1.42.4',
     'upgrade_from': ['v1.42.1'],
     'downgrade_to': [],
     'applied_patches': ['KUBE.1', 'KUBE.2'],
     'available_patches': ['KUBE.3'],
     },
    {'version': 'v1.43.1',
     'upgrade_from': ['v1.42.2'],
     'downgrade_to': [],
     'applied_patches': ['KUBE.11', 'KUBE.12'],
     'available_patches': ['KUBE.13'],
     },
]


def mock_get_kube_versions():
    return FAKE_KUBE_VERSIONS


def mock_load_kube_config(path):
    return


@mock.patch('kubernetes.config.load_kube_config', mock_load_kube_config)
@mock.patch('sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
class TestKubeOperator(base.TestCase):

    def setup_result(self):
        self.single_pod_result = {
            'test-pod-1': kubernetes.client.V1PodList(
                api_version="v1",
                items=[
                    kubernetes.client.V1Pod(
                        api_version="v1",
                        kind="Pod",
                        metadata=kubernetes.client.V1ObjectMeta(
                            name="test-pod-1",
                            namespace="test-namespace-1"),
                        status=kubernetes.client.V1PodStatus(
                            conditions=[
                                kubernetes.client.V1PodCondition(
                                    status="True",
                                    type="Initialized"),
                                kubernetes.client.V1PodCondition(
                                    status="False",
                                    type="Ready"),
                                kubernetes.client.V1PodCondition(
                                    status="True",
                                    type="ContainersReady"),
                                kubernetes.client.V1PodCondition(
                                    status="True",
                                    type="PodScheduled"),
                            ],
                        ),
                        spec=kubernetes.client.V1PodSpec(
                            containers=[
                                kubernetes.client.V1Container(
                                    name="test-container-1",
                                    image="test-image-1:imageversion-1"),
                            ],
                        ),
                    ),
                ]
            ),
        }

        self.no_pod_result = {
            'test-pod-1': kubernetes.client.V1PodList(
                api_version="v1",
                items=[]
            )
        }

        self.multiple_pod_result = {
            'test-pod-1': kubernetes.client.V1PodList(
                api_version="v1",
                items=[
                    kubernetes.client.V1Pod(
                        api_version="v1",
                        kind="Pod",
                        metadata=kubernetes.client.V1ObjectMeta(
                            name="test-pod-1",
                            namespace="test-namespace-1"),
                        status=kubernetes.client.V1PodStatus(
                            conditions=[
                                kubernetes.client.V1PodCondition(
                                    status="True",
                                    type="Initialized"),
                                kubernetes.client.V1PodCondition(
                                    status="False",
                                    type="Ready"),
                                kubernetes.client.V1PodCondition(
                                    status="True",
                                    type="ContainersReady"),
                                kubernetes.client.V1PodCondition(
                                    status="True",
                                    type="PodScheduled"),
                            ],
                        ),
                        spec=kubernetes.client.V1PodSpec(
                            containers=[
                                kubernetes.client.V1Container(
                                    name="test-container-1",
                                    image="test-image-1:imageversion-1"),
                            ],
                        ),
                    ),
                    kubernetes.client.V1Pod(
                        api_version="v1",
                        kind="Pod",
                        metadata=kubernetes.client.V1ObjectMeta(
                            name="test-pod-1",
                            namespace="test-namespace-1"),
                        status=kubernetes.client.V1PodStatus(
                            conditions=[
                                kubernetes.client.V1PodCondition(
                                    status="True",
                                    type="Initialized"),
                                kubernetes.client.V1PodCondition(
                                    status="False",
                                    type="Ready"),
                                kubernetes.client.V1PodCondition(
                                    status="True",
                                    type="ContainersReady"),
                                kubernetes.client.V1PodCondition(
                                    status="True",
                                    type="PodScheduled"),
                            ],
                        ),
                        spec=kubernetes.client.V1PodSpec(
                            containers=[
                                kubernetes.client.V1Container(
                                    name="test-container-2",
                                    image="test-image-2:imageversion-2"),
                            ],
                        ),
                    ),
                ],
            ),
        }

        self.cp_pods_result = {
            'kube-apiserver-test-node-1':
                kubernetes.client.V1PodList(
                    api_version="v1",
                    items=[
                        kubernetes.client.V1Pod(
                            api_version="v1",
                            kind="Pod",
                            metadata=kubernetes.client.V1ObjectMeta(
                                name="kube-apiserver-test-node-1",
                                namespace="kube-system"),
                            spec=kubernetes.client.V1PodSpec(
                                containers=[
                                    kubernetes.client.V1Container(
                                        name="kube-apiserver",
                                        image="test-image-1:v1.42.1"),
                                ],
                            ),
                        ),
                    ],
                ),
            'kube-controller-manager-test-node-1':
                kubernetes.client.V1PodList(
                    api_version="v1",
                    items=[
                        kubernetes.client.V1Pod(
                            api_version="v1",
                            kind="Pod",
                            metadata=kubernetes.client.V1ObjectMeta(
                                name="kube-controller-manager-test-node-1",
                                namespace="kube-system"),
                            spec=kubernetes.client.V1PodSpec(
                                containers=[
                                    kubernetes.client.V1Container(
                                        name="kube-controller-manager",
                                        image="test-image-2:v1.42.1"),
                                ],
                            ),
                        ),
                    ],
                ),
            'kube-scheduler-test-node-1':
                kubernetes.client.V1PodList(
                    api_version="v1",
                    items=[
                        kubernetes.client.V1Pod(
                            api_version="v1",
                            kind="Pod",
                            metadata=kubernetes.client.V1ObjectMeta(
                                name="kube-scheduler-test-node-1",
                                namespace="kube-system"),
                            spec=kubernetes.client.V1PodSpec(
                                containers=[
                                    kubernetes.client.V1Container(
                                        name="kube-scheduler",
                                        image="test-image-3:v1.42.1"),
                                ],
                            ),
                        ),
                    ],
                ),
            'kube-apiserver-test-node-2':
                kubernetes.client.V1PodList(
                    api_version="v1",
                    items=[
                        kubernetes.client.V1Pod(
                            api_version="v1",
                            kind="Pod",
                            metadata=kubernetes.client.V1ObjectMeta(
                                name="kube-apiserver-test-node-2",
                                namespace="kube-system"),
                            spec=kubernetes.client.V1PodSpec(
                                containers=[
                                    kubernetes.client.V1Container(
                                        name="kube-apiserver",
                                        image="test-image-1:v1.42.1"),
                                ],
                            ),
                        ),
                    ],
                ),
            'kube-controller-manager-test-node-2':
                kubernetes.client.V1PodList(
                    api_version="v1",
                    items=[
                        kubernetes.client.V1Pod(
                            api_version="v1",
                            kind="Pod",
                            metadata=kubernetes.client.V1ObjectMeta(
                                name="kube-controller-manager-test-node-2",
                                namespace="kube-system"),
                            spec=kubernetes.client.V1PodSpec(
                                containers=[
                                    kubernetes.client.V1Container(
                                        name="kube-controller-manager",
                                        image="test-image-2:v1.42.1"),
                                ],
                            ),
                        ),
                    ],
                ),
            'kube-scheduler-test-node-2':
                kubernetes.client.V1PodList(
                    api_version="v1",
                    items=[
                        kubernetes.client.V1Pod(
                            api_version="v1",
                            kind="Pod",
                            metadata=kubernetes.client.V1ObjectMeta(
                                name="kube-scheduler-test-node-2",
                                namespace="kube-system"),
                            spec=kubernetes.client.V1PodSpec(
                                containers=[
                                    kubernetes.client.V1Container(
                                        name="kube-scheduler",
                                        image="test-image-3:v1.42.1"),
                                ],
                            ),
                        ),
                    ],
                ),
        }

        self.single_node_result = kubernetes.client.V1NodeList(
            api_version="v1",
            items=[
                kubernetes.client.V1Pod(
                    api_version="v1",
                    kind="Node",
                    metadata=kubernetes.client.V1ObjectMeta(
                        name="test-node-1",
                        namespace="test-namespace-1"),
                    status=kubernetes.client.V1NodeStatus(
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
            ]
        )

        self.multi_node_result = kubernetes.client.V1NodeList(
            api_version="v1",
            items=[
                kubernetes.client.V1Pod(
                    api_version="v1",
                    kind="Node",
                    metadata=kubernetes.client.V1ObjectMeta(
                        name="test-node-1",
                        namespace="test-namespace-1"),
                    status=kubernetes.client.V1NodeStatus(
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
                kubernetes.client.V1Pod(
                    api_version="v1",
                    kind="Node",
                    metadata=kubernetes.client.V1ObjectMeta(
                        name="test-node-2",
                        namespace="test-namespace-1"),
                    status=kubernetes.client.V1NodeStatus(
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
        )

    def setUp(self):
        super(TestKubeOperator, self).setUp()

        self.setup_result()

        self.list_namespaced_pod_result = None

        def mock_list_namespaced_pod(obj, namespace, field_selector=""):
            pod_name = field_selector.split('metadata.name=', 1)[1]
            return self.list_namespaced_pod_result[pod_name]
        self.mocked_list_namespaced_pod = mock.patch(
            'kubernetes.client.CoreV1Api.list_namespaced_pod',
            mock_list_namespaced_pod)
        self.mocked_list_namespaced_pod.start()

        self.list_node_result = None

        def mock_list_node(obj, label_selector=""):
            return self.list_node_result
        self.mocked_list_node = mock.patch(
            'kubernetes.client.CoreV1Api.list_node',
            mock_list_node)
        self.mocked_list_node.start()

        self.kube_operator = kube.KubeOperator()

    def tearDown(self):
        super(TestKubeOperator, self).tearDown()

        self.mocked_list_namespaced_pod.stop()
        self.mocked_list_node.stop()

    def test_kube_get_image_by_pod_name(self):

        self.list_namespaced_pod_result = self.single_pod_result

        result = self.kube_operator.kube_get_image_by_pod_name(
            'test-pod-1', 'test-namespace-1', 'test-container-1')
        assert result == "test-image-1:imageversion-1"

    def test_kube_get_image_by_pod_name_no_pod(self):

        self.list_namespaced_pod_result = self.no_pod_result

        result = self.kube_operator.kube_get_image_by_pod_name(
            'test-pod-1', 'test-namespace-1', 'test-container-1')
        assert result is None

    def test_kube_get_image_by_pod_name_multiple_pods(self):

        self.list_namespaced_pod_result = self.multiple_pod_result

        result = self.kube_operator.kube_get_image_by_pod_name(
            'test-pod-1', 'test-namespace-1', 'test-container-1')
        assert result == "test-image-1:imageversion-1"

    def test_kube_get_control_plane_versions(self):

        self.list_namespaced_pod_result = self.cp_pods_result
        self.list_node_result = self.single_node_result

        result = self.kube_operator.kube_get_control_plane_versions()
        assert result == {'test-node-1': 'v1.42.1'}

    def test_kube_get_control_plane_versions_mixed_versions(self):

        self.list_namespaced_pod_result = self.cp_pods_result
        self.list_node_result = self.single_node_result

        self.cp_pods_result['kube-controller-manager-test-node-1'].items[0].\
            spec.containers[0].image = "test-image-2:v1.42.0"

        result = self.kube_operator.kube_get_control_plane_versions()
        assert result == {'test-node-1': 'v1.42.0'}

    def test_kube_get_control_plane_versions_multi_node(self):

        self.list_namespaced_pod_result = self.cp_pods_result
        self.list_node_result = self.multi_node_result

        result = self.kube_operator.kube_get_control_plane_versions()
        assert result == {'test-node-1': 'v1.42.1',
                          'test-node-2': 'v1.42.1'}

    def test_kube_get_control_plane_versions_multi_node_mixed_versions(self):

        self.list_namespaced_pod_result = self.cp_pods_result
        self.list_node_result = self.multi_node_result

        self.cp_pods_result['kube-controller-manager-test-node-1'].items[0].\
            spec.containers[0].image = "test-image-2:v1.42.0"
        self.cp_pods_result['kube-scheduler-test-node-2'].items[0].\
            spec.containers[0].image = "test-image-3:v1.42.3"

        result = self.kube_operator.kube_get_control_plane_versions()
        assert result == {'test-node-1': 'v1.42.0',
                          'test-node-2': 'v1.42.1'}

    def test_kube_get_kubelet_versions(self):

        self.list_node_result = self.single_node_result

        result = self.kube_operator.kube_get_kubelet_versions()
        assert result == {'test-node-1': 'v1.42.4'}

    def test_kube_get_kubelet_versions_multi_node(self):

        self.list_node_result = self.multi_node_result

        result = self.kube_operator.kube_get_kubelet_versions()
        assert result == {'test-node-1': 'v1.42.4',
                          'test-node-2': 'v1.42.3'}

    def test_kube_get_version_states(self):

        self.list_namespaced_pod_result = self.cp_pods_result
        self.list_node_result = self.single_node_result

        result = self.kube_operator.kube_get_version_states()

        assert result == {'v1.41.3': 'available',
                          'v1.42.0': 'available',
                          'v1.42.1': 'partial',
                          'v1.42.3': 'available',
                          'v1.42.4': 'partial',
                          'v1.43.1': 'available'}

    def test_kube_get_version_states_active(self):

        self.list_namespaced_pod_result = self.cp_pods_result
        self.list_node_result = self.single_node_result
        self.single_node_result.items[0].status.node_info.kubelet_version = \
            "v1.42.1"

        result = self.kube_operator.kube_get_version_states()
        assert result == {'v1.41.3': 'available',
                          'v1.42.0': 'available',
                          'v1.42.1': 'active',
                          'v1.42.3': 'available',
                          'v1.42.4': 'available',
                          'v1.43.1': 'available'}

    def test_kube_get_version_states_multi_node(self):

        self.list_namespaced_pod_result = self.cp_pods_result
        self.list_node_result = self.multi_node_result

        result = self.kube_operator.kube_get_version_states()
        assert result == {'v1.41.3': 'available',
                          'v1.42.0': 'available',
                          'v1.42.1': 'partial',
                          'v1.42.3': 'partial',
                          'v1.42.4': 'partial',
                          'v1.43.1': 'available'}

    def test_kube_get_version_states_ignore_unknown_version(self):

        self.list_namespaced_pod_result = self.cp_pods_result
        self.cp_pods_result['kube-controller-manager-test-node-1'].items[0].\
            spec.containers[0].image = "test-image-2:v1.48.0"
        self.list_node_result = self.single_node_result
        self.single_node_result.items[0].status.node_info.kubelet_version = \
            "v1.49.1"

        result = self.kube_operator.kube_get_version_states()
        assert result == {'v1.41.3': 'available',
                          'v1.42.0': 'available',
                          'v1.42.1': 'active',
                          'v1.42.3': 'available',
                          'v1.42.4': 'available',
                          'v1.43.1': 'available'}
