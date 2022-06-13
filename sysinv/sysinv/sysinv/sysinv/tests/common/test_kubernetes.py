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

FAKE_POD_STATUS = kubernetes.client.V1PodStatus(
    conditions=[
        kubernetes.client.V1PodCondition(
            status="True",
            type="Initialized"),
        kubernetes.client.V1PodCondition(
            status="True",
            type="Ready"),
        kubernetes.client.V1PodCondition(
            status="True",
            type="ContainersReady"),
        kubernetes.client.V1PodCondition(
            status="True",
            type="PodScheduled"),
    ],
)

FAKE_SERVICE_ACCOUNT_TOKEN = 'c3VwZXJzZWNyZXR0b2tlbgo='


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
                            status=FAKE_POD_STATUS,
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
                            status=FAKE_POD_STATUS,
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
                            status=FAKE_POD_STATUS,
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
                            status=FAKE_POD_STATUS,
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
                            status=FAKE_POD_STATUS,
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
                            status=FAKE_POD_STATUS,
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

        self.cp_pods_missing_result = {
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
                    items=[],
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
                    items=[],
                ),
        }

        self.cp_pods_list_result = kubernetes.client.V1PodList(
            api_version="v1",
            items=[
                kubernetes.client.V1Pod(
                    api_version="v1",
                    kind="Pod",
                    metadata=kubernetes.client.V1ObjectMeta(
                        name="kube-apiserver-test-node-1",
                        namespace="kube-system"),
                    status=FAKE_POD_STATUS,
                    spec=kubernetes.client.V1PodSpec(
                        containers=[
                            kubernetes.client.V1Container(
                                name="kube-apiserver",
                                image="test-image-1:v1.42.1"),
                        ],
                    ),
                ),
                kubernetes.client.V1Pod(
                    api_version="v1",
                    kind="Pod",
                    metadata=kubernetes.client.V1ObjectMeta(
                        name="kube-controller-manager-test-node-1",
                        namespace="kube-system"),
                    status=FAKE_POD_STATUS,
                    spec=kubernetes.client.V1PodSpec(
                        containers=[
                            kubernetes.client.V1Container(
                                name="kube-controller-manager",
                                image="test-image-2:v1.42.1"),
                        ],
                    ),
                ),
                kubernetes.client.V1Pod(
                    api_version="v1",
                    kind="Pod",
                    metadata=kubernetes.client.V1ObjectMeta(
                        name="kube-scheduler-test-node-1",
                        namespace="kube-system"),
                    status=FAKE_POD_STATUS,
                    spec=kubernetes.client.V1PodSpec(
                        containers=[
                            kubernetes.client.V1Container(
                                name="kube-scheduler",
                                image="test-image-3:v1.42.1"),
                        ],
                    ),
                ),
                kubernetes.client.V1Pod(
                    api_version="v1",
                    kind="Pod",
                    metadata=kubernetes.client.V1ObjectMeta(
                        name="kube-apiserver-test-node-2",
                        namespace="kube-system"),
                    status=FAKE_POD_STATUS,
                    spec=kubernetes.client.V1PodSpec(
                        containers=[
                            kubernetes.client.V1Container(
                                name="kube-apiserver",
                                image="test-image-1:v1.42.1"),
                        ],
                    ),
                ),
                kubernetes.client.V1Pod(
                    api_version="v1",
                    kind="Pod",
                    metadata=kubernetes.client.V1ObjectMeta(
                        name="kube-controller-manager-test-node-2",
                        namespace="kube-system"),
                    status=FAKE_POD_STATUS,
                    spec=kubernetes.client.V1PodSpec(
                        containers=[
                            kubernetes.client.V1Container(
                                name="kube-controller-manager",
                                image="test-image-2:v1.42.1"),
                        ],
                    ),
                ),
                kubernetes.client.V1Pod(
                    api_version="v1",
                    kind="Pod",
                    metadata=kubernetes.client.V1ObjectMeta(
                        name="kube-scheduler-test-node-2",
                        namespace="kube-system"),
                    status=FAKE_POD_STATUS,
                    spec=kubernetes.client.V1PodSpec(
                        containers=[
                            kubernetes.client.V1Container(
                                name="kube-scheduler",
                                image="test-image-3:v1.42.1"),
                        ],
                    ),
                ),
            ],
        )

        self.single_node_result = kubernetes.client.V1NodeList(
            api_version="v1",
            items=[
                kubernetes.client.V1Node(
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
                kubernetes.client.V1Node(
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
                kubernetes.client.V1Node(
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

        self.config_map_result = kubernetes.client.V1ConfigMap(
            api_version="v1",
            data={"ClusterConfiguration":
                  "apiServer:\n"
                  "  certSANs:\n"
                  "  - 127.0.0.1\n"
                  "  - 192.168.206.2\n"
                  "apiVersion: kubeadm.k8s.io/v1beta2\n"
                  "kubernetesVersion: v1.42.4\n"
                  "kind: ClusterStatus\n"
                  },
            metadata=kubernetes.client.V1ObjectMeta(
                name="kubeadm-config",
                namespace="kube-system"),
        )

        self.config_map_result_no_version = kubernetes.client.V1ConfigMap(
            api_version="v1",
            data={"ClusterConfiguration":
                  "apiServer:\n"
                  "  certSANs:\n"
                  "  - 127.0.0.1\n"
                  "  - 192.168.206.2\n"
                  "apiVersion: kubeadm.k8s.io/v1beta2\n"
                  "kind: ClusterStatus\n"
                  },
            metadata=kubernetes.client.V1ObjectMeta(
                name="kubeadm-config",
                namespace="kube-system"),
        )

        self.service_account_result = kubernetes.client.V1ServiceAccount(
            api_version="v1",
            kind="ServiceAccount",
            metadata=kubernetes.client.V1ObjectMeta(
                name="test-service-account-1",
                namespace="kube-system"),
            secrets=[kubernetes.client.V1ObjectReference(
                kind="Secret",
                namespace="kube-system",
                name="test-service-account-secret-1"
            )]
        )

        self.service_account_token_result = kubernetes.client.V1Secret(
            api_version="v1",
            kind="Secret",
            metadata=kubernetes.client.V1ObjectMeta(
                name="test-service-account-secret-1",
                namespace="kube-system"),
            data={
                'token': FAKE_SERVICE_ACCOUNT_TOKEN
            }
        )

        self.single_helmrepository_result = {
            'kind': 'HelmRepositoryList',
            'apiVersion': 'source.toolkit.fluxcd.io/v1beta1',
            'items': [
                {

                    'apiVersion': 'source.toolkit.fluxcd.io/v1beta1',
                    'kind': 'HelmRepository',
                    'spec': {
                        'url': 'http://192.168.206.1:8877/helm_charts/'
                               'stx-platform',
                        'interval': '1h0m0s',
                        'timeout': '1m0s',
                    },
                    'status': {},  # Lots of stuff, omitting
                    'metadata': {
                        'name': 'stx-platform',
                        'generation': 3,
                        'namespace': 'cert-manager',
                        'managedFields': [],  # Ommiting some stuff here too
                        'finalizers': [
                            'finalizers.fluxcd.io'
                        ],
                        'resourceVersion': '2176218',
                        'creationTimestamp': '2022-05-31T16:59:27Z',
                        'annotations': {},  # Ommiting some stuff here too
                        'selfLink': '/apis/source.toolkit.fluxcd.io/v1beta1/'
                                    'namespaces/cert-manager/helmrepositories/'
                                    'stx-platform',
                        'uid': '95989df9-b7bd-413a-bd1b-5f746c54e7c6',
                    }
                },
            ]
        }

        self.multiple_helmrepository_result = {
            'kind': 'HelmRepositoryList',
            'apiVersion': 'source.toolkit.fluxcd.io/v1beta1',
            'items': [
                {

                    'apiVersion': 'source.toolkit.fluxcd.io/v1beta1',
                    'kind': 'HelmRepository',
                    'spec': {
                        'url': 'http://192.168.206.1:8877/helm_charts/'
                               'stx-platform',
                        'interval': '1h0m0s',
                        'timeout': '1m0s',
                    },
                    'status': {},  # Lots of stuff, omitting
                    'metadata': {
                        'name': 'stx-platform',
                        'generation': 3,
                        'namespace': 'cert-manager',
                        'managedFields': [],  # Ommiting some stuff here too
                        'finalizers': [
                            'finalizers.fluxcd.io'
                        ],
                        'resourceVersion': '2176218',
                        'creationTimestamp': '2022-05-31T16:59:27Z',
                        'annotations': {},  # Ommiting some stuff here too
                        'selfLink': '/apis/source.toolkit.fluxcd.io/v1beta1/'
                                    'namespaces/cert-manager/helmrepositories/'
                                    'stx-platform',
                        'uid': '95989df9-b7bd-413a-bd1b-5f746c54e7c6',
                    }
                },
                {

                    'apiVersion': 'source.toolkit.fluxcd.io/v1beta1',
                    'kind': 'HelmRepository',
                    'spec': {
                        'url': 'http://192.168.206.1:8877/helm_charts/'
                               'stx-platform',
                        'interval': '1h0m0s',
                        'timeout': '1m0s',
                    },
                    'status': {},  # Lots of stuff, omitting
                    'metadata': {
                        'name': 'stx-platform',
                        'generation': 1,
                        'namespace': 'kube-system',
                        'managedFields': [],  # Ommiting some stuff here too
                        'finalizers': [
                            'finalizers.fluxcd.io'
                        ],
                        'resourceVersion': '2176116',
                        'creationTimestamp': '2022-05-31T16:49:21Z',
                        'annotations': {},  # Ommiting some stuff here too
                        'selfLink': '/apis/source.toolkit.fluxcd.io/v1beta1/'
                                    'namespaces/kube-system/helmrepositories/'
                                    'stx-platform',
                        'uid': '2d5a9df9-b7bd-413a-bd1b-5f746cab4f',
                    }
                },
            ]
        }

        self.no_helmrepository_result = {
            'kind': 'HelmRepositoryList',
            'apiVersion': 'source.toolkit.fluxcd.io/v1beta1',
            'items': []
        }

    def setUp(self):
        super(TestKubeOperator, self).setUp()

        self.setup_result()

        self.list_namespaced_pod_result = None

        def mock_is_k8s_configured():
            return True
        self.mocked_is_k8s_configured = mock.patch(
            'sysinv.common.kubernetes.is_k8s_configured',
            mock_is_k8s_configured)
        self.mocked_is_k8s_configured.start()

        def mock_list_namespaced_pod(obj, namespace, field_selector=""):
            pod_name = field_selector.split('metadata.name=', 1)[1]
            return self.list_namespaced_pod_result[pod_name]
        self.mocked_list_namespaced_pod = mock.patch(
            'kubernetes.client.CoreV1Api.list_namespaced_pod',
            mock_list_namespaced_pod)
        self.mocked_list_namespaced_pod.start()

        self.list_pod_for_all_namespaces_result = None

        def mock_list_pod_for_all_namespaces(obj, label_selector=""):
            return self.list_pod_for_all_namespaces_result
        self.mocked_list_pod_for_all_namespaces = mock.patch(
            'kubernetes.client.CoreV1Api.list_pod_for_all_namespaces',
            mock_list_pod_for_all_namespaces)
        self.mocked_list_pod_for_all_namespaces.start()

        self.list_node_result = None

        def mock_list_node(obj, label_selector=""):
            return self.list_node_result
        self.mocked_list_node = mock.patch(
            'kubernetes.client.CoreV1Api.list_node',
            mock_list_node)
        self.mocked_list_node.start()

        self.list_custom_resource_helmrepository = None

        self.read_namespaced_config_map_result = None

        def mock_read_namespaced_config_map(obj, configmap, namespace):
            return self.read_namespaced_config_map_result
        self.mocked_read_namespaced_config_map = mock.patch(
            'kubernetes.client.CoreV1Api.read_namespaced_config_map',
            mock_read_namespaced_config_map)
        self.mocked_read_namespaced_config_map.start()

        def mock_read_namespaced_service_account(obj, name, namespace):
            return self.read_namespaced_service_account_result
        self.mocked_read_namespaced_service_account = mock.patch(
            'kubernetes.client.CoreV1Api.read_namespaced_service_account',
            mock_read_namespaced_service_account)
        self.mocked_read_namespaced_service_account.start()

        def mock_read_namespaced_secret(obj, name, namespace):
            return self.read_namespaced_secret_result
        self.mocked_read_namespaced_secret = mock.patch(
            'kubernetes.client.CoreV1Api.read_namespaced_secret',
            mock_read_namespaced_secret)
        self.mocked_read_namespaced_secret.start()

        self.kube_operator = kube.KubeOperator()

    def tearDown(self):
        super(TestKubeOperator, self).tearDown()

        self.mocked_list_namespaced_pod.stop()
        self.mocked_list_pod_for_all_namespaces.stop()
        self.mocked_list_node.stop()
        self.mocked_read_namespaced_config_map.stop()
        self.mocked_read_namespaced_service_account.stop()
        self.mocked_read_namespaced_secret.stop()

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

    def test_kube_get_control_plane_pod_ready_status(self):

        self.list_pod_for_all_namespaces_result = self.cp_pods_list_result
        self.list_node_result = self.multi_node_result

        result = self.kube_operator.kube_get_control_plane_pod_ready_status()
        assert result == {'kube-apiserver-test-node-1': 'True',
                          'kube-controller-manager-test-node-1': 'True',
                          'kube-scheduler-test-node-1': 'True',
                          'kube-apiserver-test-node-2': 'True',
                          'kube-controller-manager-test-node-2': 'True',
                          'kube-scheduler-test-node-2': 'True'}

    def test_kube_get_control_plane_pod_ready_status_single_node(self):

        self.list_pod_for_all_namespaces_result = self.cp_pods_list_result
        del self.cp_pods_list_result.items[5]
        del self.cp_pods_list_result.items[4]
        del self.cp_pods_list_result.items[3]
        self.list_node_result = self.single_node_result

        result = self.kube_operator.kube_get_control_plane_pod_ready_status()
        assert result == {'kube-apiserver-test-node-1': 'True',
                          'kube-controller-manager-test-node-1': 'True',
                          'kube-scheduler-test-node-1': 'True'}

    def test_kube_get_control_plane_pod_ready_status_missing_pods(self):

        self.list_pod_for_all_namespaces_result = self.cp_pods_list_result
        del self.cp_pods_list_result.items[5]
        del self.cp_pods_list_result.items[1]
        self.list_node_result = self.multi_node_result

        result = self.kube_operator.kube_get_control_plane_pod_ready_status()
        assert result == {'kube-apiserver-test-node-1': 'True',
                          'kube-controller-manager-test-node-1': None,
                          'kube-scheduler-test-node-1': 'True',
                          'kube-apiserver-test-node-2': 'True',
                          'kube-controller-manager-test-node-2': 'True',
                          'kube-scheduler-test-node-2': None}

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

    def test_kube_get_control_plane_versions_missing_component(self):

        self.list_namespaced_pod_result = self.cp_pods_missing_result
        self.list_node_result = self.multi_node_result

        self.cp_pods_missing_result['kube-apiserver-test-node-1'].\
            items[0].spec.containers[0].image = "test-image-1:v1.42.0"
        self.cp_pods_missing_result['kube-controller-manager-test-node-2'].\
            items[0].spec.containers[0].image = "test-image-3:v1.42.3"

        result = self.kube_operator.kube_get_control_plane_versions()
        assert result == {'test-node-1': 'v1.42.0',
                          'test-node-2': 'v1.42.1'}

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

        assert result == {'v1.41.3': 'unavailable',
                          'v1.42.0': 'unavailable',
                          'v1.42.1': 'partial',
                          'v1.42.3': 'unavailable',
                          'v1.42.4': 'partial',
                          'v1.43.1': 'unavailable'}

    def test_kube_get_version_states_active(self):

        self.list_namespaced_pod_result = self.cp_pods_result
        self.list_node_result = self.single_node_result
        self.single_node_result.items[0].status.node_info.kubelet_version = \
            "v1.42.1"

        result = self.kube_operator.kube_get_version_states()
        assert result == {'v1.41.3': 'unavailable',
                          'v1.42.0': 'unavailable',
                          'v1.42.1': 'active',
                          'v1.42.3': 'available',
                          'v1.42.4': 'available',
                          'v1.43.1': 'unavailable'}

    def test_kube_get_version_states_multi_node(self):

        self.list_namespaced_pod_result = self.cp_pods_result
        self.list_node_result = self.multi_node_result

        result = self.kube_operator.kube_get_version_states()
        assert result == {'v1.41.3': 'unavailable',
                          'v1.42.0': 'unavailable',
                          'v1.42.1': 'partial',
                          'v1.42.3': 'partial',
                          'v1.42.4': 'partial',
                          'v1.43.1': 'unavailable'}

    def test_kube_get_version_states_ignore_unknown_version(self):

        self.list_namespaced_pod_result = self.cp_pods_result
        self.cp_pods_result['kube-controller-manager-test-node-1'].items[0].\
            spec.containers[0].image = "test-image-2:v1.48.0"
        self.list_node_result = self.single_node_result
        self.single_node_result.items[0].status.node_info.kubelet_version = \
            "v1.49.1"

        result = self.kube_operator.kube_get_version_states()
        assert result == {'v1.41.3': 'unavailable',
                          'v1.42.0': 'unavailable',
                          'v1.42.1': 'active',
                          'v1.42.3': 'available',
                          'v1.42.4': 'available',
                          'v1.43.1': 'unavailable'}

    def test_kube_get_kubernetes_version(self):

        self.read_namespaced_config_map_result = self.config_map_result

        result = self.kube_operator.kube_get_kubernetes_version()
        assert result == 'v1.42.4'

    def test_kube_get_kubernetes_version_missing_version(self):

        self.read_namespaced_config_map_result = \
            self.config_map_result_no_version

        result = self.kube_operator.kube_get_kubernetes_version()
        assert result is None

    def test_kube_get_service_account_token(self):

        self.read_namespaced_service_account_result = \
            self.service_account_result

        self.read_namespaced_secret_result = \
            self.service_account_token_result

        result = self.kube_operator.kube_get_service_account_token(
            'test-service-account-1', kube.NAMESPACE_KUBE_SYSTEM)
        self.assertEqual(result, FAKE_SERVICE_ACCOUNT_TOKEN)

    def test_kube_get_service_account_token_not_found(self):

        self.read_namespaced_service_account_result = None
        self.read_namespaced_secret_result = None

        result = self.kube_operator.kube_get_service_account_token(
            'test-service-account-1', kube.NAMESPACE_KUBE_SYSTEM)
        self.assertEqual(result, None)

    def mock_list_cluster_custom_resource(self, group, version, plural, pretty=False, label_selector="",
                                          resource_version="", watch=False):
        if plural.lower() in ("helmrepository", "helmrepositories"):
            return self.list_custom_resource_helmrepository

    @mock.patch('kubernetes.client.CustomObjectsApi.list_cluster_custom_object')
    def test_kube_list_custom_resource_single_helmrepository(self, mock_list_cluster_custom_object):
        mock_list_cluster_custom_object.side_effect = self.mock_list_cluster_custom_resource
        self.list_custom_resource_helmrepository = self.single_helmrepository_result

        result = self.kube_operator.list_custom_resources(
            'source.toolkit.fluxcd.io',
            'v1beta1',
            'helmrepositories'
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0],
            self.single_helmrepository_result.get("items")[0]
        )
        mock_list_cluster_custom_object.assert_called_once_with(
            'source.toolkit.fluxcd.io',
            'v1beta1',
            'helmrepositories',
            pretty=False,
            label_selector="",
            resource_version="",
            watch=False
        )

    @mock.patch('kubernetes.client.CustomObjectsApi.list_cluster_custom_object')
    def test_kube_list_custom_resource_multiple_helmrepositores(self, mock_list_cluster_custom_object):
        mock_list_cluster_custom_object.side_effect = self.mock_list_cluster_custom_resource
        self.list_custom_resource_helmrepository = self.multiple_helmrepository_result

        result = self.kube_operator.list_custom_resources(
            'source.toolkit.fluxcd.io',
            'v1beta1',
            'helmrepositories'
        )
        self.assertEqual(len(result), 2)
        self.assertEqual(
            result[0],
            self.multiple_helmrepository_result.get("items")[0]
        )
        self.assertEqual(
            result[1],
            self.multiple_helmrepository_result.get("items")[1]
        )
        mock_list_cluster_custom_object.assert_called_once_with(
            'source.toolkit.fluxcd.io',
            'v1beta1',
            'helmrepositories',
            pretty=False,
            label_selector="",
            resource_version="",
            watch=False
        )

    @mock.patch('kubernetes.client.CustomObjectsApi.list_cluster_custom_object')
    def test_kube_list_custom_resource_no_helmrepository(self, mock_list_cluster_custom_object):
        mock_list_cluster_custom_object.side_effect = self.mock_list_cluster_custom_resource
        self.list_custom_resource_helmrepository = self.no_helmrepository_result

        result = self.kube_operator.list_custom_resources(
            'source.toolkit.fluxcd.io',
            'v1beta1',
            'helmrepositories'
        )
        self.assertEqual(result, [])
        mock_list_cluster_custom_object.assert_called_once_with(
            'source.toolkit.fluxcd.io',
            'v1beta1',
            'helmrepositories',
            pretty=False,
            label_selector="",
            resource_version="",
            watch=False
        )

    @mock.patch('kubernetes.client.CustomObjectsApi.list_cluster_custom_object')
    def test_kube_list_custom_resource_label_selector(self, mock_list_cluster_custom_object):
        mock_list_cluster_custom_object.side_effect = self.mock_list_cluster_custom_resource
        self.list_custom_resource_helmrepository = self.multiple_helmrepository_result

        self.kube_operator.list_custom_resources(
            'source.toolkit.fluxcd.io',
            'v1beta1',
            'helmrepositories',
            label_selector=("app.kubernetes.io/name=test")
        )
        mock_list_cluster_custom_object.assert_called_once_with(
            'source.toolkit.fluxcd.io',
            'v1beta1',
            'helmrepositories',
            pretty=False,
            label_selector=("app.kubernetes.io/name=test"),
            resource_version="",
            watch=False
        )

    @mock.patch('kubernetes.client.CustomObjectsApi.list_cluster_custom_object')
    def test_kube_list_custom_resource_pretty(self, mock_list_cluster_custom_object):
        mock_list_cluster_custom_object.side_effect = self.mock_list_cluster_custom_resource
        self.list_custom_resource_helmrepository = self.multiple_helmrepository_result

        self.kube_operator.list_custom_resources(
            'source.toolkit.fluxcd.io',
            'v1beta1',
            'helmrepositories',
            pretty=True
        )
        mock_list_cluster_custom_object.assert_called_once_with(
            'source.toolkit.fluxcd.io',
            'v1beta1',
            'helmrepositories',
            pretty=True,
            label_selector="",
            resource_version="",
            watch=False
        )


class TestKubernetesUtilities(base.TestCase):
    def test_is_kube_version_supported(self):
        self.assertTrue(kube.is_kube_version_supported('v1.42.3', 'v1.42.1', 'v1.43.1'))
        self.assertTrue(kube.is_kube_version_supported('v1.42.3', 'v1.42.3', 'v1.42.3'))
        self.assertTrue(kube.is_kube_version_supported('v1.42.3', 'v1.42.1', None))
        self.assertTrue(kube.is_kube_version_supported('v1.42.3', None, 'v1.43.1'))
        self.assertTrue(kube.is_kube_version_supported('v1.42.3', None, None))
        self.assertFalse(kube.is_kube_version_supported('v1.42.3', 'v1.42.1', 'v1.42.2'))
        self.assertFalse(kube.is_kube_version_supported('v1.42.3', 'v1.42.2', 'v1.42.2'))
        self.assertFalse(kube.is_kube_version_supported('v1.42.3', 'v1.43.1', None))
        self.assertFalse(kube.is_kube_version_supported('v1.42.3', None, 'v1.41.5'))
