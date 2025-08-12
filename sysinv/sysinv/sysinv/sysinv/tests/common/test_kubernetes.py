#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the kubernetes utilities.
"""

import kubernetes
import mock
import subprocess

from sysinv.common import kubernetes as kube

from sysinv.tests import base
from sysinv.common import constants
from sysinv.common import exception

import tsconfig.tsconfig as tsc

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
    {'version': 'v1.44.0',
     'upgrade_from': ['v1.43.1'],
     'downgrade_to': [],
     'applied_patches': ['KUBE.11', 'KUBE.12'],
     'available_patches': ['KUBE.13'],
     },
    {'version': 'v1.45.1',
     'upgrade_from': ['v1.44.0'],
     'downgrade_to': [],
     'applied_patches': ['KUBE.11', 'KUBE.12'],
     'available_patches': ['KUBE.13'],
     },
    {'version': 'v1.45.3',
     'upgrade_from': ['v1.45.1'],
     'downgrade_to': [],
     'applied_patches': ['KUBE.11', 'KUBE.12'],
     'available_patches': ['KUBE.13'],
     }
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
                  "apiVersion: kubeadm.k8s.io/v1beta3\n"
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
                  "apiVersion: kubeadm.k8s.io/v1beta3\n"
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

        self.read_clusterrolebinding_result = kubernetes.client.V1ClusterRoleBinding(
            api_version="rbac.authorization.k8s.io/v1",
            kind="ClusterRoleBinding",
            metadata=kubernetes.client.V1ObjectMeta(
                name="test_system:test_node",
            ),
            role_ref=kubernetes.client.V1RoleRef(
                api_group='rbac.authorization.k8s.io',
                kind='ClusterRole',
                name='test_system:test_node'
            ),
            subjects=[kubernetes.client.RbacV1Subject(
                kind='User',
                name='test_system:test_node:test_hostname',
                api_group='rbac.authorization.k8s.io',
            )],
        )

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

        def mock_read_namespaced_secret(obj, name, namespace, _request_timeout=(30, 30)):
            return self.read_namespaced_secret_result
        self.mocked_read_namespaced_secret = mock.patch(
            'kubernetes.client.CoreV1Api.read_namespaced_secret',
            mock_read_namespaced_secret)
        self.mocked_read_namespaced_secret.start()

        def mock_read_clusterrolebinding(obj, name):
            return self.read_clusterrolebinding_result
        self.mocked_read_clusterrolebinding = mock.patch(
            'kubernetes.client.RbacAuthorizationV1Api.read_cluster_role_binding',
            mock_read_clusterrolebinding)
        self.mocked_read_clusterrolebinding.start()

        self.kube_operator = kube.KubeOperator()

    def tearDown(self):
        super(TestKubeOperator, self).tearDown()

        self.mocked_list_namespaced_pod.stop()
        self.mocked_list_pod_for_all_namespaces.stop()
        self.mocked_list_node.stop()
        self.mocked_read_namespaced_config_map.stop()
        self.mocked_read_namespaced_service_account.stop()
        self.mocked_read_namespaced_secret.stop()
        self.mocked_read_clusterrolebinding.stop()

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

        with mock.patch('retrying.time.sleep', return_value=None):
            self.assertRaises(ValueError,
                              self.kube_operator.kube_get_control_plane_versions)

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

    def test_kubelet_version_skew(self):

        self.list_node_result = self.single_node_result

        # same minor version
        result = self.kube_operator.kubelet_version_skew('v1.42.3', 'v1.42.0')
        assert result == 0

        # control plane newer than kubelet and skew 1, i.e., 43 - 42
        result = self.kube_operator.kubelet_version_skew('v1.43.1', 'v1.42.0')
        assert result == 1

        # kubelet newer than control plane by 1
        result = self.kube_operator.kubelet_version_skew('v1.41.1', 'v1.42.1')
        assert result == -1

        # kubelet much newer than control plane
        result = self.kube_operator.kubelet_version_skew('v1.0.0', 'v1.42.1')
        assert result == -42

        # no leading 'v' and skew 3, i.e., 44 - 41
        result = self.kube_operator.kubelet_version_skew('1.44.5', '1.41.1')
        assert result == 3

        # skew of 2, i.e., 45 - 43
        result = self.kube_operator.kubelet_version_skew('v1.45.1', 'v1.43.7')
        assert result == 2

        # major kubernetes version change
        result = self.kube_operator.kubelet_version_skew('v2.0.0', 'v1.42.1')
        assert result == 58

        # huge skew
        result = self.kube_operator.kubelet_version_skew('v1.42.1', 'v1.26.0')
        assert result == 16

    def test_kubelet_version_skew_invalid(self):

        self.list_node_result = self.single_node_result

        # missing kubeadm_version
        try:
            self.kube_operator.kubelet_version_skew(None, 'v1.43.1')
        except Exception as e:
            self.assertIn("Invalid kubelet version skew input", str(e))

        # missing kubelet_version
        try:
            self.kube_operator.kubelet_version_skew('v1.43.1', None)
        except Exception as e:
            self.assertIn("Invalid kubelet version skew input", str(e))

        # invalid kubeadm_version
        try:
            self.kube_operator.kubelet_version_skew('v1', 'v1.43.1')
        except Exception as e:
            self.assertIn("Invalid kubelet version skew input", str(e))

    def test_kube_get_higher_patch_version(self):

        self.list_node_result = self.single_node_result

        result = self.kube_operator.kube_get_higher_patch_version('v1.41.3', 'v1.43.1')
        assert result == ['v1.42.4', 'v1.43.1']

    def test_kube_get_higher_patch_version_increment_check(self):

        self.list_node_result = self.single_node_result

        result = self.kube_operator.kube_get_higher_patch_version('v1.41.3', 'v1.45.1')
        assert result == ['v1.42.4', 'v1.43.1', 'v1.44.0', 'v1.45.1']

    def test_kube_get_higher_patch_version_check_same_minor(self):

        self.list_node_result = self.single_node_result

        result = self.kube_operator.kube_get_higher_patch_version('v1.42.0', 'v1.42.3')
        assert result == ['v1.42.3']

    def test_kube_get_higher_patch_version_check_nohigher(self):

        self.list_node_result = self.single_node_result

        result = self.kube_operator.kube_get_higher_patch_version('v1.43.1', 'v1.42.4')
        assert result == []

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
                          'v1.43.1': 'unavailable',
                          'v1.44.0': 'unavailable',
                          'v1.45.1': 'unavailable',
                          'v1.45.3': 'unavailable'}

    def active(self):

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
                          'v1.43.1': 'active',
                          'v1.44.0': 'active',
                          'v1.45.1': 'active',
                          'v1.45.3': 'active'}

    def test_kube_get_version_states_active_simplex(self):

        tsc.system_mode = constants.SYSTEM_MODE_SIMPLEX
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
                          'v1.43.1': 'available',
                          'v1.44.0': 'available',
                          'v1.45.1': 'available',
                          'v1.45.3': 'available'}

    def test_kube_get_version_states_multi_node(self):

        self.list_namespaced_pod_result = self.cp_pods_result
        self.list_node_result = self.multi_node_result

        result = self.kube_operator.kube_get_version_states()
        assert result == {'v1.41.3': 'unavailable',
                          'v1.42.0': 'unavailable',
                          'v1.42.1': 'partial',
                          'v1.42.3': 'partial',
                          'v1.42.4': 'partial',
                          'v1.43.1': 'unavailable',
                          'v1.44.0': 'unavailable',
                          'v1.45.1': 'unavailable',
                          'v1.45.3': 'unavailable'}

    def test_kube_get_version_states_ignore_unknown_version(self):
        tsc.system_mode = constants.SYSTEM_MODE_DUPLEX
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
                          'v1.43.1': 'available',
                          'v1.44.0': 'available',
                          'v1.45.1': 'available',
                          'v1.45.3': 'available'}

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

    def test_kubeadm_configmap_reformat(self):
        mock_kube_patch_config_map = mock.MagicMock()
        p2 = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_patch_config_map',
            mock_kube_patch_config_map)
        p2.start().return_value = None
        self.addCleanup(p2.stop)

        # Test IPv4 only in block style
        self.read_namespaced_config_map_result = kubernetes.client.V1ConfigMap(
            api_version="v1",
            data={"ClusterConfiguration":
                  "apiServer:\n"
                  "  certSANs:\n"
                  "  - 127.0.0.1\n"
                  "  - 192.168.206.2\n"
                  },
            metadata=kubernetes.client.V1ObjectMeta(
                name="kubeadm-config",
                namespace="kube-system"),
        )
        self.kube_operator.kubeadm_configmap_reformat('dummy')
        mock_kube_patch_config_map.assert_not_called()

        # Test IPv4 only in flow style
        self.read_namespaced_config_map_result = kubernetes.client.V1ConfigMap(
            api_version="v1",
            data={"ClusterConfiguration":
                  "apiServer:\n"
                  "  certSANs: [127.0.0.1, 192.168.206.2]\n"
                  },
            metadata=kubernetes.client.V1ObjectMeta(
                name="kubeadm-config",
                namespace="kube-system"),
        )
        self.kube_operator.kubeadm_configmap_reformat('dummy')
        mock_kube_patch_config_map.assert_not_called()

        # Test IPv6 and IPv4 in block style
        self.read_namespaced_config_map_result = kubernetes.client.V1ConfigMap(
            api_version="v1",
            data={"ClusterConfiguration":
                  "apiServer:\n"
                  "  certSANs:\n"
                  "  - ::1\n"
                  "  - 192.168.206.2\n"
                  },
            metadata=kubernetes.client.V1ObjectMeta(
                name="kubeadm-config",
                namespace="kube-system"),
        )
        self.kube_operator.kubeadm_configmap_reformat('dummy')
        mock_kube_patch_config_map.assert_not_called()

        # Test IPv6 and IPv4 in flow style
        self.read_namespaced_config_map_result = kubernetes.client.V1ConfigMap(
            api_version="v1",
            data={"ClusterConfiguration":
                  "apiServer:\n"
                  "  certSANs: [::1, 127.0.0.1]\n"
                  },
            metadata=kubernetes.client.V1ObjectMeta(
                name="kubeadm-config",
                namespace="kube-system"),
        )
        self.kube_operator.kubeadm_configmap_reformat('dummy')
        patch_config_map_arg = {
            'data': {
                'ClusterConfiguration':
                    'apiServer:\n  certSANs:\n  - ::1\n  - 127.0.0.1\n'}}
        mock_kube_patch_config_map.assert_called_with(
                'kubeadm-config', 'kube-system', patch_config_map_arg)

    def test_read_clusterrolebinding_success(self):
        mock_read_clusterrolebinding = mock.MagicMock()
        mocked_read_clusterrolebinding = mock.patch(
            'kubernetes.client.RbacAuthorizationV1Api.read_cluster_role_binding',
            mock_read_clusterrolebinding
        )
        mocked_read_clusterrolebinding.start().return_value = self.read_clusterrolebinding_result
        self.addCleanup(mocked_read_clusterrolebinding.stop)

        fake_clusterrole_binding_name = "test_system:test_node"
        result = self.kube_operator.kube_read_clusterrolebinding(fake_clusterrole_binding_name)
        mock_read_clusterrolebinding.assert_called_with(fake_clusterrole_binding_name)
        self.assertEqual(result, self.read_clusterrolebinding_result)

    def test_read_clusterrolebinding_exception(self):
        mock_read_clusterrolebinding = mock.MagicMock()
        mocked_read_clusterrolebinding = mock.patch(
            'kubernetes.client.RbacAuthorizationV1Api.read_cluster_role_binding',
            mock_read_clusterrolebinding
        )
        mocked_read_clusterrolebinding.start().side_effect = Exception("Fake Error")
        self.addCleanup(mocked_read_clusterrolebinding.stop)
        self.assertRaises(  # noqa: H202
            Exception,
            self.kube_operator.kube_read_clusterrolebinding,
        )

    def test_patch_clusterrolebinding_success(self):
        mock_patch_clusterrolebinding = mock.MagicMock()
        mocked_patch_clusterrolebinding = mock.patch(
            'kubernetes.client.RbacAuthorizationV1Api.patch_cluster_role_binding',
            mock_patch_clusterrolebinding
        )
        mocked_patch_clusterrolebinding.start().return_value = self.read_clusterrolebinding_result
        self.addCleanup(mocked_patch_clusterrolebinding.stop)
        fake_clusterrole_binding_name = "test_system:test_node"
        self.kube_operator.kube_patch_clusterrolebinding(fake_clusterrole_binding_name, {})
        mock_patch_clusterrolebinding.assert_called_with(fake_clusterrole_binding_name, {})

    def test_patch_clusterrolebinding_exception(self):
        mock_patch_clusterrolebinding = mock.MagicMock()
        mocked_patch_clusterrolebinding = mock.patch(
            'kubernetes.client.RbacAuthorizationV1Api.patch_cluster_role_binding',
            mock_patch_clusterrolebinding
        )
        mocked_patch_clusterrolebinding.start().side_effect = Exception("Fake Error")
        self.addCleanup(mocked_patch_clusterrolebinding.stop)
        self.assertRaises(     # noqa: H202
            Exception,
            self.kube_operator.kube_patch_clusterrolebinding,
        )

    def test_get_all_supported_k8s_versions_success(self):
        """Test successful execution of method get_all_supported_k8s_versions()
        """
        expected_versions = ['fake_version1', 'fake_version2']
        mock_os_listdir = mock.MagicMock()
        p = mock.patch('os.listdir', mock_os_listdir)
        p.start().return_value = expected_versions
        self.addCleanup(p.stop)

        actual_versions = kube.get_all_supported_k8s_versions()

        self.assertEqual(expected_versions, actual_versions)
        mock_os_listdir.assert_called_once()

    def test_get_all_supported_k8s_versions_failure(self):
        """Test failure of method get_all_supported_k8s_versions()
        """
        mock_os_listdir = mock.MagicMock()
        p = mock.patch('os.listdir', mock_os_listdir)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException, kube.get_all_supported_k8s_versions)
        mock_os_listdir.assert_called_once()

    def test_get_k8s_images_success(self):
        """Test successful execution of method get_k8s_images()
        """
        fake_output = 'fake_registry1/fake_image1:fake_tag1\nfake_registry2/fake_image2:fake_tag2\n'
        expected_result = {'fake_image1': 'fake_registry1/fake_image1:fake_tag1',
                           'fake_image2': 'fake_registry2/fake_image2:fake_tag2'}

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start().return_value = (fake_output, None)
        self.addCleanup(p.stop)

        actual_result = kube.get_k8s_images('fake_version')

        self.assertEqual(expected_result, actual_result)
        mock_utils_execute.assert_called_once()

    def test_get_k8s_images_failure(self):
        """Test failure of method get_k8s_images()
        """
        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          kube.get_k8s_images,
                          'fake_version')
        mock_utils_execute.assert_called_once()

    def test_get_k8s_images_for_all_versions(self):
        """Test successful execution of method get_k8s_images_for_all_versions()
        """
        fake_versions = ['fake_version1', 'fake_version2']
        fake_images = {'fake_image1': 'fake_registry1/fake_image1:fake_tag1',
                           'fake_image2': 'fake_registry2/fake_image2:fake_tag2'}
        expected_result = {
            'fake_version1': {'fake_image1': 'fake_registry1/fake_image1:fake_tag1',
                              'fake_image2': 'fake_registry2/fake_image2:fake_tag2'},
            'fake_version2': {'fake_image1': 'fake_registry1/fake_image1:fake_tag1',
                              'fake_image2': 'fake_registry2/fake_image2:fake_tag2'},
        }

        mock_get_all_supported_k8s_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_all_supported_k8s_versions',
                       mock_get_all_supported_k8s_versions)
        p.start().return_value = fake_versions
        self.addCleanup(p.stop)

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().return_value = fake_images
        self.addCleanup(p.stop)

        actual_result = kube.get_k8s_images_for_all_versions()

        self.assertEqual(expected_result, actual_result)
        mock_get_all_supported_k8s_versions.assert_called_once()
        self.assertEqual(mock_get_k8s_images.call_count, 2)
        mock_get_k8s_images.assert_called()

    def test_get_k8s_images_for_all_versions_failure(self):
        """Test failure of method get_k8s_images_for_all_versions()
        """
        fake_versions = ['fake_version1', 'fake_version2']

        mock_get_all_supported_k8s_versions = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_all_supported_k8s_versions',
                       mock_get_all_supported_k8s_versions)
        p.start().return_value = fake_versions
        self.addCleanup(p.stop)

        mock_get_k8s_images = mock.MagicMock()
        p = mock.patch('sysinv.common.kubernetes.get_k8s_images', mock_get_k8s_images)
        p.start().side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException, kube.get_k8s_images_for_all_versions)
        mock_get_all_supported_k8s_versions.assert_called_once()
        mock_get_k8s_images.assert_called()

    def test_disable_kubelet_garbage_collection_success(self):
        """Test successful execution of method disable_kubelet_garbage_collection()
        """
        expected_config_update = \
                'KUBELET_KUBEADM_ARGS="--image-gc-high-threshold 100 --fake-flag=fake_value"\n'

        mock_file_open = mock.mock_open(read_data='KUBELET_KUBEADM_ARGS="--fake-flag=fake_value"\n')
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        kube.disable_kubelet_garbage_collection()

        mock_file_open.return_value.write.assert_called_with(expected_config_update)
        self.assertEqual(mock_file_open.call_count, 2)

    def test_disable_kubelet_garbage_collection_success_with_no_prior_config(self):
        """Test successful execution of method disable_kubelet_garbage_collection() with no prior
           config flags
        """
        expected_config_update = \
                'KUBELET_KUBEADM_ARGS="--image-gc-high-threshold 100 "\n'

        mock_file_open = mock.mock_open(read_data='KUBELET_KUBEADM_ARGS=""\n')
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        kube.disable_kubelet_garbage_collection()

        mock_file_open.return_value.write.assert_called_with(expected_config_update)
        self.assertEqual(mock_file_open.call_count, 2)

    def test_disable_kubelet_garbage_collection_failure(self):
        """Test failure of method disable_kubelet_garbage_collection()
        """
        mock_file_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_file_open)
        p.start().return_value.read.side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException, kube.disable_kubelet_garbage_collection)
        mock_file_open.return_value.write.assert_not_called()

    def test_enable_kubelet_garbage_collection_success(self):
        """Test successful execution of method enable_kubelet_garbage_collection()
        """
        expected_config_update = \
                'KUBELET_KUBEADM_ARGS="--fake-flag=fake_value"\n'

        mock_file_open = mock.mock_open(
            read_data='KUBELET_KUBEADM_ARGS="--image-gc-high-threshold 100 --fake-flag=fake_value"\n')  # pylint: disable=line-too-long # noqa: E501
        p = mock.patch('builtins.open', mock_file_open)
        p.start()
        self.addCleanup(p.stop)

        kube.enable_kubelet_garbage_collection()

        mock_file_open.return_value.write.assert_called_with(expected_config_update)
        self.assertEqual(mock_file_open.call_count, 2)

    def test_enable_kubelet_garbage_collection_failure(self):
        """Test failure of method enable_kubelet_garbage_collection()
        """
        mock_file_open = mock.mock_open()
        p = mock.patch('builtins.open', mock_file_open)
        p.start().return_value.read.side_effect = Exception("Fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException, kube.enable_kubelet_garbage_collection)
        mock_file_open.return_value.write.assert_not_called()

    def test_kubectl_apply_success_integer_timeout(self):
        """Test kubectl apply successful execution: integer timeout
        """
        fake_manifest = "fake manifest"
        fake_timeout = 150
        cmd = ["kubectl", f"--kubeconfig={kube.KUBERNETES_ADMIN_CONF}", "apply",
               "-f", fake_manifest, f"--request-timeout={fake_timeout}s"]

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        kube.kubectl_apply(fake_manifest, fake_timeout)

        mock_utils_execute.assert_called_once_with(
            *cmd, attempts=5, delay_on_retry=True, check_exit_code=0)

    def test_kubectl_apply_success_float_timeout(self):
        """Test kubectl apply successful execution: float timeout
        """
        fake_manifest = "fake manifest"
        fake_timeout = 150.49345
        cmd = ["kubectl", f"--kubeconfig={kube.KUBERNETES_ADMIN_CONF}", "apply",
               "-f", fake_manifest, f"--request-timeout={fake_timeout}s"]

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        kube.kubectl_apply(fake_manifest, fake_timeout)

        mock_utils_execute.assert_called_once_with(
            *cmd, attempts=5, delay_on_retry=True, check_exit_code=0)

    def test_kubectl_apply_success_string_timeout(self):
        """Test kubectl apply successful execution: valid string input for timeout
        """
        fake_manifest = "fake manifest"
        fake_timeout = '80'
        cmd = ["kubectl", f"--kubeconfig={kube.KUBERNETES_ADMIN_CONF}", "apply",
               "-f", fake_manifest, f"--request-timeout={fake_timeout}s"]

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        kube.kubectl_apply(fake_manifest, fake_timeout)

        mock_utils_execute.assert_called_once_with(
            *cmd, attempts=5, delay_on_retry=True, check_exit_code=0)

    def test_kubectl_apply_success_bool_timeout(self):
        """Test kubectl apply successful execution: bool timeout (invalid input)
        """
        fake_manifest = "fake manifest"
        fake_timeout = True
        cmd = ["kubectl", f"--kubeconfig={kube.KUBERNETES_ADMIN_CONF}", "apply",
               "-f", fake_manifest, "--request-timeout=60s"]

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        kube.kubectl_apply(fake_manifest, fake_timeout)

        mock_utils_execute.assert_called_once_with(
            *cmd, attempts=5, delay_on_retry=True, check_exit_code=0)

    def test_kubectl_apply_success_random_invalid_string(self):
        """Test kubectl apply successful execution: random string (invalid input)
        """
        fake_manifest = "fake manifest"
        fake_timeout = "fake invalid string"
        cmd = ["kubectl", f"--kubeconfig={kube.KUBERNETES_ADMIN_CONF}", "apply",
               "-f", fake_manifest, "--request-timeout=60s"]

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start()
        self.addCleanup(p.stop)

        kube.kubectl_apply(fake_manifest, fake_timeout)

        mock_utils_execute.assert_called_once_with(
            *cmd, attempts=5, delay_on_retry=True, check_exit_code=0)

    def test_kubectl_apply_failure(self):
        """Test kubectl apply failure
        """
        fake_manifest = "fake manifest"
        fake_timeout = 150
        cmd = ["kubectl", f"--kubeconfig={kube.KUBERNETES_ADMIN_CONF}", "apply",
               "-f", fake_manifest, f"--request-timeout={fake_timeout}s"]

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start().side_effect = Exception("fake error")
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          kube.kubectl_apply,
                          fake_manifest,
                          fake_timeout)

        mock_utils_execute.assert_called_once_with(
            *cmd, attempts=5, delay_on_retry=True, check_exit_code=0)

    def test_kubectl_apply_failure_command_timeout(self):
        """Test kubectl apply failure
        """
        fake_manifest = "fake manifest"
        fake_timeout = 150
        cmd = ["kubectl", f"--kubeconfig={kube.KUBERNETES_ADMIN_CONF}", "apply",
               "-f", fake_manifest, f"--request-timeout={fake_timeout}s"]

        mock_utils_execute = mock.MagicMock()
        p = mock.patch('sysinv.common.utils.execute', mock_utils_execute)
        p.start().side_effect = subprocess.TimeoutExpired(cmd, fake_timeout)
        self.addCleanup(p.stop)

        self.assertRaises(exception.SysinvException,
                          kube.kubectl_apply,
                          fake_manifest,
                          fake_timeout)

        mock_utils_execute.assert_called_once_with(
            *cmd, attempts=5, delay_on_retry=True, check_exit_code=0)


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
