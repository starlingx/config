# Copyright (c) 2019-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
from sysinv.tests.db import base as dbbase
from sysinv.tests.puppet import base
from sysinv.common import constants


class PlatformIPv4WorkerHostTestCase(base.PuppetTestCaseMixin,
                                     dbbase.WorkerHostTestCase):

    def test_nfs_proto_version(self):
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(self.mock_write_config, {
            'platform::params::nfs_proto': 'udp'
        })


class PlatformIPv6WorkerHostTestCase(base.PuppetTestCaseMixin,
                                     dbbase.BaseIPv6Mixin,
                                     dbbase.WorkerHostTestCase):

    def test_nfs_proto_version(self):
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(self.mock_write_config, {
            'platform::params::nfs_proto': 'udp6'
        })


class PlatformTestCaseKubernetesReservedMemory(base.PuppetTestCaseMixin,
                                       dbbase.WorkerHostTestCase):

    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    def test_eviction_threshold_in_Mi(self, MockKubeOperator):
        mock_operator = MockKubeOperator.return_value
        mock_operator.kube_get_node_status.return_value = \
            mock.MagicMock(status=mock.MagicMock(capacity={"memory": "24591168Ki"}))
        mock_operator.kube_read_config_map.return_value = \
            mock.MagicMock(data={'kubelet': 'evictionHard:\n  memory.available: "100Mi"'})

        host = mock.MagicMock(hostname='test-host')
        result = self.operator.platform._get_kubelet_eviction_hard_config_MiB(host)
        self.assertEqual(result, 100)

    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    def test_eviction_threshold_in_Gi(self, MockKubeOperator):
        mock_operator = MockKubeOperator.return_value
        mock_operator.kube_get_node_status.return_value = \
            mock.MagicMock(status=mock.MagicMock(capacity={"memory": "24591168Ki"}))
        mock_operator.kube_read_config_map.return_value = \
            mock.MagicMock(data={'kubelet': 'evictionHard:\n  memory.available: "1Gi"'})

        host = mock.MagicMock(hostname='test-host')
        result = self.operator.platform._get_kubelet_eviction_hard_config_MiB(host)
        self.assertEqual(result, 1024)

    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    def test_eviction_threshold_in_percentage(self, MockKubeOperator):
        mock_operator = MockKubeOperator.return_value
        mock_operator.kube_get_node_status.return_value = \
            mock.MagicMock(status=mock.MagicMock(capacity={"memory": "24591168Ki"}))
        mock_operator.kube_read_config_map.return_value = \
            mock.MagicMock(data={'kubelet': 'evictionHard:\n  memory.available: "10%"'})

        host = mock.MagicMock(hostname='test-host')
        result = self.operator.platform._get_kubelet_eviction_hard_config_MiB(host)
        print(result)
        self.assertEqual(result, 2518135640 / (1024 * 1024))

    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    def test_eviction_threshold_in_Mi_fail(self, MockKubeOperator):
        """
            Mock exception when eviction hard memory values are
            not in either Mi, Gi or % units
        """
        host = mock.MagicMock(hostname='test-host')
        mock_operator = MockKubeOperator.return_value
        mock_operator.kube_get_node_status.return_value = \
            mock.MagicMock(status=mock.MagicMock(capacity={"memory": "24591168Ki"}))
        mock_operator.kube_read_config_map.return_value = \
            Exception("Eviction threshold value is expected to be in Mi,Gi,{}"
                                      "units".format("%"))
        self.assertRaises(Exception,  # noqa: H202
            self.operator.platform._get_kubelet_eviction_hard_config_MiB(host))

    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    def test_eviction_threshold_in_Mi_fail_kubelet_config(self, MockKubeOperator):
        """
            Mock exception when unable to retrieve kubelet hard
            eviction memory
        """
        host = mock.MagicMock(hostname='test-host')
        mock_operator = MockKubeOperator.return_value
        mock_operator.kube_get_node_status.return_value = \
            mock.MagicMock(status=mock.MagicMock(capacity={"memory": "24591168Ki"}))
        mock_operator.kube_read_config_map.return_value = \
            Exception("Unable to retrieve kubelet hard eviction memory")
        self.assertRaises(Exception,  # noqa: H202
            self.operator.platform._get_kubelet_eviction_hard_config_MiB(host))

    @mock.patch('sysinv.common.utils.get_personalities')
    @mock.patch('sysinv.db.api.get_instance')
    @mock.patch('sysinv.common.utils.get_numa_index_list')
    @mock.patch('sysinv.puppet.platform.PlatformPuppet._get_kubelet_eviction_hard_config_MiB')
    def test_get_host_memory_config(self, mock_eviction, mock_numa_list, mock_dbapi,
                                                           mock_personalities):
        """
            Mock Kubernetes reserved memory for 2 numa nodes
        """
        config = {}
        mock_personalities.return_value = [constants.WORKER]

        mock_memory = mock.MagicMock()
        mock_memory.platform_reserved_mib = 8500
        mock_dbapi.imemory_get_by_ihost.return_value = [mock_memory]

        mock_numa_list.return_value = {0: [mock_memory], 1: [mock_memory]}

        mock_eviction.return_value = 100

        mock_host = mock.MagicMock()
        mock_host.id = 1

        # Get only k8s_reserved_memory parameter from a dictionary
        result = self.operator.platform._get_host_memory_config(mock_host)
        config_key = 'platform::kubernetes::params::k8s_reserved_memory'
        config_value = result[config_key]
        k8s_reserved_memory_config = {config_key: config_value}

        Platform_size_in_B = (8500 * (1024 * 1024))
        Eviction_memory_in_B = (100 * (1024 * 1024))

        expected_reserved_memory_node_0 = \
            Platform_size_in_B + Eviction_memory_in_B // 2 + Eviction_memory_in_B % 2
        expected_reserved_memory_node_1 = \
            Platform_size_in_B + Eviction_memory_in_B // 2

        expected_k8s_reserved_memory = "\"0:memory={};1:memory={}\"".\
            format(expected_reserved_memory_node_0, expected_reserved_memory_node_1)

        config.update({
            'platform::kubernetes::params::k8s_reserved_memory': expected_k8s_reserved_memory}
        )
        self.assertEqual(k8s_reserved_memory_config, config)

    @mock.patch('sysinv.common.utils.get_personalities')
    @mock.patch('sysinv.db.api.get_instance')
    @mock.patch('sysinv.common.utils.get_numa_index_list')
    @mock.patch('sysinv.puppet.platform.PlatformPuppet._get_kubelet_eviction_hard_config_MiB')
    def test_get_host_memory_config_odd_numa_nodes(self, mock_eviction, mock_numa_list,
                                                        mock_dbapi, mock_personalities):
        """
            Mock Kubernetes reserved memory for 3 numa nodes
        """
        config = {}
        mock_personalities.return_value = [constants.WORKER]

        mock_memory = mock.MagicMock()
        mock_memory.platform_reserved_mib = 8500
        mock_dbapi.imemory_get_by_ihost.return_value = [mock_memory]

        mock_numa_list.return_value = {0: [mock_memory], 1: [mock_memory], 2: [mock_memory]}

        mock_eviction.return_value = 100

        mock_host = mock.MagicMock()
        mock_host.id = 1

        # Get only k8s_reserved_memory parameter from a dictionary
        result = self.operator.platform._get_host_memory_config(mock_host)
        config_key = 'platform::kubernetes::params::k8s_reserved_memory'
        config_value = result[config_key]
        k8s_reserved_memory_config = {config_key: config_value}

        Platform_size_in_B = (8500 * (1024 * 1024))
        Eviction_memory_in_B = (100 * (1024 * 1024))

        expected_reserved_memory_node_0 = \
            Platform_size_in_B + Eviction_memory_in_B // 3 + (100 * (1024 * 1024)) % 3
        expected_reserved_memory_node_1 = \
            Platform_size_in_B + Eviction_memory_in_B // 3
        expected_reserved_memory_node_2 = \
            Platform_size_in_B + Eviction_memory_in_B // 3

        expected_k8s_reserved_memory = "\"0:memory={};1:memory={};2:memory={}\"".\
            format(expected_reserved_memory_node_0, expected_reserved_memory_node_1,
                expected_reserved_memory_node_2)

        config.update({
            'platform::kubernetes::params::k8s_reserved_memory': expected_k8s_reserved_memory}
        )
        self.assertEqual(k8s_reserved_memory_config, config)
