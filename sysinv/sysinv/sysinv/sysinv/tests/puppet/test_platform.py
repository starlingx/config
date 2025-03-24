# Copyright (c) 2019-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
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


class PlatformTestCaseStalldConfig(base.PuppetTestCaseMixin,
                                   dbbase.BaseHostTestCase):

    def _create_test_host_cpus(self, host,
                               platform=0, application=0, isolated=0,
                               threads=1):
        counts = [platform, application, isolated]
        functions = [constants.PLATFORM_FUNCTION,
                     constants.APPLICATION_FUNCTION,
                     constants.ISOLATED_FUNCTION]

        nodes = self.dbapi.inode_get_by_ihost(host.id)
        for node in nodes:
            cpu = 0
            for count, function in zip(counts, functions):
                for _ in range(0, count):
                    for thread in range(0, threads):
                        self.dbapi.icpu_create(host.id,
                            dbutils.get_test_icpu(
                                forinodeid=node.id,
                                cpu=cpu, thread=thread,
                                allocated_function=function))
                    cpu = cpu + 1

    def _configure_cpus(self, platform=0, application=0, isolated=0):
        self._create_test_host_cpus(self.host,
                                    platform=platform,
                                    application=application,
                                    isolated=isolated)
        self._create_test_host_addresses(self.host.hostname)

    def _create_test_host_cpus_using_spec(self,
                                          host,
                                          cpu_assignment_spec: dict):
        node = self.dbapi.inode_get_by_ihost(host.id)[0]
        for function, _d in cpu_assignment_spec.items():
            for thread, cpu_ids in _d.items():
                for cpu_id in cpu_ids:
                    icpu = dbutils.get_test_icpu(forinodeid=node.id,
                                                  cpu=cpu_id,
                                                  thread=thread,
                                                  allocated_function=function)
                    self.dbapi.icpu_create(host.id, icpu)

    def _configure_cpus_using_assignment_spec(self, cpu_assignment_spec):
        self._create_test_host_cpus_using_spec(self.host, cpu_assignment_spec)
        self._create_test_host_addresses(self.host.hostname)

    def _create_host_labels_in_db(self, labels):
        for label_str in labels:
            k, v = label_str.split('=')
            self.dbapi.label_create(self.host.id,
                                    {'host_id': self.host.id,
                                     'label_key': k,
                                     'label_value': v})

    def setUp(self):
        super(PlatformTestCaseStalldConfig, self).setUp()
        self.host = self._create_test_host(constants.WORKER)

    def test_get_stalld_config_defaults(self):
        """ stalld disabled with application default
            0-1 platform cpus
            2-7 application cpus
            8-9 isolated cpus
        """
        self._configure_cpus(platform=2, application=6, isolated=2)
        stalld_cpu_list = "2-9"
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(self.mock_write_config, {
            "platform::stalld::params::enable":
                False,
            "platform::stalld::params::cpu_list":
                f"'{stalld_cpu_list}'"
        })

    def test_get_stalld_config_enabled_cpus_default(self):
        """ stalld enabled with cpu default=application
            0-1 platform cpus
            2-7 application cpus
            8-9 isolated cpus
        """
        self._configure_cpus(platform=2, application=6, isolated=2)
        labels = [
            # starlingx.io/stalld=enabled
            f"{constants.LABEL_STALLD}={constants.LABEL_VALUE_STALLD_ENABLED}"
        ]
        self._create_host_labels_in_db(labels)
        stalld_cpu_list = "2-9"
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(self.mock_write_config, {
            "platform::stalld::params::enable":
                True,
            "platform::stalld::params::cpu_list":
                f"'{stalld_cpu_list}'"
        })

    def test_get_stalld_config_enabled_cpus_all(self):
        """ stalld enabled with all cpus
            0-1 platform cpus
            2-7 application cpus
            8-9 isolated cpus
        """
        self._configure_cpus(platform=2, application=6, isolated=2)
        labels = [
            # starlingx.io/stalld=enabled
            f"{constants.LABEL_STALLD}={constants.LABEL_VALUE_STALLD_ENABLED}",
            # starlingx.io/stalld_cpu_functions=all
            f"{constants.LABEL_STALLD_CPU_FUNCTIONS}={constants.LABEL_VALUE_CPU_ALL}"
        ]
        self._create_host_labels_in_db(labels)
        stalld_cpu_list = "0-9"
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(self.mock_write_config, {
            "platform::stalld::params::enable":
                True,
            "platform::stalld::params::cpu_list":
                f"'{stalld_cpu_list}'"
        })

    def test_get_stalld_config_enabled_cpus_application(self):
        """ stalld enabled with application cpus
            0-1 platform cpus
            2-7 application cpus
            8-9 isolated cpus
        """
        self._configure_cpus(platform=2, application=6, isolated=2)
        labels = [
            # starlingx.io/stalld=enabled
            f"{constants.LABEL_STALLD}={constants.LABEL_VALUE_STALLD_ENABLED}",
            # starlingx.io/stalld_cpu_functions=application
            f"{constants.LABEL_STALLD_CPU_FUNCTIONS}={constants.LABEL_VALUE_CPU_APPLICATION}"
        ]
        self._create_host_labels_in_db(labels)
        stalld_cpu_list = "2-9"
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(self.mock_write_config, {
            "platform::stalld::params::enable":
                True,
            "platform::stalld::params::cpu_list":
                f"'{stalld_cpu_list}'"
        })

    def test_get_stalld_config_enabled_cpus_isolated(self):
        """ stalld enabled with application-isolated cpus
            0-1 platform cpus
            2-7 application cpus
            8-9 isolated cpus
        """
        self._configure_cpus(platform=2, application=6, isolated=2)
        labels = [
            # starlingx.io/stalld=enabled
            f"{constants.LABEL_STALLD}={constants.LABEL_VALUE_STALLD_ENABLED}",
            # starlingx.io/stalld_cpu_functions=application-isolated
            f"{constants.LABEL_STALLD_CPU_FUNCTIONS}={constants.LABEL_VALUE_CPU_APPLICATION_ISOLATED}"
        ]
        self._create_host_labels_in_db(labels)
        stalld_cpu_list = "8-9"
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(self.mock_write_config, {
            "platform::stalld::params::enable":
                True,
            "platform::stalld::params::cpu_list":
                f"'{stalld_cpu_list}'"
        })

    def test_get_stalld_config_case_insensitive(self):
        """ stalld enabled with application-isolated cpus
            0-1 platform cpus
            2-7 application cpus
            8-9 isolated cpus
        """
        self._configure_cpus(platform=2, application=6, isolated=2)
        labels = [
            # starlingx.io/stalld=enabled
            f"{constants.LABEL_STALLD}=EnablED",
            # starlingx.io/stalld_cpu_functions=application-isolated
            f"{constants.LABEL_STALLD_CPU_FUNCTIONS}=APPlicaTion-iSOLAted"
        ]
        self._create_host_labels_in_db(labels)
        stalld_cpu_list = "8-9"
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(self.mock_write_config, {
            "platform::stalld::params::enable":
                True,
            "platform::stalld::params::cpu_list":
                f"'{stalld_cpu_list}'"
        })

    def test_get_stalld_config_enabled_cpus_isolated_not_configured(self):
        """ stalld enabled with application-isolated cpus
            but cpu list is empty so stalld will be disabled in config
            0-1 platform cpus
            2-9 application cpus
            n/a isolated cpus
        """
        self._configure_cpus(platform=2, application=8, isolated=0)
        labels = [
            # starlingx.io/stalld=enabled
            f"{constants.LABEL_STALLD}={constants.LABEL_VALUE_STALLD_ENABLED}",
            # starlingx.io/stalld_cpu_functions=application-isolated
            f"{constants.LABEL_STALLD_CPU_FUNCTIONS}={constants.LABEL_VALUE_CPU_APPLICATION_ISOLATED}"
        ]
        self._create_host_labels_in_db(labels)
        stalld_cpu_list = ""
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(self.mock_write_config, {
            "platform::stalld::params::enable":
                False,
            "platform::stalld::params::cpu_list":
                f"'{stalld_cpu_list}'"
        })

    def test_get_stalld_config_bad_data_in_db(self):
        """ stalld enabled with bad value
            stalld defaults to disabled
            0-1 platform cpus
            2-7 application cpus
            8-9 isolated cpus
        """
        self._configure_cpus(platform=2, application=6, isolated=2)
        labels = [
            # starlingx.io/stalld=%#@#%#@
            f"{constants.LABEL_STALLD}=%#@#%#@",
        ]
        self._create_host_labels_in_db(labels)
        stalld_cpu_list = "2-9"
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(self.mock_write_config, {
            "platform::stalld::params::enable":
                False,
            "platform::stalld::params::cpu_list":
                f"'{stalld_cpu_list}'"
        })

    def test_get_stalld_config_cpus_bad_data_in_db(self):
        """ stalld enabled with bad cpu function value
            stalld cpu function defaults to application
            0-1 platform cpus
            2-7 application cpus
            8-9 isolated cpus
        """
        self._configure_cpus(platform=2, application=6, isolated=2)
        labels = [
            # starlingx.io/stalld=enabled
            f"{constants.LABEL_STALLD}={constants.LABEL_VALUE_STALLD_ENABLED}",
            # starlingx.io/stalld_cpu_functions=%#@#%#@
            f"{constants.LABEL_STALLD_CPU_FUNCTIONS}=%#@#%#@"
        ]
        self._create_host_labels_in_db(labels)
        stalld_cpu_list = "2-9"
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(self.mock_write_config, {
            "platform::stalld::params::enable":
                True,
            "platform::stalld::params::cpu_list":
                f"'{stalld_cpu_list}'"
        })

    def test_get_stalld_config_enabled_cpus_application_with_threads(self):
        """ stalld enabled with application cpus (with 2 threads)
            and discontinous cpu ids
            platform:       0-1         ... thread 0
                            10-11       ... thread 1
            application:    2-7         ... thread 0
                            12-17       ... thread 1
            isolated:       8-9         ... thread 0
                            18-19       ... thread 1
        """
        _THREAD_0, _THREAD_1 = 0, 1
        cpu_assignment_spec = {
            constants.PLATFORM_FUNCTION: {
                _THREAD_0: [0, 1],
                _THREAD_1: [10, 11]
            },
            constants.APPLICATION_FUNCTION: {
                _THREAD_0: [2, 3, 4, 5, 6, 7],
                _THREAD_1: [12, 13, 14, 15, 16, 17]
            },
            constants.ISOLATED_FUNCTION: {
                _THREAD_0: [8, 9],
                _THREAD_1: [18, 19]
            }
        }
        # Add application CPUs
        self._configure_cpus_using_assignment_spec(cpu_assignment_spec)
        labels = [
            f"{constants.LABEL_STALLD}={constants.LABEL_VALUE_STALLD_ENABLED}",
            f"{constants.LABEL_STALLD_CPU_FUNCTIONS}={constants.LABEL_VALUE_CPU_APPLICATION_ISOLATED}"
        ]
        self._create_host_labels_in_db(labels)
        stalld_cpu_list = "8-9,18-19"
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(self.mock_write_config, {
            "platform::stalld::params::enable": True,
            "platform::stalld::params::cpu_list": f"'{stalld_cpu_list}'"
        })

    def test_get_stalld_config_enabled_cpus_all_with_custom_parameters(self):
        """ stalld enabled with all cpus
            0-1 platform cpus
            2-7 application cpus
            8-9 isolated cpus
        """
        self._configure_cpus(platform=2, application=6, isolated=2)
        custom_parameter1, value1 = "string_parameter", "string_value1"
        custom_parameter2, value2 = "numeric_parameter", 1792992

        labels = [
            # starlingx.io/stalld=enabled
            f"{constants.LABEL_STALLD}={constants.LABEL_VALUE_STALLD_ENABLED}",
            # starlingx.io/stalld_cpu_functions=all
            f"{constants.LABEL_STALLD_CPU_FUNCTIONS}={constants.LABEL_VALUE_CPU_ALL}",
            f"{constants.CUSTOM_STALLD_LABEL_STRING}{custom_parameter1}={value1}",
            f"{constants.CUSTOM_STALLD_LABEL_STRING}{custom_parameter2}={value2}"
        ]
        self._create_host_labels_in_db(labels)
        stalld_cpu_list = "0-9"
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(self.mock_write_config, {
            "platform::stalld::params::enable":
                True,
            "platform::stalld::params::cpu_list":
                f"'{stalld_cpu_list}'",
            f"platform::stalld::params::{custom_parameter1}":
                f"'{value1}'",
            f"platform::stalld::params::{custom_parameter2}":
                f"'{value2}'"
        })
