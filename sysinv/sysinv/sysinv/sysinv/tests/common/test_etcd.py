#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the etcd utilities.
"""

import mock
from collections import OrderedDict
from subprocess import TimeoutExpired

from sysinv.tests import base
from sysinv.common import etcd
from sysinv.common import exception
from sysinv.common import kubernetes


class FakePopen(object):

    def __init__(self, **kwargs):
        self.fake_kill_called = False

    def communicate(self, timeout=60):
        return "Snapshot saved at", "fake err"

    def kill(self):
        self.fake_kill_called = True


FAKE_ETCD_CLUSTER = OrderedDict([('caFile', '/etc/etcd/ca.crt'),
                                ('certFile', '/etc/kubernetes/pki/apiserver-etcd-client.crt'),
                                ('endpoints', ['https://192.168.206.1:2379']),
                                ('keyFile', '/etc/kubernetes/pki/apiserver-etcd-client.key')])


class TestEtcd(base.TestCase):

    def setUp(self):
        super(TestEtcd, self).setUp()

        self.fake_configmap_data = kubernetes.client.V1ConfigMap(
            api_version='v1',
            data={'ClusterConfiguration': 'apiServer:\n'
                                            '  certSANs:\n'
                                            '  - 192.168.206.1\n'
                                            '  - 127.0.0.1\n'
                                            '  - 10.10.6.3\n'
                                            '  extraArgs:\n'
                                            '    event-ttl: 24h\n'
                                            '  extraVolumes:\n'
                                            '  - hostPath: '
                                            '/etc/kubernetes/encryption-provider.yaml\n'
                                            'apiVersion: kubeadm.k8s.io/v1beta3\n'
                                            'controllerManager:\n'
                                            '  extraArgs:\n'
                                            '    pod-eviction-timeout: 30s\n'
                                            '    feature-gates: CSIMigrationPortworx=false\n'
                                            '  extraVolumes:\n'
                                            'kind: ClusterConfiguration\n'
                                            'etcd:\n'
                                            '  external:\n'
                                            '    caFile: /etc/etcd/ca.crt\n'
                                            '    certFile: '
                                            '/etc/kubernetes/pki/apiserver-etcd-client.crt\n'
                                            '    endpoints:\n'
                                            '    - https://192.168.206.1:2379\n'
                                            '    keyFile: '
                                            '/etc/kubernetes/pki/apiserver-etcd-client.key\n'
                                            'kubernetesVersion: v1.42.1\n'
                                            'scheduler: {}\n'},
            metadata=kubernetes.client.V1ObjectMeta(
                        name='kubeadm-config',
                        namespace='kube-system'),
        )

    def tearDown(self):
        super(TestEtcd, self).tearDown()

    def test_get_cluster_information(self):
        mock_kube_read_config_map = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_read_config_map',
            mock_kube_read_config_map)
        p.start().return_value = self.fake_configmap_data
        self.addCleanup(p.stop)

        result = etcd.get_cluster_information()
        mock_kube_read_config_map.assert_called_with(
            'kubeadm-config', 'kube-system')
        self.assertEqual(result, FAKE_ETCD_CLUSTER)

    def test_get_cluster_information_fail(self):
        mock_kube_read_config_map = mock.MagicMock()
        p = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_read_config_map',
            mock_kube_read_config_map)
        p.start().side_effect = Exception("kube operator error")
        self.addCleanup(p.stop)

        self.assertRaises(Exception, etcd.get_cluster_information)  # noqa: H202
        mock_kube_read_config_map.assert_called_with(
            'kubeadm-config', 'kube-system')

    def test_snapshot_etcd(self):
        mock_get_cluster_information = mock.MagicMock()
        self.mocked_get_cluster_information = mock.patch(
            'sysinv.common.etcd.get_cluster_information',
            mock_get_cluster_information)
        self.mocked_get_cluster_information.start().return_value = \
            FAKE_ETCD_CLUSTER

        mock_os_path_dirname = mock.MagicMock()
        p = mock.patch('os.path.dirname', mock_os_path_dirname)
        p.start().return_value = "/fake/path/"
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        fake_subprocess_popen = FakePopen()
        p = mock.patch('subprocess.Popen')
        mock_subprocess_popen = p.start()
        mock_subprocess_popen.return_value = fake_subprocess_popen
        self.addCleanup(p.stop)

        etcd.snapshot_etcd("/fake/path/file")
        mock_os_path_dirname.assert_called_with("/fake/path/file")
        mock_os_path_exists.assert_called_with("/fake/path/")
        cmd = ["etcdctl", "--cert", FAKE_ETCD_CLUSTER['certFile'], "--key",
               FAKE_ETCD_CLUSTER['keyFile'], "--cacert",
               FAKE_ETCD_CLUSTER['caFile'], "--endpoints",
               ",".join(FAKE_ETCD_CLUSTER['endpoints']), "snapshot", "save",
               "/fake/path/file"]
        mock_subprocess_popen.assert_called_with(cmd, stdout=-1, stderr=-1,
                                                 env=etcd.ETCD_API_ENV_VAR)

    def test_snapshot_etcd_command_fail(self):
        mock_get_cluster_information = mock.MagicMock()
        self.mocked_get_cluster_information = mock.patch(
            'sysinv.common.etcd.get_cluster_information',
            mock_get_cluster_information)
        self.mocked_get_cluster_information.start().return_value = \
            FAKE_ETCD_CLUSTER

        mock_os_path_dirname = mock.MagicMock()
        p = mock.patch('os.path.dirname', mock_os_path_dirname)
        p.start().return_value = '/fake/path/'
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        fake_subprocess_popen = FakePopen()

        def failed_communicate(timeout=60):
            return "failed stdout", "failed stderr"

        fake_subprocess_popen.communicate = failed_communicate
        p = mock.patch('subprocess.Popen')
        mock_subprocess_popen = p.start()
        mock_subprocess_popen.return_value = fake_subprocess_popen
        self.addCleanup(p.stop)

        self.assertRaises(exception.EtcdOperationFailure,
                          etcd.snapshot_etcd,
                          "/fake/path/file")
        cmd = ["etcdctl", "--cert", FAKE_ETCD_CLUSTER['certFile'], "--key",
               FAKE_ETCD_CLUSTER['keyFile'], "--cacert",
               FAKE_ETCD_CLUSTER['caFile'], "--endpoints",
               ",".join(FAKE_ETCD_CLUSTER['endpoints']), "snapshot", "save",
               "/fake/path/file"]
        mock_subprocess_popen.assert_called_with(cmd, stdout=-1, stderr=-1,
                                                 env=etcd.ETCD_API_ENV_VAR)

    def test_snapshot_etcd_exception(self):
        mock_get_cluster_information = mock.MagicMock()
        self.mocked_get_cluster_information = mock.patch(
            'sysinv.common.etcd.get_cluster_information',
            mock_get_cluster_information)
        self.mocked_get_cluster_information.start().return_value = \
            FAKE_ETCD_CLUSTER

        mock_os_path_dirname = mock.MagicMock()
        p = mock.patch('os.path.dirname', mock_os_path_dirname)
        p.start().return_value = '/fake/path/'
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        p = mock.patch('subprocess.Popen')
        mock_subprocess_popen = p.start()
        mock_subprocess_popen.side_effect = Exception(
            "failed to execute command")
        self.addCleanup(p.stop)

        self.assertRaises(Exception,  # noqa: H202
                          etcd.snapshot_etcd,
                          "/fake/path/file")
        cmd = ["etcdctl", "--cert", FAKE_ETCD_CLUSTER['certFile'], "--key",
               FAKE_ETCD_CLUSTER['keyFile'], "--cacert",
               FAKE_ETCD_CLUSTER['caFile'], "--endpoints",
               ",".join(FAKE_ETCD_CLUSTER['endpoints']), "snapshot", "save",
               "/fake/path/file"]
        mock_subprocess_popen.assert_called_with(cmd, stdout=-1, stderr=-1,
                                                 env=etcd.ETCD_API_ENV_VAR)

    def test_snapshot_etcd_timedout(self):
        mock_get_cluster_information = mock.MagicMock()
        self.mocked_get_cluster_information = mock.patch(
            'sysinv.common.etcd.get_cluster_information',
            mock_get_cluster_information)
        self.mocked_get_cluster_information.start().return_value = \
            FAKE_ETCD_CLUSTER

        mock_os_path_dirname = mock.MagicMock()
        p = mock.patch('os.path.dirname', mock_os_path_dirname)
        p.start().return_value = '/fake/path/'
        self.addCleanup(p.stop)

        mock_os_path_exists = mock.MagicMock()
        p = mock.patch('os.path.exists', mock_os_path_exists)
        p.start().return_value = True
        self.addCleanup(p.stop)

        fake_subprocess_popen = FakePopen()

        def timed_out_communicate(timeout=60):
            raise TimeoutExpired("fake command", 60, "timed out")

        fake_subprocess_popen.communicate = timed_out_communicate
        p = mock.patch('subprocess.Popen')
        mock_subprocess_popen = p.start()
        mock_subprocess_popen.return_value = fake_subprocess_popen
        self.addCleanup(p.stop)

        self.assertRaises(TimeoutExpired,  # noqa: H202
                          etcd.snapshot_etcd,
                          "/fake/path/file")
        cmd = ["etcdctl", "--cert", FAKE_ETCD_CLUSTER['certFile'], "--key",
               FAKE_ETCD_CLUSTER['keyFile'], "--cacert",
               FAKE_ETCD_CLUSTER['caFile'], "--endpoints",
               ",".join(FAKE_ETCD_CLUSTER['endpoints']), "snapshot", "save",
               "/fake/path/file"]
        mock_subprocess_popen.assert_called_with(cmd, stdout=-1, stderr=-1,
                                                 env=etcd.ETCD_API_ENV_VAR)
        self.assertTrue(fake_subprocess_popen.fake_kill_called)
