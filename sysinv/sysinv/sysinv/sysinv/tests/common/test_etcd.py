#
# Copyright (c) 2023, 2026 Wind River Systems, Inc.
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
from sysinv.common import constants
from sysinv.common import etcd
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import utils


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
                                            'apiVersion: kubeadm.k8s.io/v1beta4\n'
                                            'controllerManager:\n'
                                            '  extraArgs:\n'
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
               ",".join(FAKE_ETCD_CLUSTER['endpoints'])]  \
            + etcd.etcdctl_timeouts(etcd.ETCDCTL_SNAPSHOT_COMMAND_TIMEOUT) \
            + ["snapshot", "save",
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
               ",".join(FAKE_ETCD_CLUSTER['endpoints'])]  \
            + etcd.etcdctl_timeouts(etcd.ETCDCTL_SNAPSHOT_COMMAND_TIMEOUT) \
            + ["snapshot", "save",
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
               ",".join(FAKE_ETCD_CLUSTER['endpoints'])]  \
            + etcd.etcdctl_timeouts(etcd.ETCDCTL_SNAPSHOT_COMMAND_TIMEOUT) \
            + ["snapshot", "save",
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
               ",".join(FAKE_ETCD_CLUSTER['endpoints'])]  \
            + etcd.etcdctl_timeouts(etcd.ETCDCTL_SNAPSHOT_COMMAND_TIMEOUT) \
            + ["snapshot", "save",
               "/fake/path/file"]
        mock_subprocess_popen.assert_called_with(cmd, stdout=-1, stderr=-1,
                                                 env=etcd.ETCD_API_ENV_VAR)
        self.assertTrue(fake_subprocess_popen.fake_kill_called)


class TestEtcdClusterHealth(base.TestCase):
    """Tests for the cluster health accounting used by the health audit.

    Health is reported against the member count the system is configured
    for rather than the count currently registered, and a learner is never
    counted healthy because it does not vote and etcd refuses the health
    RPC against it.
    """

    def _member(self, name, is_learner=False, has_client_url=True):
        return {
            'name': name,
            'isLearner': is_learner,
            'clientURLs': ['https://192.168.206.2:2379'] if has_client_url
            else [],
        }

    def test_get_configured_member_count_simplex(self):
        self.assertEqual(
            etcd.ETCD_MEMBERS_SIMPLEX,
            etcd.get_configured_member_count(constants.SYSTEM_MODE_SIMPLEX))

    def test_get_configured_member_count_duplex(self):
        self.assertEqual(
            etcd.ETCD_MEMBERS_DUPLEX,
            etcd.get_configured_member_count(constants.SYSTEM_MODE_DUPLEX))

    def test_get_configured_member_count_duplex_direct(self):
        self.assertEqual(
            etcd.ETCD_MEMBERS_DUPLEX,
            etcd.get_configured_member_count(
                constants.SYSTEM_MODE_DUPLEX_DIRECT))

    def test_is_voting_member(self):
        self.assertTrue(etcd.is_voting_member(self._member('fixed-0')))
        self.assertFalse(
            etcd.is_voting_member(self._member('controller', is_learner=True)))

    def test_is_voting_member_absent_flag(self):
        # An older etcd may omit the key; absence means a voting member.
        self.assertTrue(etcd.is_voting_member({'name': 'fixed-0'}))

    @mock.patch.object(etcd, 'is_endpoint_healthy', return_value=True)
    @mock.patch.object(etcd, 'get_members')
    def test_cluster_health_all_voters_healthy(self, mock_members, _health):
        mock_members.return_value = [self._member('fixed-0'),
                                     self._member('fixed-1'),
                                     self._member('controller')]
        healthy, total, degraded = etcd.get_cluster_health(
            system_mode=constants.SYSTEM_MODE_DUPLEX)
        self.assertEqual(3, healthy)
        self.assertEqual(3, total)
        self.assertEqual([], degraded)

    @mock.patch.object(etcd, 'is_endpoint_healthy', return_value=True)
    @mock.patch.object(etcd, 'get_members')
    def test_cluster_health_learner_is_not_healthy(self, mock_members,
                                                   _health):
        # A learner replicates but does not vote, so the cluster is degraded
        # even though every member is reachable.
        mock_members.return_value = [self._member('fixed-0'),
                                     self._member('fixed-1'),
                                     self._member('controller',
                                                  is_learner=True)]
        healthy, total, degraded = etcd.get_cluster_health(
            system_mode=constants.SYSTEM_MODE_DUPLEX)
        self.assertEqual(2, healthy)
        self.assertEqual(3, total)
        self.assertEqual(['controller (learner)'], degraded)

    @mock.patch.object(etcd, 'is_endpoint_healthy', return_value=True)
    @mock.patch.object(etcd, 'get_members')
    def test_cluster_health_counts_unregistered_members(self, mock_members,
                                                        _health):
        # While the cluster is being grown the registered count is below the
        # configured count; the total must stay at the configured value.
        mock_members.return_value = [self._member('fixed-0'),
                                     self._member('controller')]
        healthy, total, degraded = etcd.get_cluster_health(
            system_mode=constants.SYSTEM_MODE_DUPLEX)
        self.assertEqual(2, healthy)
        self.assertEqual(3, total)
        self.assertEqual(['1 member(s) not registered'], degraded)

    @mock.patch.object(etcd, 'is_endpoint_healthy', return_value=False)
    @mock.patch.object(etcd, 'get_members')
    def test_cluster_health_unreachable_members(self, mock_members, _health):
        mock_members.return_value = [self._member('fixed-0'),
                                     self._member('fixed-1'),
                                     self._member('controller')]
        healthy, total, degraded = etcd.get_cluster_health(
            system_mode=constants.SYSTEM_MODE_DUPLEX)
        self.assertEqual(0, healthy)
        self.assertEqual(3, total)
        self.assertEqual(['fixed-0', 'fixed-1', 'controller'], degraded)

    @mock.patch.object(etcd, 'is_endpoint_healthy', return_value=True)
    @mock.patch.object(etcd, 'get_members')
    def test_cluster_health_member_without_client_url(self, mock_members,
                                                      _health):
        mock_members.return_value = [self._member('fixed-0'),
                                     self._member('fixed-1'),
                                     self._member('controller',
                                                  has_client_url=False)]
        healthy, total, degraded = etcd.get_cluster_health(
            system_mode=constants.SYSTEM_MODE_DUPLEX)
        self.assertEqual(2, healthy)
        self.assertEqual(3, total)
        self.assertEqual(['controller'], degraded)

    @mock.patch.object(etcd, 'is_endpoint_healthy', return_value=True)
    @mock.patch.object(etcd, 'get_members')
    def test_cluster_health_simplex(self, mock_members, _health):
        mock_members.return_value = [self._member('fixed-0')]
        healthy, total, degraded = etcd.get_cluster_health(
            system_mode=constants.SYSTEM_MODE_SIMPLEX)
        self.assertEqual(1, healthy)
        self.assertEqual(1, total)
        self.assertEqual([], degraded)

    @mock.patch.object(etcd, 'get_members', return_value=[])
    def test_cluster_health_no_members(self, _members):
        # etcdctl unavailable or the cluster is not formed yet.
        healthy, total, degraded = etcd.get_cluster_health(
            system_mode=constants.SYSTEM_MODE_DUPLEX)
        self.assertEqual(0, healthy)
        self.assertEqual(3, total)
        self.assertEqual([], degraded)

    @mock.patch.object(etcd, 'is_endpoint_healthy', return_value=True)
    @mock.patch.object(etcd, 'get_members')
    def test_cluster_health_without_system_mode(self, mock_members, _health):
        # Callers that do not supply a system mode fall back to the
        # registered count, preserving the previous behaviour.
        mock_members.return_value = [self._member('fixed-0'),
                                     self._member('controller')]
        healthy, total, degraded = etcd.get_cluster_health()
        self.assertEqual(2, healthy)
        self.assertEqual(2, total)
        self.assertEqual([], degraded)


class TestEtcdMembership(base.TestCase):
    """Tests for member registration and promotion.

    Registration changes the quorum requirement the moment it happens
    rather than when the member starts, so members are registered as
    learners and only promoted once they are serving.
    """

    def _member(self, name, member_id=1, is_learner=False):
        return {'name': name, 'ID': member_id, 'isLearner': is_learner}

    @mock.patch.object(etcd, 'get_members')
    @mock.patch.object(etcd.utils, 'execute')
    def test_add_member_defaults_to_learner(self, mock_execute, mock_members):
        mock_members.side_effect = [[], [self._member('fixed-1', 0x2a, True)]]

        etcd.add_member('fixed-1', 'https://192.168.206.3:2380')

        args = mock_execute.call_args[0]
        self.assertIn('--learner', args)
        self.assertIn('member', args)
        self.assertIn('add', args)

    @mock.patch.object(etcd, 'get_members')
    @mock.patch.object(etcd.utils, 'execute')
    def test_add_member_as_voter_when_asked(self, mock_execute, mock_members):
        mock_members.side_effect = [[], [self._member('fixed-1', 0x2a)]]

        etcd.add_member('fixed-1', 'https://192.168.206.3:2380',
                        learner=False)

        self.assertNotIn('--learner', mock_execute.call_args[0])

    @mock.patch.object(etcd, 'get_members')
    @mock.patch.object(etcd.utils, 'execute')
    def test_add_member_is_idempotent(self, mock_execute, mock_members):
        mock_members.return_value = [self._member('fixed-1', 0x2a, True)]

        member_id = etcd.add_member('fixed-1', 'https://192.168.206.3:2380')

        self.assertEqual('2a', member_id)
        mock_execute.assert_not_called()

    def _unstarted(self, peer_url, member_id=0x85cc):
        """A member registered but not started: etcd has not learned its name.

        This is the shape seen on lab unr2603dx:
          | 85ccd830c19bea33 | unstarted | | https://192.168.206.2:2380 | | true |
        """
        return {'name': '', 'ID': member_id, 'isLearner': True,
                'peerURLs': [peer_url]}

    @mock.patch.object(etcd, 'get_members')
    @mock.patch.object(etcd.utils, 'execute')
    def test_add_member_treats_an_unstarted_member_as_present(
            self, mock_execute, mock_members):
        # Registered on an earlier pass, not yet started, so no name. A
        # name-only check reported it absent and the add was retried, which
        # etcd rejects for the duplicate peer URL.
        peer_url = 'https://192.168.206.2:2380'
        mock_members.return_value = [self._unstarted(peer_url)]

        member_id = etcd.add_member('fixed-0', peer_url)

        self.assertEqual('85cc', member_id)
        mock_execute.assert_not_called()

    @mock.patch.object(etcd, 'get_members')
    @mock.patch.object(etcd.utils, 'execute')
    def test_add_member_returns_the_id_of_a_member_with_no_name_yet(
            self, mock_execute, mock_members):
        # Post-add: the member exists but has not started, so it is only
        # identifiable by peer URL. This previously raised "not present after
        # add", so the caller never started the member, the member never
        # acquired a name, and the audit retried forever.
        peer_url = 'https://192.168.206.2:2380'
        mock_members.side_effect = [[], [self._unstarted(peer_url)]]

        member_id = etcd.add_member('fixed-0', peer_url)

        self.assertEqual('85cc', member_id)
        mock_execute.assert_called_once()

    @mock.patch.object(etcd, 'get_members')
    @mock.patch.object(etcd.utils, 'execute')
    def test_add_member_raises_when_the_member_is_really_absent(
            self, mock_execute, mock_members):
        # A genuine failure must still raise; the peer URL is named so the
        # message identifies the member that has no name.
        mock_members.side_effect = [[], []]

        self.assertRaises(exception.SysinvException, etcd.add_member,
                          'fixed-0', 'https://192.168.206.2:2380')

    @mock.patch.object(etcd, 'get_members')
    @mock.patch.object(etcd.utils, 'execute')
    def test_remove_member_removes_an_unstarted_member_by_peer_url(
            self, mock_execute, mock_members):
        """A rollback has to clear members that never started.

        Those carry no name, so a name-only lookup reported them absent and
        the removal did nothing, leaving a stale member registered.
        """
        peer_url = 'https://192.168.206.2:2380'
        mock_members.return_value = [self._unstarted(peer_url)]

        etcd.remove_member('fixed-0', peer_url=peer_url)

        args = mock_execute.call_args[0]
        self.assertIn('remove', args)
        self.assertIn('85cc', args)

    @mock.patch.object(etcd, 'get_members')
    @mock.patch.object(etcd.utils, 'execute')
    def test_remove_member_without_peer_url_misses_an_unstarted_member(
            self, mock_execute, mock_members):
        # Documents the behaviour the caller must avoid: with no peer URL an
        # unstarted member is invisible and the removal is a no-op.
        mock_members.return_value = [
            self._unstarted('https://192.168.206.2:2380')]

        etcd.remove_member('fixed-0')

        mock_execute.assert_not_called()

    @mock.patch.object(etcd, 'get_members')
    def test_find_member_matches_name_or_peer_url(self, mock_members):
        peer_url = 'https://192.168.206.2:2380'
        mock_members.return_value = [self._unstarted(peer_url)]

        self.assertIsNone(etcd.find_member('fixed-0'))
        self.assertIsNotNone(etcd.find_member('fixed-0', peer_url=peer_url))
        self.assertIsNone(
            etcd.find_member('fixed-0', peer_url='https://192.168.206.9:2380'))

    @mock.patch.object(etcd, 'get_members')
    @mock.patch.object(etcd.utils, 'execute')
    def test_add_member_rejects_a_member_with_no_id(
            self, mock_execute, mock_members):
        # '0' matches no member, and the ID is passed to promote_member() and
        # member remove, so a placeholder would act against nothing.
        peer_url = 'https://192.168.206.2:2380'
        mock_members.return_value = [
            {'name': '', 'ID': 0, 'isLearner': True, 'peerURLs': [peer_url]}]

        self.assertRaises(exception.SysinvException, etcd.add_member,
                          'fixed-0', peer_url)

    @mock.patch.object(etcd, 'get_members')
    @mock.patch.object(etcd.utils, 'execute')
    def test_promote_member(self, mock_execute, mock_members):
        mock_members.return_value = [self._member('fixed-1', 0x2a, True)]

        etcd.promote_member('fixed-1')

        args = mock_execute.call_args[0]
        self.assertIn('promote', args)
        self.assertIn('2a', args)

    @mock.patch.object(etcd, 'get_members')
    @mock.patch.object(etcd.utils, 'execute')
    def test_promote_member_already_voting(self, mock_execute, mock_members):
        mock_members.return_value = [self._member('fixed-1', 0x2a)]

        etcd.promote_member('fixed-1')

        mock_execute.assert_not_called()

    @mock.patch.object(etcd, 'get_members')
    def test_promote_member_absent(self, mock_members):
        mock_members.return_value = [self._member('fixed-0', 0x1)]

        self.assertRaises(exception.SysinvException,
                          etcd.promote_member, 'fixed-1')

    @mock.patch.object(etcd, 'get_members')
    @mock.patch.object(etcd.utils, 'execute')
    def test_promote_member_failure_raises(self, mock_execute, mock_members):
        mock_members.return_value = [self._member('fixed-1', 0x2a, True)]
        mock_execute.side_effect = Exception('etcdserver: can only promote a '
                                             'learner member which is in sync')

        self.assertRaises(exception.SysinvException,
                          etcd.promote_member, 'fixed-1')


class TestEtcdUrlFormatting(base.TestCase):
    """Tests for RFC 2732 formatting of etcd member URLs.

    An unbracketed IPv6 address is not a valid "host:port". etcd rejects
    such a URL outright rather than interpreting it, so every address has
    to be formatted before a port is appended. IPv4 is unaffected, which
    is why the omission is invisible on an IPv4 deployment.
    """

    def _peer_url(self, address):
        return "https://%s:%s" % (utils.format_url_address(address),
                                  etcd.ETCD_PEER_PORT)

    def _client_url(self, address):
        return "https://%s:%s" % (utils.format_url_address(address),
                                  etcd.ETCD_PORT)

    def test_ipv4_client_url_is_unchanged(self):
        self.assertEqual('https://10.10.10.10:2379',
                         self._client_url('10.10.10.10'))

    def test_ipv4_peer_url_is_unchanged(self):
        self.assertEqual('https://10.10.10.10:2380',
                         self._peer_url('10.10.10.10'))

    def test_ipv6_client_url_is_bracketed(self):
        self.assertEqual('https://[2001:db8::1]:2379',
                         self._client_url('2001:db8::1'))

    def test_ipv6_peer_url_is_bracketed(self):
        self.assertEqual('https://[2001:db8::1]:2380',
                         self._peer_url('2001:db8::1'))

    def test_already_bracketed_ipv6_is_not_double_bracketed(self):
        # netaddr rejects a bracketed literal, and format_url_address
        # returns the input untouched, so re-formatting is safe.
        self.assertEqual('https://[2001:db8::1]:2379',
                         self._client_url('[2001:db8::1]'))

    def test_ipv6_address_seen_on_hardware(self):
        # The address that exposed this on an IPv6 lab: unbracketed it
        # renders https://aefd:205::2:2379, which etcd refuses with
        # 'URL address does not have the form "host:port"'.
        self.assertEqual('https://[aefd:205::2]:2379',
                         self._client_url('aefd:205::2'))
        self.assertEqual('https://[aefd:205::2]:2380',
                         self._peer_url('aefd:205::2'))


class EtcdEndpointResolutionTestCase(base.TestCase):
    """The cluster must be reachable when nothing listens on loopback.

    Loopback is served by the fixed instance, not the floating one. During an
    upgrade activate the fixed instances are deliberately not started, so a
    helper that assumes loopback finds nothing listening and every membership
    operation fails with connection refused.
    """

    def test_etcdctl_base_resolves_cluster_endpoints_when_none_given(self):
        with mock.patch.object(etcd, 'get_cluster_endpoints',
                               return_value='https://192.168.206.1:2379'):
            args = etcd._etcdctl_base()
        self.assertIn('https://192.168.206.1:2379', args)
        self.assertNotIn(etcd.ETCD_LOCAL_ENDPOINT, args)

    def test_etcdctl_base_honours_an_explicit_endpoint(self):
        args = etcd._etcdctl_base('https://192.168.206.3:2379')
        self.assertIn('https://192.168.206.3:2379', args)

    def test_cluster_endpoints_never_returns_a_name(self):
        # The etcd certificates carry IP subjectAltNames and no DNS names, so a
        # hostname endpoint fails verification against every member.
        with mock.patch.object(etcd, '_resolve_name',
                               side_effect=lambda n: {
                                   'controller-cluster-host': '192.168.206.1',
                                   'controller-0-cluster-host': '192.168.206.2',
                                   'controller-1-cluster-host': '192.168.206.3',
                               }.get(n)):
            endpoints = etcd.get_cluster_endpoints()
        for name in etcd.ETCD_CLUSTER_HOST_NAMES:
            self.assertNotIn(name, endpoints)
        self.assertIn('192.168.206.1', endpoints)

    def test_cluster_endpoints_deduplicates_simplex(self):
        # On simplex the floating and controller-0 names are the same address.
        with mock.patch.object(etcd, '_resolve_name',
                               side_effect=lambda n: {
                                   'controller-cluster-host': '192.168.206.1',
                                   'controller-0-cluster-host': '192.168.206.1',
                               }.get(n)):
            endpoints = etcd.get_cluster_endpoints()
        self.assertEqual('https://192.168.206.1:2379', endpoints)

    def test_member_exists_finds_an_unstarted_learner_by_peer_url(self):
        # A registered member that has not started carries no name.
        members = [{'ID': 1, 'name': '',
                    'peerURLs': ['https://192.168.206.1:2380'],
                    'isLearner': True}]
        with mock.patch.object(etcd, 'get_members', return_value=members):
            self.assertFalse(etcd.member_exists('controller'))
            self.assertTrue(etcd.member_exists(
                'controller', peer_url='https://192.168.206.1:2380'))
